//! Broker-backed dispatch handling behind explicit verification and persistence seams.

use std::io::Write;

use buzz_core::ci::{CiJobState, CI_MAX_SAFE_INTEGER};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::control::{
    admit_request, complete_attempt, AdmitRequestInput, AdmittedLease, AuthenticatedCiRequest,
    BoundedExecutionEvidence, BrokerTransport, CiWorkflowPolicy, ExecutionBackendError,
};
use crate::transport::{
    encode_frame, ArtifactEvidence, AttemptFailureReason, AttemptOutcome, ExecuteJob, LogEvidence,
    ReceiptWriteError, ReceiptWriter, RefusalReason, RunnerReceipt, RunnerRequest,
    SelectedJobAttempt, RECEIPT_SET_DIGEST_DOMAIN, RUNNER_TRANSPORT_SCHEMA_VERSION,
};
use crate::{
    build_teardown_attestation, BrokerManifestBinding, ControlError, RequestAuthorizer,
    TeardownLeaseReceipt,
};

const MAX_ARTIFACTS_PER_JOB: usize = 128;
const MAX_ARTIFACT_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_PATH_BYTES: usize = 4096;
const MAX_MEDIA_TYPE_BYTES: usize = 256;
const MAX_LOGICAL_NAME_BYTES: usize = 1024;
const MAX_REASON_BYTES: usize = 1024;

/// Request facts established by signature, channel, workflow, and manifest verification.
#[derive(Clone, Debug)]
pub struct VerifiedDispatch {
    /// Dedicated signer that controld will use for status publication.
    pub relay_signer: String,
    /// One reviewed broker binding per request job, in request order.
    pub jobs: Vec<VerifiedJob>,
}

/// Trusted policy and broker binding for one selected job.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedJob {
    pub workflow_policy: CiWorkflowPolicy,
    pub binding: BrokerManifestBinding,
}

/// Verification seam. Production composition must validate the signed relay event and broker manifest.
pub trait DispatchVerifier {
    fn verify(&self, request: &RunnerRequest, now: u64) -> Result<VerifiedDispatch, RefusalReason>;
}

/// Complete unprivileged output for one broker-admitted job.
#[derive(Clone, Debug)]
pub struct JobExecution {
    pub state: CiJobState,
    pub reason: Option<String>,
    pub started_at: u64,
    pub finished_at: u64,
    pub log: LogEvidence,
    pub artifacts: Vec<ArtifactEvidence>,
    pub broker_evidence: BoundedExecutionEvidence,
}

/// Unprivileged executor. It receives only a reviewed job and an opaque broker lease.
pub trait JobExecutor {
    fn execute(
        &mut self,
        job: &ExecuteJob,
        lease: &AdmittedLease,
        deadline_at: u64,
    ) -> Result<JobExecution, ExecutionBackendError>;
}

/// Atomic replay journal for a complete terminal receipt set.
pub trait ReceiptJournal {
    fn load(
        &self,
        dispatch_id: &str,
        request_frame_digest: [u8; 32],
    ) -> Result<Option<Vec<RunnerReceipt>>, ReceiptJournalError>;

    fn store_if_absent(
        &mut self,
        dispatch_id: &str,
        request_frame_digest: [u8; 32],
        receipts: &[RunnerReceipt],
    ) -> Result<JournalWrite, ReceiptJournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalWrite {
    Written,
    Existing(Vec<RunnerReceipt>),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("runner receipt journal failed")]
pub struct ReceiptJournalError;

/// Production handler assembled from explicit verification, broker, execution, and journal parts.
pub struct BrokerAttemptHandler<A, V, T, E, J> {
    authorizer: A,
    verifier: V,
    broker: T,
    executor: E,
    journal: J,
}

impl<A, V, T, E, J> BrokerAttemptHandler<A, V, T, E, J> {
    pub const fn new(authorizer: A, verifier: V, broker: T, executor: E, journal: J) -> Self {
        Self {
            authorizer,
            verifier,
            broker,
            executor,
            journal,
        }
    }

    pub fn into_parts(self) -> (A, V, T, E, J) {
        (
            self.authorizer,
            self.verifier,
            self.broker,
            self.executor,
            self.journal,
        )
    }
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("receipt journal failed")]
    Journal(#[from] ReceiptJournalError),
    #[error("stored receipt set conflicts with reconstructed receipts")]
    JournalConflict,
    #[error("receipt set could not be encoded")]
    Receipt(#[from] ReceiptWriteError),
    #[error("receipt set frame could not be encoded")]
    Frame(#[from] crate::transport::FrameError),
}

impl<A, V, T, E, J> BrokerAttemptHandler<A, V, T, E, J>
where
    A: RequestAuthorizer,
    V: DispatchVerifier,
    T: BrokerTransport,
    E: JobExecutor,
    J: ReceiptJournal,
{
    /// Reconcile a prior dispatch or execute it once, then replay its exact terminal receipt set.
    pub fn handle(
        &mut self,
        request: RunnerRequest,
        request_frame_digest: [u8; 32],
        writer: &mut impl Write,
    ) -> Result<(), HandlerError> {
        let dispatch_id = request.refusal_identity().0.to_owned();
        if let Some(stored) = self.journal.load(&dispatch_id, request_frame_digest)? {
            return write_receipts(writer, &stored).map_err(HandlerError::Receipt);
        }

        let receipts = self.build_receipts(&request)?;
        let canonical = match self.journal.store_if_absent(
            &dispatch_id,
            request_frame_digest,
            receipts.as_slice(),
        )? {
            JournalWrite::Written => receipts,
            JournalWrite::Existing(existing) if existing == receipts => existing,
            JournalWrite::Existing(_) => return Err(HandlerError::JournalConflict),
        };
        write_receipts(writer, &canonical).map_err(HandlerError::Receipt)
    }

    fn build_receipts(
        &mut self,
        request: &RunnerRequest,
    ) -> Result<Vec<RunnerReceipt>, HandlerError> {
        let RunnerRequest::ExecuteAttempt {
            dispatch_id,
            request_event_id,
            request_event,
            signed_request_digest,
            assigned_at,
            deadline_at,
            jobs,
            ..
        } = request;
        let identity = ReceiptIdentity {
            dispatch_id,
            request_event_id,
            run_id: request_event.run_id.as_str(),
            attempt: request_event.attempt,
        };

        let verified = match self.verifier.verify(request, *assigned_at) {
            Ok(verified) if verified.jobs.len() == jobs.len() => verified,
            Ok(_) => return Ok(vec![identity.refused(RefusalReason::InvalidManifest)]),
            Err(reason) => return Ok(vec![identity.refused(reason)]),
        };
        let signed_request_digest = match decode_digest(signed_request_digest) {
            Some(digest) => digest,
            None => return Ok(vec![identity.refused(RefusalReason::InvalidRequest)]),
        };

        let mut receipts = vec![RunnerReceipt::Accepted {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: dispatch_id.clone(),
            request_event_id: request_event_id.clone(),
            run_id: request_event.run_id.clone(),
            attempt: request_event.attempt,
            receipt_sequence: 1,
            accepted_at: *assigned_at,
        }];
        let mut sequence = 2_u64;
        let mut selected = Vec::with_capacity(jobs.len());
        let mut teardown_receipts = Vec::with_capacity(jobs.len());
        let mut finished_at = *assigned_at;

        for (job, verified_job) in jobs.iter().zip(verified.jobs.iter()) {
            if *deadline_at <= finished_at {
                push_infrastructure_terminal(
                    &mut receipts,
                    identity,
                    sequence,
                    *deadline_at,
                    selected,
                    AttemptFailureReason::DeadlineExceeded,
                )?;
                return Ok(receipts);
            }
            let input = AdmitRequestInput {
                request: AuthenticatedCiRequest::new(request_event, signed_request_digest),
                workflow_policy: verified_job.workflow_policy,
                binding: verified_job.binding,
                now: finished_at,
            };
            let lease = match admit_request(input, &self.authorizer, &mut self.broker) {
                Ok(lease) => lease,
                Err(error) => {
                    push_infrastructure_terminal(
                        &mut receipts,
                        identity,
                        sequence,
                        finished_at,
                        selected,
                        attempt_failure(error),
                    )?;
                    return Ok(receipts);
                }
            };
            let execution = match self.executor.execute(job, &lease, *deadline_at) {
                Ok(execution) if valid_execution(job, &execution, *deadline_at) => execution,
                Ok(_) => {
                    push_infrastructure_terminal(
                        &mut receipts,
                        identity,
                        sequence,
                        finished_at,
                        selected,
                        AttemptFailureReason::EvidenceInvalid,
                    )?;
                    return Ok(receipts);
                }
                Err(error) => {
                    push_infrastructure_terminal(
                        &mut receipts,
                        identity,
                        sequence,
                        finished_at,
                        selected,
                        execution_failure(error),
                    )?;
                    return Ok(receipts);
                }
            };
            let terminal =
                match complete_attempt(lease, execution.broker_evidence, &mut self.broker) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        push_infrastructure_terminal(
                            &mut receipts,
                            identity,
                            sequence,
                            execution.finished_at,
                            selected,
                            attempt_failure(error),
                        )?;
                        return Ok(receipts);
                    }
                };

            receipts.push(RunnerReceipt::JobStarted {
                schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
                dispatch_id: dispatch_id.clone(),
                request_event_id: request_event_id.clone(),
                run_id: request_event.run_id.clone(),
                attempt: request_event.attempt,
                receipt_sequence: sequence,
                job_id: job.job_id.clone(),
                job_attempt: job.attempt,
                started_at: execution.started_at,
            });
            sequence += 1;
            receipts.push(RunnerReceipt::JobFinished {
                schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
                dispatch_id: dispatch_id.clone(),
                request_event_id: request_event_id.clone(),
                run_id: request_event.run_id.clone(),
                attempt: request_event.attempt,
                receipt_sequence: sequence,
                job_id: job.job_id.clone(),
                job_attempt: job.attempt,
                state: execution.state,
                reason: execution.reason,
                started_at: execution.started_at,
                finished_at: execution.finished_at,
                log: execution.log,
                artifacts: execution.artifacts,
            });
            sequence += 1;
            finished_at = finished_at.max(execution.finished_at);
            selected.push(SelectedJobAttempt {
                job_id: job.job_id.clone(),
                attempt: job.attempt,
            });
            teardown_receipts.push(TeardownLeaseReceipt {
                job_id: job.job_id.clone(),
                job_manifest_digest: verified_job.binding.job_manifest_digest,
                receipt: terminal,
            });
        }

        let selected_pairs: Vec<_> = selected
            .iter()
            .map(|selected| (selected.job_id.clone(), selected.attempt))
            .collect();
        let teardown = match build_teardown_attestation(
            request_event_id,
            signed_request_digest,
            request_event,
            &verified.relay_signer,
            &selected_pairs,
            teardown_receipts,
        ) {
            Ok(teardown) => teardown,
            Err(_) => {
                push_infrastructure_terminal(
                    &mut receipts,
                    identity,
                    sequence,
                    finished_at,
                    selected,
                    AttemptFailureReason::TeardownUnproven,
                )?;
                return Ok(receipts);
            }
        };
        let digest = receipt_set_digest(&receipts)?;
        receipts.push(RunnerReceipt::AttemptFinished {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: dispatch_id.clone(),
            request_event_id: request_event_id.clone(),
            run_id: request_event.run_id.clone(),
            attempt: request_event.attempt,
            receipt_sequence: sequence,
            outcome: AttemptOutcome::Completed,
            reason: None,
            finished_at,
            selected_job_attempts: selected,
            teardown_attestation: Some(teardown),
            receipt_set_digest: digest,
        });
        Ok(receipts)
    }
}

#[derive(Clone, Copy)]
struct ReceiptIdentity<'a> {
    dispatch_id: &'a str,
    request_event_id: &'a str,
    run_id: &'a str,
    attempt: u32,
}

impl ReceiptIdentity<'_> {
    fn refused(self, reason: RefusalReason) -> RunnerReceipt {
        RunnerReceipt::Refused {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: self.dispatch_id.to_owned(),
            request_event_id: self.request_event_id.to_owned(),
            run_id: self.run_id.to_owned(),
            attempt: self.attempt,
            receipt_sequence: 1,
            reason,
        }
    }
}

fn push_infrastructure_terminal(
    receipts: &mut Vec<RunnerReceipt>,
    identity: ReceiptIdentity<'_>,
    sequence: u64,
    finished_at: u64,
    selected_job_attempts: Vec<SelectedJobAttempt>,
    reason: AttemptFailureReason,
) -> Result<(), crate::transport::FrameError> {
    let digest = receipt_set_digest(receipts)?;
    receipts.push(RunnerReceipt::AttemptFinished {
        schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
        dispatch_id: identity.dispatch_id.to_owned(),
        request_event_id: identity.request_event_id.to_owned(),
        run_id: identity.run_id.to_owned(),
        attempt: identity.attempt,
        receipt_sequence: sequence,
        outcome: AttemptOutcome::InfrastructureFailure,
        reason: Some(reason),
        finished_at,
        selected_job_attempts,
        teardown_attestation: None,
        receipt_set_digest: digest,
    });
    Ok(())
}

fn receipt_set_digest(receipts: &[RunnerReceipt]) -> Result<String, crate::transport::FrameError> {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_SET_DIGEST_DOMAIN);
    for receipt in receipts {
        hasher.update(encode_frame(receipt)?);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_receipts(
    writer: &mut impl Write,
    receipts: &[RunnerReceipt],
) -> Result<(), ReceiptWriteError> {
    let mut writer = ReceiptWriter::new(writer);
    for receipt in receipts {
        writer.send(receipt)?;
    }
    Ok(())
}

fn valid_execution(job: &ExecuteJob, execution: &JobExecution, deadline_at: u64) -> bool {
    execution.state.is_terminal()
        && execution.started_at > 0
        && execution.finished_at >= execution.started_at
        && execution.finished_at <= deadline_at
        && execution.finished_at <= CI_MAX_SAFE_INTEGER
        && execution
            .reason
            .as_ref()
            .is_none_or(|reason| reason.len() <= MAX_REASON_BYTES)
        && !execution.log.truncated
        && execution.log.byte_length <= execution.log.cap_bytes
        && execution.log.relative_path.len() <= MAX_EVIDENCE_PATH_BYTES
        && is_relative_evidence_path(&execution.log.relative_path)
        && is_lower_hex(&execution.log.sha256, 64)
        && execution.artifacts.len() <= MAX_ARTIFACTS_PER_JOB
        && execution
            .artifacts
            .iter()
            .try_fold(0_usize, |total, artifact| {
                total
                    .checked_add(artifact.relative_path.len())?
                    .checked_add(artifact.sha256.len())?
                    .checked_add(artifact.media_type.len())?
                    .checked_add(artifact.logical_name.len())
            })
            .is_some_and(|total| total <= MAX_ARTIFACT_DESCRIPTOR_BYTES)
        && execution.artifacts.iter().all(|artifact| {
            artifact.relative_path.len() <= MAX_EVIDENCE_PATH_BYTES
                && artifact.media_type.len() <= MAX_MEDIA_TYPE_BYTES
                && artifact.logical_name.len() <= MAX_LOGICAL_NAME_BYTES
                && is_relative_evidence_path(&artifact.relative_path)
                && is_lower_hex(&artifact.sha256, 64)
                && !artifact.media_type.is_empty()
                && !artifact.logical_name.is_empty()
        })
        && job.attempt > 0
}

fn is_relative_evidence_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

fn attempt_failure(error: ControlError) -> AttemptFailureReason {
    match error {
        ControlError::ExecutionBackendUnavailable | ControlError::BrokerUnavailable => {
            AttemptFailureReason::BackendUnavailable
        }
        ControlError::ExpiredRequest => AttemptFailureReason::DeadlineExceeded,
        ControlError::InvalidExecutionEvidence | ControlError::InvalidBrokerResponse => {
            AttemptFailureReason::EvidenceInvalid
        }
        _ => AttemptFailureReason::ReconciliationFailed,
    }
}

fn execution_failure(error: ExecutionBackendError) -> AttemptFailureReason {
    match error {
        ExecutionBackendError::Unavailable => AttemptFailureReason::BackendUnavailable,
        ExecutionBackendError::Failed => AttemptFailureReason::ExecutionFailed,
        ExecutionBackendError::MissingEvidence => AttemptFailureReason::EvidenceInvalid,
        ExecutionBackendError::DeadlineExceeded => AttemptFailureReason::DeadlineExceeded,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;

    use buzz_ci_broker_protocol::{
        AdmitAttemptRequest, BrokerResponse, BrokerState, CompleteAttemptRequest, Conclusion,
        GetAttemptRequest, ResponseCode, TrustClass,
    };
    use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};

    use super::*;
    use crate::transport::{read_frame, write_frame, FrameError, MAX_FRAME_BODY_BYTES};

    struct Allow;

    impl RequestAuthorizer for Allow {
        fn authorize(&self, _request: &CiRequestEnvelope) -> bool {
            true
        }
    }

    struct Verify;

    impl DispatchVerifier for Verify {
        fn verify(
            &self,
            request: &RunnerRequest,
            _now: u64,
        ) -> Result<VerifiedDispatch, RefusalReason> {
            let RunnerRequest::ExecuteAttempt { jobs, .. } = request;
            Ok(VerifiedDispatch {
                relay_signer: "77".repeat(32),
                jobs: jobs
                    .iter()
                    .map(|job| VerifiedJob {
                        workflow_policy: CiWorkflowPolicy::new(
                            Some(TrustClass::AcceptedReviewed),
                            false,
                        ),
                        binding: BrokerManifestBinding {
                            signed_request_digest: [0x12; 32],
                            audience_digest: decode_digest(&job.audience_digest).unwrap(),
                            job_manifest_digest: decode_digest(&job.job_manifest_digest).unwrap(),
                            isolation_profile_digest: decode_digest(&job.isolation_profile_digest)
                                .unwrap(),
                        },
                    })
                    .collect(),
            })
        }
    }

    #[derive(Default)]
    struct MemoryJournal(HashMap<String, ([u8; 32], Vec<RunnerReceipt>)>);

    impl ReceiptJournal for MemoryJournal {
        fn load(
            &self,
            dispatch_id: &str,
            request_frame_digest: [u8; 32],
        ) -> Result<Option<Vec<RunnerReceipt>>, ReceiptJournalError> {
            match self.0.get(dispatch_id) {
                Some((stored_digest, receipts)) if *stored_digest == request_frame_digest => {
                    Ok(Some(receipts.clone()))
                }
                Some(_) => Err(ReceiptJournalError),
                None => Ok(None),
            }
        }

        fn store_if_absent(
            &mut self,
            dispatch_id: &str,
            request_frame_digest: [u8; 32],
            receipts: &[RunnerReceipt],
        ) -> Result<JournalWrite, ReceiptJournalError> {
            if let Some((stored_digest, existing)) = self.0.get(dispatch_id) {
                if *stored_digest != request_frame_digest {
                    return Err(ReceiptJournalError);
                }
                return Ok(JournalWrite::Existing(existing.clone()));
            }
            self.0.insert(
                dispatch_id.to_owned(),
                (request_frame_digest, receipts.to_vec()),
            );
            Ok(JournalWrite::Written)
        }
    }

    #[derive(Default)]
    struct Broker {
        lease: Option<AdmitAttemptRequest>,
    }

    impl BrokerTransport for Broker {
        fn admit(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
            self.lease = Some(request);
            Ok(BrokerResponse {
                code: ResponseCode::Ok,
                retry_after_millis: 0,
                attempt_id: [9; 16],
                run_id: request.run_id,
                accepted_request_digest: request.signed_request_digest,
                job_manifest_digest: request.job_manifest_digest,
                tip_oid: Some(request.tip_oid),
                broker_state: BrokerState::Leased,
                conclusion: Conclusion::None,
                terminal_reason: 0,
                generation: 1,
                accepted_at: request.issued_at,
                updated_at: request.issued_at,
                lease_generation: 1,
                evidence_set_digest: [0; 32],
                teardown_digest: [0; 32],
                attempt: request.attempt,
            })
        }

        fn get(&mut self, _request: GetAttemptRequest) -> Result<BrokerResponse, ControlError> {
            Err(ControlError::TransportFailure)
        }

        fn complete(
            &mut self,
            request: CompleteAttemptRequest,
        ) -> Result<BrokerResponse, ControlError> {
            let lease = self.lease.unwrap();
            Ok(BrokerResponse {
                code: ResponseCode::Ok,
                retry_after_millis: 0,
                attempt_id: request.lease_id,
                run_id: request.run_id,
                accepted_request_digest: request.signed_request_digest,
                job_manifest_digest: lease.job_manifest_digest,
                tip_oid: Some(lease.tip_oid),
                broker_state: BrokerState::Terminal,
                conclusion: request.advisory_conclusion,
                terminal_reason: 0,
                generation: request.lease_generation,
                accepted_at: lease.issued_at,
                updated_at: request.terminal_at,
                lease_generation: request.lease_generation,
                evidence_set_digest: request.evidence_set_digest,
                teardown_digest: [8; 32],
                attempt: request.attempt,
            })
        }
    }

    struct Execute;

    impl JobExecutor for Execute {
        fn execute(
            &mut self,
            _job: &ExecuteJob,
            _lease: &AdmittedLease,
            _deadline_at: u64,
        ) -> Result<JobExecution, ExecutionBackendError> {
            Ok(JobExecution {
                state: CiJobState::Success,
                reason: None,
                started_at: 11,
                finished_at: 12,
                log: LogEvidence {
                    relative_path: "dispatch/test/attempt-1.log".into(),
                    sha256: "aa".repeat(32),
                    byte_length: 4,
                    cap_bytes: 1024,
                    truncated: false,
                },
                artifacts: Vec::new(),
                broker_evidence: BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 12)
                    .unwrap(),
            })
        }
    }

    fn request() -> RunnerRequest {
        RunnerRequest::ExecuteAttempt {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: "123e4567-e89b-12d3-a456-426614174010".into(),
            request_event_id: "11".repeat(32),
            request_event: CiRequestEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_type: CiRequestType::Run,
                target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
                pr_root_event_id: "33".repeat(32),
                pr_update_event_id: None,
                source_clone_url: "https://relay.example/git/repo".into(),
                immutable_source_ref: "refs/nostr/source".into(),
                tip_oid: "44".repeat(20),
                source_branch: "feature".into(),
                base_ref: "refs/heads/main".into(),
                base_oid: "55".repeat(20),
                workflow_id: "ci".into(),
                workflow_digest: "66".repeat(32),
                job_ids: vec!["test".into()],
                run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
                attempt: 1,
                parent_attempt: None,
                parent_run_id: None,
                trigger_event_id: "33".repeat(32),
                actor: "77".repeat(32),
                timeout_seconds: 10,
                idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
                issued_at: 10,
                expires_at: 20,
            },
            signed_request_digest: "12".repeat(32),
            assigned_at: 10,
            deadline_at: 20,
            jobs: vec![ExecuteJob {
                job_id: "test".into(),
                attempt: 1,
                parent_attempt: 0,
                workflow_path: ".github/workflows/ci.yml".into(),
                job_manifest: "{}".into(),
                job_manifest_digest: "99".repeat(32),
                audience_digest: "aa".repeat(32),
                isolation_profile_digest: "bb".repeat(32),
            }],
        }
    }

    #[test]
    fn same_frame_replays_but_a_second_client_with_divergent_frame_is_rejected() {
        let mut handler = BrokerAttemptHandler::new(
            Allow,
            Verify,
            Broker::default(),
            Execute,
            MemoryJournal::default(),
        );
        let mut first = Vec::new();
        handler.handle(request(), [0x42; 32], &mut first).unwrap();
        let mut replay = Vec::new();
        handler.handle(request(), [0x42; 32], &mut replay).unwrap();
        assert_eq!(first, replay);

        let mut cursor = Cursor::new(first);
        let mut kinds = Vec::new();
        let mut terminal_outcome = None;
        loop {
            match read_frame::<RunnerReceipt>(&mut cursor) {
                Ok(receipt) => {
                    if let RunnerReceipt::AttemptFinished { outcome, .. } = &receipt {
                        terminal_outcome = Some(*outcome);
                    }
                    kinds.push((receipt.receipt_sequence(), receipt.is_terminal()));
                    if receipt.is_terminal() {
                        break;
                    }
                }
                Err(error) => panic!("receipt frame: {error}"),
            }
        }
        assert_eq!(kinds, vec![(1, false), (2, false), (3, false), (4, true)]);
        assert_eq!(terminal_outcome, Some(AttemptOutcome::Completed));

        assert!(matches!(
            handler.handle(request(), [0x43; 32], &mut Vec::new()),
            Err(HandlerError::Journal(_))
        ));
    }

    #[test]
    fn execution_descriptor_bounds_are_enforced() {
        let RunnerRequest::ExecuteAttempt { jobs, .. } = request();
        let mut execution = JobExecution {
            state: CiJobState::Success,
            reason: None,
            started_at: 11,
            finished_at: 12,
            log: LogEvidence {
                relative_path: "dispatch/test/attempt-1.log".into(),
                sha256: "aa".repeat(32),
                byte_length: 4,
                cap_bytes: 1024,
                truncated: false,
            },
            artifacts: Vec::new(),
            broker_evidence: BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 12)
                .unwrap(),
        };
        execution.reason = Some("x".repeat(MAX_REASON_BYTES + 1));
        assert!(!valid_execution(&jobs[0], &execution, 20));
        execution.reason = None;
        execution.artifacts.push(ArtifactEvidence {
            relative_path: "artifact.txt".into(),
            sha256: "aa".repeat(32),
            byte_length: 1,
            media_type: "text/plain".into(),
            logical_name: "x".repeat(MAX_LOGICAL_NAME_BYTES + 1),
        });

        assert!(!valid_execution(&jobs[0], &execution, 20));
    }

    #[test]
    fn receipt_digest_propagates_oversized_frame_errors() {
        let receipt = RunnerReceipt::JobFinished {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: "123e4567-e89b-12d3-a456-426614174010".into(),
            request_event_id: "11".repeat(32),
            run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
            attempt: 1,
            receipt_sequence: 1,
            job_id: "test".into(),
            job_attempt: 1,
            state: CiJobState::Failure,
            reason: Some("x".repeat(MAX_FRAME_BODY_BYTES)),
            started_at: 11,
            finished_at: 12,
            log: LogEvidence {
                relative_path: "test.log".into(),
                sha256: "aa".repeat(32),
                byte_length: 0,
                cap_bytes: 1,
                truncated: false,
            },
            artifacts: Vec::new(),
        };

        assert!(matches!(
            receipt_set_digest(&[receipt]),
            Err(FrameError::Oversized)
        ));
    }

    #[test]
    fn verifier_refusal_never_contacts_broker() {
        struct Refuse;
        impl DispatchVerifier for Refuse {
            fn verify(
                &self,
                _request: &RunnerRequest,
                _now: u64,
            ) -> Result<VerifiedDispatch, RefusalReason> {
                Err(RefusalReason::Unauthorized)
            }
        }
        let mut handler = BrokerAttemptHandler::new(
            Allow,
            Refuse,
            Broker::default(),
            Execute,
            MemoryJournal::default(),
        );
        let mut bytes = Vec::new();
        handler.handle(request(), [0x42; 32], &mut bytes).unwrap();
        let receipt: RunnerReceipt = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert!(matches!(
            receipt,
            RunnerReceipt::Refused {
                reason: RefusalReason::Unauthorized,
                ..
            }
        ));
        let (_, _, broker, _, _) = handler.into_parts();
        assert!(broker.lease.is_none());
    }

    #[test]
    fn owner_refusal_precedes_broker_admission_and_execution() {
        struct Deny;
        impl RequestAuthorizer for Deny {
            fn authorize(&self, _request: &CiRequestEnvelope) -> bool {
                false
            }
        }
        struct MustNotExecute;
        impl JobExecutor for MustNotExecute {
            fn execute(
                &mut self,
                _job: &ExecuteJob,
                _lease: &AdmittedLease,
                _deadline_at: u64,
            ) -> Result<JobExecution, ExecutionBackendError> {
                panic!("executor called before owner authorization")
            }
        }
        let mut handler = BrokerAttemptHandler::new(
            Deny,
            Verify,
            Broker::default(),
            MustNotExecute,
            MemoryJournal::default(),
        );
        let mut bytes = Vec::new();
        handler.handle(request(), [0x42; 32], &mut bytes).unwrap();
        let (_, _, broker, _, _) = handler.into_parts();
        assert!(broker.lease.is_none());
    }

    #[test]
    fn fixture_request_stays_transport_valid() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request()).unwrap();
        assert!(!bytes.is_empty());
    }
}
