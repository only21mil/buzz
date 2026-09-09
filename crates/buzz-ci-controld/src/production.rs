//! Fail-closed control-plane orchestration for accepted requests.
//!
//! Network clients, key custody, and the runner socket remain injected host
//! seams. This module owns their ordering, durable publication intents, event
//! envelopes, evidence binding, and descriptor-relative output reads.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_core::ci::{
    artifact_reference_tags, check_tags, evidence_finalized_tags, job_status_tags,
    log_reference_tags, run_status_tags, teardown_attestation_tags, validate_signed_ci_event,
    CiArtifactReferenceEnvelope, CiCheckEnvelope, CiConcurrencyGroup, CiEvidenceFinalizedEnvelope,
    CiFinalizedJobAttempt, CiJobState, CiJobStatusEnvelope, CiLogReferenceEnvelope,
    CiRequestEnvelope, CiRequestType, CiRunState, CiRunStatusEnvelope, CiSkipPolicy,
    CiTeardownAttestationEnvelope, ValidatedCiEnvelope, CI_SCHEMA_VERSION,
};
use buzz_core::kind::{
    KIND_CI_ARTIFACT_REFERENCE, KIND_CI_CHECK, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::runner_client::{
    AttemptOutcome, PreparedRunnerRequest, RefusalReason, RunnerClient, RunnerConnector,
    ValidatedRunnerResult,
};
use crate::{RunIdentity, RunRecord, RunState, StateError, StoreWrite};

/// One stored, relay-accepted kind-46100 intake item.
#[derive(Clone, Debug)]
pub struct AcceptedRequest {
    pub channel_id: String,
    pub watch_cursor: u64,
    pub event_id: String,
    pub envelope: CiRequestEnvelope,
}

/// Exact frozen request identity required for an acceptance-only poll.
///
/// The binding is checked before any run state, publication intent, runner
/// dispatch, or channel cursor mutation can occur.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRequestBinding {
    pub channel_id: String,
    pub event_id: String,
    pub envelope: CiRequestEnvelope,
}

impl AcceptedRequestBinding {
    fn matches(&self, accepted: &AcceptedRequest) -> bool {
        accepted.channel_id == self.channel_id
            && accepted.event_id == self.event_id
            && accepted.envelope == self.envelope
    }
}

/// Trusted static manifest facts used in signed kind-46102 events.
#[derive(Clone, Debug)]
pub struct JobMetadata {
    pub job_id: String,
    pub name: String,
    pub required: bool,
    pub skip_policy: CiSkipPolicy,
    pub selected_job_instance: String,
    pub also_reruns: Vec<String>,
}

/// Runner-owned log or artifact path and immutable descriptor facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputDescriptor {
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Clone, Debug)]
pub struct ArtifactCompletion {
    pub descriptor: OutputDescriptor,
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
}

/// One terminal job receipt already validated against the runner receipt stream.
#[derive(Clone, Debug)]
pub struct JobCompletion {
    pub metadata: JobMetadata,
    pub attempt: u32,
    pub state: CiJobState,
    pub reason: Option<String>,
    pub started_at: u64,
    pub finished_at: u64,
    pub log: OutputDescriptor,
    pub log_cap_bytes: u64,
    pub artifacts: Vec<ArtifactCompletion>,
}

/// Complete runner terminal result, including independently verifiable teardown.
#[derive(Clone, Debug)]
pub struct AttemptCompletion {
    pub jobs: Vec<JobCompletion>,
    pub teardown: CiTeardownAttestationEnvelope,
    pub finished_at: u64,
}

/// Concrete signed event passed to the relay publisher.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedCiEvent {
    pub event_id: String,
    pub kind: u32,
    pub content: String,
    pub tags: serde_json::Value,
    pub signed_event: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StoredPublication {
    Pending(SignedCiEvent),
    Accepted {
        signed: SignedCiEvent,
        relay_event_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObject {
    pub url: String,
    pub sha256: String,
    pub byte_length: u64,
}

/// One authenticated exact-event relay readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedEventRead {
    pub event: SignedCiEvent,
    pub proof: crate::source::Nip98Proof,
    pub binding: crate::source::Nip98Binding,
}

/// One authenticated, bounded evidence-object readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedObjectRead {
    pub bytes: Vec<u8>,
    pub proof: crate::source::Nip98Proof,
    pub binding: crate::source::Nip98Binding,
}

/// Closed failure of the acceptance-only authenticated export surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportReadError {
    Unavailable,
    Refused,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedEvidenceObject {
    pub name: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedEvidenceExport {
    pub subject: String,
    pub generation: u64,
    pub authorization_digest: String,
    pub request_event_id: String,
    pub run_id: String,
    pub job_id: String,
    pub attempt: u32,
    pub objects: Vec<ExportedEvidenceObject>,
}

/// Relay intake and evidence/publication transport.
pub trait RelayControl {
    type Error;

    fn next_accepted(
        &mut self,
        channel_id: &str,
        after_cursor: u64,
    ) -> Result<Option<AcceptedRequest>, Self::Error>;

    fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error>;

    /// Confirm whether the relay already accepted this exact signed event.
    ///
    /// A durable pending publication may outlive the relay's timestamp window
    /// after an acknowledgement is lost. Callers must reconcile the exact
    /// event before replacing its signature with a fresh one.
    fn publication_exists(&mut self, event: &SignedCiEvent) -> Result<bool, Self::Error>;

    /// Whether `error` is the relay's exact unauthorized-CI-status-signer
    /// refusal of a publish (HTTP 400 `invalid CI envelope: unauthorized CI
    /// status signer`). Only that refusal may be deferred until the
    /// activation's own kind-46107 grant is approved; every other error keeps
    /// its terminal meaning. Implementations without a distinguishable wire
    /// error keep the default.
    fn is_unauthorized_status_signer(&self, _error: &Self::Error) -> bool {
        false
    }

    fn put_log(
        &mut self,
        accepted: &AcceptedRequest,
        job: &JobCompletion,
        bytes: &[u8],
    ) -> Result<StoredObject, Self::Error>;

    fn put_artifact(
        &mut self,
        accepted: &AcceptedRequest,
        job: &JobCompletion,
        artifact: &ArtifactCompletion,
        bytes: &[u8],
    ) -> Result<StoredObject, Self::Error>;

    /// Read one exact CI event through the existing author-bound query path.
    fn read_exact_event(
        &mut self,
        _event_id: &str,
        _kind: u32,
        _author: &str,
    ) -> Result<AuthenticatedEventRead, ExportReadError> {
        Err(ExportReadError::Unavailable)
    }

    /// Read one signed-reference evidence URL with an exact byte ceiling.
    fn read_evidence_object(
        &mut self,
        _url: &str,
        _expected_sha256: &str,
        _expected_bytes: u64,
        _maximum_bytes: u64,
    ) -> Result<AuthenticatedObjectRead, ExportReadError> {
        Err(ExportReadError::Unavailable)
    }
}

/// Dedicated keyholder. Implementations must sign exact content and tags.
pub trait CiSigner {
    type Error;

    fn pubkey(&self) -> &str;
    fn generation(&self) -> u64 {
        0
    }
    fn sign(
        &mut self,
        kind: u32,
        content: &str,
        tags: serde_json::Value,
    ) -> Result<SignedCiEvent, Self::Error>;
}

/// Runner socket and reconciliation seam.
/// What the control plane tells a running attempt between broker reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchDecision {
    /// Keep reconciling.
    Continue,
    /// Stop the job now and record it cancelled with this reason.
    Cancel(String),
}

/// Reason prefix recorded on a run superseded by a newer request in its
/// concurrency group; the superseding request's event ID follows the colon.
pub const CONCURRENCY_SUPERSEDED_REASON: &str = "concurrency_superseded_by";
/// Reason recorded on a run whose attempt finished after the run deadline.
pub const RUN_DEADLINE_REASON: &str = "run_deadline_exceeded";
/// Reason recorded on a rerun whose lineage does not match the stored parent.
pub const RERUN_LINEAGE_REASON: &str = "rerun_lineage_mismatch";
/// How many accepted requests past the head the supersession look-ahead reads.
const SUPERSESSION_LOOKAHEAD: usize = 8;
/// How many watch ticks pass between relay probes for a superseding request.
const SUPERSESSION_PROBE_TICKS: u32 = 5;

pub trait AttemptExecutor {
    type Error;

    fn execute(&mut self, request: &AcceptedRequest) -> Result<AttemptCompletion, Self::Error>;

    /// Execute while consulting `watch` between reconciliation reads. An
    /// executor that cannot stop a running job keeps the default and never
    /// consults the watch; the runner v2 executor overrides it.
    fn execute_watched(
        &mut self,
        request: &AcceptedRequest,
        watch: &mut dyn FnMut() -> WatchDecision,
    ) -> Result<AttemptCompletion, Self::Error> {
        let _ = watch;
        self.execute(request)
    }

    /// Whether a validated runner refusal proves this request expired before admission.
    /// Only this request-local terminal condition may advance the relay cursor without
    /// closing controller capacity; transport and every other refusal remain fail-closed.
    fn is_expired_refusal(&self, _error: &Self::Error) -> bool {
        false
    }
}

/// Host-owned preparation step for one accepted controller request.
pub trait RunnerAttemptPreparer {
    type Error;

    /// Compile the selected jobs and bind them to one immutable runner request.
    fn prepare(&mut self, accepted: &AcceptedRequest)
        -> Result<PreparedRunnerAttempt, Self::Error>;
}

/// One prepared runner request and its trusted publication metadata.
pub struct PreparedRunnerAttempt {
    request: PreparedRunnerRequest,
    jobs: BTreeMap<String, JobMetadata>,
}

impl PreparedRunnerAttempt {
    /// Bind publication metadata to every job in the exact prepared request.
    pub fn new(
        request: PreparedRunnerRequest,
        jobs: Vec<JobMetadata>,
    ) -> Result<Self, RunnerBridgeError> {
        let mut jobs_by_id = BTreeMap::new();
        for metadata in jobs {
            if metadata.job_id.is_empty()
                || jobs_by_id
                    .insert(metadata.job_id.clone(), metadata)
                    .is_some()
            {
                return Err(RunnerBridgeError::JobMetadataMismatch);
            }
        }
        if jobs_by_id.keys().map(String::as_str).ne(request.job_ids()) {
            return Err(RunnerBridgeError::JobMetadataMismatch);
        }
        Ok(Self {
            request,
            jobs: jobs_by_id,
        })
    }
}

/// Failure before the production controller receives a complete runner result.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RunnerBridgeError {
    #[error("runner request preparation failed")]
    Preparation,
    #[error("prepared runner request does not match the accepted controller request")]
    RequestMismatch,
    #[error("runner job metadata does not match the prepared job set")]
    JobMetadataMismatch,
    #[error("runner client validation failed")]
    Client,
    #[error("runner refused the accepted request")]
    Refused,
    #[error("runner proved the accepted request expired before admission")]
    ExpiredRefusal,
    #[error("runner terminal result lacks complete teardown-backed evidence")]
    Incomplete,
}

impl RunnerBridgeError {
    const fn is_expired_refusal(&self) -> bool {
        matches!(self, Self::ExpiredRefusal)
    }
}

/// Production controller executor backed by the frozen runner protocol client.
pub struct RunnerAttemptExecutor<C, P> {
    client: RunnerClient<C>,
    preparer: P,
}

impl<C, P> RunnerAttemptExecutor<C, P> {
    /// Compose the controller's runner seam from a client and host preparer.
    pub const fn new(client: RunnerClient<C>, preparer: P) -> Self {
        Self { client, preparer }
    }

    /// Return the client and preparer after host composition finishes.
    pub fn into_parts(self) -> (RunnerClient<C>, P) {
        (self.client, self.preparer)
    }
}

impl<C, P> AttemptExecutor for RunnerAttemptExecutor<C, P>
where
    C: RunnerConnector,
    P: RunnerAttemptPreparer,
{
    type Error = RunnerBridgeError;

    fn execute(&mut self, accepted: &AcceptedRequest) -> Result<AttemptCompletion, Self::Error> {
        let mut prepared = self
            .preparer
            .prepare(accepted)
            .map_err(|_| RunnerBridgeError::Preparation)?;
        if !prepared
            .request
            .matches_request(&accepted.event_id, &accepted.envelope)
        {
            return Err(RunnerBridgeError::RequestMismatch);
        }
        let result = self
            .client
            .execute(&prepared.request)
            .map_err(|_| RunnerBridgeError::Client)?;
        let receipt = match result {
            ValidatedRunnerResult::Finished(receipt) => receipt,
            ValidatedRunnerResult::Refused {
                reason: RefusalReason::Expired,
            } => return Err(RunnerBridgeError::ExpiredRefusal),
            ValidatedRunnerResult::Refused { .. } => return Err(RunnerBridgeError::Refused),
        };
        if receipt.outcome != AttemptOutcome::Completed {
            return Err(RunnerBridgeError::Incomplete);
        }
        let teardown = receipt
            .teardown_attestation
            .ok_or(RunnerBridgeError::Incomplete)?;
        let mut jobs = Vec::with_capacity(receipt.jobs.len());
        for job in receipt.jobs {
            let metadata = prepared
                .jobs
                .remove(&job.job_id)
                .ok_or(RunnerBridgeError::JobMetadataMismatch)?;
            let artifacts = job
                .artifacts
                .into_iter()
                .map(|artifact| ArtifactCompletion {
                    descriptor: OutputDescriptor {
                        relative_path: artifact.relative_path,
                        sha256: artifact.sha256,
                        byte_length: artifact.byte_length,
                    },
                    artifact_id: artifact.logical_name.clone(),
                    name: artifact.logical_name,
                    media_type: artifact.media_type,
                })
                .collect();
            jobs.push(JobCompletion {
                metadata,
                attempt: job.attempt,
                state: job.state,
                reason: job.reason,
                started_at: job.started_at,
                finished_at: job.finished_at,
                log: OutputDescriptor {
                    relative_path: job.log.relative_path,
                    sha256: job.log.sha256,
                    byte_length: job.log.byte_length,
                },
                log_cap_bytes: job.log.cap_bytes,
                artifacts,
            });
        }
        if !prepared.jobs.is_empty() {
            return Err(RunnerBridgeError::JobMetadataMismatch);
        }
        Ok(AttemptCompletion {
            jobs,
            teardown,
            finished_at: receipt.finished_at,
        })
    }

    fn is_expired_refusal(&self, error: &Self::Error) -> bool {
        error.is_expired_refusal()
    }
}

/// Descriptor-bound access to runner output bytes.
pub trait EvidenceReader {
    type Error;

    fn read(&self, descriptor: &OutputDescriptor) -> Result<Vec<u8>, Self::Error>;
}

/// Durable control state. Every external action is preceded by a stable intent.
pub trait ControlStore {
    type Error;

    fn cursor(&self, channel_id: &str) -> Result<u64, Self::Error>;
    fn advance_cursor(
        &mut self,
        channel_id: &str,
        expected: u64,
        next: u64,
    ) -> Result<bool, Self::Error>;
    fn load_run(&self, identity: &RunIdentity) -> Result<Option<(u64, RunRecord)>, Self::Error>;

    /// Load every stored record for one `(run_id, attempt)` regardless of
    /// the request event that created it. Rerun lineage validation reads the
    /// parent attempt through this seam; a refused rerun leaves its own
    /// record at the same attempt, so more than one may exist.
    fn load_run_attempts(
        &self,
        run_id: Uuid,
        attempt: u32,
    ) -> Result<Vec<(u64, RunRecord)>, Self::Error>;

    fn compare_and_swap_run(
        &mut self,
        identity: &RunIdentity,
        expected_revision: Option<u64>,
        next: &RunRecord,
    ) -> Result<StoreWrite, Self::Error>;
    fn load_publication(&self, key: &str) -> Result<Option<StoredPublication>, Self::Error>;
    fn record_publication_intent(
        &mut self,
        key: &str,
        event: &SignedCiEvent,
    ) -> Result<bool, Self::Error>;
    fn refresh_pending_publication(
        &mut self,
        key: &str,
        expected_event_id: &str,
        replacement: &SignedCiEvent,
    ) -> Result<bool, Self::Error>;
    /// Mark `key` (a pending publication) as deferred: the relay refused its
    /// replay as an unauthorized status signer before this activation's grant
    /// was approved. Idempotent. The marker survives restarts.
    fn defer_publication(&mut self, key: &str) -> Result<(), Self::Error>;
    /// Every deferred publication key, in a stable order. A key leaves the set
    /// only through `accept_publication`.
    fn deferred_publications(&self) -> Result<Vec<String>, Self::Error>;
    /// Record the relay's acceptance of the exact pending event and clear any
    /// deferral marker for `key` in the same durable write.
    fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error>;
}

/// One handler poll step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollStep {
    /// No accepted request after the cursor.
    Idle,
    /// One accepted request settled and the cursor advanced.
    Completed,
    /// The head request's publication was refused as an unauthorized status
    /// signer before the activation grant; it is recorded as deferred and the
    /// cursor did not move.
    Deferred,
}

#[derive(Debug, Error)]
pub enum ProductionError {
    #[error("relay control operation failed")]
    Relay,
    #[error("control persistence failed")]
    Store,
    #[error("CI signer failed")]
    Signer,
    #[error("runner dispatch or reconciliation failed")]
    Runner,
    #[error("runner evidence access failed")]
    Evidence,
    #[error("accepted request or runner result is invalid")]
    Invalid,
    #[error("durable state transition failed")]
    State(#[from] StateError),
    #[error("publication intent conflicts with a different signed event")]
    PublicationConflict,
    #[error("publication replay deferred until the activation grant is approved")]
    DeferredPublication,
}

/// Broker-backed C3/C4 control handler. It has no default production composition.
pub struct ProductionHandler<R, S, X, P, O> {
    relay: R,
    signer: S,
    executor: X,
    store: P,
    output: O,
    /// While set, a replayed pending publication that the relay refuses as an
    /// unauthorized status signer is recorded as deferred instead of failing
    /// the poll. The service enables it at startup until the activation's
    /// first kind-46107 grant is approved, then clears it before the replay.
    defer_unauthorized_refusals: bool,
}

impl<R, S, X, P, O> ProductionHandler<R, S, X, P, O> {
    pub const fn new(relay: R, signer: S, executor: X, store: P, output: O) -> Self {
        Self {
            relay,
            signer,
            executor,
            store,
            output,
            defer_unauthorized_refusals: false,
        }
    }

    pub fn set_replay_deferral(&mut self, enabled: bool) {
        self.defer_unauthorized_refusals = enabled;
    }

    pub const fn replay_deferral(&self) -> bool {
        self.defer_unauthorized_refusals
    }
}

impl<R, S, X, P, O> ProductionHandler<R, S, X, P, O>
where
    R: RelayControl,
    S: CiSigner,
    X: AttemptExecutor,
    P: ControlStore,
    O: EvidenceReader,
{
    /// Consume at most one accepted request after the durable channel cursor.
    pub fn poll_once(&mut self, channel_id: &str) -> Result<PollStep, ProductionError> {
        self.poll_head(channel_id, false, None)
    }

    /// Consume only the exact frozen request selected by an acceptance stage.
    pub fn poll_once_bound(
        &mut self,
        channel_id: &str,
        expected: &AcceptedRequestBinding,
    ) -> Result<PollStep, ProductionError> {
        self.poll_head(channel_id, false, Some(expected))
    }

    /// Replay every deferred publication through the ordinary pending path
    /// (exact retry, exact-event read-back, re-sign), then settle the channel
    /// head when its run is already terminal so the cursor moves past the
    /// replayed request without executing anything. Callers clear replay
    /// deferral first: a refusal here is terminal, as it is after the grant.
    /// Returns the number of deferred keys that were replayed.
    pub fn replay_deferred_publications(
        &mut self,
        channel_id: &str,
    ) -> Result<usize, ProductionError> {
        let deferred = self
            .store
            .deferred_publications()
            .map_err(|_| ProductionError::Store)?;
        for key in &deferred {
            let stored = self
                .store
                .load_publication(key)
                .map_err(|_| ProductionError::Store)?
                .ok_or(ProductionError::PublicationConflict)?;
            self.republish(key, stored)?;
        }
        if !deferred.is_empty() {
            while self.poll_head(channel_id, true, None)? == PollStep::Completed {}
        }
        Ok(deferred.len())
    }

    /// Replay deferred acceptance publications only when the channel head is
    /// the exact frozen request selected by the acceptance stage.
    ///
    /// The head check precedes every publication retry. Unlike the general
    /// post-qualification replay path, this settles at most that one request.
    pub fn replay_deferred_publications_bound(
        &mut self,
        channel_id: &str,
        expected: &AcceptedRequestBinding,
    ) -> Result<usize, ProductionError> {
        let deferred = self
            .store
            .deferred_publications()
            .map_err(|_| ProductionError::Store)?;
        if deferred.is_empty() {
            return Ok(0);
        }
        let cursor = self
            .store
            .cursor(channel_id)
            .map_err(|_| ProductionError::Store)?;
        let accepted = self
            .relay
            .next_accepted(channel_id, cursor)
            .map_err(|_| ProductionError::Relay)?
            .ok_or(ProductionError::Invalid)?;
        if accepted.watch_cursor <= cursor
            || accepted.channel_id != channel_id
            || !expected.matches(&accepted)
        {
            return Err(ProductionError::Invalid);
        }
        for key in &deferred {
            let stored = self
                .store
                .load_publication(key)
                .map_err(|_| ProductionError::Store)?
                .ok_or(ProductionError::PublicationConflict)?;
            self.republish(key, stored)?;
        }
        let _ = self.poll_head(channel_id, true, Some(expected))?;
        Ok(deferred.len())
    }

    /// Re-read the selected successful attempt through authenticated relay
    /// APIs. No locally stored content or runner output is exported.
    pub fn export_first_evidence(
        &mut self,
        expected: &AcceptedRequestBinding,
        job_id: &str,
        attempt: u32,
    ) -> Result<AuthenticatedEvidenceExport, ProductionError> {
        let accepted = AcceptedRequest {
            channel_id: expected.channel_id.clone(),
            watch_cursor: 1,
            event_id: expected.event_id.clone(),
            envelope: expected.envelope.clone(),
        };
        if attempt == 0
            || expected.envelope.attempt != attempt
            || !expected.envelope.job_ids.iter().any(|id| id == job_id)
        {
            return Err(ProductionError::Invalid);
        }
        let identity = run_identity(&accepted)?;
        let (_, record) = self
            .store
            .load_run(&identity)
            .map_err(|_| ProductionError::Store)?
            .ok_or(ProductionError::Invalid)?;
        if record.state() != RunState::Success {
            return Err(ProductionError::Invalid);
        }
        let signer = self.signer.pubkey().to_owned();
        let signer_generation = self.signer.generation();
        if signer_generation == 0 {
            return Err(ProductionError::Invalid);
        }
        let status_id = accepted_publication_id(
            &self.store,
            &format!("{}:job:{job_id}:{attempt}:status:3", accepted.event_id),
        )?;
        let status = read_validated_event(
            &mut self.relay,
            &status_id,
            KIND_CI_JOB_STATUS,
            &signer,
            signer_generation,
            &accepted.channel_id,
        )?;
        let ValidatedCiEnvelope::JobStatus(status) = status else {
            return Err(ProductionError::Invalid);
        };
        if !matches!(status.state, CiJobState::Success)
            || status.sequence != 3
            || status.job_id != job_id
            || status.attempt != attempt
            || status.request_event_id != accepted.event_id
            || status.run_id != accepted.envelope.run_id
            || status.workflow_id != accepted.envelope.workflow_id
            || status.target_repo_a != accepted.envelope.target_repo_a
            || status.tip_oid != accepted.envelope.tip_oid
            || status.base_oid != accepted.envelope.base_oid
            || status.relay_signer != signer
            || status.artifact_refs.len() != 1
        {
            return Err(ProductionError::Invalid);
        }
        let log_id = status.log_ref.ok_or(ProductionError::Invalid)?;
        let log = read_validated_event(
            &mut self.relay,
            &log_id,
            KIND_CI_LOG_REFERENCE,
            &signer,
            signer_generation,
            &accepted.channel_id,
        )?;
        let ValidatedCiEnvelope::LogReference(log) = log else {
            return Err(ProductionError::Invalid);
        };
        if log.request_event_id != accepted.event_id
            || log.run_id != accepted.envelope.run_id
            || log.workflow_id != accepted.envelope.workflow_id
            || log.target_repo_a != accepted.envelope.target_repo_a
            || log.tip_oid != accepted.envelope.tip_oid
            || log.job_id != job_id
            || log.attempt != attempt
            || log.truncated
            || log.inline.is_some()
            || log.byte_length > 16 * 1024 * 1024
            || log.cap_bytes < log.byte_length
            || log.relay_signer != signer
        {
            return Err(ProductionError::Invalid);
        }
        let log_url = log.url.ok_or(ProductionError::Invalid)?;
        if url::Url::parse(&log_url)
            .map_err(|_| ProductionError::Invalid)?
            .path()
            != format!(
                "/ci/logs/{}/{}/{}/{}/{}",
                accepted.event_id, accepted.envelope.run_id, job_id, attempt, log.log_sha256
            )
        {
            return Err(ProductionError::Invalid);
        }
        let mut plans = vec![(
            "log",
            "job.log".to_owned(),
            log.log_sha256,
            log.byte_length,
            log_url,
        )];
        let mut object_names = std::collections::BTreeSet::from(["job.log".to_owned()]);
        let mut object_urls = std::collections::BTreeSet::from([plans[0].4.clone()]);
        for artifact_id in &status.artifact_refs {
            let event = read_validated_event(
                &mut self.relay,
                artifact_id,
                KIND_CI_ARTIFACT_REFERENCE,
                &signer,
                signer_generation,
                &accepted.channel_id,
            )?;
            let ValidatedCiEnvelope::ArtifactReference(artifact) = event else {
                return Err(ProductionError::Invalid);
            };
            if artifact.request_event_id != accepted.event_id
                || artifact.run_id != accepted.envelope.run_id
                || artifact.workflow_id != accepted.envelope.workflow_id
                || artifact.target_repo_a != accepted.envelope.target_repo_a
                || artifact.tip_oid != accepted.envelope.tip_oid
                || artifact.job_id != job_id
                || artifact.attempt != attempt
                || artifact.byte_length > 32 * 1024
                || artifact.relay_signer != signer
                || artifact.artifact_id != "result"
                || !object_names.insert(artifact.name.clone())
                || !object_urls.insert(artifact.url.clone())
            {
                return Err(ProductionError::Invalid);
            }
            if url::Url::parse(&artifact.url)
                .map_err(|_| ProductionError::Invalid)?
                .path()
                != format!(
                    "/ci/artifacts/{}/{}/{}/{}/{}/{}",
                    accepted.event_id,
                    accepted.envelope.run_id,
                    job_id,
                    attempt,
                    artifact.artifact_id,
                    artifact.sha256
                )
            {
                return Err(ProductionError::Invalid);
            }
            plans.push((
                "artifact",
                artifact.name,
                artifact.sha256,
                artifact.byte_length,
                artifact.url,
            ));
        }

        let evidence_id = record
            .terminal_facts()
            .evidence_finalized_event_id()
            .ok_or(ProductionError::Invalid)?;
        let evidence = read_validated_event(
            &mut self.relay,
            evidence_id,
            KIND_CI_EVIDENCE_FINALIZED,
            &signer,
            signer_generation,
            &accepted.channel_id,
        )?;
        let ValidatedCiEnvelope::EvidenceFinalized(evidence) = evidence else {
            return Err(ProductionError::Invalid);
        };
        if evidence.request_event_id != accepted.event_id
            || evidence.run_id != accepted.envelope.run_id
            || evidence.workflow_id != accepted.envelope.workflow_id
            || evidence.target_repo_a != accepted.envelope.target_repo_a
            || evidence.tip_oid != accepted.envelope.tip_oid
            || evidence.relay_signer != signer
            || evidence.attempt != attempt
            || evidence.finalized_job_attempts.len() != 1
            || evidence.finalized_job_attempts[0].job_id != job_id
            || evidence.finalized_job_attempts[0].attempt != attempt
            || evidence.finalized_job_attempts[0].log_ref != log_id
            || evidence.finalized_job_attempts[0].artifact_refs != status.artifact_refs
        {
            return Err(ProductionError::Invalid);
        }
        let teardown_id = record
            .terminal_facts()
            .teardown_attestation_event_id()
            .ok_or(ProductionError::Invalid)?;
        let teardown = read_validated_event(
            &mut self.relay,
            teardown_id,
            KIND_CI_TEARDOWN_ATTESTATION,
            &signer,
            signer_generation,
            &accepted.channel_id,
        )?;
        let ValidatedCiEnvelope::TeardownAttestation(teardown) = teardown else {
            return Err(ProductionError::Invalid);
        };
        if teardown
            .validate_context(
                &accepted.event_id,
                &accepted.envelope,
                &[(job_id.to_owned(), attempt)],
            )
            .is_err()
            || teardown.request_event_id != accepted.event_id
            || teardown.run_id != accepted.envelope.run_id
            || teardown.workflow_id != accepted.envelope.workflow_id
            || teardown.target_repo_a != accepted.envelope.target_repo_a
            || teardown.tip_oid != accepted.envelope.tip_oid
            || teardown.base_oid != accepted.envelope.base_oid
            || teardown.attempt != attempt
            || !teardown.lease_empty
            || teardown.relay_signer != signer
        {
            return Err(ProductionError::Invalid);
        }
        let terminal_id = record.terminal_event_id().ok_or(ProductionError::Invalid)?;
        let terminal = read_validated_event(
            &mut self.relay,
            terminal_id,
            KIND_CI_RUN_STATUS,
            &signer,
            signer_generation,
            &accepted.channel_id,
        )?;
        let ValidatedCiEnvelope::RunStatus(terminal) = terminal else {
            return Err(ProductionError::Invalid);
        };
        if !matches!(terminal.state, CiRunState::Success)
            || terminal.request_event_id != accepted.event_id
            || terminal.run_id != accepted.envelope.run_id
            || terminal.workflow_id != accepted.envelope.workflow_id
            || terminal.target_repo_a != accepted.envelope.target_repo_a
            || terminal.tip_oid != accepted.envelope.tip_oid
            || terminal.base_oid != accepted.envelope.base_oid
            || terminal.attempt != attempt
            || terminal.sequence != record.sequence()
            || terminal.job_ids != accepted.envelope.job_ids
            || terminal.relay_signer != signer
        {
            return Err(ProductionError::Invalid);
        }

        let mut subject = None;
        let mut generation = None;
        let mut objects = Vec::with_capacity(plans.len());
        let mut transcript = Vec::from(b"buzz-ci-acceptance-export-authority:v1\0".as_slice());
        for (kind, name, sha256, byte_length, url) in plans {
            let maximum = byte_length;
            let read = self
                .relay
                .read_evidence_object(&url, &sha256, byte_length, maximum)
                .map_err(map_export_error)?;
            if read.binding.method != crate::source::HttpMethod::Get
                || read.binding.url.as_str() != url
                || read.binding.payload_sha256.is_some()
                || read.binding.publisher.is_some()
                || read.binding.query_filter.is_some()
                || read.bytes.len() as u64 != byte_length
                || hex::encode(Sha256::digest(&read.bytes)) != sha256
            {
                return Err(ProductionError::Invalid);
            }
            if subject
                .as_ref()
                .is_some_and(|value| value != &read.proof.subject)
                || generation.is_some_and(|value| value != read.proof.generation)
            {
                return Err(ProductionError::Invalid);
            }
            subject.get_or_insert(read.proof.subject.clone());
            generation.get_or_insert(read.proof.generation);
            for field in [
                "GET",
                url.as_str(),
                read.proof.subject.as_str(),
                &read.proof.generation.to_string(),
                accepted.event_id.as_str(),
                accepted.envelope.run_id.as_str(),
                job_id,
                &attempt.to_string(),
                kind,
                name.as_str(),
                sha256.as_str(),
                &byte_length.to_string(),
            ] {
                transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
                transcript.extend_from_slice(field.as_bytes());
            }
            objects.push(ExportedEvidenceObject {
                name,
                sha256,
                bytes: read.bytes,
            });
        }
        Ok(AuthenticatedEvidenceExport {
            subject: subject.ok_or(ProductionError::Invalid)?,
            generation: generation.ok_or(ProductionError::Invalid)?,
            authorization_digest: hex::encode(Sha256::digest(transcript)),
            request_event_id: accepted.event_id,
            run_id: accepted.envelope.run_id,
            job_id: job_id.to_owned(),
            attempt,
            objects,
        })
    }

    fn poll_head(
        &mut self,
        channel_id: &str,
        terminal_only: bool,
        expected: Option<&AcceptedRequestBinding>,
    ) -> Result<PollStep, ProductionError> {
        let cursor = self
            .store
            .cursor(channel_id)
            .map_err(|_| ProductionError::Store)?;
        let Some(accepted) = self
            .relay
            .next_accepted(channel_id, cursor)
            .map_err(|_| ProductionError::Relay)?
        else {
            return Ok(PollStep::Idle);
        };
        if accepted.channel_id != channel_id || accepted.watch_cursor <= cursor {
            return Err(ProductionError::Invalid);
        }
        if expected.is_some_and(|binding| !binding.matches(&accepted)) {
            return Err(ProductionError::Invalid);
        }
        if terminal_only {
            let identity = run_identity(&accepted)?;
            let terminal = self
                .store
                .load_run(&identity)
                .map_err(|_| ProductionError::Store)?
                .is_some_and(|(_, record)| record.state().is_terminal());
            if !terminal {
                return Ok(PollStep::Idle);
            }
        }
        let superseder = if terminal_only || expected.is_some() {
            None
        } else {
            self.find_superseder(channel_id, &accepted)?
        };
        let handled = match superseder {
            Some(superseder) => self.handle_superseded(&accepted, &superseder),
            None => self.handle_accepted(&accepted),
        };
        match handled {
            Ok(()) => {}
            Err(ProductionError::DeferredPublication) => return Ok(PollStep::Deferred),
            Err(error) => return Err(error),
        }
        if !self
            .store
            .advance_cursor(channel_id, cursor, accepted.watch_cursor)
            .map_err(|_| ProductionError::Store)?
        {
            return Err(ProductionError::PublicationConflict);
        }
        Ok(PollStep::Completed)
    }

    /// Look past the channel head for a newer initial request in the head's
    /// concurrency group. GitHub's `cancel-in-progress` on pull-request refs
    /// covers queued runs too: a newer push to the same branch makes the
    /// older run's result moot, so the older head is recorded cancelled
    /// without running. Bounded to `SUPERSESSION_LOOKAHEAD` reads.
    fn find_superseder(
        &mut self,
        channel_id: &str,
        head: &AcceptedRequest,
    ) -> Result<Option<AcceptedRequest>, ProductionError> {
        let group = CiConcurrencyGroup::of(&head.envelope);
        if !group.cancel_in_progress {
            return Ok(None);
        }
        let mut cursor = head.watch_cursor;
        for _ in 0..SUPERSESSION_LOOKAHEAD {
            let Some(next) = self
                .relay
                .next_accepted(channel_id, cursor)
                .map_err(|_| ProductionError::Relay)?
            else {
                return Ok(None);
            };
            if next.channel_id != channel_id || next.watch_cursor <= cursor {
                return Err(ProductionError::Invalid);
            }
            if supersedes(&group, head, &next) {
                return Ok(Some(next));
            }
            cursor = next.watch_cursor;
        }
        Ok(None)
    }

    /// Record a queued head cancelled because `superseder` replaced it in its
    /// concurrency group, and publish its terminal status and check. A head
    /// that is already terminal only settles its pending publications.
    fn handle_superseded(
        &mut self,
        accepted: &AcceptedRequest,
        superseder: &AcceptedRequest,
    ) -> Result<(), ProductionError> {
        let identity = run_identity(accepted)?;
        let (revision, record) = self.load_or_queue(accepted, &identity)?;
        if record.state().is_terminal() {
            return self.settle_terminal(accepted, &identity, revision, record);
        }
        if record.state() == RunState::Queued {
            self.publish_run(accepted, &record, "run:queued")?;
        }
        let now = host_now()?
            .max(record.queued_at())
            .max(record.started_at().unwrap_or(0));
        let cancelled = record.transition(
            RunState::Cancelled,
            now,
            Some(format!(
                "{CONCURRENCY_SUPERSEDED_REASON}:{}",
                superseder.event_id
            )),
        )?;
        self.finish_terminal(accepted, &identity, revision, cancelled)
    }

    fn load_or_queue(
        &mut self,
        accepted: &AcceptedRequest,
        identity: &RunIdentity,
    ) -> Result<(u64, RunRecord), ProductionError> {
        let queued = RunRecord::queued(identity.clone(), accepted.envelope.issued_at)?;
        match self
            .store
            .load_run(identity)
            .map_err(|_| ProductionError::Store)?
        {
            Some(existing) => Ok(existing),
            None => match self
                .store
                .compare_and_swap_run(identity, None, &queued)
                .map_err(|_| ProductionError::Store)?
            {
                StoreWrite::Written { revision } => Ok((revision, queued)),
                StoreWrite::Conflict { .. } => Err(ProductionError::PublicationConflict),
            },
        }
    }

    /// Publish whatever a terminal record still lacks: its terminal run
    /// status, then its check.
    fn settle_terminal(
        &mut self,
        accepted: &AcceptedRequest,
        identity: &RunIdentity,
        mut revision: u64,
        mut record: RunRecord,
    ) -> Result<(), ProductionError> {
        if record.terminal_event_id().is_none() {
            let terminal_event_id = self.publish_run(accepted, &record, "run:terminal")?;
            record = record.with_terminal_event(terminal_event_id)?;
            revision = persist_run(&mut self.store, identity, revision, &record)?;
        }
        if record.check_event_id().is_none() {
            let check_event_id = self.publish_check(accepted, &record)?;
            let bound = record.with_check_event(check_event_id)?;
            persist_run(&mut self.store, identity, revision, &bound)?;
        }
        Ok(())
    }

    /// Persist a terminal transition, publish its run status, bind it, then
    /// publish and bind the one terminal check for the attempt.
    fn finish_terminal(
        &mut self,
        accepted: &AcceptedRequest,
        identity: &RunIdentity,
        revision: u64,
        terminal: RunRecord,
    ) -> Result<(), ProductionError> {
        let terminal_revision = persist_run(&mut self.store, identity, revision, &terminal)?;
        self.settle_terminal(accepted, identity, terminal_revision, terminal)
    }

    fn handle_accepted(&mut self, accepted: &AcceptedRequest) -> Result<(), ProductionError> {
        let identity = run_identity(accepted)?;
        let (mut revision, mut record) = self.load_or_queue(accepted, &identity)?;
        if record.state().is_terminal() {
            return self.settle_terminal(accepted, &identity, revision, record);
        }

        if record.state() == RunState::Queued {
            self.publish_run(accepted, &record, "run:queued")?;
        }
        if accepted.envelope.request_type == CiRequestType::Rerun {
            if let Err(reason) = validate_rerun_lineage(&self.store, accepted)? {
                self.publish_terminal_infrastructure_failure(
                    accepted,
                    &identity,
                    revision,
                    &record,
                    &format!("{RERUN_LINEAGE_REASON}:{reason}"),
                )?;
                return Ok(());
            }
        }
        let completion = {
            let Self {
                relay, executor, ..
            } = self;
            let group = CiConcurrencyGroup::of(&accepted.envelope);
            let mut ticks = 0_u32;
            let mut watch = || {
                ticks = ticks.wrapping_add(1);
                if !group.cancel_in_progress || ticks % SUPERSESSION_PROBE_TICKS != 1 {
                    return WatchDecision::Continue;
                }
                match relay.next_accepted(&accepted.channel_id, accepted.watch_cursor) {
                    Ok(Some(next)) if supersedes(&group, accepted, &next) => WatchDecision::Cancel(
                        format!("{CONCURRENCY_SUPERSEDED_REASON}:{}", next.event_id),
                    ),
                    _ => WatchDecision::Continue,
                }
            };
            executor.execute_watched(accepted, &mut watch)
        };
        let completion = match completion {
            Ok(completion) => completion,
            Err(error) => {
                let expired = self.executor.is_expired_refusal(&error);
                self.publish_terminal_infrastructure_failure(
                    accepted,
                    &identity,
                    revision,
                    &record,
                    if expired {
                        "request_expired_before_admission"
                    } else {
                        "runner_or_evidence_provider_failure"
                    },
                )?;
                if expired {
                    return Ok(());
                }
                return Err(ProductionError::Runner);
            }
        };
        if let Err(error) = validate_completion(accepted, &completion, self.signer.pubkey()) {
            self.publish_terminal_infrastructure_failure(
                accepted,
                &identity,
                revision,
                &record,
                "runner_or_evidence_provider_failure",
            )?;
            return Err(error);
        }

        if record.state() == RunState::Queued {
            let running = record.transition(RunState::Running, first_started(&completion), None)?;
            revision = persist_run(&mut self.store, &identity, revision, &running)?;
            record = running;
        }
        if record.state() == RunState::Running {
            self.publish_run(accepted, &record, "run:running")?;
            let finalized_job_attempts = match self.publish_completion(accepted, &completion) {
                Ok(finalized) => finalized,
                Err(error @ (ProductionError::Evidence | ProductionError::Invalid)) => {
                    self.publish_terminal_infrastructure_failure(
                        accepted,
                        &identity,
                        revision,
                        &record,
                        "runner_or_evidence_provider_failure",
                    )?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };

            // The run deadline is the request's signed `timeout_seconds`
            // measured from the moment it was queued; it bounds the whole
            // attempt, evidence sealing included, not just the job.
            let run_deadline_at = record
                .queued_at()
                .saturating_add(accepted.envelope.timeout_seconds);
            let (terminal_state, reason) = if completion.finished_at > run_deadline_at {
                (RunState::TimedOut, Some(RUN_DEADLINE_REASON.to_owned()))
            } else {
                (
                    terminal_run_state(&completion.jobs),
                    terminal_reason(&completion.jobs),
                )
            };
            if terminal_state == RunState::Success {
                let evidence = CiEvidenceFinalizedEnvelope {
                    schema_version: CI_SCHEMA_VERSION,
                    request_event_id: accepted.event_id.clone(),
                    run_id: accepted.envelope.run_id.clone(),
                    workflow_id: accepted.envelope.workflow_id.clone(),
                    target_repo_a: accepted.envelope.target_repo_a.clone(),
                    tip_oid: accepted.envelope.tip_oid.clone(),
                    attempt: accepted.envelope.attempt,
                    finalized_job_attempts,
                    finalized_at: completion.finished_at,
                    relay_signer: self.signer.pubkey().to_owned(),
                };
                let evidence_id = self.publish_envelope(
                    accepted,
                    KIND_CI_EVIDENCE_FINALIZED,
                    &evidence,
                    evidence_finalized_tags(&accepted.channel_id, &evidence)
                        .map_err(|_| ProductionError::Invalid)?,
                    "evidence:finalized",
                )?;
                let teardown_id = self.publish_envelope(
                    accepted,
                    KIND_CI_TEARDOWN_ATTESTATION,
                    &completion.teardown,
                    teardown_attestation_tags(&accepted.channel_id, &completion.teardown)
                        .map_err(|_| ProductionError::Invalid)?,
                    "teardown",
                )?;
                record = record.with_evidence_finalized(evidence_id)?;
                record = record.with_teardown_attestation(teardown_id)?;
            }
            let terminal = record.transition(terminal_state, completion.finished_at, reason)?;
            self.finish_terminal(accepted, &identity, revision, terminal)?;
        }
        Ok(())
    }

    fn publish_terminal_infrastructure_failure(
        &mut self,
        accepted: &AcceptedRequest,
        identity: &RunIdentity,
        revision: u64,
        record: &RunRecord,
        reason: &str,
    ) -> Result<(), ProductionError> {
        let now = host_now()?
            .max(record.queued_at())
            .max(record.started_at().unwrap_or(0));
        let terminal = record.transition(
            RunState::InfrastructureFailure,
            now,
            Some(reason.to_owned()),
        )?;
        self.finish_terminal(accepted, identity, revision, terminal)
    }

    /// Publish the one kind-46108 terminal check for a terminal attempt. It
    /// names the terminal run status it summarises and, for a success, both
    /// terminal facts, so a reader can verify every claim against stored
    /// events.
    fn publish_check(
        &mut self,
        accepted: &AcceptedRequest,
        record: &RunRecord,
    ) -> Result<String, ProductionError> {
        let run_status_event_id = record
            .terminal_event_id()
            .ok_or(ProductionError::Invalid)?
            .to_owned();
        let envelope = CiCheckEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: accepted.event_id.clone(),
            run_id: accepted.envelope.run_id.clone(),
            workflow_id: accepted.envelope.workflow_id.clone(),
            target_repo_a: accepted.envelope.target_repo_a.clone(),
            tip_oid: accepted.envelope.tip_oid.clone(),
            base_oid: accepted.envelope.base_oid.clone(),
            attempt: accepted.envelope.attempt,
            conclusion: run_state(record.state()),
            reason: record.reason().map(str::to_owned),
            run_status_event_id,
            evidence_finalized_event_id: record
                .terminal_facts()
                .evidence_finalized_event_id()
                .map(str::to_owned),
            teardown_attestation_event_id: record
                .terminal_facts()
                .teardown_attestation_event_id()
                .map(str::to_owned),
            concurrency_group: CiConcurrencyGroup::of(&accepted.envelope).key,
            published_at: record.finished_at().ok_or(ProductionError::Invalid)?,
            relay_signer: self.signer.pubkey().to_owned(),
        };
        self.publish_envelope(
            accepted,
            KIND_CI_CHECK,
            &envelope,
            check_tags(&accepted.channel_id, &envelope).map_err(|_| ProductionError::Invalid)?,
            "run:check",
        )
    }

    fn publish_completion(
        &mut self,
        accepted: &AcceptedRequest,
        completion: &AttemptCompletion,
    ) -> Result<Vec<CiFinalizedJobAttempt>, ProductionError> {
        let mut finalized_jobs = Vec::with_capacity(completion.jobs.len());
        for job in &completion.jobs {
            let queued = job_envelope(
                accepted,
                job,
                self.signer.pubkey(),
                1,
                CiJobState::Queued,
                None,
                Vec::new(),
            );
            self.publish_envelope(
                accepted,
                KIND_CI_JOB_STATUS,
                &queued,
                job_status_tags(&accepted.channel_id, &queued)
                    .map_err(|_| ProductionError::Invalid)?,
                &format!("job:{}:{}:status:1", job.metadata.job_id, job.attempt),
            )?;
            let running = job_envelope(
                accepted,
                job,
                self.signer.pubkey(),
                2,
                CiJobState::Running,
                None,
                Vec::new(),
            );
            self.publish_envelope(
                accepted,
                KIND_CI_JOB_STATUS,
                &running,
                job_status_tags(&accepted.channel_id, &running)
                    .map_err(|_| ProductionError::Invalid)?,
                &format!("job:{}:{}:status:2", job.metadata.job_id, job.attempt),
            )?;
            let finalized = self.finalized_job(accepted, job)?;
            let terminal = job_envelope(
                accepted,
                job,
                self.signer.pubkey(),
                3,
                job.state,
                Some(finalized.log_ref.clone()),
                finalized.artifact_refs.clone(),
            );
            self.publish_envelope(
                accepted,
                KIND_CI_JOB_STATUS,
                &terminal,
                job_status_tags(&accepted.channel_id, &terminal)
                    .map_err(|_| ProductionError::Invalid)?,
                &format!("job:{}:{}:status:3", job.metadata.job_id, job.attempt),
            )?;
            finalized_jobs.push(finalized);
        }
        Ok(finalized_jobs)
    }

    fn finalized_job(
        &mut self,
        accepted: &AcceptedRequest,
        job: &JobCompletion,
    ) -> Result<CiFinalizedJobAttempt, ProductionError> {
        let log_bytes = self
            .output
            .read(&job.log)
            .map_err(|_| ProductionError::Evidence)?;
        verify_bytes(&job.log, &log_bytes)?;
        let stored = self
            .relay
            .put_log(accepted, job, &log_bytes)
            .map_err(|_| ProductionError::Relay)?;
        verify_stored(&job.log, &stored)?;
        let log = CiLogReferenceEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: accepted.event_id.clone(),
            run_id: accepted.envelope.run_id.clone(),
            workflow_id: accepted.envelope.workflow_id.clone(),
            target_repo_a: accepted.envelope.target_repo_a.clone(),
            tip_oid: accepted.envelope.tip_oid.clone(),
            job_id: job.metadata.job_id.clone(),
            attempt: job.attempt,
            log_sha256: job.log.sha256.clone(),
            byte_length: job.log.byte_length,
            cap_bytes: job.log_cap_bytes,
            truncated: false,
            url: Some(stored.url),
            inline: None,
            created_at: job.finished_at,
            relay_signer: self.signer.pubkey().to_owned(),
        };
        let log_ref = self.publish_envelope(
            accepted,
            KIND_CI_LOG_REFERENCE,
            &log,
            log_reference_tags(&accepted.channel_id, &log).map_err(|_| ProductionError::Invalid)?,
            &format!(
                "log:{}:{}:{}",
                job.metadata.job_id, job.attempt, job.log.sha256
            ),
        )?;
        let mut artifact_refs = Vec::with_capacity(job.artifacts.len());
        for artifact in &job.artifacts {
            let bytes = self
                .output
                .read(&artifact.descriptor)
                .map_err(|_| ProductionError::Evidence)?;
            verify_bytes(&artifact.descriptor, &bytes)?;
            let stored = self
                .relay
                .put_artifact(accepted, job, artifact, &bytes)
                .map_err(|_| ProductionError::Relay)?;
            verify_stored(&artifact.descriptor, &stored)?;
            let envelope = CiArtifactReferenceEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: accepted.event_id.clone(),
                run_id: accepted.envelope.run_id.clone(),
                workflow_id: accepted.envelope.workflow_id.clone(),
                target_repo_a: accepted.envelope.target_repo_a.clone(),
                tip_oid: accepted.envelope.tip_oid.clone(),
                job_id: job.metadata.job_id.clone(),
                attempt: job.attempt,
                artifact_id: artifact.artifact_id.clone(),
                name: artifact.name.clone(),
                media_type: artifact.media_type.clone(),
                sha256: artifact.descriptor.sha256.clone(),
                byte_length: artifact.descriptor.byte_length,
                url: stored.url,
                created_at: job.finished_at,
                relay_signer: self.signer.pubkey().to_owned(),
            };
            artifact_refs.push(
                self.publish_envelope(
                    accepted,
                    KIND_CI_ARTIFACT_REFERENCE,
                    &envelope,
                    artifact_reference_tags(&accepted.channel_id, &envelope)
                        .map_err(|_| ProductionError::Invalid)?,
                    &format!(
                        "artifact:{}:{}:{}",
                        job.metadata.job_id, job.attempt, artifact.artifact_id
                    ),
                )?,
            );
        }
        Ok(CiFinalizedJobAttempt {
            job_id: job.metadata.job_id.clone(),
            attempt: job.attempt,
            log_ref,
            artifact_refs,
        })
    }

    fn publish_run(
        &mut self,
        accepted: &AcceptedRequest,
        record: &RunRecord,
        key: &str,
    ) -> Result<String, ProductionError> {
        let state = run_state(record.state());
        let envelope = CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: accepted.event_id.clone(),
            run_id: accepted.envelope.run_id.clone(),
            workflow_id: accepted.envelope.workflow_id.clone(),
            target_repo_a: accepted.envelope.target_repo_a.clone(),
            tip_oid: accepted.envelope.tip_oid.clone(),
            base_oid: accepted.envelope.base_oid.clone(),
            attempt: accepted.envelope.attempt,
            sequence: record.sequence(),
            state,
            conclusion: state
                .is_terminal()
                .then(|| format!("{state:?}").to_lowercase()),
            reason: record.reason().map(str::to_owned),
            started_at: record.started_at(),
            finished_at: record.finished_at(),
            job_ids: accepted.envelope.job_ids.clone(),
            relay_signer: self.signer.pubkey().to_owned(),
        };
        self.publish_envelope(
            accepted,
            KIND_CI_RUN_STATUS,
            &envelope,
            run_status_tags(&accepted.channel_id, &envelope)
                .map_err(|_| ProductionError::Invalid)?,
            key,
        )
    }

    fn publish_envelope<T: Serialize>(
        &mut self,
        accepted: &AcceptedRequest,
        kind: u32,
        envelope: &T,
        tags: Vec<nostr::Tag>,
        suffix: &str,
    ) -> Result<String, ProductionError> {
        let key = format!("{}:{suffix}", accepted.event_id);
        if let Some(stored) = self
            .store
            .load_publication(&key)
            .map_err(|_| ProductionError::Store)?
        {
            return self.republish(&key, stored);
        }
        let content = serde_json::to_string(envelope).map_err(|_| ProductionError::Invalid)?;
        let tags = serde_json::to_value(tags).map_err(|_| ProductionError::Invalid)?;
        let signed = self
            .signer
            .sign(kind, &content, tags)
            .map_err(|_| ProductionError::Signer)?;
        if signed.kind != kind || signed.content != content || signed.event_id.len() != 64 {
            return Err(ProductionError::Invalid);
        }
        if !self
            .store
            .record_publication_intent(&key, &signed)
            .map_err(|_| ProductionError::Store)?
        {
            let stored = self
                .store
                .load_publication(&key)
                .map_err(|_| ProductionError::Store)?
                .ok_or(ProductionError::PublicationConflict)?;
            return self.republish(&key, stored);
        }
        self.republish(&key, StoredPublication::Pending(signed))
    }

    fn republish(
        &mut self,
        key: &str,
        stored: StoredPublication,
    ) -> Result<String, ProductionError> {
        match stored {
            StoredPublication::Accepted { relay_event_id, .. } => Ok(relay_event_id),
            StoredPublication::Pending(signed) => {
                if self.defer_unauthorized_refusals && self.is_deferred(key)? {
                    // Already refused before the grant: do not re-sign or
                    // re-publish on every poll; the grant approval replays it.
                    return Err(ProductionError::DeferredPublication);
                }
                self.publish_pending(key, signed)
            }
        }
    }

    fn is_deferred(&self, key: &str) -> Result<bool, ProductionError> {
        Ok(self
            .store
            .deferred_publications()
            .map_err(|_| ProductionError::Store)?
            .iter()
            .any(|deferred| deferred == key))
    }

    /// Map a refused publish. Only the relay's exact unauthorized-signer
    /// refusal, and only while replay deferral is enabled, becomes a durable
    /// deferral; everything else is the terminal relay failure it always was.
    fn refuse_or_defer(&mut self, key: &str, error: &R::Error) -> ProductionError {
        if self.defer_unauthorized_refusals && self.relay.is_unauthorized_status_signer(error) {
            return match self.store.defer_publication(key) {
                Ok(()) => ProductionError::DeferredPublication,
                Err(_) => ProductionError::Store,
            };
        }
        ProductionError::Relay
    }

    fn publish_pending(
        &mut self,
        key: &str,
        signed: SignedCiEvent,
    ) -> Result<String, ProductionError> {
        let accepted_id = match self.relay.publish(&signed) {
            Ok(accepted_id) => accepted_id,
            Err(_) => return self.reconcile_failed_publication(key, signed),
        };
        self.accept_published(key, signed, accepted_id)
    }

    fn reconcile_failed_publication(
        &mut self,
        key: &str,
        signed: SignedCiEvent,
    ) -> Result<String, ProductionError> {
        if self
            .relay
            .publication_exists(&signed)
            .map_err(|_| ProductionError::Relay)?
        {
            self.store
                .accept_publication(key, &signed.event_id)
                .map_err(|_| ProductionError::Store)?;
            return Ok(signed.event_id);
        }

        let replacement = self
            .signer
            .sign(signed.kind, &signed.content, signed.tags.clone())
            .map_err(|_| ProductionError::Signer)?;
        if replacement.kind != signed.kind
            || replacement.content != signed.content
            || replacement.tags != signed.tags
            || replacement.event_id.len() != 64
        {
            return Err(ProductionError::Invalid);
        }
        if !self
            .store
            .refresh_pending_publication(key, &signed.event_id, &replacement)
            .map_err(|_| ProductionError::Store)?
        {
            let reconciled = self
                .store
                .load_publication(key)
                .map_err(|_| ProductionError::Store)?
                .ok_or(ProductionError::PublicationConflict)?;
            return self.republish(key, reconciled);
        }
        let accepted_id = match self.relay.publish(&replacement) {
            Ok(accepted_id) => accepted_id,
            Err(error) => return Err(self.refuse_or_defer(key, &error)),
        };
        self.accept_published(key, replacement, accepted_id)
    }

    fn accept_published(
        &mut self,
        key: &str,
        signed: SignedCiEvent,
        accepted_id: String,
    ) -> Result<String, ProductionError> {
        if accepted_id != signed.event_id {
            return Err(ProductionError::PublicationConflict);
        }
        self.store
            .accept_publication(key, &accepted_id)
            .map_err(|_| ProductionError::Store)?;
        Ok(accepted_id)
    }
}

fn host_now() -> Result<u64, ProductionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProductionError::Invalid)
}

/// Whether `next` replaces `head` in `group`: a later initial request for a
/// different run in the same group. A rerun of the same run never supersedes
/// its own lineage.
fn supersedes(group: &CiConcurrencyGroup, head: &AcceptedRequest, next: &AcceptedRequest) -> bool {
    next.watch_cursor > head.watch_cursor
        && next.envelope.run_id != head.envelope.run_id
        && next.envelope.request_type == CiRequestType::Run
        && CiConcurrencyGroup::of(&next.envelope).key == group.key
}

/// A rerun executes only against the parent attempt controld itself stored:
/// same run, contiguous attempt, terminal parent, and the same immutable
/// source and workflow tuple. The relay checks the same lineage; controld
/// does not trust that check and fails closed on its own record.
fn validate_rerun_lineage<P: ControlStore>(
    store: &P,
    accepted: &AcceptedRequest,
) -> Result<Result<(), &'static str>, ProductionError> {
    let request = &accepted.envelope;
    let run_id = Uuid::parse_str(&request.run_id).map_err(|_| ProductionError::Invalid)?;
    let Some(parent_attempt) = request.parent_attempt else {
        return Ok(Err("missing parent attempt"));
    };
    if request.parent_run_id.as_deref() != Some(request.run_id.as_str())
        || request.attempt != parent_attempt.saturating_add(1)
    {
        return Ok(Err("attempt does not follow its parent"));
    }
    let parents = store
        .load_run_attempts(run_id, parent_attempt)
        .map_err(|_| ProductionError::Store)?;
    if parents.is_empty() {
        return Ok(Err("parent attempt is not stored"));
    }
    let Some((_, parent)) = parents.iter().find(|(_, parent)| {
        let identity = parent.identity();
        identity.tip_oid() == request.tip_oid
            && identity.workflow_id() == request.workflow_id
            && identity.target_repo_a() == request.target_repo_a
    }) else {
        return Ok(Err("immutable coordinates differ from the parent"));
    };
    if !parent.state().is_terminal() {
        return Ok(Err("parent attempt is not terminal"));
    }
    Ok(Ok(()))
}

fn run_identity(accepted: &AcceptedRequest) -> Result<RunIdentity, ProductionError> {
    accepted
        .envelope
        .validate()
        .map_err(|_| ProductionError::Invalid)?;
    if accepted.event_id.len() != 64 || accepted.event_id != accepted.event_id.to_lowercase() {
        return Err(ProductionError::Invalid);
    }
    Ok(RunIdentity::new(
        accepted.event_id.clone(),
        Uuid::parse_str(&accepted.envelope.run_id).map_err(|_| ProductionError::Invalid)?,
        accepted.envelope.attempt,
        accepted.envelope.target_repo_a.clone(),
        accepted.envelope.tip_oid.clone(),
        accepted.envelope.workflow_id.clone(),
    )?)
}

fn persist_run<P: ControlStore>(
    store: &mut P,
    identity: &RunIdentity,
    revision: u64,
    next: &RunRecord,
) -> Result<u64, ProductionError> {
    match store
        .compare_and_swap_run(identity, Some(revision), next)
        .map_err(|_| ProductionError::Store)?
    {
        StoreWrite::Written { revision } => Ok(revision),
        StoreWrite::Conflict { .. } => Err(ProductionError::PublicationConflict),
    }
}

fn validate_completion(
    accepted: &AcceptedRequest,
    completion: &AttemptCompletion,
    signer: &str,
) -> Result<(), ProductionError> {
    if completion.jobs.is_empty()
        || completion.finished_at == 0
        || completion.jobs.len() != accepted.envelope.job_ids.len()
        || completion.teardown.request_event_id != accepted.event_id
        || completion.teardown.run_id != accepted.envelope.run_id
        || completion.teardown.relay_signer != signer
        || completion.teardown.validate().is_err()
    {
        return Err(ProductionError::Invalid);
    }
    let mut ids: Vec<_> = completion
        .jobs
        .iter()
        .map(|job| job.metadata.job_id.as_str())
        .collect();
    ids.sort_unstable();
    let mut expected: Vec<_> = accepted
        .envelope
        .job_ids
        .iter()
        .map(String::as_str)
        .collect();
    expected.sort_unstable();
    if ids != expected || completion.jobs.iter().any(|job| !job.state.is_terminal()) {
        return Err(ProductionError::Invalid);
    }
    Ok(())
}

fn verify_bytes(descriptor: &OutputDescriptor, bytes: &[u8]) -> Result<(), ProductionError> {
    if bytes.len() as u64 != descriptor.byte_length
        || hex::encode(Sha256::digest(bytes)) != descriptor.sha256
    {
        return Err(ProductionError::Evidence);
    }
    Ok(())
}

fn verify_stored(
    descriptor: &OutputDescriptor,
    stored: &StoredObject,
) -> Result<(), ProductionError> {
    if stored.sha256 != descriptor.sha256 || stored.byte_length != descriptor.byte_length {
        return Err(ProductionError::Evidence);
    }
    Ok(())
}

fn accepted_publication_id<P: ControlStore>(
    store: &P,
    key: &str,
) -> Result<String, ProductionError> {
    match store
        .load_publication(key)
        .map_err(|_| ProductionError::Store)?
    {
        Some(StoredPublication::Accepted {
            signed,
            relay_event_id,
        }) if signed.event_id == relay_event_id => Ok(relay_event_id),
        _ => Err(ProductionError::Invalid),
    }
}

fn read_validated_event<R: RelayControl>(
    relay: &mut R,
    event_id: &str,
    kind: u32,
    signer: &str,
    signer_generation: u64,
    channel_id: &str,
) -> Result<ValidatedCiEnvelope, ProductionError> {
    let read = relay
        .read_exact_event(event_id, kind, signer)
        .map_err(map_export_error)?;
    let expected_filter =
        format!(r#"[{{"ids":["{event_id}"],"authors":["{signer}"],"kinds":[{kind}],"limit":1}}]"#)
            .into_bytes();
    let expected_digest = hex::encode(Sha256::digest(&expected_filter));
    if read.event.event_id != event_id
        || read.event.kind != kind
        || read.proof.subject != signer
        || read.proof.generation != signer_generation
        || read.binding.method != crate::source::HttpMethod::Post
        || read.binding.publisher.as_deref() != Some(signer)
        || read.binding.query_filter.as_deref() != Some(expected_filter.as_slice())
        || read.binding.payload_sha256.as_deref() != Some(expected_digest.as_str())
        || read.binding.url.path() != "/query"
        || read.binding.url.query().is_some()
        || read.binding.url.fragment().is_some()
    {
        return Err(ProductionError::Invalid);
    }
    let event: nostr::Event =
        serde_json::from_value(read.event.signed_event).map_err(|_| ProductionError::Invalid)?;
    if event.id.to_hex() != read.event.event_id
        || event.kind.as_u16() as u32 != read.event.kind
        || event.content != read.event.content
        || serde_json::to_value(&event.tags).map_err(|_| ProductionError::Invalid)?
            != read.event.tags
        || !lower_hex(&read.proof.event_id, 64)
    {
        return Err(ProductionError::Invalid);
    }
    let authorized = std::collections::HashSet::from([signer.to_owned()]);
    validate_signed_ci_event(&event, channel_id, &authorized).map_err(|_| ProductionError::Invalid)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_export_error(error: ExportReadError) -> ProductionError {
    match error {
        ExportReadError::Unavailable | ExportReadError::Refused => ProductionError::Relay,
        ExportReadError::Invalid => ProductionError::Invalid,
    }
}

fn first_started(completion: &AttemptCompletion) -> u64 {
    completion
        .jobs
        .iter()
        .map(|job| job.started_at)
        .min()
        .unwrap_or(completion.finished_at)
}

fn terminal_run_state(jobs: &[JobCompletion]) -> RunState {
    if jobs.iter().any(|job| job.state == CiJobState::TimedOut) {
        RunState::TimedOut
    } else if jobs.iter().any(|job| job.state == CiJobState::Cancelled) {
        RunState::Cancelled
    } else if jobs
        .iter()
        .all(|job| matches!(job.state, CiJobState::Success | CiJobState::Skipped))
    {
        RunState::Success
    } else {
        RunState::Failure
    }
}

fn terminal_reason(jobs: &[JobCompletion]) -> Option<String> {
    jobs.iter().find_map(|job| job.reason.clone())
}

fn run_state(state: RunState) -> CiRunState {
    match state {
        RunState::Queued => CiRunState::Queued,
        RunState::Running => CiRunState::Running,
        RunState::Success => CiRunState::Success,
        RunState::Failure => CiRunState::Failure,
        RunState::Cancelled => CiRunState::Cancelled,
        RunState::TimedOut => CiRunState::TimedOut,
        RunState::InfrastructureFailure => CiRunState::InfrastructureFailure,
    }
}

fn job_envelope(
    accepted: &AcceptedRequest,
    job: &JobCompletion,
    signer: &str,
    sequence: u64,
    state: CiJobState,
    log_ref: Option<String>,
    artifact_refs: Vec<String>,
) -> CiJobStatusEnvelope {
    CiJobStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: accepted.event_id.clone(),
        run_id: accepted.envelope.run_id.clone(),
        workflow_id: accepted.envelope.workflow_id.clone(),
        target_repo_a: accepted.envelope.target_repo_a.clone(),
        tip_oid: accepted.envelope.tip_oid.clone(),
        base_oid: accepted.envelope.base_oid.clone(),
        job_id: job.metadata.job_id.clone(),
        name: job.metadata.name.clone(),
        attempt: job.attempt,
        parent_attempt: (job.attempt > 1).then_some(job.attempt - 1),
        sequence,
        state,
        conclusion: state
            .is_terminal()
            .then(|| format!("{state:?}").to_lowercase()),
        reason: job.reason.clone(),
        required: job.metadata.required,
        skip_policy: job.metadata.skip_policy,
        selected_job_instance: job.metadata.selected_job_instance.clone(),
        also_reruns: job.metadata.also_reruns.clone(),
        started_at: (state != CiJobState::Queued).then_some(job.started_at),
        finished_at: state.is_terminal().then_some(job.finished_at),
        log_ref,
        artifact_refs,
        relay_signer: signer.to_owned(),
    }
}

/// Linux descriptor-relative evidence reader. Every path component is opened
/// beneath the pre-opened root with `O_NOFOLLOW`; the final file must be a
/// single-link mode-0600 regular file whose size matches the receipt.
#[cfg(target_os = "linux")]
pub struct DescriptorOutputReader {
    root: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl DescriptorOutputReader {
    pub fn open(root: &Path) -> Result<Self, io::Error> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;
        let root = open(
            root,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        Ok(Self { root })
    }
}

#[cfg(target_os = "linux")]
impl EvidenceReader for DescriptorOutputReader {
    type Error = io::Error;

    fn read(&self, descriptor: &OutputDescriptor) -> Result<Vec<u8>, Self::Error> {
        use nix::fcntl::{openat, OFlag};
        use nix::sys::stat::{fstat, Mode, SFlag};
        use std::fs::File;
        use std::os::fd::OwnedFd;

        let path = Path::new(&descriptor.relative_path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid evidence path",
            ));
        }
        let components: Vec<_> = path.components().collect();
        if components.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty evidence path",
            ));
        }
        let mut directory: Option<OwnedFd> = None;
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                unreachable!()
            };
            let parent = directory.as_ref().unwrap_or(&self.root);
            let last = index + 1 == components.len();
            let flags = if last {
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
            } else {
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
            };
            directory = Some(openat(parent, *name, flags, Mode::empty()).map_err(io::Error::from)?);
        }
        let fd = directory
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty evidence path"))?;
        let stat = fstat(&fd).map_err(io::Error::from)?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
            || stat.st_nlink != 1
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_size < 0
            || stat.st_size as u64 != descriptor.byte_length
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe evidence file",
            ));
        }
        let mut bytes = Vec::with_capacity(descriptor.byte_length as usize);
        File::from(fd)
            .take(descriptor.byte_length.saturating_add(1))
            .read_to_end(&mut bytes)?;
        verify_bytes(descriptor, &bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "evidence mismatch"))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeSet, HashMap, VecDeque};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::rc::Rc;

    use buzz_core::ci::{CiRequestType, CiTeardownLease};

    use super::*;
    use crate::store::DurableControlStore;

    const CHANNEL: &str = "123e4567-e89b-12d3-a456-426614174099";
    const SIGNER: &str = "7777777777777777777777777777777777777777777777777777777777777777";

    #[derive(Default)]
    struct MemoryStore {
        cursor: u64,
        run: Option<(u64, RunRecord)>,
        /// Earlier attempts visible to rerun lineage validation only.
        lineage: Vec<(u64, RunRecord)>,
        publications: HashMap<String, StoredPublication>,
        deferred: BTreeSet<String>,
    }

    impl ControlStore for MemoryStore {
        type Error = ();

        fn cursor(&self, _channel_id: &str) -> Result<u64, Self::Error> {
            Ok(self.cursor)
        }

        fn advance_cursor(
            &mut self,
            _channel_id: &str,
            expected: u64,
            next: u64,
        ) -> Result<bool, Self::Error> {
            if self.cursor != expected {
                return Ok(false);
            }
            self.cursor = next;
            Ok(true)
        }

        fn load_run(
            &self,
            _identity: &RunIdentity,
        ) -> Result<Option<(u64, RunRecord)>, Self::Error> {
            Ok(self.run.clone())
        }

        fn load_run_attempts(
            &self,
            run_id: Uuid,
            attempt: u32,
        ) -> Result<Vec<(u64, RunRecord)>, Self::Error> {
            Ok(self
                .lineage
                .iter()
                .chain(self.run.iter())
                .filter(|(_, record)| {
                    record.identity().run_id() == run_id && record.identity().attempt() == attempt
                })
                .cloned()
                .collect())
        }

        fn compare_and_swap_run(
            &mut self,
            _identity: &RunIdentity,
            expected_revision: Option<u64>,
            next: &RunRecord,
        ) -> Result<StoreWrite, Self::Error> {
            let actual = self.run.as_ref().map(|(revision, _)| *revision);
            if actual != expected_revision {
                return Ok(StoreWrite::Conflict {
                    actual_revision: actual,
                });
            }
            let revision = actual.unwrap_or(0) + 1;
            self.run = Some((revision, next.clone()));
            Ok(StoreWrite::Written { revision })
        }

        fn load_publication(&self, key: &str) -> Result<Option<StoredPublication>, Self::Error> {
            Ok(self.publications.get(key).cloned())
        }

        fn record_publication_intent(
            &mut self,
            key: &str,
            event: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            if self.publications.contains_key(key) {
                return Ok(false);
            }
            self.publications
                .insert(key.to_owned(), StoredPublication::Pending(event.clone()));
            Ok(true)
        }

        fn refresh_pending_publication(
            &mut self,
            key: &str,
            expected_event_id: &str,
            replacement: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            let Some(StoredPublication::Pending(stored)) = self.publications.get(key) else {
                return Err(());
            };
            if stored.event_id != expected_event_id
                || stored.kind != replacement.kind
                || stored.content != replacement.content
                || stored.tags != replacement.tags
            {
                return Err(());
            }
            self.publications.insert(
                key.to_owned(),
                StoredPublication::Pending(replacement.clone()),
            );
            Ok(true)
        }

        fn defer_publication(&mut self, key: &str) -> Result<(), Self::Error> {
            if !matches!(
                self.publications.get(key),
                Some(StoredPublication::Pending(_))
            ) {
                return Err(());
            }
            self.deferred.insert(key.to_owned());
            Ok(())
        }

        fn deferred_publications(&self) -> Result<Vec<String>, Self::Error> {
            Ok(self.deferred.iter().cloned().collect())
        }

        fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error> {
            let Some(StoredPublication::Pending(signed)) = self.publications.get(key).cloned()
            else {
                return Err(());
            };
            self.publications.insert(
                key.to_owned(),
                StoredPublication::Accepted {
                    signed,
                    relay_event_id: event_id.to_owned(),
                },
            );
            self.deferred.remove(key);
            Ok(())
        }
    }

    struct DeterministicSigner;

    impl CiSigner for DeterministicSigner {
        type Error = ();

        fn pubkey(&self) -> &str {
            SIGNER
        }

        fn sign(
            &mut self,
            kind: u32,
            content: &str,
            tags: serde_json::Value,
        ) -> Result<SignedCiEvent, Self::Error> {
            let event_id = hex::encode(
                Sha256::new()
                    .chain_update(kind.to_be_bytes())
                    .chain_update(content.as_bytes())
                    .finalize(),
            );
            Ok(SignedCiEvent {
                event_id: event_id.clone(),
                kind,
                content: content.to_owned(),
                tags,
                signed_event: serde_json::json!({"id": event_id, "kind": kind}),
            })
        }
    }

    struct MemoryOutput(Vec<u8>);

    impl EvidenceReader for MemoryOutput {
        type Error = ();

        fn read(&self, _descriptor: &OutputDescriptor) -> Result<Vec<u8>, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct Executor(AttemptCompletion);

    impl AttemptExecutor for Executor {
        type Error = ();

        fn execute(
            &mut self,
            _request: &AcceptedRequest,
        ) -> Result<AttemptCompletion, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct FailingExecutor;

    impl AttemptExecutor for FailingExecutor {
        type Error = ();

        fn execute(
            &mut self,
            _request: &AcceptedRequest,
        ) -> Result<AttemptCompletion, Self::Error> {
            Err(())
        }
    }

    struct ExpiredRefusalExecutor;

    impl AttemptExecutor for ExpiredRefusalExecutor {
        type Error = RunnerBridgeError;

        fn execute(
            &mut self,
            _request: &AcceptedRequest,
        ) -> Result<AttemptCompletion, Self::Error> {
            Err(RunnerBridgeError::ExpiredRefusal)
        }

        fn is_expired_refusal(&self, error: &Self::Error) -> bool {
            error.is_expired_refusal()
        }
    }

    struct Relay {
        accepted: Option<AcceptedRequest>,
        published: Vec<u32>,
        job_statuses: Vec<CiJobStatusEnvelope>,
        intent_signal: Option<Rc<Cell<bool>>>,
        refuse_publication: bool,
    }

    impl RelayControl for Relay {
        type Error = ();

        fn next_accepted(
            &mut self,
            _channel_id: &str,
            after_cursor: u64,
        ) -> Result<Option<AcceptedRequest>, Self::Error> {
            Ok(self
                .accepted
                .as_ref()
                .filter(|accepted| accepted.watch_cursor > after_cursor)
                .cloned())
        }

        fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
            if let Some(signal) = self.intent_signal.as_ref() {
                assert!(signal.get(), "relay called before durable intent returned");
            }
            if self.refuse_publication {
                return Err(());
            }
            if event.kind == KIND_CI_JOB_STATUS {
                self.job_statuses
                    .push(serde_json::from_str(&event.content).expect("job status envelope"));
            }
            self.published.push(event.kind);
            Ok(event.event_id.clone())
        }

        fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn put_log(
            &mut self,
            accepted: &AcceptedRequest,
            job: &JobCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Ok(StoredObject {
                url: format!(
                    "https://relay.example/ci/logs/{}/{}/{}/{}/{}",
                    accepted.event_id,
                    accepted.envelope.run_id,
                    job.metadata.job_id,
                    job.attempt,
                    job.log.sha256
                ),
                sha256: job.log.sha256.clone(),
                byte_length: job.log.byte_length,
            })
        }

        fn put_artifact(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &JobCompletion,
            _artifact: &ArtifactCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(())
        }
    }

    fn accepted() -> AcceptedRequest {
        AcceptedRequest {
            channel_id: CHANNEL.into(),
            watch_cursor: 7,
            event_id: "11".repeat(32),
            envelope: CiRequestEnvelope {
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
                actor: "88".repeat(32),
                timeout_seconds: 30,
                idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
                issued_at: 10,
                expires_at: 40,
            },
        }
    }

    struct ChannelHeadRelay {
        heads: Vec<AcceptedRequest>,
        observed: Vec<String>,
    }

    impl RelayControl for ChannelHeadRelay {
        type Error = ();

        fn next_accepted(
            &mut self,
            _channel_id: &str,
            after_cursor: u64,
        ) -> Result<Option<AcceptedRequest>, Self::Error> {
            let next = self
                .heads
                .iter()
                .filter(|accepted| accepted.watch_cursor > after_cursor)
                .min_by_key(|accepted| accepted.watch_cursor)
                .cloned();
            if let Some(accepted) = &next {
                self.observed.push(accepted.event_id.clone());
            }
            Ok(next)
        }

        fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
            Ok(event.event_id.clone())
        }

        fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn put_log(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &JobCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(())
        }

        fn put_artifact(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &JobCompletion,
            _artifact: &ArtifactCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(())
        }
    }

    fn frozen_binding(expected: &AcceptedRequest) -> AcceptedRequestBinding {
        AcceptedRequestBinding {
            channel_id: expected.channel_id.clone(),
            event_id: expected.event_id.clone(),
            envelope: expected.envelope.clone(),
        }
    }

    #[test]
    fn bound_poll_refuses_foreign_head_without_consuming_expected_request_behind_it() {
        let mut expected = accepted();
        expected.watch_cursor = 8;
        let mut foreign = expected.clone();
        foreign.watch_cursor = 7;
        foreign.event_id = "99".repeat(32);
        foreign.envelope.run_id = "123e4567-e89b-12d3-a456-426614174099".into();
        let binding = frozen_binding(&expected);
        let mut handler = ProductionHandler::new(
            ChannelHeadRelay {
                heads: vec![foreign.clone(), expected],
                observed: Vec::new(),
            },
            DeterministicSigner,
            FailingExecutor,
            MemoryStore::default(),
            MemoryOutput(Vec::new()),
        );

        for _ in 0..2 {
            assert!(matches!(
                handler.poll_once_bound(CHANNEL, &binding),
                Err(ProductionError::Invalid)
            ));
            assert_eq!(handler.store.cursor, 0);
            assert!(handler.store.run.is_none());
            assert!(handler.store.publications.is_empty());
        }
        assert_eq!(handler.relay.observed, vec![foreign.event_id; 2]);
    }

    #[test]
    fn bound_deferred_replay_refuses_foreign_terminal_head_before_any_mutation() {
        let mut run_a = accepted();
        run_a.watch_cursor = 8;
        let mut foreign = run_a.clone();
        foreign.watch_cursor = 7;
        foreign.event_id = "99".repeat(32);
        foreign.envelope.run_id = "123e4567-e89b-12d3-a456-426614174099".into();
        let foreign_identity = run_identity(&foreign).expect("foreign identity");
        let foreign_terminal = RunRecord::queued(foreign_identity, 10)
            .expect("queued foreign run")
            .transition(
                RunState::InfrastructureFailure,
                12,
                Some("relay".to_owned()),
            )
            .expect("terminal foreign run");
        let publication_key = format!("{}:run:terminal", foreign.event_id);
        let pending = StoredPublication::Pending(SignedCiEvent {
            event_id: "aa".repeat(32),
            kind: KIND_CI_RUN_STATUS,
            content: "{}".to_owned(),
            tags: serde_json::json!([]),
            signed_event: serde_json::json!({
                "id": "aa".repeat(32),
                "kind": KIND_CI_RUN_STATUS
            }),
        });
        let store = MemoryStore {
            cursor: 0,
            run: Some((1, foreign_terminal.clone())),
            lineage: Vec::new(),
            publications: HashMap::from([(publication_key.clone(), pending.clone())]),
            deferred: BTreeSet::from([publication_key.clone()]),
        };
        let binding = frozen_binding(&run_a);
        let run_a_event_id = run_a.event_id.clone();
        let mut handler = ProductionHandler::new(
            ChannelHeadRelay {
                heads: vec![foreign.clone(), run_a],
                observed: Vec::new(),
            },
            CountingSigner(0),
            FailingExecutor,
            store,
            MemoryOutput(Vec::new()),
        );

        assert!(matches!(
            handler.replay_deferred_publications_bound(CHANNEL, &binding),
            Err(ProductionError::Invalid)
        ));
        assert_eq!(handler.store.cursor, 0);
        assert_eq!(handler.store.run, Some((1, foreign_terminal)));
        assert_eq!(
            handler.store.publications,
            HashMap::from([(publication_key.clone(), pending)])
        );
        assert_eq!(handler.store.deferred, BTreeSet::from([publication_key]));
        assert_eq!(handler.signer.0, 0);
        assert_eq!(handler.relay.observed, vec![foreign.event_id]);
        assert!(!handler.relay.observed.contains(&run_a_event_id));
    }

    #[test]
    fn frozen_binding_rejects_cross_lineage_and_authority_drift() {
        let expected = accepted();
        let binding = frozen_binding(&expected);
        assert!(binding.matches(&expected));

        let mut mismatches = Vec::new();
        let mut drift = expected.clone();
        drift.event_id = "99".repeat(32);
        mismatches.push(("signed request digest", drift));
        let mut drift = expected.clone();
        drift.channel_id = "123e4567-e89b-12d3-a456-426614174098".into();
        mismatches.push(("channel", drift));
        let mut drift = expected.clone();
        drift.envelope.actor = "99".repeat(32);
        mismatches.push(("actor authority", drift));
        let mut drift = expected.clone();
        drift.envelope.run_id = "123e4567-e89b-12d3-a456-426614174099".into();
        mismatches.push(("run UUID", drift));
        let mut drift = expected.clone();
        drift.envelope.target_repo_a = format!("30617:{}:foreign", "22".repeat(32));
        mismatches.push(("repository", drift));
        let mut drift = expected.clone();
        drift.envelope.tip_oid = "77".repeat(20);
        mismatches.push(("tip object", drift));
        let mut drift = expected.clone();
        drift.envelope.base_ref = "refs/heads/foreign".into();
        mismatches.push(("base ref", drift));
        let mut drift = expected.clone();
        drift.envelope.base_oid = "77".repeat(20);
        mismatches.push(("base object", drift));
        let mut drift = expected.clone();
        drift.envelope.workflow_id = "foreign".into();
        mismatches.push(("workflow ID", drift));
        let mut drift = expected.clone();
        drift.envelope.workflow_digest = "77".repeat(32);
        mismatches.push(("workflow digest", drift));
        let mut drift = expected.clone();
        drift.envelope.job_ids = vec!["foreign".into()];
        mismatches.push(("job selection", drift));
        let mut drift = expected.clone();
        drift.envelope.attempt = 2;
        drift.envelope.parent_attempt = Some(1);
        drift.envelope.parent_run_id = Some(drift.envelope.run_id.clone());
        mismatches.push(("attempt lineage", drift));

        for (field, drift) in mismatches {
            assert!(!binding.matches(&drift), "accepted drift in {field}");
        }

        let mut rerun = expected;
        rerun.event_id = "aa".repeat(32);
        rerun.envelope.request_type = CiRequestType::Rerun;
        rerun.envelope.attempt = 2;
        rerun.envelope.parent_attempt = Some(1);
        rerun.envelope.parent_run_id = Some(rerun.envelope.run_id.clone());
        let rerun_binding = frozen_binding(&rerun);
        for (field, drift) in [
            ("parent attempt", {
                let mut drift = rerun.clone();
                drift.envelope.parent_attempt = None;
                drift
            }),
            ("parent run", {
                let mut drift = rerun.clone();
                drift.envelope.parent_run_id = None;
                drift
            }),
            ("rerun attempt", {
                let mut drift = rerun.clone();
                drift.envelope.attempt = 1;
                drift
            }),
        ] {
            assert!(!rerun_binding.matches(&drift), "accepted drift in {field}");
        }
    }

    fn completion(log: &[u8]) -> AttemptCompletion {
        let accepted = accepted();
        AttemptCompletion {
            jobs: vec![JobCompletion {
                metadata: JobMetadata {
                    job_id: "test".into(),
                    name: "Test".into(),
                    required: true,
                    skip_policy: CiSkipPolicy::Forbid,
                    selected_job_instance: "test".into(),
                    also_reruns: Vec::new(),
                },
                attempt: 1,
                state: CiJobState::Success,
                reason: None,
                started_at: 11,
                finished_at: 12,
                log: OutputDescriptor {
                    relative_path: "dispatch/test/attempt-1.log".into(),
                    sha256: hex::encode(Sha256::digest(log)),
                    byte_length: log.len() as u64,
                },
                log_cap_bytes: 1024,
                artifacts: Vec::new(),
            }],
            teardown: CiTeardownAttestationEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: accepted.event_id,
                run_id: accepted.envelope.run_id,
                workflow_id: accepted.envelope.workflow_id,
                target_repo_a: accepted.envelope.target_repo_a,
                tip_oid: accepted.envelope.tip_oid,
                base_oid: accepted.envelope.base_oid,
                workflow_digest: accepted.envelope.workflow_digest,
                attempt: 1,
                leases: vec![CiTeardownLease {
                    job_id: "test".into(),
                    attempt: 1,
                    lease_id: "123e4567-e89b-12d3-a456-426614174010".into(),
                }],
                lease_empty: true,
                teardown_at: 12,
                relay_signer: SIGNER.into(),
            },
            finished_at: 12,
        }
    }

    fn signed_job_status(
        accepted: &AcceptedRequest,
        job: &JobCompletion,
        sequence: u64,
        state: CiJobState,
    ) -> SignedCiEvent {
        let envelope = job_envelope(accepted, job, SIGNER, sequence, state, None, Vec::new());
        let content = serde_json::to_string(&envelope).expect("job status content");
        let tags = serde_json::to_value(
            job_status_tags(&accepted.channel_id, &envelope).expect("job status tags"),
        )
        .expect("serialized job status tags");
        DeterministicSigner
            .sign(KIND_CI_JOB_STATUS, &content, tags)
            .expect("signed job status")
    }

    #[test]
    fn expected_recovery_poll_rejects_a_later_head_without_consuming_it() {
        let log = b"ok\n".to_vec();
        let accepted = accepted();
        let mut expected = frozen_binding(&accepted);
        expected.event_id = "22".repeat(32);
        let relay = Relay {
            accepted: Some(accepted),
            published: Vec::new(),
            job_statuses: Vec::new(),
            intent_signal: None,
            refuse_publication: false,
        };
        let mut handler = ProductionHandler::new(
            relay,
            DeterministicSigner,
            Executor(completion(&log)),
            MemoryStore::default(),
            MemoryOutput(log),
        );

        assert!(matches!(
            handler.poll_once_bound(CHANNEL, &expected),
            Err(ProductionError::Invalid)
        ));
        assert_eq!(handler.store.cursor, 0);
        assert!(handler.store.run.is_none());
        assert!(handler.relay.published.is_empty());
    }

    #[test]
    fn accepted_request_bypasses_legacy_job_keys_and_publishes_full_signed_lifecycle() {
        let log = b"ok\n".to_vec();
        let accepted = accepted();
        let completion = completion(&log);
        let legacy_running =
            signed_job_status(&accepted, &completion.jobs[0], 1, CiJobState::Running);
        let legacy_terminal =
            signed_job_status(&accepted, &completion.jobs[0], 2, CiJobState::Success);
        let legacy_running_key = format!("{}:job:test:1:running", accepted.event_id);
        let legacy_terminal_key = format!("{}:job:test:1:terminal", accepted.event_id);
        let relay = Relay {
            accepted: Some(accepted.clone()),
            published: Vec::new(),
            job_statuses: Vec::new(),
            intent_signal: None,
            refuse_publication: false,
        };
        let mut handler = ProductionHandler::new(
            relay,
            DeterministicSigner,
            Executor(completion),
            MemoryStore {
                publications: HashMap::from([
                    (
                        legacy_running_key.clone(),
                        StoredPublication::Pending(legacy_running),
                    ),
                    (
                        legacy_terminal_key.clone(),
                        StoredPublication::Pending(legacy_terminal),
                    ),
                ]),
                ..MemoryStore::default()
            },
            MemoryOutput(log),
        );

        assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
        assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Idle);
        assert_eq!(
            handler.relay.published,
            vec![46101, 46101, 46102, 46102, 46103, 46102, 46105, 46106, 46101, 46108]
        );
        assert_eq!(
            handler
                .relay
                .job_statuses
                .iter()
                .map(|status| (status.sequence, status.state))
                .collect::<Vec<_>>(),
            vec![
                (1, CiJobState::Queued),
                (2, CiJobState::Running),
                (3, CiJobState::Success),
            ]
        );
        assert_eq!(handler.relay.job_statuses[0].started_at, None);
        assert_eq!(handler.relay.job_statuses[1].started_at, Some(11));
        assert!(matches!(
            handler.store.publications.get(&legacy_running_key),
            Some(StoredPublication::Pending(_))
        ));
        assert!(matches!(
            handler.store.publications.get(&legacy_terminal_key),
            Some(StoredPublication::Pending(_))
        ));
        for sequence in 1..=3 {
            assert!(matches!(
                handler.store.publications.get(&format!(
                    "{}:job:test:1:status:{sequence}",
                    accepted.event_id
                )),
                Some(StoredPublication::Accepted { .. })
            ));
        }
        assert_eq!(handler.store.cursor, 7);
        assert_eq!(
            handler.store.run.as_ref().unwrap().1.state(),
            RunState::Success
        );
    }

    #[test]
    fn failed_run_publishes_completion_without_finalization_or_teardown_events() {
        let log = b"deterministic failure\n".to_vec();
        let accepted = accepted();
        let mut failed = completion(&log);
        failed.jobs[0].state = CiJobState::Failure;
        failed.jobs[0].reason = Some("fixture_failure".into());
        let relay = Relay {
            accepted: Some(accepted.clone()),
            published: Vec::new(),
            job_statuses: Vec::new(),
            intent_signal: None,
            refuse_publication: false,
        };
        let mut handler = ProductionHandler::new(
            relay,
            DeterministicSigner,
            Executor(failed),
            MemoryStore::default(),
            MemoryOutput(log),
        );

        assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
        assert!(!handler
            .relay
            .published
            .contains(&KIND_CI_EVIDENCE_FINALIZED));
        assert!(!handler
            .relay
            .published
            .contains(&KIND_CI_TEARDOWN_ATTESTATION));
        let record = &handler.store.run.as_ref().unwrap().1;
        assert_eq!(record.state(), RunState::Failure);
        assert_eq!(record.reason(), Some("fixture_failure"));
        let wire = serde_json::to_value(record).unwrap();
        assert!(wire["facts"]["evidence_finalized_event_id"].is_null());
        assert!(wire["facts"]["teardown_attestation_event_id"].is_null());
        assert!(record.terminal_event_id().is_some());
    }

    #[test]
    fn runner_failure_publishes_durable_terminal_infrastructure_status() {
        let mut handler = ProductionHandler::new(
            Relay {
                accepted: Some(accepted()),
                published: Vec::new(),
                job_statuses: Vec::new(),
                intent_signal: None,
                refuse_publication: false,
            },
            DeterministicSigner,
            FailingExecutor,
            MemoryStore::default(),
            MemoryOutput(Vec::new()),
        );

        assert!(matches!(
            handler.poll_once(CHANNEL),
            Err(ProductionError::Runner)
        ));
        assert_eq!(handler.relay.published, vec![46101, 46101, 46108]);
        let record = &handler.store.run.as_ref().expect("durable run").1;
        assert_eq!(record.state(), RunState::InfrastructureFailure);
        assert_eq!(record.reason(), Some("runner_or_evidence_provider_failure"));
        assert!(record.terminal_event_id().is_some());
        assert!(record.check_event_id().is_some());
        assert_eq!(handler.store.cursor, 0);
    }

    #[test]
    fn expired_runner_refusal_is_terminal_for_only_that_request() {
        assert!(RunnerBridgeError::ExpiredRefusal.is_expired_refusal());
        assert!(!RunnerBridgeError::Refused.is_expired_refusal());
        let mut handler = ProductionHandler::new(
            Relay {
                accepted: Some(accepted()),
                published: Vec::new(),
                job_statuses: Vec::new(),
                intent_signal: None,
                refuse_publication: false,
            },
            DeterministicSigner,
            ExpiredRefusalExecutor,
            MemoryStore::default(),
            MemoryOutput(Vec::new()),
        );

        assert!(matches!(
            handler.poll_once(CHANNEL),
            Ok(PollStep::Completed)
        ));
        assert_eq!(handler.relay.published, vec![46101, 46101, 46108]);
        let record = &handler.store.run.as_ref().expect("durable run").1;
        assert_eq!(record.state(), RunState::InfrastructureFailure);
        assert_eq!(record.reason(), Some("request_expired_before_admission"));
        assert!(record.terminal_event_id().is_some());
        assert_eq!(handler.store.cursor, 7);
    }

    #[test]
    fn restart_republishes_running_status_before_completion() {
        let accepted = accepted();
        let identity = RunIdentity::new(
            accepted.event_id.clone(),
            Uuid::parse_str(&accepted.envelope.run_id).expect("run id"),
            accepted.envelope.attempt,
            accepted.envelope.target_repo_a.clone(),
            accepted.envelope.tip_oid.clone(),
            accepted.envelope.workflow_id.clone(),
        )
        .expect("identity");
        let queued = RunRecord::queued(identity, accepted.envelope.issued_at).expect("queued");
        let running = queued
            .transition(RunState::Running, 11, None)
            .expect("running");
        let log = b"ok\n".to_vec();
        let mut handler = ProductionHandler::new(
            Relay {
                accepted: Some(accepted),
                published: Vec::new(),
                job_statuses: Vec::new(),
                intent_signal: None,
                refuse_publication: false,
            },
            DeterministicSigner,
            Executor(completion(&log)),
            MemoryStore {
                cursor: 0,
                run: Some((2, running)),
                lineage: Vec::new(),
                publications: HashMap::new(),
                deferred: BTreeSet::new(),
            },
            MemoryOutput(log),
        );

        assert_eq!(
            handler.poll_once(CHANNEL).expect("reconcile running"),
            PollStep::Completed
        );
        assert_eq!(handler.relay.published.first(), Some(&KIND_CI_RUN_STATUS));
        assert!(handler
            .store
            .publications
            .contains_key(&format!("{}:run:running", "11".repeat(32))));
    }

    #[test]
    fn restart_binds_unpublished_terminal_status_before_advancing_cursor() {
        let accepted = accepted();
        let identity = RunIdentity::new(
            accepted.event_id.clone(),
            Uuid::parse_str(&accepted.envelope.run_id).expect("run id"),
            accepted.envelope.attempt,
            accepted.envelope.target_repo_a.clone(),
            accepted.envelope.tip_oid.clone(),
            accepted.envelope.workflow_id.clone(),
        )
        .expect("identity");
        let terminal = RunRecord::queued(identity, accepted.envelope.issued_at)
            .expect("queued")
            .transition(RunState::Running, 11, None)
            .expect("running")
            .transition(RunState::Failure, 12, Some("failed".to_owned()))
            .expect("terminal");
        let expected = frozen_binding(&accepted);
        let mut handler = ProductionHandler::new(
            Relay {
                accepted: Some(accepted),
                published: Vec::new(),
                job_statuses: Vec::new(),
                intent_signal: None,
                refuse_publication: false,
            },
            DeterministicSigner,
            FailingExecutor,
            MemoryStore {
                cursor: 0,
                run: Some((3, terminal)),
                lineage: Vec::new(),
                publications: HashMap::new(),
                deferred: BTreeSet::new(),
            },
            MemoryOutput(Vec::new()),
        );

        assert_eq!(
            handler
                .poll_once_bound(CHANNEL, &expected)
                .expect("reconcile exact terminal without re-execution"),
            PollStep::Completed
        );
        assert_eq!(
            handler.relay.published,
            vec![KIND_CI_RUN_STATUS, KIND_CI_CHECK]
        );
        assert_eq!(handler.store.cursor, 7);
        assert!(handler
            .store
            .run
            .as_ref()
            .expect("stored run")
            .1
            .terminal_event_id()
            .is_some());
    }

    #[test]
    fn failed_pending_publication_is_reconciled_before_its_signature_is_refreshed() {
        struct ReconcileRelay {
            exists: bool,
            fail_first: bool,
            published: Vec<String>,
        }

        impl RelayControl for ReconcileRelay {
            type Error = ();

            fn next_accepted(
                &mut self,
                _channel_id: &str,
                _after_cursor: u64,
            ) -> Result<Option<AcceptedRequest>, Self::Error> {
                Ok(None)
            }

            fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
                if self.fail_first {
                    self.fail_first = false;
                    return Err(());
                }
                self.published.push(event.event_id.clone());
                Ok(event.event_id.clone())
            }

            fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
                Ok(self.exists)
            }

            fn put_log(
                &mut self,
                _accepted: &AcceptedRequest,
                _job: &JobCompletion,
                _bytes: &[u8],
            ) -> Result<StoredObject, Self::Error> {
                Err(())
            }

            fn put_artifact(
                &mut self,
                _accepted: &AcceptedRequest,
                _job: &JobCompletion,
                _artifact: &ArtifactCompletion,
                _bytes: &[u8],
            ) -> Result<StoredObject, Self::Error> {
                Err(())
            }
        }

        struct RefreshingSigner;

        impl CiSigner for RefreshingSigner {
            type Error = ();

            fn pubkey(&self) -> &str {
                SIGNER
            }

            fn sign(
                &mut self,
                kind: u32,
                content: &str,
                tags: serde_json::Value,
            ) -> Result<SignedCiEvent, Self::Error> {
                Ok(SignedCiEvent {
                    event_id: "bb".repeat(32),
                    kind,
                    content: content.to_owned(),
                    tags: tags.clone(),
                    signed_event: serde_json::json!({
                        "id": "bb".repeat(32),
                        "kind": kind,
                        "content": content,
                        "tags": tags,
                        "created_at": SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("clock")
                            .as_secs()
                    }),
                })
            }
        }

        let key = format!("{}:run:terminal", "11".repeat(32));
        let stale = SignedCiEvent {
            event_id: "aa".repeat(32),
            kind: KIND_CI_RUN_STATUS,
            content: "{}".to_owned(),
            tags: serde_json::json!([]),
            signed_event: serde_json::json!({
                "id": "aa".repeat(32),
                "kind": KIND_CI_RUN_STATUS,
                "content": "{}",
                "tags": [],
                "created_at": 1
            }),
        };
        let mut handler = ProductionHandler::new(
            ReconcileRelay {
                exists: false,
                fail_first: true,
                published: Vec::new(),
            },
            RefreshingSigner,
            FailingExecutor,
            MemoryStore {
                publications: HashMap::from([(
                    key.clone(),
                    StoredPublication::Pending(stale.clone()),
                )]),
                ..MemoryStore::default()
            },
            MemoryOutput(Vec::new()),
        );

        assert_eq!(
            handler
                .republish(&key, StoredPublication::Pending(stale.clone()))
                .expect("refresh absent publication"),
            "bb".repeat(32)
        );
        assert_eq!(handler.relay.published, vec!["bb".repeat(32)]);
        assert!(matches!(
            handler.store.publications.get(&key),
            Some(StoredPublication::Accepted { signed, relay_event_id })
                if signed.event_id == "bb".repeat(32) && relay_event_id == &"bb".repeat(32)
        ));

        let mut reconciled = ProductionHandler::new(
            ReconcileRelay {
                exists: true,
                fail_first: true,
                published: Vec::new(),
            },
            RefreshingSigner,
            FailingExecutor,
            MemoryStore {
                publications: HashMap::from([(
                    key.clone(),
                    StoredPublication::Pending(stale.clone()),
                )]),
                ..MemoryStore::default()
            },
            MemoryOutput(Vec::new()),
        );
        assert_eq!(
            reconciled
                .republish(&key, StoredPublication::Pending(stale))
                .expect("reconcile accepted publication"),
            "aa".repeat(32)
        );
        assert!(reconciled.relay.published.is_empty());
        assert!(matches!(
            reconciled.store.publications.get(&key),
            Some(StoredPublication::Accepted { signed, relay_event_id })
                if signed.event_id == "aa".repeat(32) && relay_event_id == &"aa".repeat(32)
        ));
    }

    #[test]
    fn refused_publication_leaves_durable_intent_for_restart_replay() {
        struct SignallingStore {
            durable: DurableControlStore,
            intent_signal: Rc<Cell<bool>>,
        }

        impl ControlStore for SignallingStore {
            type Error = crate::store::StoreError;

            fn cursor(&self, channel_id: &str) -> Result<u64, Self::Error> {
                self.durable.cursor(channel_id)
            }

            fn advance_cursor(
                &mut self,
                channel_id: &str,
                expected: u64,
                next: u64,
            ) -> Result<bool, Self::Error> {
                self.durable.advance_cursor(channel_id, expected, next)
            }

            fn load_run(
                &self,
                identity: &RunIdentity,
            ) -> Result<Option<(u64, RunRecord)>, Self::Error> {
                self.durable.load_run(identity)
            }

            fn load_run_attempts(
                &self,
                run_id: Uuid,
                attempt: u32,
            ) -> Result<Vec<(u64, RunRecord)>, Self::Error> {
                self.durable.load_run_attempts(run_id, attempt)
            }

            fn compare_and_swap_run(
                &mut self,
                identity: &RunIdentity,
                expected_revision: Option<u64>,
                next: &RunRecord,
            ) -> Result<StoreWrite, Self::Error> {
                self.durable
                    .compare_and_swap_run(identity, expected_revision, next)
            }

            fn load_publication(
                &self,
                key: &str,
            ) -> Result<Option<StoredPublication>, Self::Error> {
                self.durable.load_publication(key)
            }

            fn record_publication_intent(
                &mut self,
                key: &str,
                event: &SignedCiEvent,
            ) -> Result<bool, Self::Error> {
                let written = self.durable.record_publication_intent(key, event)?;
                self.intent_signal.set(true);
                Ok(written)
            }

            fn refresh_pending_publication(
                &mut self,
                key: &str,
                expected_event_id: &str,
                replacement: &SignedCiEvent,
            ) -> Result<bool, Self::Error> {
                self.durable
                    .refresh_pending_publication(key, expected_event_id, replacement)
            }

            fn defer_publication(&mut self, key: &str) -> Result<(), Self::Error> {
                self.durable.defer_publication(key)
            }

            fn deferred_publications(&self) -> Result<Vec<String>, Self::Error> {
                self.durable.deferred_publications()
            }

            fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error> {
                self.durable.accept_publication(key, event_id)
            }
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(directory.path()).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let uid = fs::metadata(&root).expect("metadata").uid();
        let signal = Rc::new(Cell::new(false));
        let store = SignallingStore {
            durable: DurableControlStore::open(root.clone(), uid).expect("store"),
            intent_signal: Rc::clone(&signal),
        };
        let log = b"ok\n".to_vec();
        let mut handler = ProductionHandler::new(
            Relay {
                accepted: Some(accepted()),
                published: Vec::new(),
                job_statuses: Vec::new(),
                intent_signal: Some(Rc::clone(&signal)),
                refuse_publication: true,
            },
            DeterministicSigner,
            Executor(completion(&log)),
            store,
            MemoryOutput(log),
        );

        assert!(matches!(
            handler.poll_once(CHANNEL),
            Err(ProductionError::Relay)
        ));
        assert!(signal.get());
        drop(handler);
        let reopened = DurableControlStore::open(root, uid).expect("reopen");
        assert!(matches!(
            reopened
                .load_publication(&format!("{}:run:queued", "11".repeat(32)))
                .expect("load intent"),
            Some(StoredPublication::Pending(_))
        ));
        assert_eq!(reopened.cursor(CHANNEL).expect("cursor"), 0);
    }

    /// Relay double for the grant-order scenario: every publish consumes one
    /// scripted answer (an empty script accepts), and only `Unauthorized` is
    /// the relay's exact unauthorized-status-signer refusal.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Refusal {
        Unauthorized,
        Other,
    }

    struct ScriptedRelay {
        accepted: Option<AcceptedRequest>,
        answers: VecDeque<Result<(), Refusal>>,
        published: Vec<String>,
        exists: bool,
    }

    impl ScriptedRelay {
        fn new(accepted: Option<AcceptedRequest>, answers: &[Result<(), Refusal>]) -> Self {
            Self {
                accepted,
                answers: answers.iter().copied().collect(),
                published: Vec::new(),
                exists: false,
            }
        }
    }

    impl RelayControl for ScriptedRelay {
        type Error = Refusal;

        fn next_accepted(
            &mut self,
            _channel_id: &str,
            after_cursor: u64,
        ) -> Result<Option<AcceptedRequest>, Self::Error> {
            Ok(self
                .accepted
                .as_ref()
                .filter(|accepted| accepted.watch_cursor > after_cursor)
                .cloned())
        }

        fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
            self.published.push(event.event_id.clone());
            match self.answers.pop_front() {
                Some(Err(refusal)) => Err(refusal),
                _ => Ok(event.event_id.clone()),
            }
        }

        fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
            Ok(self.exists)
        }

        fn is_unauthorized_status_signer(&self, error: &Self::Error) -> bool {
            *error == Refusal::Unauthorized
        }

        fn put_log(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &JobCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(Refusal::Other)
        }

        fn put_artifact(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &JobCompletion,
            _artifact: &ArtifactCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(Refusal::Other)
        }
    }

    /// Every signature gets a fresh id, as a keyholder re-sign does.
    struct CountingSigner(u64);

    impl CiSigner for CountingSigner {
        type Error = ();

        fn pubkey(&self) -> &str {
            SIGNER
        }

        fn sign(
            &mut self,
            kind: u32,
            content: &str,
            tags: serde_json::Value,
        ) -> Result<SignedCiEvent, Self::Error> {
            self.0 += 1;
            let event_id = hex::encode(Sha256::digest(self.0.to_be_bytes()));
            Ok(SignedCiEvent {
                event_id: event_id.clone(),
                kind,
                content: content.to_owned(),
                tags: tags.clone(),
                signed_event: serde_json::json!({"id": event_id, "kind": kind, "content": content, "tags": tags}),
            })
        }
    }

    fn counted_id(count: u64) -> String {
        hex::encode(Sha256::digest(count.to_be_bytes()))
    }

    fn terminal_key() -> String {
        format!("{}:run:terminal", "11".repeat(32))
    }

    fn stale_terminal_event() -> SignedCiEvent {
        SignedCiEvent {
            event_id: "aa".repeat(32),
            kind: KIND_CI_RUN_STATUS,
            content: "{}".to_owned(),
            tags: serde_json::json!([]),
            signed_event: serde_json::json!({"id": "aa".repeat(32), "kind": KIND_CI_RUN_STATUS}),
        }
    }

    /// The M12 production shape: the head request's run is already terminal
    /// locally, its terminal kind-46101 publication is still pending, and the
    /// cursor has not moved past the request.
    fn stale_terminal_record() -> RunRecord {
        let identity = run_identity(&accepted()).expect("identity");
        RunRecord::queued(identity, 10)
            .expect("queued")
            .transition(
                RunState::InfrastructureFailure,
                12,
                Some("relay".to_owned()),
            )
            .expect("terminal")
    }

    fn stale_terminal_store() -> MemoryStore {
        MemoryStore {
            run: Some((1, stale_terminal_record())),
            publications: HashMap::from([(
                terminal_key(),
                StoredPublication::Pending(stale_terminal_event()),
            )]),
            ..MemoryStore::default()
        }
    }

    type GrantOrderHandler = ProductionHandler<
        ScriptedRelay,
        CountingSigner,
        FailingExecutor,
        MemoryStore,
        MemoryOutput,
    >;

    fn grant_order_handler(
        answers: &[Result<(), Refusal>],
        store: MemoryStore,
        deferral: bool,
    ) -> GrantOrderHandler {
        let mut handler = ProductionHandler::new(
            ScriptedRelay::new(Some(accepted()), answers),
            CountingSigner(0),
            FailingExecutor,
            store,
            MemoryOutput(Vec::new()),
        );
        handler.set_replay_deferral(deferral);
        handler
    }

    #[test]
    fn startup_replay_refused_as_unauthorized_signer_is_deferred_before_the_grant() {
        // Exact retry fails on age, the read-back finds nothing, the re-signed
        // event is refused as an unauthorized signer: deferred, not terminal.
        let mut handler = grant_order_handler(
            &[Err(Refusal::Other), Err(Refusal::Unauthorized)],
            stale_terminal_store(),
            true,
        );
        assert_eq!(
            handler.poll_once(CHANNEL).expect("deferred poll"),
            PollStep::Deferred
        );
        assert_eq!(
            handler.relay.published,
            vec!["aa".repeat(32), counted_id(1)]
        );
        assert_eq!(
            handler.store.deferred_publications().expect("deferred"),
            vec![terminal_key()]
        );
        assert!(matches!(
            handler.store.publications.get(&terminal_key()),
            Some(StoredPublication::Pending(signed)) if signed.event_id == counted_id(1)
        ));
        assert_eq!(handler.store.cursor, 0, "the head request is not consumed");
        assert!(handler
            .store
            .run
            .as_ref()
            .expect("run")
            .1
            .terminal_event_id()
            .is_none());

        // While deferred and before the grant, later polls neither re-sign nor
        // touch the relay; the deferral is answered by the grant approval.
        assert_eq!(
            handler.poll_once(CHANNEL).expect("still deferred"),
            PollStep::Deferred
        );
        assert_eq!(handler.relay.published.len(), 2);
        assert_eq!(handler.signer.0, 1);
        assert_eq!(
            handler.store.deferred_publications().expect("deferred"),
            vec![terminal_key()]
        );
    }

    #[test]
    fn deferred_replay_is_retried_after_the_grant_and_settles_the_head() {
        let mut handler = grant_order_handler(
            &[Err(Refusal::Other), Err(Refusal::Unauthorized)],
            stale_terminal_store(),
            true,
        );
        assert_eq!(
            handler.poll_once(CHANNEL).expect("deferred poll"),
            PollStep::Deferred
        );

        // The grant is acknowledged: deferral is cleared and the replay goes
        // through the ordinary pending path (exact retry succeeds here).
        handler.set_replay_deferral(false);
        assert_eq!(
            handler
                .replay_deferred_publications(CHANNEL)
                .expect("replay"),
            1
        );
        assert_eq!(
            handler.relay.published,
            vec!["aa".repeat(32), counted_id(1), counted_id(1), counted_id(2)]
        );
        assert!(handler
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
        assert!(matches!(
            handler.store.publications.get(&terminal_key()),
            Some(StoredPublication::Accepted { signed, relay_event_id })
                if signed.event_id == counted_id(1) && *relay_event_id == counted_id(1)
        ));
        let (_, record) = handler.store.run.clone().expect("run");
        assert_eq!(record.terminal_event_id(), Some(counted_id(1).as_str()));
        assert_eq!(
            handler.store.cursor, 7,
            "the terminal head is settled and consumed"
        );
        assert_eq!(handler.poll_once(CHANNEL).expect("idle"), PollStep::Idle);
        assert_eq!(
            handler
                .replay_deferred_publications(CHANNEL)
                .expect("nothing left"),
            0
        );
        assert_eq!(handler.relay.published.len(), 4);
    }

    #[test]
    fn bound_deferred_replay_settles_only_the_exact_expected_head() {
        let expected = accepted();
        let binding = frozen_binding(&expected);
        let mut handler = grant_order_handler(
            &[Err(Refusal::Other), Err(Refusal::Unauthorized)],
            stale_terminal_store(),
            true,
        );
        assert_eq!(
            handler.poll_once(CHANNEL).expect("deferred poll"),
            PollStep::Deferred
        );

        handler.set_replay_deferral(false);
        assert_eq!(
            handler
                .replay_deferred_publications_bound(CHANNEL, &binding)
                .expect("bound replay"),
            1
        );
        assert_eq!(handler.store.cursor, expected.watch_cursor);
        assert!(handler
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
    }

    #[test]
    fn durable_deferral_survives_restart_and_replays_from_the_reopened_store() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(directory.path()).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let uid = fs::metadata(&root).expect("metadata").uid();
        let mut store = DurableControlStore::open(root.clone(), uid).expect("store");
        let identity = run_identity(&accepted()).expect("identity");
        store
            .compare_and_swap_run(&identity, None, &stale_terminal_record())
            .expect("write run");
        assert!(store
            .record_publication_intent(&terminal_key(), &stale_terminal_event())
            .expect("intent"));
        let mut handler = ProductionHandler::new(
            ScriptedRelay::new(
                Some(accepted()),
                &[Err(Refusal::Other), Err(Refusal::Unauthorized)],
            ),
            CountingSigner(0),
            FailingExecutor,
            store,
            MemoryOutput(Vec::new()),
        );
        handler.set_replay_deferral(true);
        assert_eq!(
            handler.poll_once(CHANNEL).expect("deferred poll"),
            PollStep::Deferred
        );
        drop(handler);

        let reopened = DurableControlStore::open(root.clone(), uid).expect("reopen");
        assert_eq!(
            reopened.deferred_publications().expect("deferred"),
            vec![terminal_key()]
        );
        assert!(matches!(
            reopened.load_publication(&terminal_key()).expect("publication"),
            Some(StoredPublication::Pending(signed)) if signed.event_id == counted_id(1)
        ));
        assert_eq!(reopened.cursor(CHANNEL).expect("cursor"), 0);

        // A restart before the grant keeps deferring without touching the relay.
        let mut restarted = ProductionHandler::new(
            ScriptedRelay::new(Some(accepted()), &[]),
            CountingSigner(1),
            FailingExecutor,
            reopened,
            MemoryOutput(Vec::new()),
        );
        restarted.set_replay_deferral(true);
        assert_eq!(
            restarted.poll_once(CHANNEL).expect("deferred poll"),
            PollStep::Deferred
        );
        assert!(restarted.relay.published.is_empty());

        // After the grant the reopened store replays and clears the marker.
        restarted.set_replay_deferral(false);
        assert_eq!(
            restarted
                .replay_deferred_publications(CHANNEL)
                .expect("replay"),
            1
        );
        assert_eq!(
            restarted.relay.published,
            vec![counted_id(1), counted_id(2)]
        );
        drop(restarted);
        let settled = DurableControlStore::open(root, uid).expect("reopen settled");
        assert!(settled
            .deferred_publications()
            .expect("deferred")
            .is_empty());
        assert!(matches!(
            settled.load_publication(&terminal_key()).expect("publication"),
            Some(StoredPublication::Accepted { relay_event_id, .. }) if relay_event_id == counted_id(1)
        ));
        assert_eq!(settled.cursor(CHANNEL).expect("cursor"), 7);
        let (_, record) = settled
            .load_run(&identity)
            .expect("run")
            .expect("stored run");
        assert_eq!(record.terminal_event_id(), Some(counted_id(1).as_str()));
    }

    #[test]
    fn an_unauthorized_refusal_after_the_grant_is_terminal_as_before() {
        // Deferral cleared (grant approved, or a restart after it): terminal.
        let mut handler = grant_order_handler(
            &[Err(Refusal::Other), Err(Refusal::Unauthorized)],
            stale_terminal_store(),
            false,
        );
        assert!(matches!(
            handler.poll_once(CHANNEL),
            Err(ProductionError::Relay)
        ));
        assert!(handler
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
        assert_eq!(handler.store.cursor, 0);

        // The replay itself is refused after the grant: terminal, marker kept
        // durable for the next activation's grant rather than dropped.
        let mut store = stale_terminal_store();
        store
            .defer_publication(&terminal_key())
            .expect("deferred marker");
        let mut replaying = grant_order_handler(
            &[Err(Refusal::Unauthorized), Err(Refusal::Unauthorized)],
            store,
            false,
        );
        assert!(matches!(
            replaying.replay_deferred_publications(CHANNEL),
            Err(ProductionError::Relay)
        ));
        assert_eq!(
            replaying.store.deferred_publications().expect("deferred"),
            vec![terminal_key()]
        );
        assert!(matches!(
            replaying.store.publications.get(&terminal_key()),
            Some(StoredPublication::Pending(_))
        ));
        assert_eq!(replaying.store.cursor, 0);
    }

    #[test]
    fn other_refusals_keep_their_terminal_meaning_while_deferral_is_enabled() {
        let mut handler = grant_order_handler(
            &[Err(Refusal::Other), Err(Refusal::Other)],
            stale_terminal_store(),
            true,
        );
        assert!(matches!(
            handler.poll_once(CHANNEL),
            Err(ProductionError::Relay)
        ));
        assert!(handler
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
        assert!(matches!(
            handler.store.publications.get(&terminal_key()),
            Some(StoredPublication::Pending(signed)) if signed.event_id == counted_id(1)
        ));
        assert_eq!(handler.store.cursor, 0);

        // An unauthorized refusal of the exact retry followed by an ordinary
        // refusal of the re-signed event is the ordinary terminal failure too.
        let mut mixed = grant_order_handler(
            &[Err(Refusal::Unauthorized), Err(Refusal::Other)],
            stale_terminal_store(),
            true,
        );
        assert!(matches!(
            mixed.poll_once(CHANNEL),
            Err(ProductionError::Relay)
        ));
        assert!(mixed
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
    }

    #[test]
    fn replay_republishes_a_queued_head_without_executing_it() {
        let identity = run_identity(&accepted()).expect("identity");
        let queued_key = format!("{}:run:queued", "11".repeat(32));
        let queued_event = SignedCiEvent {
            event_id: "cc".repeat(32),
            kind: KIND_CI_RUN_STATUS,
            content: "{}".to_owned(),
            tags: serde_json::json!([]),
            signed_event: serde_json::json!({"id": "cc".repeat(32), "kind": KIND_CI_RUN_STATUS}),
        };
        let mut store = MemoryStore {
            run: Some((1, RunRecord::queued(identity, 10).expect("queued"))),
            publications: HashMap::from([(
                queued_key.clone(),
                StoredPublication::Pending(queued_event),
            )]),
            ..MemoryStore::default()
        };
        store
            .defer_publication(&queued_key)
            .expect("deferred marker");
        let mut handler = grant_order_handler(&[], store, false);
        assert_eq!(
            handler
                .replay_deferred_publications(CHANNEL)
                .expect("replay"),
            1
        );
        assert_eq!(handler.relay.published, vec!["cc".repeat(32)]);
        assert!(matches!(
            handler.store.publications.get(&queued_key),
            Some(StoredPublication::Accepted { .. })
        ));
        assert!(handler
            .store
            .deferred_publications()
            .expect("deferred")
            .is_empty());
        // The queued run is left to the ordinary poll: not executed, no
        // terminal publication, cursor unchanged.
        assert_eq!(
            handler.store.run.as_ref().expect("run").1.state(),
            RunState::Queued
        );
        assert!(!handler.store.publications.contains_key(&terminal_key()));
        assert_eq!(handler.store.cursor, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reader_rejects_symlink_and_accepts_mode_0600_file() {
        use std::fs;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("buzz-ci-output-reader-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let bytes = b"bounded\n";
        let file = root.join("attempt.log");
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let descriptor = OutputDescriptor {
            relative_path: "attempt.log".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
        };
        let reader = DescriptorOutputReader::open(&root).unwrap();
        assert_eq!(reader.read(&descriptor).unwrap(), bytes);

        let link = root.join("linked.log");
        symlink(&file, &link).unwrap();
        let linked = OutputDescriptor {
            relative_path: "linked.log".into(),
            ..descriptor
        };
        assert!(reader.read(&linked).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    /// Spine B4 behaviours: cancellation, deadlines, rerun lineage,
    /// concurrency groups, and terminal check publication.
    mod spine_b4 {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        use buzz_ci_broker_protocol::CancelReason;
        use buzz_core::ci::CiCheckEnvelope;
        use buzz_core::kind::KIND_CI_CHECK;

        use super::*;
        use crate::production_v2::{compose_runner_v2, AttemptControl};
        use crate::runner_v2::RunnerV2Client;
        use crate::test_broker::{
            bindings, job_metadata, process_group_alive, ProcessBroker, Signer,
        };

        /// Relay fake with several accepted heads. Heads past `reveal_after`
        /// stay invisible until `reveal` is set, so a test can make a newer
        /// request appear only once an older attempt is running.
        struct HeadRelay {
            heads: Vec<AcceptedRequest>,
            reveal_after: u64,
            reveal: Arc<AtomicBool>,
            published: Vec<u32>,
            run_statuses: Vec<CiRunStatusEnvelope>,
            checks: Vec<CiCheckEnvelope>,
        }

        impl HeadRelay {
            fn visible(heads: Vec<AcceptedRequest>) -> Self {
                Self {
                    heads,
                    reveal_after: u64::MAX,
                    reveal: Arc::new(AtomicBool::new(true)),
                    published: Vec::new(),
                    run_statuses: Vec::new(),
                    checks: Vec::new(),
                }
            }
        }

        impl RelayControl for HeadRelay {
            type Error = ();

            fn next_accepted(
                &mut self,
                _channel_id: &str,
                after_cursor: u64,
            ) -> Result<Option<AcceptedRequest>, Self::Error> {
                let revealed = self.reveal.load(Ordering::SeqCst);
                Ok(self
                    .heads
                    .iter()
                    .filter(|head| head.watch_cursor > after_cursor)
                    .filter(|head| revealed || head.watch_cursor <= self.reveal_after)
                    .min_by_key(|head| head.watch_cursor)
                    .cloned())
            }

            fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
                if event.kind == KIND_CI_RUN_STATUS {
                    self.run_statuses
                        .push(serde_json::from_str(&event.content).expect("run status"));
                }
                if event.kind == KIND_CI_CHECK {
                    self.checks
                        .push(serde_json::from_str(&event.content).expect("check"));
                }
                self.published.push(event.kind);
                Ok(event.event_id.clone())
            }

            fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
                Ok(false)
            }

            fn put_log(
                &mut self,
                accepted: &AcceptedRequest,
                job: &JobCompletion,
                _bytes: &[u8],
            ) -> Result<StoredObject, Self::Error> {
                Ok(StoredObject {
                    url: format!(
                        "https://relay.example/ci/logs/{}/{}/{}/{}/{}",
                        accepted.event_id,
                        accepted.envelope.run_id,
                        job.metadata.job_id,
                        job.attempt,
                        job.log.sha256
                    ),
                    sha256: job.log.sha256.clone(),
                    byte_length: job.log.byte_length,
                })
            }

            fn put_artifact(
                &mut self,
                _accepted: &AcceptedRequest,
                _job: &JobCompletion,
                _artifact: &ArtifactCompletion,
                _bytes: &[u8],
            ) -> Result<StoredObject, Self::Error> {
                Err(())
            }
        }

        /// Executor that must never run.
        struct RefusingExecutor;

        impl AttemptExecutor for RefusingExecutor {
            type Error = ();

            fn execute(
                &mut self,
                request: &AcceptedRequest,
            ) -> Result<AttemptCompletion, Self::Error> {
                panic!("request {} must not execute", request.event_id);
            }
        }

        /// Executor that answers each request with the next queued completion.
        struct QueuedExecutor(VecDeque<AttemptCompletion>);

        impl AttemptExecutor for QueuedExecutor {
            type Error = ();

            fn execute(
                &mut self,
                _request: &AcceptedRequest,
            ) -> Result<AttemptCompletion, Self::Error> {
                self.0.pop_front().ok_or(())
            }
        }

        /// A second initial request on `branch` for a different run.
        fn later_request(cursor: u64, branch: &str) -> AcceptedRequest {
            let mut later = accepted();
            later.watch_cursor = cursor;
            later.event_id = "12".repeat(32);
            later.envelope.run_id = "123e4567-e89b-12d3-a456-426614174021".into();
            later.envelope.idempotency_key = "123e4567-e89b-12d3-a456-426614174022".into();
            later.envelope.source_branch = branch.into();
            later
        }

        fn rerun_request(cursor: u64, event_id: &str) -> AcceptedRequest {
            let mut rerun = accepted();
            rerun.watch_cursor = cursor;
            rerun.event_id = event_id.to_owned();
            rerun.envelope.request_type = CiRequestType::Rerun;
            rerun.envelope.attempt = 2;
            rerun.envelope.parent_attempt = Some(1);
            rerun.envelope.parent_run_id = Some(rerun.envelope.run_id.clone());
            rerun.envelope.idempotency_key = "123e4567-e89b-12d3-a456-426614174032".into();
            rerun
        }

        /// The success completion fixture rebound to `request`.
        fn completion_for(request: &AcceptedRequest, log: &[u8]) -> AttemptCompletion {
            let mut completion = completion(log);
            completion.jobs[0].attempt = request.envelope.attempt;
            completion.teardown.request_event_id = request.event_id.clone();
            completion.teardown.run_id = request.envelope.run_id.clone();
            completion.teardown.attempt = request.envelope.attempt;
            completion.teardown.leases[0].attempt = request.envelope.attempt;
            completion
        }

        fn durable_store() -> (tempfile::TempDir, DurableControlStore) {
            let directory = tempfile::tempdir().expect("tempdir");
            let root = fs::canonicalize(directory.path()).expect("root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
            let uid = fs::metadata(&root).expect("metadata").uid();
            let store = DurableControlStore::open(root, uid).expect("store");
            (directory, store)
        }

        fn stored_check(store: &MemoryStore, request: &AcceptedRequest) -> CiCheckEnvelope {
            match store
                .publications
                .get(&format!("{}:run:check", request.event_id))
            {
                Some(StoredPublication::Accepted { signed, .. }) => {
                    serde_json::from_str(&signed.content).expect("check content")
                }
                other => panic!("check publication missing or pending: {other:?}"),
            }
        }

        /// Behaviour (d), running attempt: a newer initial request on the same
        /// PR branch arrives while the older run executes. The older job's
        /// process group is killed, the run is recorded cancelled with the
        /// superseding request named, and its check says so.
        #[test]
        fn later_same_group_pr_request_cancels_the_running_attempt() {
            let reveal = Arc::new(AtomicBool::new(false));
            let broker = ProcessBroker::default();
            let hook_flag = Arc::clone(&reveal);
            broker.0.lock().unwrap().on_admit = Some(Box::new(move || {
                hook_flag.store(true, Ordering::SeqCst);
            }));
            // The broker stamps admission and completion with the live
            // clock, so the request window must be live too or the run
            // deadline would already have passed.
            let now = host_now().unwrap();
            let mut head = accepted();
            head.envelope.issued_at = now;
            head.envelope.expires_at = now + 30;
            let mut later = later_request(8, "feature");
            later.envelope.issued_at = now;
            later.envelope.expires_at = now + 30;
            let relay = HeadRelay {
                heads: vec![head.clone(), later.clone()],
                reveal_after: head.watch_cursor,
                reveal,
                published: Vec::new(),
                run_statuses: Vec::new(),
                checks: Vec::new(),
            };
            let client = RunnerV2Client::new(broker.clone(), 1).unwrap();
            let mut bindings = bindings();
            bindings.workflow_id = head.envelope.workflow_id.clone();
            let (executor, output) = compose_runner_v2(
                client,
                Signer,
                bindings,
                job_metadata(),
                SIGNER.into(),
                Duration::from_millis(20),
                AttemptControl {
                    observer: None,
                    command: None,
                },
            )
            .unwrap();
            let mut handler = ProductionHandler::new(
                relay,
                DeterministicSigner,
                executor,
                MemoryStore::default(),
                output,
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);

            let group = broker.process_group();
            assert!(!process_group_alive(group), "the superseded job is gone");
            assert_eq!(broker.cancels(), vec![CancelReason::UserRequest]);
            let (_, record) = handler.store.run.clone().expect("run");
            assert_eq!(record.state(), RunState::Cancelled);
            assert_eq!(
                record.reason(),
                Some(format!("{CONCURRENCY_SUPERSEDED_REASON}:{}", later.event_id).as_str())
            );
            assert_eq!(
                handler.relay.published,
                vec![46101, 46101, 46102, 46102, 46103, 46102, 46101, 46108]
            );
            let check = handler.relay.checks.last().expect("check");
            assert_eq!(check.conclusion, CiRunState::Cancelled);
            assert_eq!(check.tip_oid, head.envelope.tip_oid);
            assert_eq!(check.run_id, head.envelope.run_id);
            assert_eq!(check.attempt, 1);
            assert_eq!(check.concurrency_group, "ci-ci-feature");
            assert_eq!(handler.store.cursor, head.watch_cursor);
        }

        /// Behaviour (d), queued head: the newer same-branch request is already
        /// accepted when the older head comes up, so the older head is
        /// recorded cancelled without ever reaching the executor.
        #[test]
        fn queued_pr_head_superseded_by_a_later_same_group_request_never_executes() {
            let head = accepted();
            let later = later_request(8, "feature");
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![head.clone(), later.clone()]),
                DeterministicSigner,
                RefusingExecutor,
                MemoryStore::default(),
                MemoryOutput(Vec::new()),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);

            assert_eq!(handler.relay.published, vec![46101, 46101, 46108]);
            let (_, record) = handler.store.run.clone().expect("run");
            assert_eq!(record.state(), RunState::Cancelled);
            assert_eq!(record.started_at(), None);
            assert_eq!(
                record.reason(),
                Some(format!("{CONCURRENCY_SUPERSEDED_REASON}:{}", later.event_id).as_str())
            );
            assert!(record.terminal_event_id().is_some());
            assert!(record.check_event_id().is_some());
            assert_eq!(handler.relay.run_statuses[1].state, CiRunState::Cancelled);
            assert_eq!(handler.relay.checks[0].conclusion, CiRunState::Cancelled);
            assert_eq!(handler.store.cursor, head.watch_cursor);
        }

        /// A newer request on another branch is a different concurrency group
        /// and leaves the head alone.
        #[test]
        fn a_request_on_another_branch_does_not_supersede_the_head() {
            let log = b"ok\n".to_vec();
            let head = accepted();
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![head.clone(), later_request(8, "other")]),
                DeterministicSigner,
                Executor(completion(&log)),
                MemoryStore::default(),
                MemoryOutput(log),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);

            let (_, record) = handler.store.run.clone().expect("run");
            assert_eq!(record.state(), RunState::Success);
            assert_eq!(handler.relay.checks[0].conclusion, CiRunState::Success);
        }

        /// Behaviour (c): a rerun whose parent attempt controld never stored
        /// is refused as an infrastructure failure and never executes.
        #[test]
        fn rerun_without_a_stored_parent_is_refused_without_execution() {
            let rerun = rerun_request(8, &"12".repeat(32));
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![rerun.clone()]),
                DeterministicSigner,
                RefusingExecutor,
                MemoryStore::default(),
                MemoryOutput(Vec::new()),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);

            assert_eq!(handler.relay.published, vec![46101, 46101, 46108]);
            let (_, record) = handler.store.run.clone().expect("run");
            assert_eq!(record.state(), RunState::InfrastructureFailure);
            assert_eq!(
                record.reason(),
                Some(format!("{RERUN_LINEAGE_REASON}:parent attempt is not stored").as_str())
            );
            assert_eq!(handler.relay.checks[0].attempt, 2);
            assert_eq!(
                handler.relay.checks[0].conclusion,
                CiRunState::InfrastructureFailure
            );
        }

        /// Behaviour (c): a rerun is a new attempt bound to the same source
        /// commit; the parent attempt's record and events stay untouched, and
        /// the latest attempt's check carries the run's conclusion. A rerun
        /// that names a different commit is refused.
        #[test]
        fn rerun_executes_against_its_stored_parent_and_leaves_it_immutable() {
            let log = b"ok\n".to_vec();
            let (_directory, store) = durable_store();
            let first = accepted();
            let mut failed = completion(&log);
            failed.jobs[0].state = CiJobState::Failure;
            failed.jobs[0].reason = Some("fixture_failure".into());
            let rerun = rerun_request(8, &"12".repeat(32));
            let mut drifted = rerun_request(9, &"13".repeat(32));
            drifted.envelope.tip_oid = "45".repeat(20);
            drifted.envelope.idempotency_key = "123e4567-e89b-12d3-a456-426614174033".into();
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![first.clone(), rerun.clone(), drifted.clone()]),
                DeterministicSigner,
                QueuedExecutor(VecDeque::from([failed, completion_for(&rerun, &log)])),
                store,
                MemoryOutput(log),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
            let run_id = Uuid::parse_str(&first.envelope.run_id).unwrap();
            let parent_before = handler
                .store
                .load_run_attempts(run_id, 1)
                .unwrap()
                .pop()
                .expect("parent attempt");
            assert_eq!(parent_before.1.state(), RunState::Failure);
            assert_eq!(handler.relay.checks[0].attempt, 1);
            assert_eq!(handler.relay.checks[0].conclusion, CiRunState::Failure);

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
            let parent_after = handler
                .store
                .load_run_attempts(run_id, 1)
                .unwrap()
                .pop()
                .expect("parent attempt");
            assert_eq!(
                parent_after, parent_before,
                "the parent attempt is immutable"
            );
            let attempt_two = |store: &DurableControlStore, event_id: &str| {
                store
                    .load_run_attempts(run_id, 2)
                    .unwrap()
                    .into_iter()
                    .find(|(_, record)| record.identity().request_event_id() == event_id)
                    .map(|(_, record)| record)
                    .expect("stored attempt two")
            };
            let second = attempt_two(&handler.store, &rerun.event_id);
            assert_eq!(second.state(), RunState::Success);
            assert_eq!(second.identity().tip_oid(), first.envelope.tip_oid);
            let latest = handler.relay.checks.last().expect("rerun check");
            assert_eq!(latest.attempt, 2);
            assert_eq!(latest.conclusion, CiRunState::Success);
            assert_eq!(latest.request_event_id, rerun.event_id);
            assert_eq!(latest.tip_oid, first.envelope.tip_oid);
            assert!(latest.evidence_finalized_event_id.is_some());
            assert!(latest.teardown_attestation_event_id.is_some());

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
            assert!(handler.executor.0.is_empty());
            assert_eq!(
                attempt_two(&handler.store, &rerun.event_id),
                second,
                "a drifted rerun does not touch the stored attempt"
            );
            assert_eq!(
                attempt_two(&handler.store, &drifted.event_id).state(),
                RunState::InfrastructureFailure
            );
            let refused = handler.relay.checks.last().expect("refusal check");
            assert_eq!(refused.conclusion, CiRunState::InfrastructureFailure);
            assert_eq!(
                refused.reason.as_deref(),
                Some(
                    format!("{RERUN_LINEAGE_REASON}:immutable coordinates differ from the parent")
                        .as_str()
                )
            );
            assert_eq!(handler.store.cursor(CHANNEL).unwrap(), 9);
        }

        /// Behaviour (b), per run: an attempt whose evidence sealed after the
        /// request's `timeout_seconds` from queueing is `timed_out`, even when
        /// the job itself reported success; no terminal facts are published.
        #[test]
        fn attempt_finishing_after_the_run_deadline_records_timed_out() {
            let log = b"ok\n".to_vec();
            let head = accepted();
            let mut late = completion(&log);
            late.finished_at = head.envelope.issued_at + head.envelope.timeout_seconds + 1;
            late.jobs[0].finished_at = late.finished_at;
            late.teardown.teardown_at = late.finished_at;
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![head.clone()]),
                DeterministicSigner,
                Executor(late),
                MemoryStore::default(),
                MemoryOutput(log),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);

            let (_, record) = handler.store.run.clone().expect("run");
            assert_eq!(record.state(), RunState::TimedOut);
            assert_eq!(record.reason(), Some(RUN_DEADLINE_REASON));
            assert!(!handler
                .relay
                .published
                .contains(&KIND_CI_EVIDENCE_FINALIZED));
            assert!(!handler
                .relay
                .published
                .contains(&KIND_CI_TEARDOWN_ATTESTATION));
            assert_eq!(handler.relay.checks[0].conclusion, CiRunState::TimedOut);
            assert_eq!(
                handler.relay.checks[0].reason.as_deref(),
                Some(RUN_DEADLINE_REASON)
            );
        }

        /// Behaviour (e): one signed check per terminal attempt, naming the
        /// exact head SHA, run and attempt, the terminal run status it
        /// summarises, and both terminal facts for a success. It is bound to
        /// the durable record and never republished.
        #[test]
        fn terminal_check_binds_head_sha_run_attempt_and_terminal_events() {
            let log = b"ok\n".to_vec();
            let head = accepted();
            let mut handler = ProductionHandler::new(
                HeadRelay::visible(vec![head.clone()]),
                DeterministicSigner,
                Executor(completion(&log)),
                MemoryStore::default(),
                MemoryOutput(log),
            );

            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Completed);
            assert_eq!(handler.poll_once(CHANNEL).unwrap(), PollStep::Idle);

            let (_, record) = handler.store.run.clone().expect("run");
            let check = stored_check(&handler.store, &head);
            assert_eq!(check, handler.relay.checks[0]);
            assert_eq!(check.schema_version, CI_SCHEMA_VERSION);
            assert_eq!(check.request_event_id, head.event_id);
            assert_eq!(check.run_id, head.envelope.run_id);
            assert_eq!(check.tip_oid, head.envelope.tip_oid);
            assert_eq!(check.base_oid, head.envelope.base_oid);
            assert_eq!(check.attempt, 1);
            assert_eq!(check.conclusion, CiRunState::Success);
            assert_eq!(check.reason, None);
            assert_eq!(
                Some(check.run_status_event_id.as_str()),
                record.terminal_event_id()
            );
            assert_eq!(
                check.evidence_finalized_event_id.as_deref(),
                record.terminal_facts().evidence_finalized_event_id()
            );
            assert_eq!(
                check.teardown_attestation_event_id.as_deref(),
                record.terminal_facts().teardown_attestation_event_id()
            );
            assert_eq!(check.concurrency_group, "ci-ci-feature");
            assert_eq!(Some(check.published_at), record.finished_at());
            assert_eq!(check.relay_signer, SIGNER);
            assert!(check
                .validate_context(&head.event_id, &head.envelope)
                .is_ok());
            assert!(record.check_event_id().is_some());
            assert_eq!(
                handler
                    .relay
                    .published
                    .iter()
                    .filter(|kind| **kind == KIND_CI_CHECK)
                    .count(),
                1
            );
            assert_eq!(handler.relay.published.last(), Some(&KIND_CI_CHECK));
        }
    }
}
