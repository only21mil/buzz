//! Capacity-one attempt and evidence bridge over runner-forwarded broker v2.

use std::collections::BTreeMap;
use std::sync::{mpsc::Receiver, mpsc::Sender, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::v2::{
    self, AttemptEvidenceCoordinates, DescribeAttemptEvidenceRequest, EvidenceDescriptor,
    EvidenceKind, ReadAttemptEvidenceRequest, WireText64,
};
use buzz_ci_broker_protocol::{Conclusion, ResponseCode};
use buzz_core::ci::{
    CiJobState, CiTeardownAttestationEnvelope, CiTeardownLease, CI_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::production::{
    AcceptedRequest, ArtifactCompletion, AttemptCompletion, AttemptExecutor, EvidenceReader,
    JobCompletion, JobMetadata, OutputDescriptor,
};
use crate::runner_v2::{
    prepare_signed_admission, AdmissionSigner, BoundAttempt, RunnerV2Client, RunnerV2Error,
    RunnerV2Transport, StaticAdmissionBindings, TerminalAttempt,
};

const MAX_EVIDENCE_ITEM_BYTES: u32 = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u32 = 32 * 1024;
const DESCRIPTOR_SET_DOMAIN: &[u8] = b"buzz-ci-execd:evidence-descriptor-set:v2\0";
const ARTIFACT_RECEIPT_SET_DOMAIN: &[u8] = b"buzz-ci-execd:artifact-receipt-set:v1\0";

/// Sanitized bridge failure. No output bytes or provider details are exposed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProductionV2Error {
    #[error("runner v2 admission or state reconciliation failed")]
    Runner,
    #[error("runner v2 terminal evidence is invalid")]
    Evidence,
    #[error("runner v2 terminal result does not match static job metadata")]
    Binding,
}

/// Durable runner boundary observations used by the acceptance cancellation
/// state machine. They contain no evidence bytes or filesystem coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptObservation {
    Active(BoundAttempt),
    Terminal(TerminalAttempt),
    Completed(VerifiedAttemptEvidence),
}

/// Path-free evidence facts verified from runner-forwarded execd descriptors
/// and bounded chunk reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAttemptEvidence {
    pub terminal: TerminalAttempt,
    pub descriptor_set_digest: [u8; 32],
    pub log_sha256: String,
    pub log_bytes: u64,
    pub artifacts: Vec<VerifiedArtifactEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifactEvidence {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptCommand {
    Continue,
}

/// Optional acceptance-only observation and release channels. Production
/// polling without a canary passes both as `None`.
pub struct AttemptControl {
    pub observer: Option<Sender<AttemptObservation>>,
    pub command: Option<Receiver<AttemptCommand>>,
}

struct SharedSession<T> {
    client: RunnerV2Client<T>,
    verified: BTreeMap<String, Vec<u8>>,
}

/// Attempt executor that admits one exact JobIntentV2 and reconciles the same
/// binding after restart.
pub struct RunnerV2AttemptExecutor<T, S> {
    session: Arc<Mutex<SharedSession<T>>>,
    signer: S,
    bindings: StaticAdmissionBindings,
    job: JobMetadata,
    relay_signer: String,
    poll_interval: Duration,
    control: AttemptControl,
}

/// Evidence reader backed only by bytes fetched through runner operations 7/8.
/// It owns no filesystem root and cannot address execd directly.
pub struct RunnerV2EvidenceReader<T> {
    session: Arc<Mutex<SharedSession<T>>>,
}

/// Compose the executor and evidence reader around one shared sequential runner
/// client. The controller's capacity-one mutable API prevents overlap.
pub fn compose_runner_v2<T, S>(
    client: RunnerV2Client<T>,
    signer: S,
    bindings: StaticAdmissionBindings,
    job: JobMetadata,
    relay_signer: String,
    poll_interval: Duration,
    control: AttemptControl,
) -> Result<(RunnerV2AttemptExecutor<T, S>, RunnerV2EvidenceReader<T>), ProductionV2Error>
where
    T: RunnerV2Transport,
    S: AdmissionSigner,
{
    bindings
        .validate()
        .map_err(|_| ProductionV2Error::Binding)?;
    if job.job_id != bindings.job_ids[0] || !lower_hex(&relay_signer, 64) || poll_interval.is_zero()
    {
        return Err(ProductionV2Error::Binding);
    }
    let session = Arc::new(Mutex::new(SharedSession {
        client,
        verified: BTreeMap::new(),
    }));
    Ok((
        RunnerV2AttemptExecutor {
            session: Arc::clone(&session),
            signer,
            bindings,
            job,
            relay_signer,
            poll_interval,
            control,
        },
        RunnerV2EvidenceReader { session },
    ))
}

impl<T, S> AttemptExecutor for RunnerV2AttemptExecutor<T, S>
where
    T: RunnerV2Transport,
    S: AdmissionSigner,
{
    type Error = ProductionV2Error;

    fn execute(&mut self, accepted: &AcceptedRequest) -> Result<AttemptCompletion, Self::Error> {
        let admission = prepare_signed_admission(accepted, &self.bindings, &mut self.signer)
            .map_err(|_| ProductionV2Error::Runner)?;
        let mut session = self.session.lock().map_err(|_| ProductionV2Error::Runner)?;
        session.verified.clear();
        session
            .client
            .register_job_intent(admission, accepted, &self.bindings)
            .map_err(|_| ProductionV2Error::Runner)?;
        let bound = session
            .client
            .admit(admission)
            .map_err(|_| ProductionV2Error::Runner)?;
        if bound.response.broker_state != buzz_ci_broker_protocol::BrokerState::Terminal {
            self.observe(AttemptObservation::Active(bound))?;
            self.await_command(admission.expires_at)?;
        }
        let terminal = session
            .client
            .wait_terminal(bound, self.poll_interval)
            .map_err(|_| ProductionV2Error::Runner)?;
        self.observe(AttemptObservation::Terminal(terminal))?;
        let coordinates = terminal
            .evidence_coordinates(accepted, &self.job.job_id)
            .map_err(|_| ProductionV2Error::Evidence)?;
        let description = session
            .client
            .describe(DescribeAttemptEvidenceRequest {
                coordinates,
                idempotency_digest: terminal.admission.idempotency_digest,
                request_frame_digest: [0; 32],
            })
            .map_err(|_| ProductionV2Error::Evidence)?;
        let descriptor_set_digest = description.descriptor_set_digest;
        let descriptors = validate_description(terminal, description)?;
        let mut stdout = None;
        let mut teardown = None;
        let mut artifacts = Vec::new();
        let mut artifact_receipt_digests = Vec::new();
        for (index, descriptor) in descriptors.into_iter().enumerate() {
            let bytes = read_verified_item(
                &mut session.client,
                coordinates,
                terminal.admission.idempotency_digest,
                index as u8,
                descriptor,
            )?;
            match descriptor.kind {
                EvidenceKind::Stdout => {
                    let parsed: ExecdEvidenceDocument =
                        serde_json::from_slice(&bytes).map_err(|_| ProductionV2Error::Evidence)?;
                    let output = parsed.validate(terminal)?;
                    stdout = Some(output);
                }
                EvidenceKind::Artifact => {
                    let declared = &self.bindings.artifacts[0];
                    let artifact_id = wire_text(descriptor.artifact_id)?;
                    let name = wire_text(descriptor.artifact_name)?;
                    let media_type = wire_text(descriptor.artifact_media_type)?;
                    if artifact_id != declared.artifact_id
                        || name != declared.name
                        || media_type != declared.media_type
                        || descriptor.length > declared.max_bytes
                        || descriptor.length > MAX_ARTIFACT_BYTES
                        || descriptor.artifact_name_digest
                            != <[u8; 32]>::from(Sha256::digest(name.as_bytes()))
                        || descriptor.artifact_media_type_digest
                            != <[u8; 32]>::from(Sha256::digest(media_type.as_bytes()))
                    {
                        return Err(ProductionV2Error::Evidence);
                    }
                    let digest = hex::encode(descriptor.digest);
                    let output_descriptor = OutputDescriptor {
                        relative_path: format!("runner-v2:{digest}"),
                        sha256: digest.clone(),
                        byte_length: u64::from(descriptor.length),
                    };
                    cache_verified(&mut session.verified, digest, bytes.clone())?;
                    artifact_receipt_digests.push(artifact_receipt_digest(
                        terminal,
                        coordinates,
                        descriptor,
                        &bytes,
                    )?);
                    artifacts.push(ArtifactCompletion {
                        descriptor: output_descriptor,
                        artifact_id: artifact_id.to_owned(),
                        name: name.to_owned(),
                        media_type: media_type.to_owned(),
                    });
                }
                EvidenceKind::Teardown => {
                    let parsed: ExecdTeardownDocument =
                        serde_json::from_slice(&bytes).map_err(|_| ProductionV2Error::Evidence)?;
                    parsed.validate(
                        terminal,
                        accepted,
                        &self.job.job_id,
                        descriptor,
                        &artifact_receipt_digests,
                    )?;
                    teardown = Some(descriptor);
                }
                EvidenceKind::Stderr => return Err(ProductionV2Error::Evidence),
            }
        }
        let output = stdout.ok_or(ProductionV2Error::Evidence)?;
        let teardown_descriptor = teardown.ok_or(ProductionV2Error::Evidence)?;
        let output_digest = hex::encode(Sha256::digest(&output));
        let output_descriptor = OutputDescriptor {
            relative_path: format!("runner-v2:{output_digest}"),
            sha256: output_digest.clone(),
            byte_length: output.len() as u64,
        };
        cache_verified(&mut session.verified, output_digest, output)?;
        let state = job_state(terminal.response.conclusion)?;
        let lease_id = hex::encode(teardown_descriptor.teardown_lease_id);
        let teardown = CiTeardownAttestationEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: accepted.event_id.clone(),
            run_id: accepted.envelope.run_id.clone(),
            workflow_id: accepted.envelope.workflow_id.clone(),
            target_repo_a: accepted.envelope.target_repo_a.clone(),
            tip_oid: accepted.envelope.tip_oid.clone(),
            base_oid: accepted.envelope.base_oid.clone(),
            workflow_digest: accepted.envelope.workflow_digest.clone(),
            attempt: accepted.envelope.attempt,
            leases: vec![CiTeardownLease {
                job_id: self.job.job_id.clone(),
                attempt: accepted.envelope.attempt,
                lease_id,
            }],
            lease_empty: true,
            teardown_at: terminal.response.updated_at,
            relay_signer: self.relay_signer.clone(),
        };
        let completion = AttemptCompletion {
            jobs: vec![JobCompletion {
                metadata: self.job.clone(),
                attempt: accepted.envelope.attempt,
                state,
                reason: terminal_reason(terminal.response.conclusion),
                started_at: terminal.response.accepted_at,
                finished_at: terminal.response.updated_at,
                log: output_descriptor,
                log_cap_bytes: u64::from(MAX_EVIDENCE_ITEM_BYTES),
                artifacts,
            }],
            teardown,
            finished_at: terminal.response.updated_at,
        };
        self.observe(AttemptObservation::Completed(VerifiedAttemptEvidence {
            terminal,
            descriptor_set_digest,
            log_sha256: completion.jobs[0].log.sha256.clone(),
            log_bytes: completion.jobs[0].log.byte_length,
            artifacts: completion.jobs[0]
                .artifacts
                .iter()
                .map(|artifact| VerifiedArtifactEvidence {
                    name: artifact.name.clone(),
                    sha256: artifact.descriptor.sha256.clone(),
                    bytes: artifact.descriptor.byte_length,
                })
                .collect(),
        }))?;
        Ok(completion)
    }
}

impl<T> EvidenceReader for RunnerV2EvidenceReader<T>
where
    T: RunnerV2Transport,
{
    type Error = ProductionV2Error;

    fn read(&self, descriptor: &OutputDescriptor) -> Result<Vec<u8>, Self::Error> {
        let bytes = self
            .session
            .lock()
            .map_err(|_| ProductionV2Error::Evidence)?
            .verified
            .get(&descriptor.sha256)
            .cloned()
            .ok_or(ProductionV2Error::Evidence)?;
        if bytes.len() as u64 != descriptor.byte_length
            || hex::encode(Sha256::digest(&bytes)) != descriptor.sha256
        {
            return Err(ProductionV2Error::Evidence);
        }
        Ok(bytes)
    }
}

impl<T, S> RunnerV2AttemptExecutor<T, S> {
    fn observe(&self, observation: AttemptObservation) -> Result<(), ProductionV2Error> {
        if self
            .control
            .observer
            .as_ref()
            .is_some_and(|observer| observer.send(observation).is_err())
        {
            return Err(ProductionV2Error::Runner);
        }
        Ok(())
    }

    fn await_command(&self, expires_at: u64) -> Result<(), ProductionV2Error> {
        let Some(receiver) = &self.control.command else {
            return Ok(());
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProductionV2Error::Runner)?
            .as_secs();
        let timeout = expires_at
            .checked_sub(now)
            .filter(|value| *value > 0)
            .map(Duration::from_secs)
            .ok_or(ProductionV2Error::Runner)?;
        match receiver.recv_timeout(timeout) {
            Ok(AttemptCommand::Continue) => Ok(()),
            Err(_) => Err(ProductionV2Error::Runner),
        }
    }
}

fn validate_description(
    terminal: TerminalAttempt,
    description: v2::EvidenceDescriptionResponse,
) -> Result<Vec<EvidenceDescriptor>, ProductionV2Error> {
    if description.code != ResponseCode::Ok
        || description.item_count != 3
        || description.descriptor_set_digest == [0; 32]
    {
        return Err(ProductionV2Error::Evidence);
    }
    let descriptors: Vec<_> = description
        .items
        .into_iter()
        .take(usize::from(description.item_count))
        .collect::<Option<Vec<_>>>()
        .ok_or(ProductionV2Error::Evidence)?;
    if descriptors.iter().any(|item| {
        item.length == 0 || item.length > MAX_EVIDENCE_ITEM_BYTES || item.digest == [0; 32]
    }) || descriptors.first().map(|item| item.kind) != Some(EvidenceKind::Stdout)
        || descriptors.get(1).map(|item| item.kind) != Some(EvidenceKind::Artifact)
        || descriptors.first().map(|item| item.digest)
            != Some(terminal.response.evidence_set_digest)
        || descriptors.last().map(|item| item.kind) != Some(EvidenceKind::Teardown)
        || descriptors.last().map(|item| item.digest) != Some(terminal.response.teardown_digest)
        || !empty_artifact_metadata(descriptors[0])
        || !empty_teardown_metadata(descriptors[0])
        || descriptors[1].artifact_id == WireText64::EMPTY
        || descriptors[1].artifact_name == WireText64::EMPTY
        || descriptors[1].artifact_media_type == WireText64::EMPTY
        || descriptors[1].artifact_name_digest == [0; 32]
        || descriptors[1].artifact_media_type_digest == [0; 32]
        || !empty_teardown_metadata(descriptors[1])
        || !empty_artifact_metadata(descriptors[2])
        || descriptors[2].teardown_lease_id == [0; 16]
        || descriptors[2].teardown_lease_generation != terminal.response.lease_generation
        || descriptors[2].teardown_attestation_digest != descriptors[2].digest
        || descriptor_set_digest(terminal, &descriptors) != description.descriptor_set_digest
    {
        return Err(ProductionV2Error::Evidence);
    }
    Ok(descriptors)
}

fn read_verified_item<T: RunnerV2Transport>(
    client: &mut RunnerV2Client<T>,
    coordinates: AttemptEvidenceCoordinates,
    idempotency_digest: [u8; 32],
    item_index: u8,
    descriptor: EvidenceDescriptor,
) -> Result<Vec<u8>, ProductionV2Error> {
    let mut bytes = Vec::with_capacity(descriptor.length as usize);
    while bytes.len() < descriptor.length as usize {
        let remaining = descriptor.length as usize - bytes.len();
        let maximum = remaining.min(v2::MAX_EVIDENCE_CHUNK_SIZE) as u32;
        let response = client
            .read(ReadAttemptEvidenceRequest {
                coordinates,
                idempotency_digest,
                request_frame_digest: [0; 32],
                kind: descriptor.kind,
                item_index,
                descriptor_digest: descriptor.digest,
                offset: bytes.len() as u32,
                max_length: maximum,
            })
            .map_err(|_| ProductionV2Error::Evidence)?;
        if response.code != ResponseCode::Ok
            || response.total_length != descriptor.length
            || response.bytes.is_empty()
        {
            return Err(ProductionV2Error::Evidence);
        }
        bytes.extend_from_slice(&response.bytes);
    }
    if bytes.len() != descriptor.length as usize
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != descriptor.digest
    {
        return Err(ProductionV2Error::Evidence);
    }
    Ok(bytes)
}

fn descriptor_set_digest(
    terminal: TerminalAttempt,
    descriptors: &[EvidenceDescriptor],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(descriptors.len() * 160 + 64);
    bytes.extend_from_slice(DESCRIPTOR_SET_DOMAIN);
    bytes.extend_from_slice(&terminal.response.execution_binding_digest);
    for descriptor in descriptors {
        bytes.push(descriptor.kind as u8);
        bytes.extend_from_slice(&descriptor.digest);
        bytes.extend_from_slice(&descriptor.length.to_be_bytes());
        bytes.extend_from_slice(&descriptor.artifact_name_digest);
        bytes.extend_from_slice(&descriptor.artifact_media_type_digest);
        bytes.extend_from_slice(&descriptor.teardown_lease_id);
        bytes.extend_from_slice(&descriptor.teardown_lease_generation.to_be_bytes());
        bytes.extend_from_slice(&descriptor.teardown_attestation_digest);
        bytes.push(descriptor.artifact_id.len);
        bytes.extend_from_slice(&descriptor.artifact_id.bytes);
        bytes.push(descriptor.artifact_name.len);
        bytes.extend_from_slice(&descriptor.artifact_name.bytes);
        bytes.push(descriptor.artifact_media_type.len);
        bytes.extend_from_slice(&descriptor.artifact_media_type.bytes);
    }
    Sha256::digest(bytes).into()
}

fn empty_artifact_metadata(descriptor: EvidenceDescriptor) -> bool {
    descriptor.artifact_name_digest == [0; 32]
        && descriptor.artifact_media_type_digest == [0; 32]
        && descriptor.artifact_id == WireText64::EMPTY
        && descriptor.artifact_name == WireText64::EMPTY
        && descriptor.artifact_media_type == WireText64::EMPTY
}

fn empty_teardown_metadata(descriptor: EvidenceDescriptor) -> bool {
    descriptor.teardown_lease_id == [0; 16]
        && descriptor.teardown_lease_generation == 0
        && descriptor.teardown_attestation_digest == [0; 32]
}

fn wire_text(value: WireText64) -> Result<String, ProductionV2Error> {
    value
        .as_str()
        .map(str::to_owned)
        .map_err(|_| ProductionV2Error::Evidence)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecdEvidenceDocument {
    schema_version: u16,
    execution_binding_digest: String,
    conclusion: String,
    output_sha256: String,
    output_length: u32,
    output: String,
}

impl ExecdEvidenceDocument {
    fn validate(self, terminal: TerminalAttempt) -> Result<Vec<u8>, ProductionV2Error> {
        let output = self.output.into_bytes();
        if self.schema_version != 1
            || self.execution_binding_digest
                != hex::encode(terminal.response.execution_binding_digest)
            || self.output_length as usize != output.len()
            || self.output_sha256 != hex::encode(Sha256::digest(&output))
            || self.conclusion != conclusion_name(terminal.response.conclusion)
        {
            return Err(ProductionV2Error::Evidence);
        }
        Ok(output)
    }
}

#[derive(Serialize)]
struct ExecdArtifactReceiptDocument<'a> {
    schema_version: u16,
    execution_binding_digest: String,
    request_event_id: String,
    run_id: String,
    workflow_id: &'a str,
    workflow_digest: String,
    job_id: &'a str,
    attempt: u32,
    artifact_id: String,
    name: String,
    media_type: String,
    sha256: String,
    byte_length: u32,
    content_hex: String,
}

fn artifact_receipt_digest(
    terminal: TerminalAttempt,
    coordinates: AttemptEvidenceCoordinates,
    descriptor: EvidenceDescriptor,
    bytes: &[u8],
) -> Result<[u8; 32], ProductionV2Error> {
    let workflow_id = coordinates
        .workflow_id
        .as_str()
        .map_err(|_| ProductionV2Error::Evidence)?;
    let job_id = coordinates
        .job_id
        .as_str()
        .map_err(|_| ProductionV2Error::Evidence)?;
    let document = ExecdArtifactReceiptDocument {
        schema_version: 1,
        execution_binding_digest: hex::encode(terminal.response.execution_binding_digest),
        request_event_id: hex::encode(coordinates.request_event_id),
        run_id: hex::encode(coordinates.run_id),
        workflow_id,
        workflow_digest: hex::encode(coordinates.workflow_digest),
        job_id,
        attempt: coordinates.attempt,
        artifact_id: wire_text(descriptor.artifact_id)?,
        name: wire_text(descriptor.artifact_name)?,
        media_type: wire_text(descriptor.artifact_media_type)?,
        sha256: hex::encode(descriptor.digest),
        byte_length: descriptor.length,
        content_hex: hex::encode(bytes),
    };
    let encoded = serde_json::to_vec(&document).map_err(|_| ProductionV2Error::Evidence)?;
    Ok(Sha256::digest(encoded).into())
}

fn cache_verified(
    cache: &mut BTreeMap<String, Vec<u8>>,
    digest: String,
    bytes: Vec<u8>,
) -> Result<(), ProductionV2Error> {
    match cache.get(&digest) {
        Some(existing) if existing == &bytes => Ok(()),
        Some(_) => Err(ProductionV2Error::Evidence),
        None => {
            cache.insert(digest, bytes);
            Ok(())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecdTeardownDocument {
    schema_version: u16,
    execution_binding_digest: String,
    evidence_set_digest: String,
    stop_reason: String,
    executor_receipt_digest: String,
    request_event_id: String,
    run_id: String,
    workflow_id: String,
    workflow_digest: String,
    job_id: String,
    attempt: u32,
    lease_id: String,
    lease_generation: u64,
    artifact_receipt_set_digest: String,
}

impl ExecdTeardownDocument {
    fn validate(
        self,
        terminal: TerminalAttempt,
        accepted: &AcceptedRequest,
        job_id: &str,
        descriptor: EvidenceDescriptor,
        artifact_receipt_digests: &[[u8; 32]],
    ) -> Result<(), ProductionV2Error> {
        let run_id = uuid::Uuid::parse_str(&accepted.envelope.run_id)
            .map_err(|_| ProductionV2Error::Evidence)?;
        let mut receipt_set = Vec::with_capacity(96);
        receipt_set.extend_from_slice(ARTIFACT_RECEIPT_SET_DOMAIN);
        receipt_set.extend_from_slice(&terminal.response.execution_binding_digest);
        for digest in artifact_receipt_digests {
            receipt_set.extend_from_slice(digest);
        }
        if self.schema_version != 1
            || self.execution_binding_digest
                != hex::encode(terminal.response.execution_binding_digest)
            || self.evidence_set_digest != hex::encode(terminal.response.evidence_set_digest)
            || !nonzero_lower_hex(&self.executor_receipt_digest, 64)
            || self.request_event_id != accepted.event_id
            || self.run_id != hex::encode(run_id.as_bytes())
            || self.workflow_id != accepted.envelope.workflow_id
            || self.workflow_digest != accepted.envelope.workflow_digest
            || self.job_id != job_id
            || self.attempt != accepted.envelope.attempt
            || self.lease_id != hex::encode(descriptor.teardown_lease_id)
            || self.lease_generation != descriptor.teardown_lease_generation
            || self.artifact_receipt_set_digest != hex::encode(Sha256::digest(receipt_set))
            || !matches!(
                self.stop_reason.as_str(),
                "cancelled" | "completed" | "expired" | "recovery"
            )
            || descriptor.teardown_lease_id == [0; 16]
            || descriptor.teardown_lease_generation != terminal.response.lease_generation
            || descriptor.teardown_attestation_digest != descriptor.digest
        {
            return Err(ProductionV2Error::Evidence);
        }
        Ok(())
    }
}

fn job_state(conclusion: Conclusion) -> Result<CiJobState, ProductionV2Error> {
    match conclusion {
        Conclusion::Success => Ok(CiJobState::Success),
        Conclusion::Failure => Ok(CiJobState::Failure),
        Conclusion::Cancelled => Ok(CiJobState::Cancelled),
        Conclusion::TimedOut => Ok(CiJobState::TimedOut),
        Conclusion::InfrastructureFailure | Conclusion::None => Err(ProductionV2Error::Binding),
    }
}

fn terminal_reason(conclusion: Conclusion) -> Option<String> {
    match conclusion {
        Conclusion::Success => None,
        other => Some(conclusion_name(other).to_owned()),
    }
}

const fn conclusion_name(conclusion: Conclusion) -> &'static str {
    match conclusion {
        Conclusion::None => "none",
        Conclusion::Success => "success",
        Conclusion::Failure => "failure",
        Conclusion::Cancelled => "cancelled",
        Conclusion::TimedOut => "timed_out",
        Conclusion::InfrastructureFailure => "infrastructure_failure",
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nonzero_lower_hex(value: &str, length: usize) -> bool {
    lower_hex(value, length) && value.bytes().any(|byte| byte != b'0')
}

impl From<RunnerV2Error> for ProductionV2Error {
    fn from(_value: RunnerV2Error) -> Self {
        Self::Runner
    }
}
