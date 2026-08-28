//! Fail-closed control-plane orchestration for accepted requests.
//!
//! Network clients, key custody, and the runner socket remain injected host
//! seams. This module owns their ordering, durable publication intents, event
//! envelopes, evidence binding, and descriptor-relative output reads.

use std::io::{self, Read};
use std::path::{Component, Path};

use buzz_core::ci::{
    artifact_reference_tags, evidence_finalized_tags, job_status_tags, log_reference_tags,
    run_status_tags, teardown_attestation_tags, CiArtifactReferenceEnvelope,
    CiEvidenceFinalizedEnvelope, CiFinalizedJobAttempt, CiJobState, CiJobStatusEnvelope,
    CiLogReferenceEnvelope, CiRequestEnvelope, CiRunState, CiRunStatusEnvelope, CiSkipPolicy,
    CiTeardownAttestationEnvelope, CI_SCHEMA_VERSION,
};
use buzz_core::kind::{
    KIND_CI_ARTIFACT_REFERENCE, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{RunIdentity, RunRecord, RunState, StateError, StoreWrite};

/// One stored, relay-accepted kind-46100 intake item.
#[derive(Clone, Debug)]
pub struct AcceptedRequest {
    pub channel_id: String,
    pub watch_cursor: u64,
    pub event_id: String,
    pub envelope: CiRequestEnvelope,
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

/// Relay intake and evidence/publication transport.
pub trait RelayControl {
    type Error;

    fn next_accepted(
        &mut self,
        channel_id: &str,
        after_cursor: u64,
    ) -> Result<Option<AcceptedRequest>, Self::Error>;

    fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error>;

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
}

/// Dedicated keyholder. Implementations must sign exact content and tags.
pub trait CiSigner {
    type Error;

    fn pubkey(&self) -> &str;
    fn sign(
        &mut self,
        kind: u32,
        content: &str,
        tags: serde_json::Value,
    ) -> Result<SignedCiEvent, Self::Error>;
}

/// Runner socket and reconciliation seam.
pub trait AttemptExecutor {
    type Error;

    fn execute(&mut self, request: &AcceptedRequest) -> Result<AttemptCompletion, Self::Error>;
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
    fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error>;
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
}

/// Broker-backed C3/C4 control handler. It has no default production composition.
pub struct ProductionHandler<R, S, X, P, O> {
    relay: R,
    signer: S,
    executor: X,
    store: P,
    output: O,
}

impl<R, S, X, P, O> ProductionHandler<R, S, X, P, O> {
    pub const fn new(relay: R, signer: S, executor: X, store: P, output: O) -> Self {
        Self {
            relay,
            signer,
            executor,
            store,
            output,
        }
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
    pub fn poll_once(&mut self, channel_id: &str) -> Result<bool, ProductionError> {
        let cursor = self
            .store
            .cursor(channel_id)
            .map_err(|_| ProductionError::Store)?;
        let Some(accepted) = self
            .relay
            .next_accepted(channel_id, cursor)
            .map_err(|_| ProductionError::Relay)?
        else {
            return Ok(false);
        };
        if accepted.channel_id != channel_id || accepted.watch_cursor <= cursor {
            return Err(ProductionError::Invalid);
        }
        self.handle_accepted(&accepted)?;
        if !self
            .store
            .advance_cursor(channel_id, cursor, accepted.watch_cursor)
            .map_err(|_| ProductionError::Store)?
        {
            return Err(ProductionError::PublicationConflict);
        }
        Ok(true)
    }

    fn handle_accepted(&mut self, accepted: &AcceptedRequest) -> Result<(), ProductionError> {
        accepted
            .envelope
            .validate()
            .map_err(|_| ProductionError::Invalid)?;
        if accepted.event_id.len() != 64 || accepted.event_id != accepted.event_id.to_lowercase() {
            return Err(ProductionError::Invalid);
        }
        let identity = RunIdentity::new(
            accepted.event_id.clone(),
            Uuid::parse_str(&accepted.envelope.run_id).map_err(|_| ProductionError::Invalid)?,
            accepted.envelope.attempt,
            accepted.envelope.target_repo_a.clone(),
            accepted.envelope.tip_oid.clone(),
            accepted.envelope.workflow_id.clone(),
        )?;
        let queued = RunRecord::queued(identity.clone(), accepted.envelope.issued_at)?;
        let (mut revision, mut record) = match self
            .store
            .load_run(&identity)
            .map_err(|_| ProductionError::Store)?
        {
            Some(existing) => existing,
            None => match self
                .store
                .compare_and_swap_run(&identity, None, &queued)
                .map_err(|_| ProductionError::Store)?
            {
                StoreWrite::Written { revision } => (revision, queued),
                StoreWrite::Conflict { .. } => return Err(ProductionError::PublicationConflict),
            },
        };
        if record.state().is_terminal() {
            return Ok(());
        }

        if record.state() == RunState::Queued {
            self.publish_run(accepted, &record, "run:queued")?;
        }
        let completion = self
            .executor
            .execute(accepted)
            .map_err(|_| ProductionError::Runner)?;
        validate_completion(accepted, &completion, self.signer.pubkey())?;

        if record.state() == RunState::Queued {
            let running = record.transition(RunState::Running, first_started(&completion), None)?;
            revision = persist_run(&mut self.store, &identity, revision, &running)?;
            record = running;
            self.publish_run(accepted, &record, "run:running")?;
        }
        if record.state() == RunState::Running {
            let finalized_job_attempts = self.publish_completion(accepted, &completion)?;

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
            let terminal = record.transition(
                terminal_run_state(&completion.jobs),
                completion.finished_at,
                terminal_reason(&completion.jobs),
            )?;
            let terminal_revision = persist_run(&mut self.store, &identity, revision, &terminal)?;
            let terminal_event_id = self.publish_run(accepted, &terminal, "run:terminal")?;
            let bound = terminal.with_terminal_event(terminal_event_id)?;
            persist_run(&mut self.store, &identity, terminal_revision, &bound)?;
        }
        Ok(())
    }

    fn publish_completion(
        &mut self,
        accepted: &AcceptedRequest,
        completion: &AttemptCompletion,
    ) -> Result<Vec<CiFinalizedJobAttempt>, ProductionError> {
        let mut finalized_jobs = Vec::with_capacity(completion.jobs.len());
        for job in &completion.jobs {
            let running = job_envelope(
                accepted,
                job,
                self.signer.pubkey(),
                1,
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
                &format!("job:{}:{}:running", job.metadata.job_id, job.attempt),
            )?;
            let finalized = self.finalized_job(accepted, job)?;
            let terminal = job_envelope(
                accepted,
                job,
                self.signer.pubkey(),
                2,
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
                &format!("job:{}:{}:terminal", job.metadata.job_id, job.attempt),
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
                let accepted_id = self
                    .relay
                    .publish(&signed)
                    .map_err(|_| ProductionError::Relay)?;
                if accepted_id != signed.event_id {
                    return Err(ProductionError::PublicationConflict);
                }
                self.store
                    .accept_publication(key, &accepted_id)
                    .map_err(|_| ProductionError::Store)?;
                Ok(accepted_id)
            }
        }
    }
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
        started_at: Some(job.started_at),
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
    use std::collections::HashMap;
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
        publications: HashMap<String, StoredPublication>,
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

    struct Relay {
        accepted: Option<AcceptedRequest>,
        published: Vec<u32>,
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
            self.published.push(event.kind);
            Ok(event.event_id.clone())
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

    #[test]
    fn accepted_request_persists_and_publishes_full_signed_lifecycle() {
        let log = b"ok\n".to_vec();
        let relay = Relay {
            accepted: Some(accepted()),
            published: Vec::new(),
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

        assert!(handler.poll_once(CHANNEL).unwrap());
        assert!(!handler.poll_once(CHANNEL).unwrap());
        assert_eq!(
            handler.relay.published,
            vec![46101, 46101, 46102, 46103, 46102, 46105, 46106, 46101]
        );
        assert_eq!(handler.store.cursor, 7);
        assert_eq!(
            handler.store.run.as_ref().unwrap().1.state(),
            RunState::Success
        );
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
}
