//! Concrete, configuration-bound verifier, owner policy, and unprivileged executor.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::{Conclusion, TrustClass};
use buzz_core::ci::{CiJobState, CiRequestEnvelope};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::RunnerHostConfig;
use crate::control::{
    AdmittedLease, BoundedExecutionEvidence, CiWorkflowPolicy, ExecutionBackendError,
    UnixBrokerTransport,
};
use crate::handler::{
    BrokerAttemptHandler, DispatchVerifier, JobExecution, JobExecutor, VerifiedDispatch,
    VerifiedJob,
};
use crate::journal::DurableReceiptJournal;
use crate::transport::{ExecuteJob, LogEvidence, RefusalReason, RunnerRequest};
use crate::{BrokerManifestBinding, RequestAuthorizer};

pub struct ConfiguredRunner {
    handler: BrokerAttemptHandler<
        OwnerAuthorizer,
        ManifestDispatchVerifier,
        UnixBrokerTransport,
        ProcessJobExecutor,
        DurableReceiptJournal,
    >,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HostConfigurationError {
    #[error("manifest verification key is invalid")]
    InvalidVerificationKey,
    #[error("evidence directory is not private")]
    InsecureEvidenceDirectory,
    #[error("receipt journal is unavailable")]
    JournalUnavailable,
}

impl ConfiguredRunner {
    pub fn new(config: &RunnerHostConfig) -> Result<Self, HostConfigurationError> {
        let handler = BrokerAttemptHandler::new(
            OwnerAuthorizer::new(config.owner_pubkey.clone()),
            ManifestDispatchVerifier::new(
                &config.manifest_verification_key,
                config.relay_signer.clone(),
            )?,
            UnixBrokerTransport::new(config.broker_socket.clone(), config.broker_uid),
            ProcessJobExecutor::new(config)?,
            DurableReceiptJournal::open(config.journal_directory.clone())
                .map_err(|_| HostConfigurationError::JournalUnavailable)?,
        );
        Ok(Self { handler })
    }

    pub fn handle(
        &mut self,
        request: RunnerRequest,
        request_frame_digest: [u8; 32],
        writer: &mut impl Write,
    ) -> Result<(), crate::handler::HandlerError> {
        self.handler.handle(request, request_frame_digest, writer)
    }
}

const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"buzz-ci-runner:job-manifest-signature:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"buzz-ci-runner:executor-evidence:v1\0";

#[derive(Clone, Debug)]
pub struct OwnerAuthorizer {
    owner_pubkey: String,
}

impl OwnerAuthorizer {
    pub fn new(owner_pubkey: String) -> Self {
        Self { owner_pubkey }
    }
}

impl RequestAuthorizer for OwnerAuthorizer {
    fn authorize(&self, request: &CiRequestEnvelope) -> bool {
        request.actor == self.owner_pubkey
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJobManifest {
    pub schema_version: u32,
    pub request_event_id: String,
    pub signed_request_digest: String,
    pub job_id: String,
    pub workflow_path: String,
    pub audience_digest: String,
    pub isolation_profile_digest: String,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub signature: String,
}

#[derive(Serialize)]
struct ManifestPayload<'a> {
    schema_version: u32,
    request_event_id: &'a str,
    signed_request_digest: &'a str,
    job_id: &'a str,
    workflow_path: &'a str,
    audience_digest: &'a str,
    isolation_profile_digest: &'a str,
    argv: &'a [String],
    environment: &'a BTreeMap<String, String>,
}

impl SignedJobManifest {
    fn payload(&self) -> ManifestPayload<'_> {
        ManifestPayload {
            schema_version: self.schema_version,
            request_event_id: &self.request_event_id,
            signed_request_digest: &self.signed_request_digest,
            job_id: &self.job_id,
            workflow_path: &self.workflow_path,
            audience_digest: &self.audience_digest,
            isolation_profile_digest: &self.isolation_profile_digest,
            argv: &self.argv,
            environment: &self.environment,
        }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload = serde_json::to_vec(&self.payload())?;
        let mut bytes = Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + payload.len());
        bytes.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct ManifestDispatchVerifier {
    key: VerifyingKey,
    relay_signer: String,
    clock: fn() -> Result<u64, ExecutionBackendError>,
}

impl ManifestDispatchVerifier {
    pub fn new(key_hex: &str, relay_signer: String) -> Result<Self, HostConfigurationError> {
        Self::with_clock(key_hex, relay_signer, now)
    }

    fn with_clock(
        key_hex: &str,
        relay_signer: String,
        clock: fn() -> Result<u64, ExecutionBackendError>,
    ) -> Result<Self, HostConfigurationError> {
        let key: [u8; 32] = hex::decode(key_hex)
            .map_err(|_| HostConfigurationError::InvalidVerificationKey)?
            .try_into()
            .map_err(|_| HostConfigurationError::InvalidVerificationKey)?;
        Ok(Self {
            key: VerifyingKey::from_bytes(&key)
                .map_err(|_| HostConfigurationError::InvalidVerificationKey)?,
            relay_signer,
            clock,
        })
    }
}

impl DispatchVerifier for ManifestDispatchVerifier {
    fn verify(
        &self,
        request: &RunnerRequest,
        _assigned_at: u64,
    ) -> Result<VerifiedDispatch, RefusalReason> {
        let RunnerRequest::ExecuteAttempt {
            request_event_id,
            request_event,
            signed_request_digest,
            deadline_at,
            jobs,
            ..
        } = request;
        let runner_now = (self.clock)().map_err(|_| RefusalReason::BackendUnavailable)?;
        if runner_now >= request_event.expires_at {
            return Err(RefusalReason::Expired);
        }
        if runner_now >= *deadline_at {
            return Err(RefusalReason::DeadlineExceeded);
        }
        let signed_digest =
            decode_digest(signed_request_digest).ok_or(RefusalReason::InvalidRequest)?;
        let mut verified = Vec::with_capacity(jobs.len());
        for job in jobs {
            let manifest: SignedJobManifest = serde_json::from_str(&job.job_manifest)
                .map_err(|_| RefusalReason::InvalidManifest)?;
            let manifest_digest: [u8; 32] = Sha256::digest(job.job_manifest.as_bytes()).into();
            let signature_bytes: [u8; 64] = hex::decode(&manifest.signature)
                .map_err(|_| RefusalReason::InvalidManifest)?
                .try_into()
                .map_err(|_| RefusalReason::InvalidManifest)?;
            let signature = Signature::from_bytes(&signature_bytes);
            if manifest.schema_version != 1
                || manifest.request_event_id != *request_event_id
                || manifest.signed_request_digest != *signed_request_digest
                || manifest.job_id != job.job_id
                || manifest.workflow_path != job.workflow_path
                || manifest.audience_digest != job.audience_digest
                || manifest.isolation_profile_digest != job.isolation_profile_digest
                || hex::encode(manifest_digest) != job.job_manifest_digest
                || self
                    .key
                    .verify(
                        &manifest
                            .signing_bytes()
                            .map_err(|_| RefusalReason::InvalidManifest)?,
                        &signature,
                    )
                    .is_err()
            {
                return Err(RefusalReason::InvalidManifest);
            }
            verified.push(VerifiedJob {
                workflow_policy: CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), false),
                binding: BrokerManifestBinding {
                    signed_request_digest: signed_digest,
                    audience_digest: decode_digest(&job.audience_digest)
                        .ok_or(RefusalReason::InvalidManifest)?,
                    job_manifest_digest: manifest_digest,
                    isolation_profile_digest: decode_digest(&job.isolation_profile_digest)
                        .ok_or(RefusalReason::InvalidManifest)?,
                },
            });
        }
        Ok(VerifiedDispatch {
            relay_signer: self.relay_signer.clone(),
            jobs: verified,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProcessJobExecutor {
    program: PathBuf,
    evidence_directory: PathBuf,
    max_argv_items: usize,
    max_argv_bytes: usize,
    max_environment_items: usize,
    max_environment_bytes: usize,
    max_output_bytes: usize,
}

impl ProcessJobExecutor {
    pub fn new(config: &RunnerHostConfig) -> Result<Self, HostConfigurationError> {
        validate_private_directory(&config.evidence_directory)
            .map_err(|_| HostConfigurationError::InsecureEvidenceDirectory)?;
        Ok(Self {
            program: config.executor_program.clone(),
            evidence_directory: config.evidence_directory.clone(),
            max_argv_items: config.max_argv_items,
            max_argv_bytes: config.max_argv_bytes,
            max_environment_items: config.max_environment_items,
            max_environment_bytes: config.max_environment_bytes,
            max_output_bytes: config.max_output_bytes,
        })
    }

    fn inputs_within_bounds(&self, manifest: &SignedJobManifest) -> bool {
        manifest.argv.len() <= self.max_argv_items
            && manifest
                .argv
                .iter()
                .all(|value| !value.is_empty() && !value.contains('\0'))
            && manifest.argv.iter().map(String::len).sum::<usize>() <= self.max_argv_bytes
            && manifest.environment.len() <= self.max_environment_items
            && manifest
                .environment
                .iter()
                .all(|(key, value)| valid_env_key(key) && !value.contains('\0'))
            && manifest
                .environment
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                <= self.max_environment_bytes
    }
}

impl JobExecutor for ProcessJobExecutor {
    fn execute(
        &mut self,
        job: &ExecuteJob,
        lease: &AdmittedLease,
        deadline_at: u64,
    ) -> Result<JobExecution, ExecutionBackendError> {
        let manifest: SignedJobManifest =
            serde_json::from_str(&job.job_manifest).map_err(|_| ExecutionBackendError::Failed)?;
        if !self.inputs_within_bounds(&manifest) {
            return Err(ExecutionBackendError::Failed);
        }
        let relative_path = format!("{}.log", hex::encode(lease.lease_id()));
        let path = self.evidence_directory.join(&relative_path);
        // The synced exclusive log entry is also the durable at-most-once execution claim.
        // A restart after this point refuses rather than invoking the program twice.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| ExecutionBackendError::MissingEvidence)?;
        file.sync_all()
            .and_then(|()| File::open(&self.evidence_directory)?.sync_all())
            .map_err(|_| ExecutionBackendError::MissingEvidence)?;
        let started_at = now()?;
        if started_at >= deadline_at {
            return Err(ExecutionBackendError::DeadlineExceeded);
        }
        let mut command = Command::new(&self.program);
        command
            .args(&manifest.argv)
            .env_clear()
            .envs(&manifest.environment)
            .stdin(Stdio::null());
        let output = run_bounded_process(&mut command, file, self.max_output_bytes, deadline_at)?;
        let finished_at = now()?.max(started_at);
        let state = if output.status.success() {
            CiJobState::Success
        } else {
            CiJobState::Failure
        };
        let conclusion = if output.status.success() {
            Conclusion::Success
        } else {
            Conclusion::Failure
        };
        let evidence_digest: [u8; 32] = Sha256::new()
            .chain_update(EVIDENCE_DOMAIN)
            .chain_update(lease.lease_id())
            .chain_update(output.log_digest)
            .finalize()
            .into();
        Ok(JobExecution {
            state,
            reason: (!output.status.success()).then(|| "executor_failed".to_owned()),
            started_at,
            finished_at,
            log: LogEvidence {
                relative_path,
                sha256: hex::encode(output.log_digest),
                byte_length: output.byte_length,
                cap_bytes: self.max_output_bytes as u64,
                truncated: false,
            },
            artifacts: Vec::new(),
            broker_evidence: BoundedExecutionEvidence::new(
                conclusion,
                evidence_digest,
                finished_at,
            )
            .map_err(|_| ExecutionBackendError::MissingEvidence)?,
        })
    }
}

struct BoundedProcessOutput {
    status: ExitStatus,
    log_digest: [u8; 32],
    byte_length: u64,
}

struct OutputSink {
    file: File,
    hasher: Sha256,
    byte_length: usize,
    max_bytes: usize,
}

fn run_bounded_process(
    command: &mut Command,
    file: File,
    max_output_bytes: usize,
    deadline_at: u64,
) -> Result<BoundedProcessOutput, ExecutionBackendError> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| ExecutionBackendError::Unavailable)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = terminate_process_group(&mut child);
        return Err(ExecutionBackendError::Unavailable);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = terminate_process_group(&mut child);
        return Err(ExecutionBackendError::Unavailable);
    };
    let sink = Arc::new(Mutex::new(OutputSink {
        file,
        hasher: Sha256::new(),
        byte_length: 0,
        max_bytes: max_output_bytes,
    }));
    let overflowed = Arc::new(AtomicBool::new(false));
    let io_failed = Arc::new(AtomicBool::new(false));
    let stdout_done = Arc::new(AtomicBool::new(false));
    let stderr_done = Arc::new(AtomicBool::new(false));
    let stdout_thread = spawn_output_drain(
        stdout,
        sink.clone(),
        overflowed.clone(),
        io_failed.clone(),
        stdout_done.clone(),
    );
    let stderr_thread = spawn_output_drain(
        stderr,
        sink.clone(),
        overflowed.clone(),
        io_failed.clone(),
        stderr_done.clone(),
    );

    let mut deadline_exceeded = false;
    let mut leader_status = None;
    let status = loop {
        if overflowed.load(Ordering::Acquire) || io_failed.load(Ordering::Acquire) {
            break terminate_process_group(&mut child)?;
        }
        match now() {
            Ok(current) if current >= deadline_at => {
                deadline_exceeded = true;
                break terminate_process_group(&mut child)?;
            }
            Ok(_) => {}
            Err(error) => {
                let _ = terminate_process_group(&mut child);
                return Err(error);
            }
        }
        if leader_status.is_none() {
            match child.try_wait() {
                Ok(status) => leader_status = status,
                Err(_) => {
                    let _ = terminate_process_group(&mut child);
                    return Err(ExecutionBackendError::Unavailable);
                }
            }
        }
        if stdout_done.load(Ordering::Acquire) && stderr_done.load(Ordering::Acquire) {
            if let Some(status) = leader_status {
                break status;
            }
        }
        thread::sleep(Duration::from_millis(10));
    };

    if stdout_thread.join().is_err() || stderr_thread.join().is_err() {
        return Err(ExecutionBackendError::MissingEvidence);
    }
    if deadline_exceeded {
        return Err(ExecutionBackendError::DeadlineExceeded);
    }
    if overflowed.load(Ordering::Acquire) || io_failed.load(Ordering::Acquire) {
        return Err(ExecutionBackendError::MissingEvidence);
    }

    let sink = Arc::try_unwrap(sink)
        .map_err(|_| ExecutionBackendError::MissingEvidence)?
        .into_inner()
        .map_err(|_| ExecutionBackendError::MissingEvidence)?;
    sink.file
        .sync_all()
        .map_err(|_| ExecutionBackendError::MissingEvidence)?;
    Ok(BoundedProcessOutput {
        status,
        log_digest: sink.hasher.finalize().into(),
        byte_length: sink.byte_length as u64,
    })
}

fn spawn_output_drain(
    mut reader: impl Read + Send + 'static,
    sink: Arc<Mutex<OutputSink>>,
    overflowed: Arc<AtomicBool>,
    io_failed: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        struct Done(Arc<AtomicBool>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _done = Done(done);
        let mut buffer = [0_u8; 8192];
        loop {
            if overflowed.load(Ordering::Acquire) || io_failed.load(Ordering::Acquire) {
                return;
            }
            let read = match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(read) => read,
                Err(_) => {
                    io_failed.store(true, Ordering::Release);
                    return;
                }
            };
            let mut sink = match sink.lock() {
                Ok(sink) => sink,
                Err(_) => {
                    io_failed.store(true, Ordering::Release);
                    return;
                }
            };
            let remaining = sink.max_bytes.saturating_sub(sink.byte_length);
            let accepted = read.min(remaining);
            if accepted > 0 {
                if sink.file.write_all(&buffer[..accepted]).is_err() {
                    io_failed.store(true, Ordering::Release);
                    return;
                }
                sink.hasher.update(&buffer[..accepted]);
                sink.byte_length += accepted;
            }
            if accepted != read {
                overflowed.store(true, Ordering::Release);
                return;
            }
        }
    })
}

fn terminate_process_group(
    child: &mut std::process::Child,
) -> Result<ExitStatus, ExecutionBackendError> {
    let raw_pid = i32::try_from(child.id()).map_err(|_| ExecutionBackendError::Unavailable)?;
    let process_group = nix::unistd::Pid::from_raw(raw_pid);
    let _ = nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGTERM);
    let grace_deadline = Instant::now() + Duration::from_millis(250);
    let mut leader_status = None;
    while Instant::now() < grace_deadline {
        if leader_status.is_none() {
            leader_status = child
                .try_wait()
                .map_err(|_| ExecutionBackendError::Unavailable)?;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL);
    if let Some(status) = leader_status {
        Ok(status)
    } else {
        child.wait().map_err(|_| ExecutionBackendError::Unavailable)
    }
}

fn now() -> Result<u64, ExecutionBackendError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| ExecutionBackendError::Failed)
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

fn valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && !key.contains('=')
        && !key.contains('\0')
        && key
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

pub(crate) fn validate_private_directory(path: &PathBuf) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use buzz_core::ci::{CiRequestType, CI_SCHEMA_VERSION};
    use ed25519_dalek::{Signer, SigningKey};

    fn request_with_manifest(key: &SigningKey) -> RunnerRequest {
        let mut manifest = SignedJobManifest {
            schema_version: 1,
            request_event_id: "11".repeat(32),
            signed_request_digest: "22".repeat(32),
            job_id: "test".into(),
            workflow_path: ".github/workflows/ci.yml".into(),
            audience_digest: "33".repeat(32),
            isolation_profile_digest: "44".repeat(32),
            argv: vec!["test".into()],
            environment: BTreeMap::from([("CI".into(), "true".into())]),
            signature: String::new(),
        };
        manifest.signature = hex::encode(key.sign(&manifest.signing_bytes().unwrap()).to_bytes());
        let job_manifest = serde_json::to_string(&manifest).unwrap();
        RunnerRequest::ExecuteAttempt {
            schema_version: 1,
            dispatch_id: "123e4567-e89b-12d3-a456-426614174010".into(),
            request_event_id: manifest.request_event_id.clone(),
            request_event: CiRequestEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_type: CiRequestType::Run,
                target_repo_a: format!("30617:{}:buzz", "55".repeat(32)),
                pr_root_event_id: "66".repeat(32),
                pr_update_event_id: None,
                source_clone_url: "https://relay.example/git/repo".into(),
                immutable_source_ref: "refs/nostr/source".into(),
                tip_oid: "77".repeat(20),
                source_branch: "feature".into(),
                base_ref: "refs/heads/main".into(),
                base_oid: "88".repeat(20),
                workflow_id: "ci".into(),
                workflow_digest: "99".repeat(32),
                job_ids: vec!["test".into()],
                run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
                attempt: 1,
                parent_attempt: None,
                parent_run_id: None,
                trigger_event_id: "66".repeat(32),
                actor: "aa".repeat(32),
                timeout_seconds: 10,
                idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
                issued_at: 10,
                expires_at: 30,
            },
            signed_request_digest: manifest.signed_request_digest.clone(),
            assigned_at: 10,
            deadline_at: 20,
            jobs: vec![ExecuteJob {
                job_id: manifest.job_id,
                attempt: 1,
                parent_attempt: 0,
                workflow_path: manifest.workflow_path,
                job_manifest_digest: hex::encode(Sha256::digest(job_manifest.as_bytes())),
                job_manifest,
                audience_digest: manifest.audience_digest,
                isolation_profile_digest: manifest.isolation_profile_digest,
            }],
        }
    }

    #[test]
    fn manifest_signature_and_raw_digest_are_both_bound() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let verifier = ManifestDispatchVerifier::with_clock(
            &hex::encode(key.verifying_key().as_bytes()),
            "bb".repeat(32),
            || Ok(10),
        )
        .unwrap();
        let request = request_with_manifest(&key);
        assert!(verifier.verify(&request, 10).is_ok());

        let mut changed_digest = request.clone();
        let RunnerRequest::ExecuteAttempt { jobs, .. } = &mut changed_digest;
        jobs[0].job_manifest_digest = "cc".repeat(32);
        assert!(matches!(
            verifier.verify(&changed_digest, 10),
            Err(RefusalReason::InvalidManifest)
        ));

        let other_key = SigningKey::from_bytes(&[8; 32]);
        let wrong_verifier = ManifestDispatchVerifier::with_clock(
            &hex::encode(other_key.verifying_key().as_bytes()),
            "bb".repeat(32),
            || Ok(10),
        )
        .unwrap();
        assert!(matches!(
            wrong_verifier.verify(&request, 10),
            Err(RefusalReason::InvalidManifest)
        ));
    }

    #[test]
    fn verifier_uses_runner_clock_for_deadline_and_expiry() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let request = request_with_manifest(&key);
        let deadline = ManifestDispatchVerifier::with_clock(
            &hex::encode(key.verifying_key().as_bytes()),
            "bb".repeat(32),
            || Ok(20),
        )
        .unwrap();
        assert!(matches!(
            deadline.verify(&request, 10),
            Err(RefusalReason::DeadlineExceeded)
        ));

        let expired = ManifestDispatchVerifier::with_clock(
            &hex::encode(key.verifying_key().as_bytes()),
            "bb".repeat(32),
            || Ok(30),
        )
        .unwrap();
        assert!(matches!(
            expired.verify(&request, 10),
            Err(RefusalReason::Expired)
        ));
    }

    #[test]
    fn executor_rejects_argv_and_environment_outside_configured_bounds() {
        let executor = ProcessJobExecutor {
            program: "/bin/true".into(),
            evidence_directory: "/tmp".into(),
            max_argv_items: 1,
            max_argv_bytes: 4,
            max_environment_items: 1,
            max_environment_bytes: 8,
            max_output_bytes: 10,
        };
        let mut manifest: SignedJobManifest = serde_json::from_str(
            match &request_with_manifest(&SigningKey::from_bytes(&[7; 32])) {
                RunnerRequest::ExecuteAttempt { jobs, .. } => &jobs[0].job_manifest,
            },
        )
        .unwrap();
        manifest.argv = vec!["test".into()];
        manifest.environment.clear();
        assert!(executor.inputs_within_bounds(&manifest));
        manifest.argv.push("extra".into());
        assert!(!executor.inputs_within_bounds(&manifest));
        manifest.argv = vec!["test".into()];
        manifest.environment.insert("bad-key".into(), "x".into());
        assert!(!executor.inputs_within_bounds(&manifest));
    }

    #[test]
    fn executor_streams_output_with_a_hard_combined_cap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bounded.log");
        let file = File::create(&path).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do printf 0123456789; done"]);

        assert!(matches!(
            run_bounded_process(&mut command, file, 128, now().unwrap() + 5),
            Err(ExecutionBackendError::MissingEvidence)
        ));
        assert!(fs::metadata(path).unwrap().len() <= 128);
    }

    #[test]
    fn executor_deadline_terminates_and_reaps_the_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("deadline.log");
        let pid_path = directory.path().join("child.pid");
        let file = File::create(&path).unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30 & child=$!; printf '%s' \"$child\" > \"$1\"")
            .arg("runner-test")
            .arg(&pid_path);
        let started = Instant::now();

        assert!(matches!(
            run_bounded_process(&mut command, file, 128, now().unwrap() + 1),
            Err(ExecutionBackendError::DeadlineExceeded)
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        let child_pid = fs::read_to_string(pid_path).unwrap();
        let child_proc = PathBuf::from(format!("/proc/{}", child_pid.trim()));
        let reap_deadline = Instant::now() + Duration::from_secs(2);
        while child_proc.exists() && Instant::now() < reap_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!child_proc.exists(), "child process was not reaped");
    }

    #[test]
    fn owner_authorizer_is_exact_and_closed() {
        let request = request_with_manifest(&SigningKey::from_bytes(&[7; 32]));
        let RunnerRequest::ExecuteAttempt { request_event, .. } = request;
        assert!(OwnerAuthorizer::new("aa".repeat(32)).authorize(&request_event));
        assert!(!OwnerAuthorizer::new("ab".repeat(32)).authorize(&request_event));
    }
}
