//! Authenticated, bounded local transport for the activation canary.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use buzz_ci_acceptance_ctl::acceptance::{AdmissionState, DRIVER_VERSION};
pub use buzz_ci_acceptance_ctl::acceptance_binding::{
    AcceptanceActorBinding, AcceptanceAuthorityBinding,
    AcceptanceBindingReceipt as AcceptanceBinding, ACCEPTANCE_BINDING_PATH,
    ACCEPTANCE_BINDING_SCHEMA,
};
use buzz_ci_acceptance_ctl::production::{
    AdapterRequest, AdapterResponse, ADAPTER_RESPONSE_SCHEMA, MAX_ADAPTER_FRAME_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ACCEPTANCE_SOCKET_PATH: &str = "/run/buzzci/controld-acceptance.sock";
pub const ACCEPTANCE_FD_NAME: &str = "buzz-ci-controld-acceptance";
pub const SYSTEMD_LISTEN_FD: i32 = 3;
const ACCEPTANCE_LEDGER_SCHEMA: &str = "buzz-ci-controld-acceptance-ledger/v1";
const ACCEPTANCE_LEDGER_NAME: &str = "acceptance-operation-ledger-v1.json";
const ACCEPTANCE_LEDGER_NEXT: &str = ".acceptance-operation-ledger-v1.json.next";
const ACCEPTANCE_LEDGER_LOCK: &str = ".acceptance-operation-ledger.lock";
const ACCEPTANCE_LEDGER_MODE: u32 = 0o600;
const MAX_ACCEPTANCE_LEDGER_BYTES: u64 = 16 * 1024 * 1024;

/// Durable request replay and sequence boundary for one activation scenario.
/// It stores only canonical request digests and bounded canonical responses.
#[derive(Clone, Debug)]
pub struct AcceptanceJournal {
    root: PathBuf,
    expected_owner_uid: u32,
    binding: AcceptanceBinding,
}

impl AcceptanceJournal {
    pub fn open(
        root: impl Into<PathBuf>,
        expected_owner_uid: u32,
        binding: AcceptanceBinding,
    ) -> Result<Self, AcceptanceSocketError> {
        let root = root.into();
        let metadata = fs::symlink_metadata(&root).map_err(|_| AcceptanceSocketError::Binding)?;
        if !normalized_absolute(&root)
            || fs::canonicalize(&root).map_err(|_| AcceptanceSocketError::Binding)? != root
            || !metadata.file_type().is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.uid() != expected_owner_uid
        {
            return Err(AcceptanceSocketError::Binding);
        }
        binding
            .validate()
            .map_err(|_| AcceptanceSocketError::Binding)?;
        let journal = Self {
            root,
            expected_owner_uid,
            binding,
        };
        journal.with_locked(|ledger| ledger.validate(&journal.binding))?;
        Ok(journal)
    }

    pub const fn acceptance_peer_uid(&self) -> u32 {
        self.binding.acceptance_peer_uid
    }

    pub const fn acceptance_peer_gid(&self) -> u32 {
        self.binding.acceptance_peer_gid
    }

    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.binding.timeout_millis)
    }

    /// Validate activation, sequence, capacity, generation, and replay bindings
    /// before invoking an operation. Exact retries return the durable response.
    pub fn execute<E>(
        &self,
        request: &AdapterRequest,
        exact_request: &[u8],
        configured_capacity: u32,
        operation: impl FnOnce(Option<&AdapterResponse>) -> Result<AdapterResponse, E>,
    ) -> Result<AdapterResponse, AcceptanceSocketError> {
        self.with_locked(|ledger| {
            ledger.validate(&self.binding)?;
            let request_digest = hex::encode(Sha256::digest(exact_request));
            if let Some(entry) = ledger
                .entries
                .iter()
                .find(|entry| entry.operation_id == request.operation_id)
            {
                if entry.request_sha256 != request_digest {
                    return Err(AcceptanceSocketError::Replay);
                }
                return serde_json::from_slice(&entry.response)
                    .map_err(|_| AcceptanceSocketError::Replay);
            }
            if configured_capacity > 1
                || request.sequence != u32::try_from(ledger.entries.len() + 1).unwrap_or(u32::MAX)
                || request.scenario_sha256 != self.binding.scenario_sha256
                || request.fixture != self.binding.fixture
                || request.host.activation_id != self.binding.activation_id
                || request.host.activation_package_digest != self.binding.activation_package_digest
                || request.host.integrated_candidate_sha
                    != self.binding.fixture.integrated_candidate_sha
                || request.host.capacity != configured_capacity
                || request.host.admission
                    != if configured_capacity == 1 {
                        AdmissionState::Open
                    } else {
                        AdmissionState::Closed
                    }
            {
                return Err(AcceptanceSocketError::Binding);
            }
            let prior = ledger
                .entries
                .last()
                .map(|entry| serde_json::from_slice::<AdapterResponse>(&entry.response))
                .transpose()
                .map_err(|_| AcceptanceSocketError::Replay)?;
            match prior.as_ref() {
                None if request.expected_controller_generation.is_some()
                    || request.expected_runner_generation.is_some()
                    || request.host.controller_generation
                        != self.binding.fixture.controller_generation
                    || request.host.runner_generation != self.binding.fixture.runner_generation =>
                {
                    return Err(AcceptanceSocketError::Binding);
                }
                Some(prior)
                    if request.expected_controller_generation
                        != Some(prior.response.snapshot.controller_generation)
                        || request.expected_runner_generation
                            != Some(prior.response.snapshot.runner_generation)
                        || request.host.controller_generation
                            < prior.response.snapshot.controller_generation
                        || request.host.runner_generation
                            < prior.response.snapshot.runner_generation =>
                {
                    return Err(AcceptanceSocketError::Binding);
                }
                _ => {}
            }
            let response =
                operation(prior.as_ref()).map_err(|_| AcceptanceSocketError::Operation)?;
            validate_response(request, &response)?;
            if response.response.snapshot.capacity != configured_capacity
                || response.response.snapshot.admission != request.host.admission
                || response.response.snapshot.controller_generation
                    != request.host.controller_generation
                || response.response.snapshot.runner_generation != request.host.runner_generation
            {
                return Err(AcceptanceSocketError::Binding);
            }
            let encoded =
                serde_json::to_vec(&response).map_err(|_| AcceptanceSocketError::Frame)?;
            if encoded.len() > MAX_ADAPTER_FRAME_BYTES {
                return Err(AcceptanceSocketError::Frame);
            }
            ledger.entries.push(AcceptanceLedgerEntry {
                sequence: request.sequence,
                operation_id: request.operation_id.clone(),
                request_sha256: request_digest,
                response: encoded,
            });
            self.persist(ledger)?;
            Ok(response)
        })
    }

    fn with_locked<T>(
        &self,
        operation: impl FnOnce(&mut AcceptanceLedger) -> Result<T, AcceptanceSocketError>,
    ) -> Result<T, AcceptanceSocketError> {
        use nix::fcntl::{Flock, FlockArg};

        let lock_path = self.root.join(ACCEPTANCE_LEDGER_LOCK);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(ACCEPTANCE_LEDGER_MODE)
            .open(&lock_path)
            .map_err(|_| AcceptanceSocketError::Replay)?;
        validate_ledger_metadata(
            &fs::symlink_metadata(&lock_path).map_err(|_| AcceptanceSocketError::Replay)?,
            self.expected_owner_uid,
        )?;
        let _lock = Flock::lock(lock, FlockArg::LockExclusive)
            .map_err(|_| AcceptanceSocketError::Replay)?;
        let path = self.root.join(ACCEPTANCE_LEDGER_NAME);
        let mut ledger = if path.exists() {
            self.read_ledger(&path)?
        } else {
            let ledger = AcceptanceLedger::new(&self.binding);
            self.persist(&ledger)?;
            ledger
        };
        operation(&mut ledger)
    }

    fn read_ledger(&self, path: &Path) -> Result<AcceptanceLedger, AcceptanceSocketError> {
        let before = fs::symlink_metadata(path).map_err(|_| AcceptanceSocketError::Replay)?;
        validate_ledger_metadata(&before, self.expected_owner_uid)?;
        if before.len() > MAX_ACCEPTANCE_LEDGER_BYTES
            || fs::canonicalize(path).map_err(|_| AcceptanceSocketError::Replay)? != path
        {
            return Err(AcceptanceSocketError::Replay);
        }
        let mut file = File::open(path).map_err(|_| AcceptanceSocketError::Replay)?;
        let opened = file.metadata().map_err(|_| AcceptanceSocketError::Replay)?;
        validate_ledger_metadata(&opened, self.expected_owner_uid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(AcceptanceSocketError::Replay);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        (&mut file)
            .take(MAX_ACCEPTANCE_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AcceptanceSocketError::Replay)?;
        if bytes.len() as u64 > MAX_ACCEPTANCE_LEDGER_BYTES {
            return Err(AcceptanceSocketError::Replay);
        }
        serde_json::from_slice(&bytes).map_err(|_| AcceptanceSocketError::Replay)
    }

    fn persist(&self, ledger: &AcceptanceLedger) -> Result<(), AcceptanceSocketError> {
        let encoded = serde_json::to_vec(ledger).map_err(|_| AcceptanceSocketError::Replay)?;
        if encoded.len() as u64 > MAX_ACCEPTANCE_LEDGER_BYTES {
            return Err(AcceptanceSocketError::Replay);
        }
        let next = self.root.join(ACCEPTANCE_LEDGER_NEXT);
        match fs::remove_file(&next) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AcceptanceSocketError::Replay),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(ACCEPTANCE_LEDGER_MODE)
            .open(&next)
            .map_err(|_| AcceptanceSocketError::Replay)?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| AcceptanceSocketError::Replay)?;
        fs::rename(&next, self.root.join(ACCEPTANCE_LEDGER_NAME))
            .map_err(|_| AcceptanceSocketError::Replay)?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AcceptanceSocketError::Replay)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceLedger {
    schema_version: String,
    scenario_sha256: String,
    activation_id: String,
    activation_package_digest: String,
    entries: Vec<AcceptanceLedgerEntry>,
}

impl AcceptanceLedger {
    fn new(binding: &AcceptanceBinding) -> Self {
        Self {
            schema_version: ACCEPTANCE_LEDGER_SCHEMA.to_owned(),
            scenario_sha256: binding.scenario_sha256.clone(),
            activation_id: binding.activation_id.clone(),
            activation_package_digest: binding.activation_package_digest.clone(),
            entries: Vec::new(),
        }
    }

    fn validate(&self, binding: &AcceptanceBinding) -> Result<(), AcceptanceSocketError> {
        if self.schema_version != ACCEPTANCE_LEDGER_SCHEMA
            || self.scenario_sha256 != binding.scenario_sha256
            || self.activation_id != binding.activation_id
            || self.activation_package_digest != binding.activation_package_digest
            || self.entries.len() > 13
            || self.entries.iter().enumerate().any(|(index, entry)| {
                entry.sequence != u32::try_from(index + 1).unwrap_or(u32::MAX)
                    || !lower_hex(&entry.operation_id, 64)
                    || !lower_hex(&entry.request_sha256, 64)
                    || entry.response.len() > MAX_ADAPTER_FRAME_BYTES
                    || serde_json::from_slice::<AdapterResponse>(&entry.response).is_err()
            })
        {
            return Err(AcceptanceSocketError::Replay);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceLedgerEntry {
    sequence: u32,
    operation_id: String,
    request_sha256: String,
    response: Vec<u8>,
}

/// Scenario operation boundary. Production must provide actual relay and
/// durable-state effects; the socket layer never synthesizes a snapshot.
pub trait AcceptanceOperationHandler {
    type Error;

    fn handle(
        &mut self,
        request: &AdapterRequest,
        exact_request: &[u8],
    ) -> Result<AdapterResponse, Self::Error>;

    /// Called only after the complete canonical response was written and the
    /// server write side was shut down successfully.
    fn response_written(&mut self, _request: &AdapterRequest) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AcceptanceSocketError {
    #[error("acceptance activation binding is invalid")]
    Binding,
    #[error("acceptance socket activation is invalid")]
    Activation,
    #[error("acceptance peer identity is invalid")]
    Unauthorized,
    #[error("acceptance frame is invalid")]
    Frame,
    #[error("acceptance operation failed closed")]
    Operation,
    #[error("acceptance operation replay is invalid")]
    Replay,
    #[error("acceptance transport is unavailable")]
    Transport,
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(target_os = "linux")]
fn validate_ledger_metadata(
    metadata: &fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), AcceptanceSocketError> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != ACCEPTANCE_LEDGER_MODE
        || metadata.uid() != expected_owner_uid
        || metadata.nlink() != 1
    {
        return Err(AcceptanceSocketError::Replay);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_systemd_environment() -> Result<(), AcceptanceSocketError> {
    let pid = parse_env_u32("LISTEN_PID")?;
    let descriptors = parse_env_u32("LISTEN_FDS")?;
    if pid != std::process::id()
        || descriptors != 1
        || std::env::var("LISTEN_FDNAMES").as_deref() != Ok(ACCEPTANCE_FD_NAME)
    {
        return Err(AcceptanceSocketError::Activation);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_systemd_listener(
    listener: UnixListener,
    expected_group_gid: u32,
) -> Result<UnixListener, AcceptanceSocketError> {
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;

    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::socket::{
        getsockname, getsockopt, sockopt::AcceptConn, sockopt::SockType, SockType as NixSockType,
        UnixAddr,
    };

    let socket_path = Path::new(ACCEPTANCE_SOCKET_PATH);
    let metadata =
        fs::symlink_metadata(socket_path).map_err(|_| AcceptanceSocketError::Activation)?;
    if expected_group_gid == 0
        || getsockopt(&listener, SockType).map_err(|_| AcceptanceSocketError::Activation)?
            != NixSockType::Stream
        || !getsockopt(&listener, AcceptConn).map_err(|_| AcceptanceSocketError::Activation)?
        || getsockname::<UnixAddr>(listener.as_raw_fd())
            .map_err(|_| AcceptanceSocketError::Activation)?
            .path()
            != Some(socket_path)
        || !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o7777 != 0o620
        || metadata.uid() != 0
        || metadata.gid() != expected_group_gid
        || metadata.nlink() != 1
    {
        return Err(AcceptanceSocketError::Activation);
    }
    let current = fcntl(listener.as_fd(), FcntlArg::F_GETFD)
        .map_err(|_| AcceptanceSocketError::Activation)?;
    let mut flags = FdFlag::from_bits_truncate(current);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(listener.as_fd(), FcntlArg::F_SETFD(flags))
        .map_err(|_| AcceptanceSocketError::Activation)?;
    Ok(listener)
}

#[cfg(not(target_os = "linux"))]
pub fn validate_systemd_environment() -> Result<(), AcceptanceSocketError> {
    Err(AcceptanceSocketError::Activation)
}

/// Authenticate exact buzzci-ctl credentials before reading one EOF-delimited
/// canonical JSON request, then write one bounded canonical JSON response.
#[cfg(target_os = "linux")]
pub fn serve_connection<H: AcceptanceOperationHandler>(
    mut stream: UnixStream,
    expected_uid: u32,
    expected_gid: u32,
    timeout: Duration,
    handler: &mut H,
) -> Result<(), AcceptanceSocketError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    if expected_uid == 0
        || expected_gid == 0
        || timeout.is_zero()
        || timeout > Duration::from_secs(300)
    {
        return Err(AcceptanceSocketError::Activation);
    }
    let peer =
        getsockopt(&stream, PeerCredentials).map_err(|_| AcceptanceSocketError::Unauthorized)?;
    if peer.uid() != expected_uid || peer.gid() != expected_gid {
        return Err(AcceptanceSocketError::Unauthorized);
    }
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| AcceptanceSocketError::Transport)?;
    let mut exact = Vec::new();
    (&mut stream)
        .take(MAX_ADAPTER_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut exact)
        .map_err(|_| AcceptanceSocketError::Transport)?;
    if exact.is_empty() || exact.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(AcceptanceSocketError::Frame);
    }
    let request: AdapterRequest =
        serde_json::from_slice(&exact).map_err(|_| AcceptanceSocketError::Frame)?;
    request
        .validate()
        .map_err(|_| AcceptanceSocketError::Frame)?;
    if serde_json::to_vec(&request).map_err(|_| AcceptanceSocketError::Frame)? != exact {
        return Err(AcceptanceSocketError::Frame);
    }
    let response = handler
        .handle(&request, &exact)
        .map_err(|_| AcceptanceSocketError::Operation)?;
    validate_response(&request, &response)?;
    let encoded = serde_json::to_vec(&response).map_err(|_| AcceptanceSocketError::Frame)?;
    if encoded.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(AcceptanceSocketError::Frame);
    }
    stream
        .write_all(&encoded)
        .and_then(|()| stream.flush())
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|_| AcceptanceSocketError::Transport)?;
    handler
        .response_written(&request)
        .map_err(|_| AcceptanceSocketError::Operation)
}

#[cfg(not(target_os = "linux"))]
pub fn serve_connection<H: AcceptanceOperationHandler>(
    _stream: UnixStream,
    _expected_uid: u32,
    _expected_gid: u32,
    _timeout: Duration,
    _handler: &mut H,
) -> Result<(), AcceptanceSocketError> {
    Err(AcceptanceSocketError::Activation)
}

fn validate_response(
    request: &AdapterRequest,
    response: &AdapterResponse,
) -> Result<(), AcceptanceSocketError> {
    if response.schema_version != ADAPTER_RESPONSE_SCHEMA
        || response.sequence != request.sequence
        || response.operation != request.operation
        || response.scenario_sha256 != request.scenario_sha256
        || response.operation_id != request.operation_id
        || response.response.schema_version != DRIVER_VERSION
        || response.response.sequence != request.sequence
        || response.response.operation != request.operation
    {
        return Err(AcceptanceSocketError::Frame);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_env_u32(key: &str) -> Result<u32, AcceptanceSocketError> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(AcceptanceSocketError::Activation)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::thread;

    use buzz_ci_acceptance_ctl::acceptance::{
        AdmissionState, DriverResponse, EvidenceObject, FixtureSpec, Operation, SystemSnapshot,
    };
    use buzz_ci_acceptance_ctl::acceptance_binding::AcceptanceBindingError;
    use buzz_ci_acceptance_ctl::acceptance_binding_test_support::{
        acceptance_binding_mutation_corpus, canonical_acceptance_binding, CANONICAL_CONTROLD_GID,
        CANONICAL_CONTROLD_UID, CANONICAL_QUALIFICATION_GID, CANONICAL_QUALIFICATION_UID,
    };
    use buzz_ci_acceptance_ctl::production::{
        expected_adapter_operation_id, ControlReadback, ADAPTER_REQUEST_SCHEMA,
    };
    use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
    use buzz_core::kind::{KIND_CI_GRANT, KIND_CI_REQUEST, KIND_DELETION};

    struct Handler;

    impl AcceptanceOperationHandler for Handler {
        type Error = ();

        fn handle(
            &mut self,
            request: &AdapterRequest,
            _exact_request: &[u8],
        ) -> Result<AdapterResponse, Self::Error> {
            Ok(AdapterResponse {
                schema_version: ADAPTER_RESPONSE_SCHEMA.into(),
                sequence: request.sequence,
                operation: request.operation,
                scenario_sha256: request.scenario_sha256.clone(),
                operation_id: request.operation_id.clone(),
                response: DriverResponse {
                    schema_version: DRIVER_VERSION.into(),
                    sequence: request.sequence,
                    operation: request.operation,
                    snapshot: SystemSnapshot {
                        capacity: 0,
                        admission: AdmissionState::Closed,
                        active_run_count: 0,
                        active_attempt_count: 0,
                        controller_generation: request.host.controller_generation,
                        runner_generation: request.host.runner_generation,
                        run: None,
                    },
                    export: None,
                },
            })
        }
    }

    fn request() -> AdapterRequest {
        let acceptance = authority();
        let event_ids = [
            &acceptance.run_event,
            &acceptance.grant_event,
            &acceptance.rerun_event,
            &acceptance.tombstone_event,
        ]
        .map(|event| Sha256::digest(serde_json::to_vec(event).unwrap()));
        let fixture = FixtureSpec {
            integrated_candidate_sha: "11".repeat(20),
            activation_id: "activation-1".into(),
            activation_package_digest: "12".repeat(32),
            run_id: "13".repeat(16),
            job_id: "test".into(),
            request_digest: hex::encode(event_ids[0]),
            manifest_digest: "15".repeat(32),
            source_oid: "16".repeat(20),
            approval_id: "17".repeat(16),
            grant_event_id: hex::encode(event_ids[1]),
            grant_digest: "19".repeat(32),
            approved_by: acceptance.actor.public_key,
            export_subject: "1b".repeat(32),
            export_authorization_digest: "1c".repeat(32),
            controller_generation: 7,
            runner_generation: 9,
            expected_log: EvidenceObject {
                name: "job.log".into(),
                sha256: "1d".repeat(32),
                bytes: 1,
            },
            expected_artifacts: vec![EvidenceObject {
                name: "result.json".into(),
                sha256: "1e".repeat(32),
                bytes: 1,
            }],
        };
        let mut request = AdapterRequest {
            schema_version: ADAPTER_REQUEST_SCHEMA.into(),
            sequence: 1,
            operation: Operation::ObserveInitial,
            scenario_sha256: "1f".repeat(32),
            operation_id: "20".repeat(32),
            fixture: fixture.clone(),
            attempt_id: None,
            expected_controller_generation: None,
            expected_runner_generation: None,
            host: ControlReadback {
                activation_id: fixture.activation_id,
                activation_package_digest: fixture.activation_package_digest,
                integrated_candidate_sha: fixture.integrated_candidate_sha,
                capacity: 0,
                admission: AdmissionState::Closed,
                controller_generation: fixture.controller_generation,
                runner_generation: fixture.runner_generation,
            },
        };
        request.operation_id = expected_adapter_operation_id(&request).unwrap();
        request
    }

    fn binding(request: &AdapterRequest) -> AcceptanceBinding {
        AcceptanceBinding {
            schema_version: ACCEPTANCE_BINDING_SCHEMA.into(),
            activation_id: request.fixture.activation_id.clone(),
            activation_package_digest: request.fixture.activation_package_digest.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            keyholder_peer_uid: CANONICAL_CONTROLD_UID,
            keyholder_peer_gid: CANONICAL_CONTROLD_GID,
            acceptance_peer_uid: CANONICAL_QUALIFICATION_UID,
            acceptance_peer_gid: CANONICAL_QUALIFICATION_GID,
            timeout_millis: 1_000,
            fixture: request.fixture.clone(),
            acceptance: authority(),
        }
    }

    fn authority() -> AcceptanceAuthorityBinding {
        let actor = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let channel = "123e4567-e89b-12d3-a456-426614174099";
        let mut run = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
            pr_root_event_id: "33".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".into(),
            immutable_source_ref: "refs/nostr/source".into(),
            tip_oid: "16".repeat(20),
            source_branch: "feature".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "55".repeat(20),
            workflow_id: "native-ci".into(),
            workflow_digest: "66".repeat(32),
            job_ids: vec!["test".into()],
            run_id: "13131313-1313-1313-1313-131313131313".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "33".repeat(32),
            actor: actor.into(),
            timeout_seconds: 30,
            idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_300,
        };
        let run_event = serde_json::json!([
            0,
            actor,
            run.issued_at,
            KIND_CI_REQUEST,
            request_tags(channel, &run).unwrap(),
            serde_json::to_string(&run).unwrap()
        ]);
        let grant_event = serde_json::json!([
            0,
            actor,
            1_800_000_001_u64,
            KIND_CI_GRANT,
            [["h", channel]],
            serde_json::to_string(&serde_json::json!({
                "schema_version": 1,
                "target_repo_a": run.target_repo_a,
                "signer_pubkey": actor,
                "valid_from": 1_800_000_001_i64,
                "valid_until": 1_800_000_600_i64,
            }))
            .unwrap()
        ]);
        run.request_type = CiRequestType::Rerun;
        run.attempt = 2;
        run.parent_attempt = Some(1);
        run.parent_run_id = Some(run.run_id.clone());
        run.idempotency_key = "123e4567-e89b-12d3-a456-426614174013".into();
        run.issued_at += 10;
        run.expires_at += 10;
        let rerun_event = serde_json::json!([
            0,
            actor,
            run.issued_at,
            KIND_CI_REQUEST,
            request_tags(channel, &run).unwrap(),
            serde_json::to_string(&run).unwrap()
        ]);
        let rerun_id = Sha256::digest(serde_json::to_vec(&rerun_event).unwrap());
        let tombstone_event = serde_json::json!([
            0,
            actor,
            1_800_000_020_u64,
            KIND_DELETION,
            [["e", hex::encode(rerun_id)]],
            ""
        ]);
        AcceptanceAuthorityBinding {
            actor: AcceptanceActorBinding {
                public_key: actor.into(),
                generation: 10,
            },
            scenario_sha256: "1f".repeat(32),
            run_event,
            grant_event,
            rerun_event,
            tombstone_event,
        }
    }

    #[test]
    fn post_freeze_binding_reloads_identically_and_rejects_dynamic_drift() {
        let expected = binding(&request());
        let canonical = serde_json::to_vec(&expected).unwrap();
        assert_eq!(
            AcceptanceBinding::from_canonical_bytes(&canonical).unwrap(),
            expected
        );
        assert_eq!(
            AcceptanceBinding::from_canonical_bytes(&canonical).unwrap(),
            expected
        );

        let mut tampered = Vec::new();

        let mut value = expected.clone();
        value.activation_package_digest = "00".repeat(32);
        tampered.push(value);

        let mut value = expected.clone();
        value.acceptance.scenario_sha256 = "00".repeat(32);
        tampered.push(value);

        let mut value = expected.clone();
        value.fixture.integrated_candidate_sha = "not-a-candidate".into();
        tampered.push(value);

        let mut value = expected.clone();
        value.fixture.request_digest = "00".repeat(32);
        tampered.push(value);

        let mut value = expected.clone();
        value.fixture.controller_generation = 0;
        tampered.push(value);

        let mut value = expected.clone();
        value.acceptance.actor.generation = 0;
        tampered.push(value);

        let mut value = expected.clone();
        value.acceptance_peer_uid = 0;
        tampered.push(value);

        for value in tampered {
            let bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(
                AcceptanceBinding::from_canonical_bytes(&bytes),
                Err(AcceptanceBindingError::Invalid)
            );
        }

        let noncanonical = serde_json::to_vec_pretty(&expected).unwrap();
        assert_eq!(
            AcceptanceBinding::from_canonical_bytes(&noncanonical),
            Err(AcceptanceBindingError::Invalid)
        );
    }

    #[test]
    fn controld_rejects_every_shared_receipt_mutation() {
        let expected = canonical_acceptance_binding();
        let canonical = serde_json::to_vec(&expected).unwrap();
        assert_eq!(
            AcceptanceBinding::from_canonical_bytes(&canonical).unwrap(),
            expected
        );
        for mutation in acceptance_binding_mutation_corpus() {
            assert_eq!(
                AcceptanceBinding::from_canonical_bytes(&mutation.bytes),
                Err(AcceptanceBindingError::Invalid),
                "mutation {}",
                mutation.name
            );
        }
    }

    #[test]
    fn exact_peer_and_canonical_eof_frame_receive_bound_response() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let expected = request();
        let encoded = serde_json::to_vec(&expected).unwrap();
        let handle = thread::spawn(move || {
            serve_connection(server, uid, gid, Duration::from_secs(1), &mut Handler)
        });
        client.write_all(&encoded).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        handle.join().unwrap().unwrap();
        let response: AdapterResponse = serde_json::from_slice(&response).unwrap();
        assert_eq!(response.operation_id, expected.operation_id);
        assert_eq!(response.response.snapshot.capacity, 0);
    }

    #[test]
    fn wrong_peer_is_rejected_before_request_bytes_are_read() {
        let (_client, server) = UnixStream::pair().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        assert_eq!(
            serve_connection(
                server,
                uid.checked_add(1).unwrap(),
                gid,
                Duration::from_secs(1),
                &mut Handler,
            ),
            Err(AcceptanceSocketError::Unauthorized)
        );
    }

    #[test]
    fn journal_replays_exact_bytes_and_rejects_divergent_or_skipped_requests() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        let request = request();
        let exact = serde_json::to_vec(&request).unwrap();
        let journal = AcceptanceJournal::open(root.path(), owner_uid, binding(&request)).unwrap();
        let expected = Handler.handle(&request, &exact).unwrap();
        let first = journal
            .execute(&request, &exact, 0, |_| Ok::<_, ()>(expected.clone()))
            .unwrap();
        assert_eq!(first, expected);

        let reopened = AcceptanceJournal::open(root.path(), owner_uid, binding(&request)).unwrap();
        let replayed = reopened
            .execute(&request, &exact, 0, |_| {
                Err::<AdapterResponse, _>("operation must not run")
            })
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&replayed).unwrap(),
            serde_json::to_vec(&first).unwrap()
        );

        let mut replaced_binding = binding(&request);
        replaced_binding.activation_id = "activation-2".into();
        replaced_binding.fixture.activation_id = "activation-2".into();
        assert!(matches!(
            AcceptanceJournal::open(root.path(), owner_uid, replaced_binding),
            Err(AcceptanceSocketError::Replay)
        ));

        let mut divergent = exact.clone();
        divergent.push(b' ');
        assert_eq!(
            reopened.execute(&request, &divergent, 0, |_| Ok::<_, ()>(expected.clone())),
            Err(AcceptanceSocketError::Replay)
        );

        let mut skipped = request.clone();
        skipped.sequence = 3;
        skipped.operation = Operation::SubmitManifest;
        skipped.operation_id = expected_adapter_operation_id(&skipped).unwrap();
        let skipped_exact = serde_json::to_vec(&skipped).unwrap();
        assert_eq!(
            reopened.execute(&skipped, &skipped_exact, 0, |_| Ok::<_, ()>(expected)),
            Err(AcceptanceSocketError::Binding)
        );
    }

    #[test]
    fn journal_rejects_fresh_root_with_mode_0755() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let request = request();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        assert!(matches!(
            AcceptanceJournal::open(root.path(), owner_uid, binding(&request)),
            Err(AcceptanceSocketError::Binding)
        ));
    }
}
