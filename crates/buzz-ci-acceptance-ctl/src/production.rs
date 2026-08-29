//! Package-bound production adapters for the capacity-one canary.
//!
//! The unprivileged driver talks to two fixed Unix sockets. The root control
//! helper owns only host capacity and process readback. Controld owns every
//! relay, signer, durable-run, and evidence operation.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::acceptance::{
    AcceptanceDriver, AdmissionState, DriverRequest, DriverResponse, FixtureSpec, Operation,
    DRIVER_VERSION,
};

/// Installed unprivileged adapter binary.
pub const DRIVER_PROGRAM: &str = "/usr/libexec/buzz-ci-capacity-one-driver";
/// Fixed unprivileged driver configuration.
pub const DRIVER_CONFIG_PATH: &str = "/etc/buzzci/acceptance-driver-v1.json";
/// Root helper socket.
pub const CONTROL_SOCKET_PATH: &str = "/run/buzzci/acceptance-control.sock";
/// Controld acceptance socket.
pub const CONTROLD_SOCKET_PATH: &str = "/run/buzzci/controld-acceptance.sock";
/// Root helper executable.
pub const CONTROL_PROGRAM: &str = "/usr/libexec/buzz-ci-acceptance-control";
/// Root helper configuration.
pub const CONTROL_CONFIG_PATH: &str = "/etc/buzzci/acceptance-control-v1.json";
/// Root activation receipt bound to each helper request.
pub const ACTIVATION_RECEIPT_PATH: &str = "/var/lib/buzzci/activation-controller/receipt-v1.json";
/// Root helper replay ledger.
pub const CONTROL_LEDGER_PATH: &str = "/var/lib/buzzci/acceptance-control/operation-ledger-v1.json";

const CONFIG_SCHEMA: &str = "buzz-ci-capacity-one-driver-config/v1";
const CONTROL_CONFIG_SCHEMA: &str = "buzz-ci-acceptance-control-config/v1";
pub const ADAPTER_REQUEST_SCHEMA: &str = "buzz-ci-capacity-one-adapter-request/v1";
pub const ADAPTER_RESPONSE_SCHEMA: &str = "buzz-ci-capacity-one-adapter-response/v1";
pub const CONTROL_REQUEST_SCHEMA: &str = "buzz-ci-acceptance-control-request/v1";
pub const CONTROL_RESPONSE_SCHEMA: &str = "buzz-ci-acceptance-control-response/v1";
const MAX_CONFIG_BYTES: u64 = 128 * 1024;
/// Maximum request or response frame.
pub const MAX_ADAPTER_FRAME_BYTES: usize = 1024 * 1024;

/// Exact installed identities and activation binding for the unprivileged driver.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDriverConfig {
    pub schema_version: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub scenario_sha256: String,
    pub run_id: String,
    pub job_id: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub approval_id: String,
    pub grant_event_id: String,
    pub grant_digest: String,
    pub qualification_uid: u32,
    pub qualification_gid: u32,
    pub controld_uid: u32,
    pub controld_gid: u32,
    pub control_socket: PathBuf,
    pub controld_socket: PathBuf,
    pub timeout_millis: u64,
}

impl ProductionDriverConfig {
    /// Load the fixed root-owned, group-readable config without following links.
    #[cfg(target_os = "linux")]
    pub fn load(path: &Path, qualification_gid: u32) -> Result<Self, DriverError> {
        let bytes = read_secure_file(path, 0, qualification_gid, 0o440, MAX_CONFIG_BYTES)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| DriverError::InvalidConfig)?;
        value.validate()?;
        Ok(value)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_path: &Path, _qualification_gid: u32) -> Result<Self, DriverError> {
        Err(DriverError::UnsupportedPlatform)
    }

    /// Validate fixed paths, identifiers, and resource bounds.
    pub fn validate(&self) -> Result<(), DriverError> {
        if self.schema_version != CONFIG_SCHEMA
            || self.qualification_uid == 0
            || self.qualification_gid == 0
            || self.controld_uid == 0
            || self.controld_gid == 0
            || self.timeout_millis == 0
            || self.timeout_millis > 300_000
            || self.control_socket != Path::new(CONTROL_SOCKET_PATH)
            || self.controld_socket != Path::new(CONTROLD_SOCKET_PATH)
            || !valid_name(&self.activation_id, 128)
            || !lower_hex(&self.activation_package_digest, &[64])
            || !lower_hex(&self.integrated_candidate_sha, &[40, 64])
            || !lower_hex(&self.scenario_sha256, &[64])
            || !lower_hex(&self.run_id, &[32])
            || !valid_name(&self.job_id, 64)
            || !lower_hex(&self.request_digest, &[64])
            || !lower_hex(&self.manifest_digest, &[64])
            || !lower_hex(&self.approval_id, &[32])
            || !lower_hex(&self.grant_event_id, &[64])
            || !lower_hex(&self.grant_digest, &[64])
        {
            return Err(DriverError::InvalidConfig);
        }
        Ok(())
    }

    fn binds(&self, request: &DriverRequest<'_>) -> bool {
        request.schema_version == DRIVER_VERSION
            && request.scenario_sha256 == self.scenario_sha256
            && request.fixture.activation_id == self.activation_id
            && request.fixture.activation_package_digest == self.activation_package_digest
            && request.fixture.integrated_candidate_sha == self.integrated_candidate_sha
            && request.fixture.run_id == self.run_id
            && request.fixture.job_id == self.job_id
            && request.fixture.request_digest == self.request_digest
            && request.fixture.manifest_digest == self.manifest_digest
            && request.fixture.approval_id == self.approval_id
            && request.fixture.grant_event_id == self.grant_event_id
            && request.fixture.grant_digest == self.grant_digest
    }
}

/// Fresh root-owned host readback attached to each controld request.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReadback {
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub capacity: u32,
    pub admission: AdmissionState,
    pub controller_generation: u64,
    pub runner_generation: u64,
}

/// Owned request sent to the controld acceptance socket.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRequest {
    pub schema_version: String,
    pub sequence: u32,
    pub operation: Operation,
    pub scenario_sha256: String,
    pub operation_id: String,
    pub fixture: FixtureSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
    pub host: ControlReadback,
}

impl AdapterRequest {
    /// Validate protocol shape and the root readback binding before any mutation.
    pub fn validate(&self) -> Result<(), DriverError> {
        if self.schema_version != ADAPTER_REQUEST_SCHEMA
            || expected_operation(self.sequence) != Some(self.operation)
            || !lower_hex(&self.scenario_sha256, &[64])
            || !lower_hex(&self.operation_id, &[64])
            || self.host.activation_id != self.fixture.activation_id
            || self.host.activation_package_digest != self.fixture.activation_package_digest
            || self.host.integrated_candidate_sha != self.fixture.integrated_candidate_sha
            || self.host.capacity > 1
            || self.host.controller_generation == 0
            || self.host.runner_generation == 0
            || self
                .attempt_id
                .as_deref()
                .is_some_and(|value| !lower_hex(value, &[32]))
        {
            return Err(DriverError::BindingMismatch);
        }
        let borrowed = DriverRequest {
            schema_version: DRIVER_VERSION,
            scenario_sha256: &self.scenario_sha256,
            sequence: self.sequence,
            operation: self.operation,
            fixture: &self.fixture,
            attempt_id: self.attempt_id.as_deref(),
            expected_controller_generation: self.expected_controller_generation,
            expected_runner_generation: self.expected_runner_generation,
        };
        if !valid_request(&borrowed) {
            return Err(DriverError::BindingMismatch);
        }
        if self.operation_id != expected_adapter_operation_id(self)? {
            return Err(DriverError::BindingMismatch);
        }
        Ok(())
    }
}

/// Bound response returned by controld.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResponse {
    pub schema_version: String,
    pub sequence: u32,
    pub operation: Operation,
    pub scenario_sha256: String,
    pub operation_id: String,
    pub response: DriverResponse,
}

/// Owned form of the canary request read by the installed driver binary.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDriverRequest {
    pub schema_version: String,
    pub scenario_sha256: String,
    pub sequence: u32,
    pub operation: Operation,
    pub fixture: FixtureSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
}

impl OwnedDriverRequest {
    pub fn borrowed(&self) -> DriverRequest<'_> {
        DriverRequest {
            schema_version: DRIVER_VERSION,
            scenario_sha256: &self.scenario_sha256,
            sequence: self.sequence,
            operation: self.operation,
            fixture: &self.fixture,
            attempt_id: self.attempt_id.as_deref(),
            expected_controller_generation: self.expected_controller_generation,
            expected_runner_generation: self.expected_runner_generation,
        }
    }

    pub fn validate_version(&self) -> Result<(), DriverError> {
        if self.schema_version == DRIVER_VERSION {
            Ok(())
        } else {
            Err(DriverError::BindingMismatch)
        }
    }
}

/// Closed root helper request. It has no program, unit, path, or argv fields.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub schema_version: String,
    pub sequence: u32,
    pub operation: ControlOperation,
    pub scenario_sha256: String,
    pub operation_id: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub run_id: String,
    pub job_id: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub approval_id: String,
    pub grant_event_id: String,
    pub grant_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
}

/// Only actions accepted by the root helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOperation {
    Observe,
    SetCapacityOne,
    RestartController,
    RestartRunner,
    SetCapacityZero,
}

/// Bound root helper response.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub schema_version: String,
    pub sequence: u32,
    pub operation: ControlOperation,
    pub scenario_sha256: String,
    pub operation_id: String,
    pub readback: ControlReadback,
}

/// One bounded socket exchange, injectable in tests.
pub trait AdapterTransport {
    type Error: std::fmt::Display;

    fn exchange(
        &mut self,
        endpoint: AdapterEndpoint,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Fixed local endpoint selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterEndpoint {
    Control,
    Controld,
}

/// Production driver over an injected Unix transport.
pub struct ProductionDriver<T> {
    config: ProductionDriverConfig,
    transport: T,
}

impl<T> ProductionDriver<T> {
    pub fn new(config: ProductionDriverConfig, transport: T) -> Result<Self, DriverError> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T> AcceptanceDriver for ProductionDriver<T>
where
    T: AdapterTransport,
{
    type Error = DriverError;

    fn execute(&mut self, request: &DriverRequest<'_>) -> Result<DriverResponse, Self::Error> {
        if !self.config.binds(request) || !valid_request(request) {
            return Err(DriverError::BindingMismatch);
        }
        let operation_id = operation_id(request)?;
        let control = control_request(request, &operation_id);
        let control_bytes = canonical_json(&control)?;
        let timeout = Duration::from_millis(self.config.timeout_millis);
        let response = self
            .transport
            .exchange(AdapterEndpoint::Control, &control_bytes, timeout)
            .map_err(|_| DriverError::Transport)?;
        let control_response: ControlResponse = parse_bounded(&response)?;
        validate_control_response(&control, &control_response)?;

        let adapter = AdapterRequest {
            schema_version: ADAPTER_REQUEST_SCHEMA.to_owned(),
            sequence: request.sequence,
            operation: request.operation,
            scenario_sha256: request.scenario_sha256.to_owned(),
            operation_id: operation_id.clone(),
            fixture: request.fixture.clone(),
            attempt_id: request.attempt_id.map(str::to_owned),
            expected_controller_generation: request.expected_controller_generation,
            expected_runner_generation: request.expected_runner_generation,
            host: control_response.readback,
        };
        adapter.validate()?;
        let adapter_bytes = canonical_json(&adapter)?;
        let response = self
            .transport
            .exchange(AdapterEndpoint::Controld, &adapter_bytes, timeout)
            .map_err(|_| DriverError::Transport)?;
        let response: AdapterResponse = parse_bounded(&response)?;
        if response.schema_version != ADAPTER_RESPONSE_SCHEMA
            || response.sequence != request.sequence
            || response.operation != request.operation
            || response.scenario_sha256 != request.scenario_sha256
            || response.operation_id != operation_id
            || response.response.schema_version != DRIVER_VERSION
            || response.response.sequence != request.sequence
            || response.response.operation != request.operation
        {
            return Err(DriverError::BindingMismatch);
        }
        validate_snapshot_host(&response.response, &adapter.host)?;
        Ok(response.response)
    }
}

fn control_request(request: &DriverRequest<'_>, operation_id: &str) -> ControlRequest {
    ControlRequest {
        schema_version: CONTROL_REQUEST_SCHEMA.to_owned(),
        sequence: request.sequence,
        operation: match request.operation {
            Operation::SetCapacityOne => ControlOperation::SetCapacityOne,
            Operation::RestartController => ControlOperation::RestartController,
            Operation::RestartRunner => ControlOperation::RestartRunner,
            Operation::SetCapacityZero => ControlOperation::SetCapacityZero,
            _ => ControlOperation::Observe,
        },
        scenario_sha256: request.scenario_sha256.to_owned(),
        operation_id: operation_id.to_owned(),
        activation_id: request.fixture.activation_id.clone(),
        activation_package_digest: request.fixture.activation_package_digest.clone(),
        integrated_candidate_sha: request.fixture.integrated_candidate_sha.clone(),
        run_id: request.fixture.run_id.clone(),
        job_id: request.fixture.job_id.clone(),
        request_digest: request.fixture.request_digest.clone(),
        manifest_digest: request.fixture.manifest_digest.clone(),
        approval_id: request.fixture.approval_id.clone(),
        grant_event_id: request.fixture.grant_event_id.clone(),
        grant_digest: request.fixture.grant_digest.clone(),
        attempt_id: request.attempt_id.map(str::to_owned),
        expected_controller_generation: request.expected_controller_generation,
        expected_runner_generation: request.expected_runner_generation,
    }
}

fn validate_control_response(
    request: &ControlRequest,
    response: &ControlResponse,
) -> Result<(), DriverError> {
    if response.schema_version != CONTROL_RESPONSE_SCHEMA
        || response.sequence != request.sequence
        || response.operation != request.operation
        || response.scenario_sha256 != request.scenario_sha256
        || response.operation_id != request.operation_id
        || response.readback.activation_id != request.activation_id
        || response.readback.activation_package_digest != request.activation_package_digest
        || response.readback.integrated_candidate_sha != request.integrated_candidate_sha
        || response.readback.capacity > 1
        || response.readback.controller_generation == 0
        || response.readback.runner_generation == 0
    {
        return Err(DriverError::BindingMismatch);
    }
    if let Some(expected) = request.expected_controller_generation {
        if request.operation != ControlOperation::RestartController
            && response.readback.controller_generation != expected
        {
            return Err(DriverError::StaleGeneration);
        }
        if request.operation == ControlOperation::RestartController
            && response.readback.controller_generation <= expected
        {
            return Err(DriverError::StaleGeneration);
        }
    }
    if let Some(expected) = request.expected_runner_generation {
        if request.operation != ControlOperation::RestartRunner
            && response.readback.runner_generation != expected
        {
            return Err(DriverError::StaleGeneration);
        }
        if request.operation == ControlOperation::RestartRunner
            && response.readback.runner_generation <= expected
        {
            return Err(DriverError::StaleGeneration);
        }
    }
    Ok(())
}

fn validate_snapshot_host(
    response: &DriverResponse,
    host: &ControlReadback,
) -> Result<(), DriverError> {
    if response.snapshot.capacity != host.capacity
        || response.snapshot.admission != host.admission
        || response.snapshot.controller_generation != host.controller_generation
        || response.snapshot.runner_generation != host.runner_generation
    {
        return Err(DriverError::BindingMismatch);
    }
    Ok(())
}

fn valid_request(request: &DriverRequest<'_>) -> bool {
    let fixture = request.fixture;
    expected_operation(request.sequence) == Some(request.operation)
        && lower_hex(request.scenario_sha256, &[64])
        && valid_name(&fixture.activation_id, 128)
        && lower_hex(&fixture.activation_package_digest, &[64])
        && lower_hex(&fixture.integrated_candidate_sha, &[40, 64])
        && lower_hex(&fixture.run_id, &[32])
        && valid_name(&fixture.job_id, 64)
        && lower_hex(&fixture.request_digest, &[64])
        && lower_hex(&fixture.manifest_digest, &[64])
        && lower_hex(&fixture.source_oid, &[40, 64])
        && lower_hex(&fixture.approval_id, &[32])
        && lower_hex(&fixture.grant_event_id, &[64])
        && lower_hex(&fixture.grant_digest, &[64])
        && lower_hex(&fixture.approved_by, &[64])
        && lower_hex(&fixture.export_subject, &[64])
        && lower_hex(&fixture.export_authorization_digest, &[64])
        && fixture.controller_generation > 0
        && fixture.runner_generation > 0
        && request
            .attempt_id
            .is_none_or(|value| lower_hex(value, &[32]))
        && match request.sequence {
            6..=10 => request.attempt_id.is_some(),
            _ => request.attempt_id.is_none(),
        }
        && match (request.sequence, request.expected_controller_generation) {
            (1, None) => true,
            (1, Some(_)) | (_, None) => false,
            (_, Some(value)) => value > 0,
        }
        && match (request.sequence, request.expected_runner_generation) {
            (1, None) => true,
            (1, Some(_)) | (_, None) => false,
            (_, Some(value)) => value > 0,
        }
}

fn expected_operation(sequence: u32) -> Option<Operation> {
    Some(match sequence {
        1 => Operation::ObserveInitial,
        2 => Operation::SetCapacityOne,
        3 => Operation::SubmitManifest,
        4 => Operation::ApproveGrant,
        5 => Operation::ResumeGrant,
        6 => Operation::AwaitFirstTerminal,
        7 => Operation::ExportFirstEvidence,
        8 => Operation::Rerun,
        9 => Operation::CancelRerun,
        10 => Operation::TombstoneRerun,
        11 => Operation::RestartController,
        12 => Operation::RestartRunner,
        13 => Operation::SetCapacityZero,
        _ => return None,
    })
}

fn operation_id(request: &DriverRequest<'_>) -> Result<String, DriverError> {
    digest_operation_id(
        request.scenario_sha256,
        request.sequence,
        request.operation,
        &request.fixture.run_id,
        &request.fixture.job_id,
        request.attempt_id,
    )
}

/// Recompute the operation ID that a controld acceptance server must require.
pub fn expected_adapter_operation_id(request: &AdapterRequest) -> Result<String, DriverError> {
    digest_operation_id(
        &request.scenario_sha256,
        request.sequence,
        request.operation,
        &request.fixture.run_id,
        &request.fixture.job_id,
        request.attempt_id.as_deref(),
    )
}

fn digest_operation_id(
    scenario_sha256: &str,
    sequence: u32,
    operation: Operation,
    run_id: &str,
    job_id: &str,
    attempt_id: Option<&str>,
) -> Result<String, DriverError> {
    let mut digest = Sha256::new();
    digest.update(b"buzz-ci-capacity-one-operation-v1\0");
    digest.update(scenario_sha256.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(canonical_json(&operation)?);
    digest.update(run_id.as_bytes());
    digest.update(job_id.as_bytes());
    if let Some(attempt_id) = attempt_id {
        digest.update(attempt_id.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

fn control_operation_id(request: &ControlRequest) -> Result<String, ControlError> {
    let operation = expected_operation(request.sequence).ok_or(ControlError::BindingMismatch)?;
    let mut digest = Sha256::new();
    digest.update(b"buzz-ci-capacity-one-operation-v1\0");
    digest.update(request.scenario_sha256.as_bytes());
    digest.update(request.sequence.to_be_bytes());
    digest.update(serde_json::to_vec(&operation).map_err(|_| ControlError::BindingMismatch)?);
    digest.update(request.run_id.as_bytes());
    digest.update(request.job_id.as_bytes());
    if let Some(attempt_id) = &request.attempt_id {
        digest.update(attempt_id.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

/// Production Unix socket transport with peer-credential checks and byte bounds.
pub struct UnixAdapterTransport {
    config: ProductionDriverConfig,
}

impl UnixAdapterTransport {
    pub fn new(config: ProductionDriverConfig) -> Self {
        Self { config }
    }
}

impl AdapterTransport for UnixAdapterTransport {
    type Error = DriverError;

    fn exchange(
        &mut self,
        endpoint: AdapterEndpoint,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Self::Error> {
        if request.len() > MAX_ADAPTER_FRAME_BYTES {
            return Err(DriverError::FrameTooLarge);
        }
        let (path, uid, gid) = match endpoint {
            AdapterEndpoint::Control => (&self.config.control_socket, 0, 0),
            AdapterEndpoint::Controld => (
                &self.config.controld_socket,
                self.config.controld_uid,
                self.config.controld_gid,
            ),
        };
        exchange_unix(
            path,
            self.config.qualification_gid,
            uid,
            gid,
            request,
            timeout,
        )
    }
}

#[cfg(target_os = "linux")]
fn exchange_unix(
    path: &Path,
    expected_socket_gid: u32,
    expected_uid: u32,
    expected_gid: u32,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DriverError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::fs::FileTypeExt;

    let metadata = fs::symlink_metadata(path).map_err(|_| DriverError::Transport)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_socket_gid
        || metadata.permissions().mode() & 0o7777 != 0o620
    {
        return Err(DriverError::WrongPeer);
    }
    let mut stream = UnixStream::connect(path).map_err(|_| DriverError::Transport)?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(|_| DriverError::WrongPeer)?;
    if peer.uid() != expected_uid || peer.gid() != expected_gid {
        return Err(DriverError::WrongPeer);
    }
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| DriverError::Transport)?;
    stream
        .write_all(request)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|_| DriverError::Transport)?;
    let mut response = Vec::new();
    stream
        .take(MAX_ADAPTER_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .map_err(|_| DriverError::Transport)?;
    if response.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(DriverError::FrameTooLarge);
    }
    Ok(response)
}

#[cfg(not(target_os = "linux"))]
fn exchange_unix(
    _path: &Path,
    _expected_socket_gid: u32,
    _expected_uid: u32,
    _expected_gid: u32,
    _request: &[u8],
    _timeout: Duration,
) -> Result<Vec<u8>, DriverError> {
    Err(DriverError::UnsupportedPlatform)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DriverError> {
    serde_json::to_vec(value).map_err(|_| DriverError::Protocol)
}

fn parse_bounded<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, DriverError> {
    if bytes.is_empty() || bytes.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(DriverError::FrameTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| DriverError::Protocol)
}

fn valid_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

#[cfg(target_os = "linux")]
fn read_secure_file(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, DriverError> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    if !valid_absolute(path) {
        return Err(DriverError::InvalidConfig);
    }
    let before = fs::symlink_metadata(path).map_err(|_| DriverError::InvalidConfig)?;
    if !before.file_type().is_file()
        || before.uid() != uid
        || before.gid() != gid
        || before.permissions().mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.len() > maximum
    {
        return Err(DriverError::InvalidConfig);
    }
    if fs::canonicalize(path).map_err(|_| DriverError::InvalidConfig)? != path {
        return Err(DriverError::InvalidConfig);
    }
    let descriptor = open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DriverError::InvalidConfig)?;
    let file = File::from(descriptor);
    let opened = file.metadata().map_err(|_| DriverError::InvalidConfig)?;
    if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
        return Err(DriverError::InvalidConfig);
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DriverError::InvalidConfig)?;
    if bytes.len() as u64 > maximum {
        return Err(DriverError::InvalidConfig);
    }
    Ok(bytes)
}

/// Sanitized driver failure. No variant includes paths, payloads, or OS details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DriverError {
    #[error("production driver configuration is invalid")]
    InvalidConfig,
    #[error("production driver request binding is invalid")]
    BindingMismatch,
    #[error("production adapter transport is unavailable")]
    Transport,
    #[error("production adapter peer identity is invalid")]
    WrongPeer,
    #[error("production adapter frame exceeds its byte limit")]
    FrameTooLarge,
    #[error("production adapter protocol response is invalid")]
    Protocol,
    #[error("production adapter generation is stale")]
    StaleGeneration,
    #[error("production adapters are supported only on Linux")]
    UnsupportedPlatform,
}

impl DriverError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingMismatch => "binding_mismatch",
            Self::Transport => "transport_unavailable",
            Self::WrongPeer => "wrong_peer",
            Self::FrameTooLarge => "frame_too_large",
            Self::Protocol => "protocol_error",
            Self::StaleGeneration => "stale_generation",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

/// Root helper config. It cannot select programs, units, sockets, or argv.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceControlConfig {
    pub schema_version: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub scenario_sha256: String,
    pub run_id: String,
    pub job_id: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub approval_id: String,
    pub grant_event_id: String,
    pub grant_digest: String,
    pub qualification_uid: u32,
    pub qualification_gid: u32,
    pub controller_generation: u64,
    pub runner_generation: u64,
}

impl AcceptanceControlConfig {
    /// Load the fixed root-owned mode-0400 helper config.
    #[cfg(target_os = "linux")]
    pub fn load(path: &Path) -> Result<Self, ControlError> {
        let bytes = read_secure_file(path, 0, 0, 0o400, MAX_CONFIG_BYTES)
            .map_err(|_| ControlError::InvalidConfig)?;
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::InvalidConfig)?;
        value.validate()?;
        Ok(value)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_path: &Path) -> Result<Self, ControlError> {
        Err(ControlError::InvalidConfig)
    }

    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != CONTROL_CONFIG_SCHEMA
            || self.qualification_uid == 0
            || self.qualification_gid == 0
            || self.controller_generation == 0
            || self.runner_generation == 0
            || !valid_name(&self.activation_id, 128)
            || !lower_hex(&self.activation_package_digest, &[64])
            || !lower_hex(&self.integrated_candidate_sha, &[40, 64])
            || !lower_hex(&self.scenario_sha256, &[64])
            || !lower_hex(&self.run_id, &[32])
            || !valid_name(&self.job_id, 64)
            || !lower_hex(&self.request_digest, &[64])
            || !lower_hex(&self.manifest_digest, &[64])
            || !lower_hex(&self.approval_id, &[32])
            || !lower_hex(&self.grant_event_id, &[64])
            || !lower_hex(&self.grant_digest, &[64])
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(())
    }

    pub fn binds(&self, request: &ControlRequest) -> bool {
        request.schema_version == CONTROL_REQUEST_SCHEMA
            && request.scenario_sha256 == self.scenario_sha256
            && request.activation_id == self.activation_id
            && request.activation_package_digest == self.activation_package_digest
            && request.integrated_candidate_sha == self.integrated_candidate_sha
            && request.run_id == self.run_id
            && request.job_id == self.job_id
            && request.request_digest == self.request_digest
            && request.manifest_digest == self.manifest_digest
            && request.approval_id == self.approval_id
            && request.grant_event_id == self.grant_event_id
            && request.grant_digest == self.grant_digest
    }

    pub fn response(&self, request: &ControlRequest, readback: ControlReadback) -> ControlResponse {
        ControlResponse {
            schema_version: CONTROL_RESPONSE_SCHEMA.to_owned(),
            sequence: request.sequence,
            operation: request.operation,
            scenario_sha256: request.scenario_sha256.clone(),
            operation_id: request.operation_id.clone(),
            readback,
        }
    }
}

/// Root helper host action boundary. Tests inject a fake implementation.
pub trait HostControl {
    type Error;

    fn observe(&mut self) -> Result<ControlReadback, Self::Error>;
    fn set_capacity_one(&mut self) -> Result<ControlReadback, Self::Error>;
    fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error>;
    fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error>;
    fn set_capacity_zero(&mut self) -> Result<ControlReadback, Self::Error>;
}

/// Fixed systemd-backed host control. Unit names and the executable are not configurable.
pub struct SystemdHostControl {
    config: AcceptanceControlConfig,
    controller_invocation: String,
    runner_invocation: String,
    controller_generation: u64,
    runner_generation: u64,
    timeout: Duration,
}

impl SystemdHostControl {
    pub fn open(config: AcceptanceControlConfig) -> Result<Self, ControlError> {
        validate_activation_receipt(&config)?;
        let timeout = Duration::from_secs(30);
        let controller_invocation = unit_invocation_optional("buzz-ci-controld.service", timeout)?;
        let runner_invocation = unit_invocation_optional("buzz-ci-runner.service", timeout)?;
        Ok(Self {
            controller_generation: config.controller_generation,
            runner_generation: config.runner_generation,
            config,
            controller_invocation,
            runner_invocation,
            timeout,
        })
    }

    fn readback(&self) -> Result<ControlReadback, ControlError> {
        validate_activation_receipt(&self.config)?;
        let target = unit_active("buzz-ci-capacity-one.target", self.timeout)?;
        let controller = unit_active("buzz-ci-controld.service", self.timeout)?;
        let runner = unit_active("buzz-ci-runner.socket", self.timeout)?;
        let execd = unit_active("buzz-ci-execd.socket", self.timeout)?;
        let keyholder = unit_active("buzz-ci-keyholder.socket", self.timeout)?;
        let capacity = u32::from(target);
        let admission = if target && controller && runner && execd && keyholder {
            AdmissionState::Open
        } else {
            AdmissionState::Closed
        };
        if capacity == 1 && admission != AdmissionState::Open {
            return Err(ControlError::ReadbackMismatch);
        }
        Ok(ControlReadback {
            activation_id: self.config.activation_id.clone(),
            activation_package_digest: self.config.activation_package_digest.clone(),
            integrated_candidate_sha: self.config.integrated_candidate_sha.clone(),
            capacity,
            admission,
            controller_generation: self.controller_generation,
            runner_generation: self.runner_generation,
        })
    }

    fn systemctl(&self, action: &'static str, unit: &'static str) -> Result<(), ControlError> {
        let output = run_bounded_command("/usr/bin/systemctl", &[action, unit], self.timeout)?;
        if output.is_empty() {
            Ok(())
        } else {
            Err(ControlError::HostAction)
        }
    }

    fn close_capacity(&self) -> Result<(), ControlError> {
        for unit in [
            "buzz-ci-capacity-one.target",
            "buzz-ci-controld.service",
            "buzz-ci-runner.service",
            "buzz-ci-runner.socket",
            "buzz-ci-execd.service",
            "buzz-ci-execd.socket",
            "buzz-ci-keyholder.service",
            "buzz-ci-keyholder.socket",
        ] {
            self.systemctl("stop", unit)?;
        }
        Ok(())
    }
}

impl HostControl for SystemdHostControl {
    type Error = ControlError;

    fn observe(&mut self) -> Result<ControlReadback, Self::Error> {
        self.readback()
    }

    fn set_capacity_one(&mut self) -> Result<ControlReadback, Self::Error> {
        self.systemctl("start", "buzz-ci-capacity-one.target")?;
        let readback = self.readback()?;
        if readback.capacity != 1 || readback.admission != AdmissionState::Open {
            let _ = self.close_capacity();
            return Err(ControlError::ReadbackMismatch);
        }
        Ok(readback)
    }

    fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error> {
        let before = unit_invocation("buzz-ci-controld.service", self.timeout)?;
        self.systemctl("restart", "buzz-ci-controld.service")?;
        let invocation = unit_invocation("buzz-ci-controld.service", self.timeout)?;
        if invocation == before
            || (!self.controller_invocation.is_empty() && invocation == self.controller_invocation)
        {
            let _ = self.close_capacity();
            return Err(ControlError::StaleGeneration);
        }
        self.controller_invocation = invocation;
        self.controller_generation = self
            .controller_generation
            .checked_add(1)
            .ok_or(ControlError::StaleGeneration)?;
        self.readback()
    }

    fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error> {
        let before = unit_invocation("buzz-ci-runner.service", self.timeout)?;
        self.systemctl("restart", "buzz-ci-runner.service")?;
        let invocation = unit_invocation("buzz-ci-runner.service", self.timeout)?;
        if invocation == before
            || (!self.runner_invocation.is_empty() && invocation == self.runner_invocation)
        {
            let _ = self.close_capacity();
            return Err(ControlError::StaleGeneration);
        }
        self.runner_invocation = invocation;
        self.runner_generation = self
            .runner_generation
            .checked_add(1)
            .ok_or(ControlError::StaleGeneration)?;
        self.readback()
    }

    fn set_capacity_zero(&mut self) -> Result<ControlReadback, Self::Error> {
        self.close_capacity()?;
        let readback = self.readback()?;
        if readback.capacity != 0 || readback.admission != AdmissionState::Closed {
            return Err(ControlError::ReadbackMismatch);
        }
        Ok(readback)
    }
}

fn validate_activation_receipt(config: &AcceptanceControlConfig) -> Result<(), ControlError> {
    let bytes = read_secure_file(
        Path::new(ACTIVATION_RECEIPT_PATH),
        0,
        0,
        0o600,
        MAX_CONFIG_BYTES,
    )
    .map_err(|_| ControlError::InvalidConfig)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::InvalidConfig)?;
    if value.get("activation_id").and_then(|item| item.as_str()) != Some(&config.activation_id)
        || value.get("package_digest").and_then(|item| item.as_str())
            != Some(&config.activation_package_digest)
        || value.get("source_commit").and_then(|item| item.as_str())
            != Some(&config.integrated_candidate_sha)
        || !matches!(
            value.get("state").and_then(|item| item.as_str()),
            Some("staged_zero" | "activating" | "active_one")
        )
    {
        return Err(ControlError::BindingMismatch);
    }
    Ok(())
}

fn unit_active(unit: &'static str, timeout: Duration) -> Result<bool, ControlError> {
    let output = run_bounded_command(
        "/usr/bin/systemctl",
        &["show", "--property=ActiveState", "--value", unit],
        timeout,
    )?;
    match output.as_slice() {
        b"active\n" => Ok(true),
        b"inactive\n" | b"failed\n" => Ok(false),
        _ => Err(ControlError::ReadbackMismatch),
    }
}

fn unit_invocation(unit: &'static str, timeout: Duration) -> Result<String, ControlError> {
    let output = run_bounded_command(
        "/usr/bin/systemctl",
        &["show", "--property=InvocationID", "--value", unit],
        timeout,
    )?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| ControlError::ReadbackMismatch)?
        .trim();
    if lower_hex(value, &[32]) {
        Ok(value.to_owned())
    } else {
        Err(ControlError::ReadbackMismatch)
    }
}

fn unit_invocation_optional(unit: &'static str, timeout: Duration) -> Result<String, ControlError> {
    let output = run_bounded_command(
        "/usr/bin/systemctl",
        &["show", "--property=InvocationID", "--value", unit],
        timeout,
    )?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| ControlError::ReadbackMismatch)?
        .trim();
    if value.is_empty() || lower_hex(value, &[32]) {
        Ok(value.to_owned())
    } else {
        Err(ControlError::ReadbackMismatch)
    }
}

fn run_bounded_command(
    program: &'static str,
    args: &[&'static str],
    timeout: Duration,
) -> Result<Vec<u8>, ControlError> {
    const MAX_OUTPUT: usize = 64 * 1024;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ControlError::HostAction)?;
    let stdout = child.stdout.take().ok_or(ControlError::HostAction)?;
    let stderr = child.stderr.take().ok_or(ControlError::HostAction)?;
    let stdout_reader = thread::spawn(move || read_process_output(stdout, MAX_OUTPUT));
    let stderr_reader = thread::spawn(move || read_process_output(stderr, MAX_OUTPUT));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|_| ControlError::HostAction)? {
            Some(value) => break value,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ControlError::HostAction);
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ControlError::HostAction)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ControlError::HostAction)??;
    if !status.success() || !stderr.is_empty() {
        return Err(ControlError::HostAction);
    }
    Ok(stdout)
}

fn read_process_output(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>, ControlError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ControlError::HostAction)?;
    if bytes.len() > maximum {
        return Err(ControlError::HostAction);
    }
    Ok(bytes)
}

/// Validate and execute one root-helper request.
pub fn handle_control<H: HostControl>(
    config: &AcceptanceControlConfig,
    request: &ControlRequest,
    host: &mut H,
) -> Result<ControlResponse, ControlError> {
    config.validate()?;
    let bound_operation_id = control_operation_id(request)?;
    if !config.binds(request)
        || !(1..=13).contains(&request.sequence)
        || expected_control_operation(request.sequence) != Some(request.operation)
        || bound_operation_id != request.operation_id
        || !lower_hex(&request.operation_id, &[64])
        || !lower_hex(&request.run_id, &[32])
        || !valid_name(&request.job_id, 64)
        || !lower_hex(&request.request_digest, &[64])
        || !lower_hex(&request.manifest_digest, &[64])
        || !lower_hex(&request.approval_id, &[32])
        || !lower_hex(&request.grant_event_id, &[64])
        || !lower_hex(&request.grant_digest, &[64])
        || request
            .attempt_id
            .as_deref()
            .is_some_and(|value| !lower_hex(value, &[32]))
    {
        return Err(ControlError::BindingMismatch);
    }
    let readback = match request.operation {
        ControlOperation::Observe => host.observe(),
        ControlOperation::SetCapacityOne => host.set_capacity_one(),
        ControlOperation::RestartController => host.restart_controller(),
        ControlOperation::RestartRunner => host.restart_runner(),
        ControlOperation::SetCapacityZero => host.set_capacity_zero(),
    }
    .map_err(|_| ControlError::HostAction)?;
    if readback.activation_id != config.activation_id
        || readback.activation_package_digest != config.activation_package_digest
        || readback.integrated_candidate_sha != config.integrated_candidate_sha
        || readback.capacity > 1
        || readback.controller_generation == 0
        || readback.runner_generation == 0
    {
        return Err(ControlError::ReadbackMismatch);
    }
    if let Some(expected) = request.expected_controller_generation {
        let valid = if request.operation == ControlOperation::RestartController {
            readback.controller_generation > expected
        } else {
            readback.controller_generation == expected
        };
        if !valid {
            return Err(ControlError::StaleGeneration);
        }
    }
    if let Some(expected) = request.expected_runner_generation {
        let valid = if request.operation == ControlOperation::RestartRunner {
            readback.runner_generation > expected
        } else {
            readback.runner_generation == expected
        };
        if !valid {
            return Err(ControlError::StaleGeneration);
        }
    }
    Ok(config.response(request, readback))
}

fn expected_control_operation(sequence: u32) -> Option<ControlOperation> {
    Some(match sequence {
        2 => ControlOperation::SetCapacityOne,
        11 => ControlOperation::RestartController,
        12 => ControlOperation::RestartRunner,
        13 => ControlOperation::SetCapacityZero,
        1 | 3..=10 => ControlOperation::Observe,
        _ => return None,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlLedger {
    schema_version: String,
    entries: BTreeMap<String, ControlLedgerEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlLedgerEntry {
    request_sha256: String,
    response: ControlResponse,
}

/// Execute once per operation ID and durably replay only byte-identical requests.
pub fn handle_control_durable<H: HostControl>(
    config: &AcceptanceControlConfig,
    request_bytes: &[u8],
    host: &mut H,
) -> Result<ControlResponse, ControlError> {
    if request_bytes.is_empty() || request_bytes.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(ControlError::BindingMismatch);
    }
    let request: ControlRequest =
        serde_json::from_slice(request_bytes).map_err(|_| ControlError::BindingMismatch)?;
    let request_sha256 = hex::encode(Sha256::digest(request_bytes));
    let mut ledger = load_control_ledger()?;
    if let Some(existing) = ledger.entries.get(&request.operation_id) {
        return if existing.request_sha256 == request_sha256 {
            Ok(existing.response.clone())
        } else {
            Err(ControlError::ReplayMismatch)
        };
    }
    let response = handle_control(config, &request, host)?;
    ledger.entries.insert(
        request.operation_id.clone(),
        ControlLedgerEntry {
            request_sha256,
            response: response.clone(),
        },
    );
    persist_control_ledger(&ledger)?;
    Ok(response)
}

fn load_control_ledger() -> Result<ControlLedger, ControlError> {
    let path = Path::new(CONTROL_LEDGER_PATH);
    if !path.exists() {
        return Ok(ControlLedger {
            schema_version: "buzz-ci-acceptance-control-ledger/v1".into(),
            entries: BTreeMap::new(),
        });
    }
    let bytes =
        read_secure_file(path, 0, 0, 0o600, MAX_CONFIG_BYTES).map_err(|_| ControlError::Ledger)?;
    let ledger: ControlLedger = serde_json::from_slice(&bytes).map_err(|_| ControlError::Ledger)?;
    if ledger.schema_version != "buzz-ci-acceptance-control-ledger/v1" || ledger.entries.len() > 13
    {
        return Err(ControlError::Ledger);
    }
    Ok(ledger)
}

fn persist_control_ledger(ledger: &ControlLedger) -> Result<(), ControlError> {
    use std::os::unix::fs::OpenOptionsExt;

    if ledger.entries.len() > 13 {
        return Err(ControlError::Ledger);
    }
    let bytes = serde_json::to_vec(ledger).map_err(|_| ControlError::Ledger)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ControlError::Ledger);
    }
    let path = Path::new(CONTROL_LEDGER_PATH);
    let parent = path.parent().ok_or(ControlError::Ledger)?;
    let temporary = parent.join(format!(".operation-ledger-v1.json.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| ControlError::Ledger)?;
    let result = file
        .write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(ControlError::Ledger);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ControlError::Ledger)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    #[error("acceptance control configuration is invalid")]
    InvalidConfig,
    #[error("acceptance control request binding is invalid")]
    BindingMismatch,
    #[error("acceptance host action failed")]
    HostAction,
    #[error("acceptance host readback does not match activation")]
    ReadbackMismatch,
    #[error("acceptance host generation is stale")]
    StaleGeneration,
    #[error("acceptance operation replay differs from the durable request")]
    ReplayMismatch,
    #[error("acceptance control ledger is unavailable")]
    Ledger,
}

impl ControlError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingMismatch => "binding_mismatch",
            Self::HostAction => "host_action_failed",
            Self::ReadbackMismatch => "readback_mismatch",
            Self::StaleGeneration => "stale_generation",
            Self::ReplayMismatch => "replay_mismatch",
            Self::Ledger => "ledger_unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible};

    use super::*;
    use crate::acceptance::{
        run_acceptance, AcceptanceScenario, ApprovalSnapshot, AttemptSnapshot, AttemptState,
        Conclusion, DriverEndpoints, ExportSnapshot, Outcome, ProcessEndpoint, RunSnapshot,
        RunState, SystemSnapshot,
    };

    fn hex(byte: char, length: usize) -> String {
        std::iter::repeat_n(byte, length).collect()
    }

    fn fixture() -> FixtureSpec {
        FixtureSpec {
            integrated_candidate_sha: hex('a', 40),
            activation_id: "buzz-ci-capacity-one-test".into(),
            activation_package_digest: hex('b', 64),
            run_id: hex('c', 32),
            job_id: "fixture".into(),
            request_digest: hex('d', 64),
            manifest_digest: hex('e', 64),
            source_oid: hex('f', 40),
            approval_id: hex('1', 32),
            grant_event_id: hex('2', 64),
            grant_digest: hex('3', 64),
            approved_by: hex('4', 64),
            export_subject: hex('5', 64),
            export_authorization_digest: hex('6', 64),
            controller_generation: 7,
            runner_generation: 9,
            expected_log: crate::acceptance::EvidenceObject {
                name: "job.log".into(),
                sha256: hex('7', 64),
                bytes: 1,
            },
            expected_artifacts: vec![crate::acceptance::EvidenceObject {
                name: "result.json".into(),
                sha256: hex('8', 64),
                bytes: 1,
            }],
        }
    }

    fn config() -> ProductionDriverConfig {
        ProductionDriverConfig {
            schema_version: CONFIG_SCHEMA.into(),
            activation_id: "buzz-ci-capacity-one-test".into(),
            activation_package_digest: hex('b', 64),
            integrated_candidate_sha: hex('a', 40),
            scenario_sha256: hex('9', 64),
            run_id: hex('c', 32),
            job_id: "fixture".into(),
            request_digest: hex('d', 64),
            manifest_digest: hex('e', 64),
            approval_id: hex('1', 32),
            grant_event_id: hex('2', 64),
            grant_digest: hex('3', 64),
            qualification_uid: 1001,
            qualification_gid: 1001,
            controld_uid: 1002,
            controld_gid: 1002,
            control_socket: CONTROL_SOCKET_PATH.into(),
            controld_socket: CONTROLD_SOCKET_PATH.into(),
            timeout_millis: 100,
        }
    }

    fn request<'a>(fixture: &'a FixtureSpec, scenario_sha256: &'a str) -> DriverRequest<'a> {
        DriverRequest {
            schema_version: DRIVER_VERSION,
            scenario_sha256,
            sequence: 2,
            operation: Operation::SetCapacityOne,
            fixture,
            attempt_id: None,
            expected_controller_generation: Some(7),
            expected_runner_generation: Some(9),
        }
    }

    struct FakeTransport {
        replies: VecDeque<Vec<u8>>,
        endpoints: Vec<AdapterEndpoint>,
    }

    impl AdapterTransport for FakeTransport {
        type Error = Infallible;

        fn exchange(
            &mut self,
            endpoint: AdapterEndpoint,
            _request: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, Self::Error> {
            self.endpoints.push(endpoint);
            Ok(self.replies.pop_front().unwrap_or_default())
        }
    }

    #[test]
    fn driver_routes_host_then_controld_and_binds_generations() {
        let fixture = fixture();
        let driver_config = config();
        let request = request(&fixture, &driver_config.scenario_sha256);
        let mut wrong_attempt = request.clone();
        let zero_attempt = "0".repeat(32);
        wrong_attempt.attempt_id = Some(&zero_attempt);
        let transport = FakeTransport {
            replies: VecDeque::new(),
            endpoints: Vec::new(),
        };
        let mut driver = ProductionDriver::new(driver_config.clone(), transport).unwrap();
        assert_eq!(
            driver.execute(&wrong_attempt),
            Err(DriverError::BindingMismatch)
        );

        let operation_id = operation_id(&request).unwrap();
        let host = ControlReadback {
            activation_id: fixture.activation_id.clone(),
            activation_package_digest: fixture.activation_package_digest.clone(),
            integrated_candidate_sha: fixture.integrated_candidate_sha.clone(),
            capacity: 1,
            admission: AdmissionState::Open,
            controller_generation: 7,
            runner_generation: 9,
        };
        let control = ControlResponse {
            schema_version: CONTROL_RESPONSE_SCHEMA.into(),
            sequence: 2,
            operation: ControlOperation::SetCapacityOne,
            scenario_sha256: request.scenario_sha256.into(),
            operation_id: operation_id.clone(),
            readback: host.clone(),
        };
        let driver_response = DriverResponse {
            schema_version: DRIVER_VERSION.into(),
            sequence: 2,
            operation: Operation::SetCapacityOne,
            snapshot: SystemSnapshot {
                capacity: 1,
                admission: AdmissionState::Open,
                active_run_count: 0,
                active_attempt_count: 0,
                controller_generation: 7,
                runner_generation: 9,
                run: None,
            },
            export: None,
        };
        let adapter = AdapterResponse {
            schema_version: ADAPTER_RESPONSE_SCHEMA.into(),
            sequence: 2,
            operation: Operation::SetCapacityOne,
            scenario_sha256: request.scenario_sha256.into(),
            operation_id,
            response: driver_response.clone(),
        };
        let transport = FakeTransport {
            replies: VecDeque::from([
                serde_json::to_vec(&control).unwrap(),
                serde_json::to_vec(&adapter).unwrap(),
            ]),
            endpoints: Vec::new(),
        };
        let mut driver = ProductionDriver::new(driver_config.clone(), transport).unwrap();
        assert_eq!(driver.execute(&request).unwrap(), driver_response);
        assert_eq!(
            driver.into_transport().endpoints,
            [AdapterEndpoint::Control, AdapterEndpoint::Controld]
        );
    }

    #[test]
    fn driver_rejects_wrong_attempt_auth_digest_restart_and_capacity() {
        let fixture = fixture();
        let driver_config = config();
        let mut bad = fixture.clone();
        bad.grant_digest = hex('a', 64);
        let bad_request = request(&bad, &driver_config.scenario_sha256);
        let transport = FakeTransport {
            replies: VecDeque::new(),
            endpoints: Vec::new(),
        };
        let mut driver = ProductionDriver::new(driver_config.clone(), transport).unwrap();
        assert_eq!(
            driver.execute(&bad_request),
            Err(DriverError::BindingMismatch)
        );

        let request = request(&fixture, &driver_config.scenario_sha256);
        let operation_id = operation_id(&request).unwrap();
        let wrong_capacity = ControlResponse {
            schema_version: CONTROL_RESPONSE_SCHEMA.into(),
            sequence: 2,
            operation: ControlOperation::SetCapacityOne,
            scenario_sha256: request.scenario_sha256.into(),
            operation_id,
            readback: ControlReadback {
                activation_id: fixture.activation_id.clone(),
                activation_package_digest: fixture.activation_package_digest.clone(),
                integrated_candidate_sha: fixture.integrated_candidate_sha.clone(),
                capacity: 2,
                admission: AdmissionState::Open,
                controller_generation: 7,
                runner_generation: 9,
            },
        };
        let transport = FakeTransport {
            replies: VecDeque::from([serde_json::to_vec(&wrong_capacity).unwrap()]),
            endpoints: Vec::new(),
        };
        let mut driver = ProductionDriver::new(driver_config.clone(), transport).unwrap();
        assert_eq!(driver.execute(&request), Err(DriverError::BindingMismatch));
    }

    #[test]
    fn control_rejects_stale_restart_generation() {
        struct FakeHost(ControlReadback);
        impl HostControl for FakeHost {
            type Error = Infallible;
            fn observe(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn set_capacity_one(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn set_capacity_zero(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
        }
        let fixture = fixture();
        let driver_config = config();
        let mut base = request(&fixture, &driver_config.scenario_sha256);
        base.sequence = 11;
        base.operation = Operation::RestartController;
        let mut control = control_request(&base, &operation_id(&base).unwrap());
        let control_config = AcceptanceControlConfig {
            schema_version: CONTROL_CONFIG_SCHEMA.into(),
            activation_id: fixture.activation_id.clone(),
            activation_package_digest: fixture.activation_package_digest.clone(),
            integrated_candidate_sha: fixture.integrated_candidate_sha.clone(),
            scenario_sha256: base.scenario_sha256.into(),
            run_id: fixture.run_id.clone(),
            job_id: fixture.job_id.clone(),
            request_digest: fixture.request_digest.clone(),
            manifest_digest: fixture.manifest_digest.clone(),
            approval_id: fixture.approval_id.clone(),
            grant_event_id: fixture.grant_event_id.clone(),
            grant_digest: fixture.grant_digest.clone(),
            qualification_uid: 1001,
            qualification_gid: 1001,
            controller_generation: 7,
            runner_generation: 9,
        };
        let mut host = FakeHost(ControlReadback {
            activation_id: fixture.activation_id,
            activation_package_digest: fixture.activation_package_digest,
            integrated_candidate_sha: fixture.integrated_candidate_sha,
            capacity: 1,
            admission: AdmissionState::Open,
            controller_generation: 7,
            runner_generation: 9,
        });
        assert_eq!(
            handle_control(&control_config, &control, &mut host),
            Err(ControlError::StaleGeneration)
        );

        control.sequence = 2;
        assert_eq!(
            handle_control(&control_config, &control, &mut host),
            Err(ControlError::BindingMismatch)
        );

        control.sequence = 11;
        control.grant_digest = hex('a', 64);
        assert_eq!(
            handle_control(&control_config, &control, &mut host),
            Err(ControlError::BindingMismatch)
        );
    }

    #[test]
    fn terminal_conclusion_names_remain_unmodified() {
        assert_eq!(
            serde_json::to_value(Conclusion::Cancelled).unwrap(),
            "cancelled"
        );
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fault {
        None,
        WrongManifest,
        UnauthenticatedExport,
        StaleRestart,
        BadCapacity,
    }

    struct ScenarioTransport {
        fault: Fault,
    }

    impl AdapterTransport for ScenarioTransport {
        type Error = Infallible;

        fn exchange(
            &mut self,
            endpoint: AdapterEndpoint,
            request: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, Self::Error> {
            Ok(match endpoint {
                AdapterEndpoint::Control => {
                    let request: ControlRequest = serde_json::from_slice(request).unwrap();
                    let (mut capacity, mut controller, runner) = match request.sequence {
                        1 => (0, 7, 9),
                        2..=10 => (1, 7, 9),
                        11 => (1, 8, 9),
                        12 => (1, 8, 10),
                        13 => (0, 8, 10),
                        _ => unreachable!(),
                    };
                    if self.fault == Fault::StaleRestart && request.sequence == 11 {
                        controller = 7;
                    }
                    if self.fault == Fault::BadCapacity && request.sequence == 2 {
                        capacity = 2;
                    }
                    let response = ControlResponse {
                        schema_version: CONTROL_RESPONSE_SCHEMA.into(),
                        sequence: request.sequence,
                        operation: request.operation,
                        scenario_sha256: request.scenario_sha256,
                        operation_id: request.operation_id,
                        readback: ControlReadback {
                            activation_id: request.activation_id,
                            activation_package_digest: request.activation_package_digest,
                            integrated_candidate_sha: request.integrated_candidate_sha,
                            capacity,
                            admission: if capacity == 0 {
                                AdmissionState::Closed
                            } else {
                                AdmissionState::Open
                            },
                            controller_generation: controller,
                            runner_generation: runner,
                        },
                    };
                    serde_json::to_vec(&response).unwrap()
                }
                AdapterEndpoint::Controld => {
                    let request: AdapterRequest = serde_json::from_slice(request).unwrap();
                    let mut response = scripted_driver_response(&request);
                    if self.fault == Fault::WrongManifest && request.sequence == 3 {
                        response.snapshot.run.as_mut().unwrap().manifest_digest = hex('0', 64);
                    }
                    if self.fault == Fault::UnauthenticatedExport && request.sequence == 7 {
                        response.export.as_mut().unwrap().authenticated = false;
                    }
                    serde_json::to_vec(&AdapterResponse {
                        schema_version: ADAPTER_RESPONSE_SCHEMA.into(),
                        sequence: request.sequence,
                        operation: request.operation,
                        scenario_sha256: request.scenario_sha256,
                        operation_id: request.operation_id,
                        response,
                    })
                    .unwrap()
                }
            })
        }
    }

    fn scripted_driver_response(request: &AdapterRequest) -> DriverResponse {
        let fixture = &request.fixture;
        let first_running = attempt(
            fixture,
            'a',
            1,
            None,
            AttemptState::Running,
            Conclusion::None,
            false,
        );
        let first_terminal = attempt(
            fixture,
            'a',
            1,
            None,
            AttemptState::Terminal,
            Conclusion::Success,
            true,
        );
        let second_running = attempt(
            fixture,
            'b',
            2,
            Some('a'),
            AttemptState::Running,
            Conclusion::None,
            false,
        );
        let second_cancelled = attempt(
            fixture,
            'b',
            2,
            Some('a'),
            AttemptState::Terminal,
            Conclusion::Cancelled,
            false,
        );
        let second_tombstoned = attempt(
            fixture,
            'b',
            2,
            Some('a'),
            AttemptState::Tombstoned,
            Conclusion::Cancelled,
            false,
        );
        let approval = |resumed| ApprovalSnapshot {
            approval_id: fixture.approval_id.clone(),
            grant_event_id: fixture.grant_event_id.clone(),
            grant_digest: fixture.grant_digest.clone(),
            approved_by: fixture.approved_by.clone(),
            resumed,
        };
        let run = match request.sequence {
            1 | 2 => None,
            3 => Some(run(
                fixture,
                RunState::AwaitingApproval,
                Conclusion::None,
                None,
                None,
                vec![],
            )),
            4 => Some(run(
                fixture,
                RunState::GrantedAwaitingResume,
                Conclusion::None,
                Some(approval(false)),
                None,
                vec![],
            )),
            5 => Some(run(
                fixture,
                RunState::Running,
                Conclusion::None,
                Some(approval(true)),
                None,
                vec![first_running],
            )),
            6 | 7 => Some(run(
                fixture,
                RunState::Terminal,
                Conclusion::Success,
                Some(approval(true)),
                Some('a'),
                vec![first_terminal],
            )),
            8 => Some(run(
                fixture,
                RunState::Running,
                Conclusion::None,
                Some(approval(true)),
                None,
                vec![first_terminal, second_running],
            )),
            9 => Some(run(
                fixture,
                RunState::Terminal,
                Conclusion::Cancelled,
                Some(approval(true)),
                Some('b'),
                vec![first_terminal, second_cancelled],
            )),
            10..=13 => Some(run(
                fixture,
                RunState::Terminal,
                Conclusion::Success,
                Some(approval(true)),
                Some('a'),
                vec![first_terminal, second_tombstoned],
            )),
            _ => unreachable!(),
        };
        let export = (request.sequence == 7).then(|| ExportSnapshot {
            authenticated: true,
            subject: fixture.export_subject.clone(),
            authorization_digest: fixture.export_authorization_digest.clone(),
            attempt_id: hex('a', 32),
            request_digest: fixture.request_digest.clone(),
            manifest_digest: fixture.manifest_digest.clone(),
            evidence_set_digest: hex('9', 64),
            objects: vec![
                fixture.expected_log.clone(),
                fixture.expected_artifacts[0].clone(),
            ],
        });
        let active = u32::from(matches!(request.sequence, 5 | 8));
        DriverResponse {
            schema_version: DRIVER_VERSION.into(),
            sequence: request.sequence,
            operation: request.operation,
            snapshot: SystemSnapshot {
                capacity: request.host.capacity,
                admission: request.host.admission,
                active_run_count: active,
                active_attempt_count: active,
                controller_generation: request.host.controller_generation,
                runner_generation: request.host.runner_generation,
                run,
            },
            export,
        }
    }

    fn attempt(
        fixture: &FixtureSpec,
        id: char,
        number: u32,
        parent: Option<char>,
        state: AttemptState,
        conclusion: Conclusion,
        evidence: bool,
    ) -> AttemptSnapshot {
        AttemptSnapshot {
            attempt_id: hex(id, 32),
            attempt: number,
            parent_attempt_id: parent.map(|value| hex(value, 32)),
            state,
            conclusion,
            integrated_candidate_sha: fixture.integrated_candidate_sha.clone(),
            request_digest: fixture.request_digest.clone(),
            manifest_digest: fixture.manifest_digest.clone(),
            source_oid: fixture.source_oid.clone(),
            evidence_set_digest: evidence.then(|| hex('9', 64)),
            log: evidence.then(|| fixture.expected_log.clone()),
            artifacts: if evidence {
                fixture.expected_artifacts.clone()
            } else {
                vec![]
            },
        }
    }

    fn run(
        fixture: &FixtureSpec,
        state: RunState,
        conclusion: Conclusion,
        approval: Option<ApprovalSnapshot>,
        selected: Option<char>,
        attempts: Vec<AttemptSnapshot>,
    ) -> RunSnapshot {
        RunSnapshot {
            run_id: fixture.run_id.clone(),
            integrated_candidate_sha: fixture.integrated_candidate_sha.clone(),
            request_digest: fixture.request_digest.clone(),
            manifest_digest: fixture.manifest_digest.clone(),
            source_oid: fixture.source_oid.clone(),
            state,
            aggregate_conclusion: conclusion,
            approval,
            selected_attempt_id: selected.map(|value| hex(value, 32)),
            attempts,
        }
    }

    fn scenario() -> AcceptanceScenario {
        let endpoint = ProcessEndpoint {
            program: DRIVER_PROGRAM.into(),
            args: vec![],
        };
        AcceptanceScenario {
            schema_version: "buzz-ci-capacity-one-scenario/v1".into(),
            fixture: fixture(),
            driver: DriverEndpoints {
                control: endpoint.clone(),
                observe: endpoint.clone(),
                export: endpoint.clone(),
                controller_process: endpoint.clone(),
                runner_process: endpoint,
                timeout_seconds: 5,
            },
        }
    }

    fn run_simulation(fault: Fault) -> crate::acceptance::AcceptanceReceipt {
        let scenario = scenario();
        let scenario_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&scenario).unwrap()));
        let mut config = config();
        config.scenario_sha256 = scenario_sha256;
        let transport = ScenarioTransport { fault };
        let mut driver = ProductionDriver::new(config, transport).unwrap();
        run_acceptance(&scenario, &mut driver)
    }

    #[test]
    fn full_production_adapter_simulation_passes_all_thirteen_stages() {
        let receipt = run_simulation(Fault::None);
        assert_eq!(receipt.outcome, Outcome::Pass);
        assert_eq!(receipt.checks.len(), 13);
    }

    #[test]
    fn simulated_auth_digest_restart_and_capacity_faults_fail_closed() {
        for fault in [
            Fault::WrongManifest,
            Fault::UnauthenticatedExport,
            Fault::StaleRestart,
            Fault::BadCapacity,
        ] {
            assert_eq!(run_simulation(fault).outcome, Outcome::Fail);
        }
    }
}
