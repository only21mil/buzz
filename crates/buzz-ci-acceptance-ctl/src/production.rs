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
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{killpg, Signal},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::acceptance::{
    AcceptanceDriver, AdmissionState, DriverRequest, DriverResponse, FixtureSpec, Operation,
    Outcome, Stage, ZeroOperation, ZeroPhaseReceipt, ZeroPhaseRequest, ZeroPhaseResponse,
    ZeroProof, ZeroRequest, ZeroTransition, DRIVER_VERSION, ZERO_PROOF_VERSION,
    ZERO_REQUEST_VERSION, ZERO_TRANSITION_VERSION,
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
/// Fixed activation controller installed by the package lane.
pub const ACTIVATION_CONTROLLER_PROGRAM: &str = "/usr/libexec/buzz-ci-activation-controller";
/// Immutable active activation package used by the fixed controller.
pub const ACTIVATION_PACKAGE_PATH: &str = "/var/lib/buzzci/activation-controller/package";
/// Root helper configuration.
pub const CONTROL_CONFIG_PATH: &str = "/etc/buzzci/acceptance-control-v1.json";
/// Root activation receipt bound to each helper request.
pub const ACTIVATION_RECEIPT_PATH: &str = "/var/lib/buzzci/activation-controller/receipt-v1.json";
/// Root helper replay ledger.
pub const CONTROL_LEDGER_PATH: &str = "/var/lib/buzzci/acceptance-control/operation-ledger-v1.json";

const EXECD_SERVICE: &str = "buzz-ci-execd.service";
const EXECD_SOCKET: &str = "buzz-ci-execd.socket";
const EXECUTOR_SERVICE: &str = "buzz-ci-executor.service";
const EXECUTOR_SOCKET: &str = "buzz-ci-executor.socket";
const EXECUTOR_SOCKET_PATH: &str = "/run/buzzci/executor.sock";
const EXECUTOR_PROGRAM: &str = "/usr/libexec/buzz-ci-executor";
const EXECUTOR_SERVICE_ACCOUNT: &str = "buzzci-job";

const CONFIG_SCHEMA: &str = "buzz-ci-capacity-one-driver-config/v1";
const CONTROL_CONFIG_SCHEMA: &str = "buzz-ci-acceptance-control-config/v1";
const CAPACITY_ONE_REQUEST_SCHEMA: &str = "buzz-ci-activation-capacity-one-request/v1";
const CAPACITY_ONE_RESPONSE_SCHEMA: &str = "buzz-ci-activation-capacity-one-response/v1";
const QUALIFICATION_ZERO_REQUEST_SCHEMA: &str = "buzz-ci-activation-qualification-zero-request/v1";
const QUALIFICATION_ZERO_RESPONSE_SCHEMA: &str =
    "buzz-ci-activation-qualification-zero-response/v1";
pub const ADAPTER_REQUEST_SCHEMA: &str = "buzz-ci-capacity-one-adapter-request/v1";
pub const ADAPTER_RESPONSE_SCHEMA: &str = "buzz-ci-capacity-one-adapter-response/v1";
pub const CONTROL_REQUEST_SCHEMA: &str = "buzz-ci-acceptance-control-request/v2";
pub const CONTROL_RESPONSE_SCHEMA: &str = "buzz-ci-acceptance-control-response/v2";
const MAX_CONFIG_BYTES: u64 = 128 * 1024;
/// The activation receipt is not a config: on a host that rolled back an
/// earlier activation it embeds the retained controller and package-module
/// payloads as `prior` records, so it is read under the controller's own
/// 1 MiB receipt bound (`activation_package.MAX_JSON_BYTES`).
const MAX_ACTIVATION_RECEIPT_BYTES: u64 = 1024 * 1024;
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

    fn binds_zero(&self, request: &ZeroRequest) -> bool {
        request.schema_version == ZERO_REQUEST_VERSION
            && request.scenario_sha256 == self.scenario_sha256
            && request.activation_id == self.activation_id
            && request.activation_package_digest == self.activation_package_digest
            && request.integrated_candidate_sha == self.integrated_candidate_sha
            && request.run_id == self.run_id
            && request
                .expected_controller_generation
                .is_none_or(|value| value > 0)
            && request
                .expected_runner_generation
                .is_none_or(|value| value > 0)
            && request
                .final_response_sha256
                .as_deref()
                .is_none_or(|value| lower_hex(value, &[64]))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_stage: Option<Stage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_response_sha256: Option<String>,
}

/// Only actions accepted by the root helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOperation {
    Observe,
    SetCapacityOne,
    RestartController,
    RestartRunner,
    PrepareCapacityZero,
    FinalizeCapacityZero,
    ProveCapacityZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CapacityOneAction {
    SetCapacityOne,
}

impl CapacityOneAction {
    const fn argument(self) -> &'static str {
        match self {
            Self::SetCapacityOne => "set-capacity-one",
        }
    }
}

#[derive(Serialize)]
struct CapacityOneRequest<'a> {
    schema_version: &'static str,
    action: CapacityOneAction,
    activation_id: &'a str,
    activation_package_digest: &'a str,
    scenario_sha256: &'a str,
    initial_controller_generation: u64,
    initial_runner_generation: u64,
    operation_id: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacityOneResponse {
    schema_version: String,
    action: CapacityOneAction,
    activation_id: String,
    activation_package_digest: String,
    scenario_sha256: String,
    operation_id: String,
    state: String,
    receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
enum QualificationZeroAction {
    #[serde(rename = "prepare_qualification_zero")]
    Prepare,
    #[serde(rename = "finalize_qualification_zero")]
    Finalize,
    #[serde(rename = "prove_qualification_zero")]
    Prove,
}

impl QualificationZeroAction {
    const fn argument(self) -> &'static str {
        match self {
            Self::Prepare => "prepare-qualification-zero",
            Self::Finalize => "finalize-qualification-zero",
            Self::Prove => "prove-qualification-zero",
        }
    }
}

#[derive(Serialize)]
struct QualificationZeroRequest<'a> {
    schema_version: &'static str,
    action: QualificationZeroAction,
    activation_id: &'a str,
    activation_package_digest: &'a str,
    scenario_sha256: &'a str,
    initial_controller_generation: u64,
    initial_runner_generation: u64,
    operation_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_stage: Option<Stage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_response_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_controller_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_runner_generation: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationZeroResponse {
    schema_version: String,
    action: QualificationZeroAction,
    activation_id: String,
    activation_package_digest: String,
    scenario_sha256: String,
    operation_id: String,
    state: String,
    receipt_sha256: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_proof: Option<ZeroProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_receipt_sha256: Option<String>,
}

pub struct HostZeroResult {
    pub proof: ZeroProof,
    pub controller_receipt_sha256: String,
}

pub struct HostCapacityOneResult {
    pub readback: ControlReadback,
    pub controller_receipt_sha256: String,
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

impl<T: AdapterTransport> ProductionDriver<T> {
    fn exchange_control_retry(
        &mut self,
        request: &ControlRequest,
    ) -> Result<(ControlResponse, u32), DriverError> {
        let bytes = canonical_json(request)?;
        let timeout = Duration::from_millis(self.config.timeout_millis);
        let mut last = DriverError::Transport;
        for attempt in 1..=2 {
            match self
                .transport
                .exchange(AdapterEndpoint::Control, &bytes, timeout)
            {
                Ok(response) => {
                    let response = parse_control_response(&response)?;
                    validate_control_response(request, &response)?;
                    return Ok((response, attempt));
                }
                Err(_) => last = DriverError::Transport,
            }
        }
        Err(last)
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
        let control_response = parse_control_response(&response)?;
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

    fn return_to_zero(&mut self, request: &ZeroRequest) -> Result<ZeroTransition, Self::Error> {
        if !self.config.binds_zero(request) {
            return Err(DriverError::BindingMismatch);
        }
        let finalize = zero_control_request(request, 14, ControlOperation::FinalizeCapacityZero)?;
        let (finalized, finalize_attempts) = self.exchange_control_retry(&finalize)?;
        let finalize_phase = zero_phase_receipt(
            request,
            &finalize,
            finalized,
            ZeroOperation::FinalizeCapacityZero,
            finalize_attempts,
        )?;

        let prove = zero_control_request(request, 15, ControlOperation::ProveCapacityZero)?;
        let (proved, prove_attempts) = self.exchange_control_retry(&prove)?;
        let prove_phase = zero_phase_receipt(
            request,
            &prove,
            proved,
            ZeroOperation::ProveCapacityZero,
            prove_attempts,
        )?;
        Ok(ZeroTransition {
            schema_version: ZERO_TRANSITION_VERSION.to_owned(),
            outcome: Outcome::Pass,
            attempts: 1,
            zero_proof: prove_phase.response.proof.clone(),
            phases: vec![finalize_phase, prove_phase],
        })
    }
}

fn zero_phase_receipt(
    zero: &ZeroRequest,
    control: &ControlRequest,
    response: ControlResponse,
    operation: ZeroOperation,
    attempts: u32,
) -> Result<ZeroPhaseReceipt, DriverError> {
    let proof = response.zero_proof.ok_or(DriverError::BindingMismatch)?;
    validate_zero_response(zero, &proof)?;
    let request = ZeroPhaseRequest {
        sequence: control.sequence,
        operation,
        operation_id: control.operation_id.clone(),
        scenario_sha256: zero.scenario_sha256.clone(),
        activation_id: zero.activation_id.clone(),
        activation_package_digest: zero.activation_package_digest.clone(),
        integrated_candidate_sha: zero.integrated_candidate_sha.clone(),
        failed_stage: zero.failed_stage,
        final_response_sha256: zero.final_response_sha256.clone(),
        expected_controller_generation: zero.expected_controller_generation,
        expected_runner_generation: zero.expected_runner_generation,
    };
    let response = ZeroPhaseResponse {
        operation_id: control.operation_id.clone(),
        controller_receipt_sha256: response
            .controller_receipt_sha256
            .ok_or(DriverError::BindingMismatch)?,
        proof,
    };
    Ok(ZeroPhaseReceipt {
        sequence: control.sequence,
        operation,
        outcome: Outcome::Pass,
        attempts,
        request_sha256: hex::encode(Sha256::digest(canonical_json(&request)?)),
        response_sha256: hex::encode(Sha256::digest(canonical_json(&response)?)),
        request,
        response,
    })
}

fn control_request(request: &DriverRequest<'_>, operation_id: &str) -> ControlRequest {
    ControlRequest {
        schema_version: CONTROL_REQUEST_SCHEMA.to_owned(),
        sequence: request.sequence,
        operation: match request.operation {
            Operation::SetCapacityOne => ControlOperation::SetCapacityOne,
            Operation::RestartController => ControlOperation::RestartController,
            Operation::RestartRunner => ControlOperation::RestartRunner,
            Operation::SetCapacityZero => ControlOperation::PrepareCapacityZero,
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
        failed_stage: None,
        final_response_sha256: None,
    }
}

fn zero_control_request(
    request: &ZeroRequest,
    sequence: u32,
    operation: ControlOperation,
) -> Result<ControlRequest, DriverError> {
    let mut control = ControlRequest {
        schema_version: CONTROL_REQUEST_SCHEMA.to_owned(),
        sequence,
        operation,
        scenario_sha256: request.scenario_sha256.clone(),
        operation_id: String::new(),
        activation_id: request.activation_id.clone(),
        activation_package_digest: request.activation_package_digest.clone(),
        integrated_candidate_sha: request.integrated_candidate_sha.clone(),
        run_id: request.run_id.clone(),
        job_id: "qualification-zero".to_owned(),
        request_digest: self_digest(&request.run_id),
        manifest_digest: self_digest(&request.scenario_sha256),
        approval_id: self_digest(&request.activation_id)[..32].to_owned(),
        grant_event_id: self_digest(&request.activation_package_digest),
        grant_digest: self_digest(&request.integrated_candidate_sha),
        attempt_id: None,
        expected_controller_generation: request.expected_controller_generation,
        expected_runner_generation: request.expected_runner_generation,
        failed_stage: Some(request.failed_stage),
        final_response_sha256: request.final_response_sha256.clone(),
    };
    control.operation_id = zero_control_operation_id(&control)?;
    Ok(control)
}

fn self_digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn validate_zero_response(request: &ZeroRequest, proof: &ZeroProof) -> Result<(), DriverError> {
    if proof.schema_version != ZERO_PROOF_VERSION
        || proof.scenario_sha256 != request.scenario_sha256
        || proof.activation_id != request.activation_id
        || proof.activation_package_digest != request.activation_package_digest
        || proof.integrated_candidate_sha != request.integrated_candidate_sha
        || proof.capacity != 0
        || proof.admission != AdmissionState::Closed
        || proof.controller_generation == 0
        || proof.runner_generation == 0
        || request
            .expected_controller_generation
            .is_some_and(|expected| proof.controller_generation != expected)
        || request
            .expected_runner_generation
            .is_some_and(|expected| proof.runner_generation != expected)
        || proof.controld_service_active
        || proof.controld_acceptance_socket_active
        || proof.controld_acceptance_socket_present
    {
        return Err(DriverError::BindingMismatch);
    }
    Ok(())
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
    let zero_operation = matches!(
        request.operation,
        ControlOperation::FinalizeCapacityZero | ControlOperation::ProveCapacityZero
    );
    let receipt_operation = zero_operation || request.operation == ControlOperation::SetCapacityOne;
    if zero_operation != response.zero_proof.is_some()
        || receipt_operation != response.controller_receipt_sha256.is_some()
        || response
            .controller_receipt_sha256
            .as_deref()
            .is_some_and(|digest| !lower_hex(digest, &[64]))
    {
        return Err(DriverError::BindingMismatch);
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
    if request.sequence >= 14 {
        return zero_control_operation_id(request).map_err(|_| ControlError::BindingMismatch);
    }
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

fn zero_control_operation_id(request: &ControlRequest) -> Result<String, DriverError> {
    let mut digest = Sha256::new();
    digest.update(b"buzz-ci-capacity-one-zero-operation-v1\0");
    digest.update(request.scenario_sha256.as_bytes());
    digest.update(request.sequence.to_be_bytes());
    digest.update(canonical_json(&request.operation)?);
    digest.update(request.activation_id.as_bytes());
    digest.update(request.activation_package_digest.as_bytes());
    digest.update(request.integrated_candidate_sha.as_bytes());
    digest.update(request.run_id.as_bytes());
    if let Some(stage) = request.failed_stage {
        digest.update(canonical_json(&stage)?);
    }
    if let Some(response) = &request.final_response_sha256 {
        digest.update(response.as_bytes());
    }
    digest.update(
        request
            .expected_controller_generation
            .unwrap_or_default()
            .to_be_bytes(),
    );
    digest.update(
        request
            .expected_runner_generation
            .unwrap_or_default()
            .to_be_bytes(),
    );
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

/// Inode facts of an endpoint socket path, read without following links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketInode {
    pub is_socket: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Accept only the inode the socket unit installs: a socket owned by root with
/// the driver's group and mode `0620`. `/run/buzzci` is root-owned mode `0711`,
/// so only root can place that inode, and `RemoveOnStop=yes` unlinks it when
/// the socket unit stops.
pub const fn socket_inode_accepted(inode: SocketInode, expected_gid: u32) -> bool {
    inode.is_socket && inode.uid == 0 && inode.gid == expected_gid && inode.mode == 0o620
}

/// Credentials the kernel reports to the connecting side. `SO_PEERCRED` names
/// the process that called `listen()`, so a connection through a systemd
/// socket unit reports pid 1 root even though the service that accepts it runs
/// as its own account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerPeer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Accept exactly two listeners: the endpoint service itself, when it bound
/// the socket, or pid 1 as root, when the socket unit bound it. Every other
/// root process, an unmappable pid, and every other identity are rejected.
/// Combined with [`socket_inode_accepted`] on the fixed path this excludes
/// every unprivileged impersonator; root can already replace the service.
pub const fn listener_peer_accepted(
    peer: ListenerPeer,
    expected_uid: u32,
    expected_gid: u32,
) -> bool {
    (peer.uid == expected_uid && peer.gid == expected_gid)
        || (peer.pid == 1 && peer.uid == 0 && peer.gid == 0)
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
    let metadata = fs::symlink_metadata(path).map_err(|_| DriverError::Transport)?;
    let inode = SocketInode {
        is_socket: metadata.file_type().is_socket(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
    };
    if !socket_inode_accepted(inode, expected_socket_gid) {
        return Err(DriverError::WrongPeer);
    }
    let stream = UnixStream::connect(path).map_err(|_| DriverError::Transport)?;
    exchange_connected(stream, expected_uid, expected_gid, request, timeout)
}

#[cfg(target_os = "linux")]
fn exchange_connected(
    mut stream: UnixStream,
    expected_uid: u32,
    expected_gid: u32,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DriverError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let peer = getsockopt(&stream, PeerCredentials).map_err(|_| DriverError::WrongPeer)?;
    let peer = ListenerPeer {
        pid: peer.pid(),
        uid: peer.uid(),
        gid: peer.gid(),
    };
    if !listener_peer_accepted(peer, expected_uid, expected_gid) {
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
        let core = request.schema_version == CONTROL_REQUEST_SCHEMA
            && request.scenario_sha256 == self.scenario_sha256
            && request.activation_id == self.activation_id
            && request.activation_package_digest == self.activation_package_digest
            && request.integrated_candidate_sha == self.integrated_candidate_sha
            && request.run_id == self.run_id;
        core && if request.sequence >= 14 {
            true
        } else {
            request.job_id == self.job_id
                && request.request_digest == self.request_digest
                && request.manifest_digest == self.manifest_digest
                && request.approval_id == self.approval_id
                && request.grant_event_id == self.grant_event_id
                && request.grant_digest == self.grant_digest
        }
    }

    pub fn response(
        &self,
        request: &ControlRequest,
        readback: ControlReadback,
        zero_proof: Option<ZeroProof>,
        controller_receipt_sha256: Option<String>,
    ) -> ControlResponse {
        ControlResponse {
            schema_version: CONTROL_RESPONSE_SCHEMA.to_owned(),
            sequence: request.sequence,
            operation: request.operation,
            scenario_sha256: request.scenario_sha256.clone(),
            operation_id: request.operation_id.clone(),
            readback,
            zero_proof,
            controller_receipt_sha256,
        }
    }
}

/// Root helper host action boundary. Tests inject a fake implementation.
pub trait HostControl {
    type Error;

    fn observe(&mut self) -> Result<ControlReadback, Self::Error>;
    fn set_capacity_one(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostCapacityOneResult, Self::Error>;
    fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error>;
    fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error>;
    fn prepare_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<ControlReadback, Self::Error>;
    fn finalize_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostZeroResult, Self::Error>;
    fn prove_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostZeroResult, Self::Error>;
    fn emergency_capacity_zero(&mut self) -> Result<ZeroProof, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnitState {
    Active,
    Inactive,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    executable: PathBuf,
    arguments: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    uid: u32,
    gid: u32,
    mode: u32,
}

trait CapacityOneRuntime {
    fn activate(&mut self, input: &[u8], timeout: Duration) -> Result<Vec<u8>, ControlError>;
    fn unit_state(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<UnitState, ControlError>;
    fn invocation(&mut self, unit: &'static str, timeout: Duration)
        -> Result<String, ControlError>;
    fn optional_invocation(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError>;
    fn fragment_path(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError>;
    fn load_state(&mut self, unit: &'static str, timeout: Duration)
        -> Result<String, ControlError>;
    fn sub_state(&mut self, unit: &'static str, timeout: Duration) -> Result<String, ControlError>;
    fn main_pid(&mut self, unit: &'static str, timeout: Duration) -> Result<u32, ControlError>;
    fn process_identity(
        &mut self,
        pid: u32,
        timeout: Duration,
    ) -> Result<ProcessIdentity, ControlError>;
    fn service_account(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<(String, String, String), ControlError>;
    fn executor_socket_identity(
        &mut self,
        timeout: Duration,
    ) -> Result<SocketIdentity, ControlError>;
    fn active_receipt_sha256(
        &mut self,
        config: &AcceptanceControlConfig,
    ) -> Result<String, ControlError>;
    fn prove_qualified_receipt(
        &mut self,
        config: &AcceptanceControlConfig,
    ) -> Result<(), ControlError>;
}

struct LiveCapacityOneRuntime {
    systemctl: Systemctl,
}

impl CapacityOneRuntime for LiveCapacityOneRuntime {
    fn activate(&mut self, input: &[u8], timeout: Duration) -> Result<Vec<u8>, ControlError> {
        run_bounded_controller(CapacityOneAction::SetCapacityOne.argument(), input, timeout)
    }

    fn unit_state(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<UnitState, ControlError> {
        self.systemctl.unit_state(unit, timeout)
    }

    fn invocation(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        self.systemctl.unit_invocation(unit, timeout)
    }

    fn optional_invocation(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        self.systemctl.unit_invocation_optional(unit, timeout)
    }

    fn fragment_path(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        self.systemctl.unit_fragment_path(unit, timeout)
    }

    fn load_state(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        self.systemctl.unit_property(unit, "LoadState", timeout)
    }

    fn sub_state(&mut self, unit: &'static str, timeout: Duration) -> Result<String, ControlError> {
        self.systemctl.unit_property(unit, "SubState", timeout)
    }

    fn main_pid(&mut self, unit: &'static str, timeout: Duration) -> Result<u32, ControlError> {
        self.systemctl.unit_main_pid(unit, timeout)
    }

    fn process_identity(
        &mut self,
        pid: u32,
        _timeout: Duration,
    ) -> Result<ProcessIdentity, ControlError> {
        live_process_identity(pid)
    }

    fn service_account(
        &mut self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<(String, String, String), ControlError> {
        Ok((
            self.systemctl.unit_property(unit, "User", timeout)?,
            self.systemctl.unit_property(unit, "Group", timeout)?,
            self.systemctl
                .unit_property(unit, "SupplementaryGroups", timeout)?,
        ))
    }

    fn executor_socket_identity(
        &mut self,
        _timeout: Duration,
    ) -> Result<SocketIdentity, ControlError> {
        live_socket_identity(Path::new(EXECUTOR_SOCKET_PATH))
    }

    fn active_receipt_sha256(
        &mut self,
        config: &AcceptanceControlConfig,
    ) -> Result<String, ControlError> {
        active_activation_receipt_sha256(config)
    }

    fn prove_qualified_receipt(
        &mut self,
        config: &AcceptanceControlConfig,
    ) -> Result<(), ControlError> {
        validate_activation_receipt_state(config, "qualified_closed")
    }
}

struct CapacityOneTransition {
    result: HostCapacityOneResult,
    controller_invocation: String,
    runner_invocation: String,
}

/// InvocationIDs the staged services carry before capacity one starts them.
///
/// systemd 259 keeps the InvocationID of a stopped service until its next stop
/// job, so after the closed qualification `buzz-ci-execd.service` is
/// `inactive`/`dead` with `MainPID=0` and a non-empty id. A retained id is not a
/// live process. Staleness is proven twice: now, by `SubState=dead` and
/// `MainPID=0`; and after the controller ran, by every service reporting an id
/// that differs from the retained one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RetainedInvocations {
    runner: String,
    execd: String,
    executor: String,
    keyholder: String,
}

fn retained_staged_invocations<R: CapacityOneRuntime>(
    runtime: &mut R,
    timeout: Duration,
) -> Result<RetainedInvocations, ControlError> {
    let mut retained = RetainedInvocations::default();
    for (unit, slot) in [
        ("buzz-ci-runner.service", &mut retained.runner),
        (EXECD_SERVICE, &mut retained.execd),
        (EXECUTOR_SERVICE, &mut retained.executor),
        ("buzz-ci-keyholder.service", &mut retained.keyholder),
    ] {
        if runtime.sub_state(unit, timeout)? != "dead" || runtime.main_pid(unit, timeout)? != 0 {
            return Err(ControlError::StaleGeneration);
        }
        *slot = runtime.optional_invocation(unit, timeout)?;
    }
    Ok(retained)
}

/// Healthy sub-states of an `Accept=no` socket unit at capacity one.
///
/// systemd reports `listening` while only the socket is up and `running` once
/// the service it triggers is active (the H6 clean host: `buzz-ci-execd.socket
/// ... ActiveState=active SubState=running`). Both mean the listener is bound
/// and serviceable. `failed`, `dead`, and every other value stay rejected.
fn accept_no_socket_is_healthy(sub_state: &str) -> bool {
    matches!(sub_state, "listening" | "running")
}

fn activate_capacity_one<R: CapacityOneRuntime>(
    config: &AcceptanceControlConfig,
    request: &ControlRequest,
    staged_controller_invocation: &str,
    staged_runner_invocation: &str,
    timeout: Duration,
    runtime: &mut R,
) -> Result<CapacityOneTransition, ControlError> {
    if request.sequence != 2
        || request.operation != ControlOperation::SetCapacityOne
        || request.expected_controller_generation != Some(config.controller_generation)
        || request.expected_runner_generation != Some(config.runner_generation)
        || !lower_hex(staged_controller_invocation, &[32])
        || !(staged_runner_invocation.is_empty() || lower_hex(staged_runner_invocation, &[32]))
    {
        return Err(ControlError::BindingMismatch);
    }
    runtime.prove_qualified_receipt(config)?;
    for unit in [
        "buzz-ci-controld.service",
        "buzz-ci-controld-acceptance.socket",
        "buzz-ci-acceptance-control.socket",
        "buzz-ci-acceptance-control.service",
    ] {
        if runtime.unit_state(unit, timeout)? != UnitState::Active {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    for unit in [
        "buzz-ci-capacity-one.target",
        "buzz-ci-runner.service",
        "buzz-ci-runner.socket",
        EXECD_SERVICE,
        EXECD_SOCKET,
        EXECUTOR_SERVICE,
        EXECUTOR_SOCKET,
        "buzz-ci-keyholder.service",
        "buzz-ci-keyholder.socket",
    ] {
        if runtime.unit_state(unit, timeout)? != UnitState::Inactive {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    if runtime.invocation("buzz-ci-controld.service", timeout)? != staged_controller_invocation {
        return Err(ControlError::StaleGeneration);
    }
    let retained = retained_staged_invocations(runtime, timeout)?;

    let body = CapacityOneRequest {
        schema_version: CAPACITY_ONE_REQUEST_SCHEMA,
        action: CapacityOneAction::SetCapacityOne,
        activation_id: &request.activation_id,
        activation_package_digest: &request.activation_package_digest,
        scenario_sha256: &request.scenario_sha256,
        initial_controller_generation: config.controller_generation,
        initial_runner_generation: config.runner_generation,
        operation_id: &request.operation_id,
    };
    let input = serde_json::to_vec(&body).map_err(|_| ControlError::HostAction)?;
    let output = runtime.activate(&input, timeout)?;
    let response_bytes = output
        .strip_suffix(b"\n")
        .ok_or(ControlError::BindingMismatch)?;
    let response: CapacityOneResponse =
        serde_json::from_slice(response_bytes).map_err(|_| ControlError::BindingMismatch)?;
    if serde_json::to_vec(&response).map_err(|_| ControlError::HostAction)? != response_bytes
        || response.schema_version != CAPACITY_ONE_RESPONSE_SCHEMA
        || response.action != CapacityOneAction::SetCapacityOne
        || response.activation_id != request.activation_id
        || response.activation_package_digest != request.activation_package_digest
        || response.scenario_sha256 != request.scenario_sha256
        || response.operation_id != request.operation_id
        || response.state != "active_one"
        || !lower_hex(&response.receipt_sha256, &[64])
        || runtime.active_receipt_sha256(config)? != response.receipt_sha256
    {
        return Err(ControlError::BindingMismatch);
    }

    for unit in [
        "buzz-ci-capacity-one.target",
        "buzz-ci-controld.service",
        "buzz-ci-controld-acceptance.socket",
        "buzz-ci-acceptance-control.socket",
        "buzz-ci-acceptance-control.service",
        "buzz-ci-runner.service",
        "buzz-ci-runner.socket",
        EXECD_SERVICE,
        EXECD_SOCKET,
        EXECUTOR_SERVICE,
        EXECUTOR_SOCKET,
        "buzz-ci-keyholder.service",
        "buzz-ci-keyholder.socket",
    ] {
        if runtime.unit_state(unit, timeout)? != UnitState::Active {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    for (unit, expected) in [
        (
            "buzz-ci-capacity-one.target",
            "/etc/systemd/system/buzz-ci-capacity-one.target",
        ),
        (
            "buzz-ci-controld.service",
            "/etc/systemd/system/buzz-ci-controld.service",
        ),
        (
            "buzz-ci-runner.socket",
            "/etc/systemd/system/buzz-ci-runner.socket",
        ),
        (EXECD_SOCKET, "/usr/lib/systemd/system/buzz-ci-execd.socket"),
        (
            "buzz-ci-keyholder.socket",
            "/etc/systemd/system/buzz-ci-keyholder.socket",
        ),
        (
            EXECD_SERVICE,
            "/usr/lib/systemd/system/buzz-ci-execd.service",
        ),
        (
            EXECUTOR_SERVICE,
            "/usr/lib/systemd/system/buzz-ci-executor.service",
        ),
        (
            EXECUTOR_SOCKET,
            "/usr/lib/systemd/system/buzz-ci-executor.socket",
        ),
    ] {
        if runtime.fragment_path(unit, timeout)? != expected {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    let controller_invocation = runtime.invocation("buzz-ci-controld.service", timeout)?;
    let runner_invocation = runtime.invocation("buzz-ci-runner.service", timeout)?;
    for unit in [
        EXECD_SERVICE,
        EXECD_SOCKET,
        EXECUTOR_SERVICE,
        EXECUTOR_SOCKET,
    ] {
        if runtime.load_state(unit, timeout)? != "loaded" {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    for unit in [EXECD_SOCKET, EXECUTOR_SOCKET] {
        if !accept_no_socket_is_healthy(&runtime.sub_state(unit, timeout)?) {
            return Err(ControlError::ReadbackMismatch);
        }
    }

    let execd_invocation = runtime.invocation(EXECD_SERVICE, timeout)?;
    let executor_invocation = runtime.invocation(EXECUTOR_SERVICE, timeout)?;
    let keyholder_invocation = runtime.invocation("buzz-ci-keyholder.service", timeout)?;
    let execd_pid = runtime.main_pid(EXECD_SERVICE, timeout)?;
    let executor_pid = runtime.main_pid(EXECUTOR_SERVICE, timeout)?;
    if controller_invocation == staged_controller_invocation
        || runner_invocation == staged_runner_invocation
        || runner_invocation == retained.runner
        || execd_invocation == retained.execd
        || executor_invocation == retained.executor
        || keyholder_invocation == retained.keyholder
        || execd_pid == 0
        || executor_pid == 0
    {
        return Err(ControlError::StaleGeneration);
    }
    if runtime.process_identity(executor_pid, timeout)?
        != (ProcessIdentity {
            executable: PathBuf::from(EXECUTOR_PROGRAM),
            arguments: vec![
                EXECUTOR_PROGRAM.as_bytes().to_vec(),
                b"--socket-activation".to_vec(),
            ],
        })
        || runtime.service_account(EXECUTOR_SERVICE, timeout)?
            != (
                EXECUTOR_SERVICE_ACCOUNT.to_owned(),
                EXECUTOR_SERVICE_ACCOUNT.to_owned(),
                String::new(),
            )
        || runtime.executor_socket_identity(timeout)?
            != (SocketIdentity {
                uid: 0,
                gid: 0,
                mode: 0o600,
            })
    {
        return Err(ControlError::ReadbackMismatch);
    }

    Ok(CapacityOneTransition {
        result: HostCapacityOneResult {
            readback: ControlReadback {
                activation_id: config.activation_id.clone(),
                activation_package_digest: config.activation_package_digest.clone(),
                integrated_candidate_sha: config.integrated_candidate_sha.clone(),
                capacity: 1,
                admission: AdmissionState::Open,
                controller_generation: config.controller_generation,
                runner_generation: config.runner_generation,
            },
            controller_receipt_sha256: response.receipt_sha256,
        },
        controller_invocation,
        runner_invocation,
    })
}

/// Fixed systemd-backed host control. Unit names and the executable are not configurable.
pub struct SystemdHostControl {
    config: AcceptanceControlConfig,
    controller_invocation: String,
    runner_invocation: String,
    controller_generation: u64,
    runner_generation: u64,
    timeout: Duration,
    systemctl: Systemctl,
}

impl SystemdHostControl {
    pub fn open(config: AcceptanceControlConfig) -> Result<Self, ControlError> {
        validate_activation_receipt(&config)?;
        let timeout = Duration::from_secs(30);
        let systemctl = Systemctl::live();
        let controller_invocation =
            systemctl.unit_invocation_optional("buzz-ci-controld.service", timeout)?;
        let runner_invocation =
            systemctl.unit_invocation_optional("buzz-ci-runner.service", timeout)?;
        Ok(Self {
            controller_generation: config.controller_generation,
            runner_generation: config.runner_generation,
            config,
            controller_invocation,
            runner_invocation,
            timeout,
            systemctl,
        })
    }

    fn readback(&self) -> Result<ControlReadback, ControlError> {
        validate_activation_receipt(&self.config)?;
        let systemctl = &self.systemctl;
        let target = systemctl.unit_active("buzz-ci-capacity-one.target", self.timeout)?;
        let controller = systemctl.unit_active("buzz-ci-controld.service", self.timeout)?;
        let runner = systemctl.unit_active("buzz-ci-runner.socket", self.timeout)?;
        let execd = systemctl.unit_active("buzz-ci-execd.socket", self.timeout)?;
        let keyholder = systemctl.unit_active("buzz-ci-keyholder.socket", self.timeout)?;
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

    fn close_capacity(&self) -> Result<(), ControlError> {
        close_capacity(&self.systemctl, self.timeout)
    }

    /// A restart that reads back the same InvocationID is a stale generation:
    /// capacity is closed before the error returns. The close is judged like
    /// every other stop (exit status plus readback), and a close failure is
    /// the error surfaced, because capacity-one units may still be running
    /// and the caller must not treat the host as closed. `StaleGeneration`
    /// is returned only once all nine units read back stopped.
    fn stale_generation_closed(&self, unit: &str) -> ControlError {
        match self.close_capacity() {
            Ok(()) => ControlError::StaleGeneration,
            Err(error) => {
                let line = serde_json::json!({
                    "schema_version": "buzz-ci-acceptance-control-note/v1",
                    "event": "stale_generation_close_failed",
                    "unit": unit,
                    "error": error.code(),
                });
                eprintln!("{line}");
                error
            }
        }
    }

    fn zero_proof(&self) -> Result<ZeroProof, ControlError> {
        let readback = self.readback()?;
        for unit in [
            "buzz-ci-capacity-one.target",
            "buzz-ci-runner.service",
            "buzz-ci-runner.socket",
            EXECD_SERVICE,
            EXECD_SOCKET,
            EXECUTOR_SERVICE,
            EXECUTOR_SOCKET,
            "buzz-ci-keyholder.service",
            "buzz-ci-keyholder.socket",
        ] {
            if self.systemctl.unit_state(unit, self.timeout)? != UnitState::Inactive {
                return Err(ControlError::ReadbackMismatch);
            }
        }
        let socket_active = self
            .systemctl
            .unit_active("buzz-ci-controld-acceptance.socket", self.timeout)?;
        let service_active = self
            .systemctl
            .unit_active("buzz-ci-controld.service", self.timeout)?;
        let socket_present = match fs::symlink_metadata(CONTROLD_SOCKET_PATH) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(ControlError::ReadbackMismatch),
        };
        Ok(ZeroProof {
            schema_version: ZERO_PROOF_VERSION.to_owned(),
            scenario_sha256: self.config.scenario_sha256.clone(),
            activation_id: self.config.activation_id.clone(),
            activation_package_digest: self.config.activation_package_digest.clone(),
            integrated_candidate_sha: self.config.integrated_candidate_sha.clone(),
            capacity: readback.capacity,
            admission: readback.admission,
            controller_generation: readback.controller_generation,
            runner_generation: readback.runner_generation,
            controld_service_active: service_active,
            controld_acceptance_socket_active: socket_active,
            controld_acceptance_socket_present: socket_present,
        })
    }

    fn controller_zero_action(
        &self,
        action: QualificationZeroAction,
        request: &ControlRequest,
    ) -> Result<String, ControlError> {
        let body = QualificationZeroRequest {
            schema_version: QUALIFICATION_ZERO_REQUEST_SCHEMA,
            action,
            activation_id: &request.activation_id,
            activation_package_digest: &request.activation_package_digest,
            scenario_sha256: &request.scenario_sha256,
            initial_controller_generation: self.config.controller_generation,
            initial_runner_generation: self.config.runner_generation,
            operation_id: &request.operation_id,
            failed_stage: request.failed_stage,
            final_response_sha256: request.final_response_sha256.as_deref(),
            expected_controller_generation: request.expected_controller_generation,
            expected_runner_generation: request.expected_runner_generation,
        };
        let input = serde_json::to_vec(&body).map_err(|_| ControlError::HostAction)?;
        let output = run_bounded_controller(action.argument(), &input, self.timeout)?;
        let response: QualificationZeroResponse =
            serde_json::from_slice(&output).map_err(|_| ControlError::HostAction)?;
        if response.schema_version != QUALIFICATION_ZERO_RESPONSE_SCHEMA
            || response.action != action
            || response.activation_id != request.activation_id
            || response.activation_package_digest != request.activation_package_digest
            || response.scenario_sha256 != request.scenario_sha256
            || response.operation_id != request.operation_id
            || response.state != "staged_zero"
            || !lower_hex(&response.receipt_sha256, &[64])
        {
            return Err(ControlError::BindingMismatch);
        }
        Ok(response.receipt_sha256)
    }
}

impl HostControl for SystemdHostControl {
    type Error = ControlError;

    fn observe(&mut self) -> Result<ControlReadback, Self::Error> {
        self.readback()
    }

    fn set_capacity_one(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostCapacityOneResult, Self::Error> {
        let mut runtime = LiveCapacityOneRuntime {
            systemctl: self.systemctl.clone(),
        };
        let transition = activate_capacity_one(
            &self.config,
            request,
            &self.controller_invocation,
            &self.runner_invocation,
            self.timeout,
            &mut runtime,
        )?;
        self.controller_invocation = transition.controller_invocation;
        self.runner_invocation = transition.runner_invocation;
        Ok(transition.result)
    }

    fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error> {
        let before = self
            .systemctl
            .unit_invocation("buzz-ci-controld.service", self.timeout)?;
        self.systemctl
            .restart("buzz-ci-controld.service", self.timeout)?;
        let invocation = self
            .systemctl
            .unit_invocation("buzz-ci-controld.service", self.timeout)?;
        if invocation == before
            || (!self.controller_invocation.is_empty() && invocation == self.controller_invocation)
        {
            return Err(self.stale_generation_closed("buzz-ci-controld.service"));
        }
        self.controller_invocation = invocation;
        self.controller_generation = self
            .controller_generation
            .checked_add(1)
            .ok_or(ControlError::StaleGeneration)?;
        self.readback()
    }

    fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error> {
        let before = self
            .systemctl
            .unit_invocation("buzz-ci-runner.service", self.timeout)?;
        self.systemctl
            .restart("buzz-ci-runner.service", self.timeout)?;
        let invocation = self
            .systemctl
            .unit_invocation("buzz-ci-runner.service", self.timeout)?;
        if invocation == before
            || (!self.runner_invocation.is_empty() && invocation == self.runner_invocation)
        {
            return Err(self.stale_generation_closed("buzz-ci-runner.service"));
        }
        self.runner_invocation = invocation;
        self.runner_generation = self
            .runner_generation
            .checked_add(1)
            .ok_or(ControlError::StaleGeneration)?;
        self.readback()
    }

    fn prepare_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<ControlReadback, Self::Error> {
        let _ = self.controller_zero_action(QualificationZeroAction::Prepare, request)?;
        self.close_capacity()?;
        reopen_controld_at_staged_zero(&self.systemctl, self.timeout)?;
        self.controller_invocation = self
            .systemctl
            .unit_invocation("buzz-ci-controld.service", self.timeout)?;
        let readback = self.readback()?;
        if readback.capacity != 0 || readback.admission != AdmissionState::Closed {
            return Err(ControlError::ReadbackMismatch);
        }
        Ok(readback)
    }

    fn finalize_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostZeroResult, Self::Error> {
        self.close_capacity()?;
        self.systemctl
            .stop("buzz-ci-controld-acceptance.socket", self.timeout)?;
        self.systemctl
            .stop("buzz-ci-controld.service", self.timeout)?;
        let controller_receipt_sha256 =
            self.controller_zero_action(QualificationZeroAction::Finalize, request)?;
        Ok(HostZeroResult {
            proof: self.zero_proof()?,
            controller_receipt_sha256,
        })
    }

    fn prove_capacity_zero(
        &mut self,
        request: &ControlRequest,
    ) -> Result<HostZeroResult, Self::Error> {
        let controller_receipt_sha256 =
            self.controller_zero_action(QualificationZeroAction::Prove, request)?;
        Ok(HostZeroResult {
            proof: self.zero_proof()?,
            controller_receipt_sha256,
        })
    }

    fn emergency_capacity_zero(&mut self) -> Result<ZeroProof, Self::Error> {
        self.close_capacity()?;
        self.systemctl
            .stop("buzz-ci-controld-acceptance.socket", self.timeout)?;
        self.systemctl
            .stop("buzz-ci-controld.service", self.timeout)?;
        self.zero_proof()
    }
}

fn activation_receipt(
    config: &AcceptanceControlConfig,
) -> Result<(Vec<u8>, serde_json::Value), ControlError> {
    let bytes = read_secure_file(
        Path::new(ACTIVATION_RECEIPT_PATH),
        0,
        0,
        0o600,
        MAX_ACTIVATION_RECEIPT_BYTES,
    )
    .map_err(|_| ControlError::InvalidConfig)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::InvalidConfig)?;
    validate_live_activation_receipt(&value, config)?;
    Ok((bytes, value))
}

/// The activation receipt must bind this activation and sit in a live phase:
/// staged zero, the closed qualification, activation, capacity one, or the
/// qualification-zero prepare the acceptance host itself drives (the
/// controller records `preparing_zero` between prepare and finalize, and the
/// prepare readback happens inside that window).
fn validate_live_activation_receipt(
    value: &serde_json::Value,
    config: &AcceptanceControlConfig,
) -> Result<(), ControlError> {
    if value.get("activation_id").and_then(|item| item.as_str()) != Some(&config.activation_id)
        || value.get("package_digest").and_then(|item| item.as_str())
            != Some(&config.activation_package_digest)
        || value.get("source_commit").and_then(|item| item.as_str())
            != Some(&config.integrated_candidate_sha)
        || !matches!(
            value.get("state").and_then(|item| item.as_str()),
            Some(
                "staged_zero" | "qualified_closed" | "activating" | "active_one" | "preparing_zero"
            )
        )
    {
        return Err(ControlError::BindingMismatch);
    }
    Ok(())
}

fn validate_activation_receipt(config: &AcceptanceControlConfig) -> Result<(), ControlError> {
    activation_receipt(config).map(|_| ())
}

fn validate_activation_receipt_state(
    config: &AcceptanceControlConfig,
    expected: &str,
) -> Result<(), ControlError> {
    let (_, value) = activation_receipt(config)?;
    if value.get("state").and_then(|item| item.as_str()) == Some(expected) {
        Ok(())
    } else {
        Err(ControlError::BindingMismatch)
    }
}

fn active_activation_receipt_sha256(
    config: &AcceptanceControlConfig,
) -> Result<String, ControlError> {
    let (bytes, value) = activation_receipt(config)?;
    if value.get("state").and_then(|item| item.as_str()) != Some("active_one")
        || !bytes.ends_with(b"\n")
    {
        return Err(ControlError::BindingMismatch);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Output of one bounded host command that exited successfully.
///
/// stderr is informational. systemd 259 prints advisory text on a successful
/// `systemctl stop <service>` while the service's socket unit is still active
/// ("Stopping 'buzz-ci-runner.service', but its triggering units are still
/// active:\nbuzz-ci-runner.socket"). Success is the exit status plus the
/// caller's readback, never the absence of stderr.
struct HostCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// The fixed systemctl executable; tests substitute a fixture program.
#[derive(Clone, Debug)]
struct Systemctl {
    program: PathBuf,
}

/// Capacity-one units in the fixed stop order shared with the activation
/// controller (`STOP_ORDER`): target first, then each service before its
/// socket.
const CAPACITY_ONE_STOP_ORDER: [&str; 9] = [
    "buzz-ci-capacity-one.target",
    "buzz-ci-runner.service",
    "buzz-ci-runner.socket",
    EXECD_SERVICE,
    EXECD_SOCKET,
    EXECUTOR_SERVICE,
    EXECUTOR_SOCKET,
    "buzz-ci-keyholder.service",
    "buzz-ci-keyholder.socket",
];

/// Stops every capacity-one unit. Each stop is judged by exit status plus
/// readback, so systemd's advisory stderr never ends the sequence early (the
/// H6 clean host stopped after `buzz-ci-runner.service` and left the runner
/// socket, execd, executor, and keyholder running on every zero path).
fn close_capacity(systemctl: &Systemctl, timeout: Duration) -> Result<(), ControlError> {
    for unit in CAPACITY_ONE_STOP_ORDER {
        systemctl.stop(unit, timeout)?;
    }
    Ok(())
}

/// Reopens controld at staged zero after the controller's prepare wrote the
/// staged configs: controld reads its capacity once at start, so the
/// capacity-one process is stopped (socket first, then service, the finalize
/// order) and started again into the zero configuration, where it serves the
/// stage-13 durable snapshot as the capacity-zero service. The controller
/// generation does not move: this is the activation's own transition, not
/// an observed restart.
fn reopen_controld_at_staged_zero(
    systemctl: &Systemctl,
    timeout: Duration,
) -> Result<(), ControlError> {
    systemctl.stop("buzz-ci-controld-acceptance.socket", timeout)?;
    systemctl.stop("buzz-ci-controld.service", timeout)?;
    systemctl.start("buzz-ci-controld-acceptance.socket", timeout)?;
    systemctl.start("buzz-ci-controld.service", timeout)
}

/// Journal line for advisory stderr from a host command that exited zero.
fn host_command_note(program: &str, arguments: &[&str], stderr: &[u8]) {
    const MAX_NOTE_BYTES: usize = 1024;
    let shown = &stderr[..stderr.len().min(MAX_NOTE_BYTES)];
    let line = serde_json::json!({
        "schema_version": "buzz-ci-acceptance-control-note/v1",
        "event": "host_command_stderr",
        "program": program,
        "arguments": arguments,
        "stderr": String::from_utf8_lossy(shown),
        "truncated": stderr.len() > MAX_NOTE_BYTES,
    });
    eprintln!("{line}");
}

impl Systemctl {
    fn live() -> Self {
        Self {
            program: PathBuf::from("/usr/bin/systemctl"),
        }
    }

    fn run(
        &self,
        arguments: &[&str],
        timeout: Duration,
    ) -> Result<HostCommandOutput, ControlError> {
        let output = run_bounded_command(&self.program, arguments, timeout)?;
        if !output.stderr.is_empty() {
            host_command_note("systemctl", arguments, &output.stderr);
        }
        Ok(output)
    }

    /// `systemctl stop`, judged by exit status and the post-stop readback: the
    /// unit must be `inactive`/`dead`, or `failed`/`failed` for a unit whose
    /// last run failed (nothing runs; the zero proof still demands inactive).
    /// Exit status nonzero, or a unit that still reads back active, fails.
    fn stop(&self, unit: &'static str, timeout: Duration) -> Result<(), ControlError> {
        self.run(&["stop", unit], timeout)?;
        let state = self.unit_state(unit, timeout)?;
        let sub_state = self.unit_property(unit, "SubState", timeout)?;
        match (state, sub_state.as_str()) {
            (UnitState::Inactive, "dead") | (UnitState::Failed, "failed") => Ok(()),
            _ => Err(ControlError::HostAction),
        }
    }

    /// `systemctl start`, judged by exit status and an `active` readback.
    fn start(&self, unit: &'static str, timeout: Duration) -> Result<(), ControlError> {
        self.run(&["start", unit], timeout)?;
        self.require_active(unit, timeout)
    }

    /// `systemctl restart`, judged by exit status and an `active` readback;
    /// callers compare the InvocationID around it.
    fn restart(&self, unit: &'static str, timeout: Duration) -> Result<(), ControlError> {
        self.run(&["restart", unit], timeout)?;
        self.require_active(unit, timeout)
    }

    fn require_active(&self, unit: &'static str, timeout: Duration) -> Result<(), ControlError> {
        if self.unit_state(unit, timeout)? == UnitState::Active {
            Ok(())
        } else {
            Err(ControlError::HostAction)
        }
    }

    fn unit_state(&self, unit: &'static str, timeout: Duration) -> Result<UnitState, ControlError> {
        let output = self
            .run(
                &["show", "--property=ActiveState", "--value", unit],
                timeout,
            )?
            .stdout;
        match output.as_slice() {
            b"active\n" => Ok(UnitState::Active),
            b"inactive\n" => Ok(UnitState::Inactive),
            b"failed\n" => Ok(UnitState::Failed),
            _ => Err(ControlError::ReadbackMismatch),
        }
    }

    fn unit_active(&self, unit: &'static str, timeout: Duration) -> Result<bool, ControlError> {
        Ok(self.unit_state(unit, timeout)? == UnitState::Active)
    }

    fn unit_invocation(
        &self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        let output = self
            .run(
                &["show", "--property=InvocationID", "--value", unit],
                timeout,
            )?
            .stdout;
        let value = std::str::from_utf8(&output)
            .map_err(|_| ControlError::ReadbackMismatch)?
            .trim();
        if lower_hex(value, &[32]) {
            Ok(value.to_owned())
        } else {
            Err(ControlError::ReadbackMismatch)
        }
    }

    fn unit_invocation_optional(
        &self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        let output = self
            .run(
                &["show", "--property=InvocationID", "--value", unit],
                timeout,
            )?
            .stdout;
        let value = std::str::from_utf8(&output)
            .map_err(|_| ControlError::ReadbackMismatch)?
            .trim();
        if value.is_empty() || lower_hex(value, &[32]) {
            Ok(value.to_owned())
        } else {
            Err(ControlError::ReadbackMismatch)
        }
    }

    fn unit_fragment_path(
        &self,
        unit: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        let output = self
            .run(
                &["show", "--property=FragmentPath", "--value", unit],
                timeout,
            )?
            .stdout;
        let value = std::str::from_utf8(&output)
            .map_err(|_| ControlError::ReadbackMismatch)?
            .strip_suffix('\n')
            .ok_or(ControlError::ReadbackMismatch)?;
        if valid_absolute(Path::new(value)) {
            Ok(value.to_owned())
        } else {
            Err(ControlError::ReadbackMismatch)
        }
    }

    fn unit_property(
        &self,
        unit: &'static str,
        property: &'static str,
        timeout: Duration,
    ) -> Result<String, ControlError> {
        let property_argument = match property {
            "LoadState" => "--property=LoadState",
            "SubState" => "--property=SubState",
            "MainPID" => "--property=MainPID",
            "User" => "--property=User",
            "Group" => "--property=Group",
            "SupplementaryGroups" => "--property=SupplementaryGroups",
            _ => return Err(ControlError::ReadbackMismatch),
        };
        let output = self
            .run(&["show", property_argument, "--value", unit], timeout)?
            .stdout;
        let value = std::str::from_utf8(&output)
            .map_err(|_| ControlError::ReadbackMismatch)?
            .strip_suffix('\n')
            .ok_or(ControlError::ReadbackMismatch)?;
        if value.contains(['\n', '\r']) {
            Err(ControlError::ReadbackMismatch)
        } else {
            Ok(value.to_owned())
        }
    }

    fn unit_main_pid(&self, unit: &'static str, timeout: Duration) -> Result<u32, ControlError> {
        self.unit_property(unit, "MainPID", timeout)?
            .parse()
            .map_err(|_| ControlError::ReadbackMismatch)
    }
}

fn live_process_identity(pid: u32) -> Result<ProcessIdentity, ControlError> {
    const MAX_CMDLINE_BYTES: u64 = 4096;
    if pid == 0 {
        return Err(ControlError::ReadbackMismatch);
    }
    let process = PathBuf::from(format!("/proc/{pid}"));
    let executable =
        fs::read_link(process.join("exe")).map_err(|_| ControlError::ReadbackMismatch)?;
    if !valid_absolute(&executable) {
        return Err(ControlError::ReadbackMismatch);
    }
    let mut command_line = Vec::new();
    File::open(process.join("cmdline"))
        .and_then(|file| {
            file.take(MAX_CMDLINE_BYTES + 1)
                .read_to_end(&mut command_line)
        })
        .map_err(|_| ControlError::ReadbackMismatch)?;
    if command_line.is_empty()
        || command_line.len() as u64 > MAX_CMDLINE_BYTES
        || !command_line.ends_with(&[0])
    {
        return Err(ControlError::ReadbackMismatch);
    }
    let arguments = command_line[..command_line.len() - 1]
        .split(|byte| *byte == 0)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if arguments.iter().any(Vec::is_empty) {
        return Err(ControlError::ReadbackMismatch);
    }
    Ok(ProcessIdentity {
        executable,
        arguments,
    })
}

fn live_socket_identity(path: &Path) -> Result<SocketIdentity, ControlError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ControlError::ReadbackMismatch)?;
    if !metadata.file_type().is_socket() {
        return Err(ControlError::ReadbackMismatch);
    }
    Ok(SocketIdentity {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
    })
}

fn run_bounded_command(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<HostCommandOutput, ControlError> {
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
    if !status.success() {
        return Err(ControlError::HostAction);
    }
    Ok(HostCommandOutput { stdout, stderr })
}

fn run_bounded_controller(
    action: &'static str,
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, ControlError> {
    run_bounded_controller_process(ACTIVATION_CONTROLLER_PROGRAM, &[action], input, timeout)
}

fn run_bounded_controller_process(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, ControlError> {
    let mut command = Command::new(program);
    command.args(args);
    run_bounded_controller_command(command, input, timeout)
}

fn run_bounded_controller_command(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, ControlError> {
    const MAX_OUTPUT: usize = 64 * 1024;
    const TERMINATE_GRACE: Duration = Duration::from_millis(100);
    const READER_GRACE: Duration = Duration::from_millis(100);
    if input.is_empty() || input.len() > MAX_OUTPUT {
        return Err(ControlError::HostAction);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| ControlError::HostAction)?;
    let process_group =
        Pid::from_raw(i32::try_from(child.id()).map_err(|_| ControlError::HostAction)?);
    let stdin = match child.stdin.take() {
        Some(value) => value,
        None => {
            terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
            return Err(ControlError::HostAction);
        }
    };
    let stdout = match child.stdout.take() {
        Some(value) => value,
        None => {
            terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
            return Err(ControlError::HostAction);
        }
    };
    let stderr = match child.stderr.take() {
        Some(value) => value,
        None => {
            terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
            return Err(ControlError::HostAction);
        }
    };
    let input_writer = process_input_writer(stdin, input.to_vec());
    let stdout_reader = process_output_reader(stdout, MAX_OUTPUT);
    let stderr_reader = process_output_reader(stderr, MAX_OUTPUT);
    let deadline = Instant::now() + timeout;
    if !matches!(input_writer.recv_timeout(timeout), Ok(Ok(()))) {
        terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
        drain_process_output(&stdout_reader, READER_GRACE);
        drain_process_output(&stderr_reader, READER_GRACE);
        return Err(ControlError::HostAction);
    }
    let status = loop {
        match child.try_wait() {
            Err(_) => {
                terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
                drain_process_output(&stdout_reader, READER_GRACE);
                drain_process_output(&stderr_reader, READER_GRACE);
                return Err(ControlError::HostAction);
            }
            Ok(Some(value)) => break value,
            Ok(None) if Instant::now() >= deadline => {
                terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
                drain_process_output(&stdout_reader, READER_GRACE);
                drain_process_output(&stderr_reader, READER_GRACE);
                return Err(ControlError::HostAction);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = match receive_process_output(&stdout_reader, deadline) {
        Ok(value) => value,
        Err(()) => {
            terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
            drain_process_output(&stdout_reader, READER_GRACE);
            drain_process_output(&stderr_reader, READER_GRACE);
            return Err(ControlError::HostAction);
        }
    }?;
    let stderr = match receive_process_output(&stderr_reader, deadline) {
        Ok(value) => value,
        Err(()) => {
            terminate_process_group(&mut child, process_group, TERMINATE_GRACE);
            drain_process_output(&stderr_reader, READER_GRACE);
            return Err(ControlError::HostAction);
        }
    }?;
    if !status.success() || !stderr.is_empty() || stdout.is_empty() {
        return Err(ControlError::HostAction);
    }
    Ok(stdout)
}

fn process_input_writer(
    mut writer: impl Write + Send + 'static,
    input: Vec<u8>,
) -> Receiver<Result<(), ControlError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = writer
            .write_all(&input)
            .and_then(|()| writer.write_all(b"\n"))
            .map_err(|_| ControlError::HostAction);
        drop(writer);
        let _ = sender.send(result);
    });
    receiver
}

fn process_output_reader(
    reader: impl Read + Send + 'static,
    maximum: usize,
) -> Receiver<Result<Vec<u8>, ControlError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(read_process_output(reader, maximum));
    });
    receiver
}

fn receive_process_output(
    receiver: &Receiver<Result<Vec<u8>, ControlError>>,
    deadline: Instant,
) -> Result<Result<Vec<u8>, ControlError>, ()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver.recv_timeout(remaining).map_err(|_| ())
}

fn drain_process_output(receiver: &Receiver<Result<Vec<u8>, ControlError>>, timeout: Duration) {
    match receiver.recv_timeout(timeout) {
        Ok(_) | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {}
    }
}

fn terminate_process_group(child: &mut std::process::Child, group: Pid, grace: Duration) {
    let _ = killpg(group, Signal::SIGTERM);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = killpg(group, Signal::SIGKILL);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
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
        || !(1..=15).contains(&request.sequence)
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
        || (request.sequence >= 14) != request.failed_stage.is_some()
        || (request.sequence <= 13
            && (request.failed_stage.is_some() || request.final_response_sha256.is_some()))
        || request
            .final_response_sha256
            .as_deref()
            .is_some_and(|value| !lower_hex(value, &[64]))
        || (request.final_response_sha256.is_some()
            && request.failed_stage != Some(Stage::PrepareCapacityZero))
        || (request.sequence >= 14 && request.attempt_id.is_some())
    {
        return Err(ControlError::BindingMismatch);
    }
    let (readback, zero_proof, controller_receipt_sha256) = match request.operation {
        ControlOperation::Observe => (
            host.observe().map_err(|_| ControlError::HostAction)?,
            None,
            None,
        ),
        ControlOperation::SetCapacityOne => {
            let result = host
                .set_capacity_one(request)
                .map_err(|_| ControlError::HostAction)?;
            (
                result.readback,
                None,
                Some(result.controller_receipt_sha256),
            )
        }
        ControlOperation::RestartController => (
            host.restart_controller()
                .map_err(|_| ControlError::HostAction)?,
            None,
            None,
        ),
        ControlOperation::RestartRunner => (
            host.restart_runner()
                .map_err(|_| ControlError::HostAction)?,
            None,
            None,
        ),
        ControlOperation::PrepareCapacityZero => (
            host.prepare_capacity_zero(request)
                .map_err(|_| ControlError::HostAction)?,
            None,
            None,
        ),
        ControlOperation::FinalizeCapacityZero => {
            let result = host
                .finalize_capacity_zero(request)
                .map_err(|_| ControlError::HostAction)?;
            (
                proof_readback(&result.proof),
                Some(result.proof),
                Some(result.controller_receipt_sha256),
            )
        }
        ControlOperation::ProveCapacityZero => {
            let result = host
                .prove_capacity_zero(request)
                .map_err(|_| ControlError::HostAction)?;
            (
                proof_readback(&result.proof),
                Some(result.proof),
                Some(result.controller_receipt_sha256),
            )
        }
    };
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
    if let Some(proof) = &zero_proof {
        if proof.capacity != 0
            || proof.admission != AdmissionState::Closed
            || proof.controld_service_active
            || proof.controld_acceptance_socket_active
            || proof.controld_acceptance_socket_present
        {
            return Err(ControlError::ReadbackMismatch);
        }
    }
    Ok(config.response(request, readback, zero_proof, controller_receipt_sha256))
}

fn proof_readback(proof: &ZeroProof) -> ControlReadback {
    ControlReadback {
        activation_id: proof.activation_id.clone(),
        activation_package_digest: proof.activation_package_digest.clone(),
        integrated_candidate_sha: proof.integrated_candidate_sha.clone(),
        capacity: proof.capacity,
        admission: proof.admission,
        controller_generation: proof.controller_generation,
        runner_generation: proof.runner_generation,
    }
}

fn expected_control_operation(sequence: u32) -> Option<ControlOperation> {
    Some(match sequence {
        2 => ControlOperation::SetCapacityOne,
        11 => ControlOperation::RestartController,
        12 => ControlOperation::RestartRunner,
        13 => ControlOperation::PrepareCapacityZero,
        14 => ControlOperation::FinalizeCapacityZero,
        15 => ControlOperation::ProveCapacityZero,
        1 | 3..=10 => ControlOperation::Observe,
        _ => return None,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlLedger {
    schema_version: String,
    activation_id: String,
    activation_package_digest: String,
    scenario_sha256: String,
    controller_generation: u64,
    runner_generation: u64,
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
    let mut ledger = load_control_ledger(config)?;
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

fn new_control_ledger(config: &AcceptanceControlConfig) -> ControlLedger {
    ControlLedger {
        schema_version: "buzz-ci-acceptance-control-ledger/v2".into(),
        activation_id: config.activation_id.clone(),
        activation_package_digest: config.activation_package_digest.clone(),
        scenario_sha256: config.scenario_sha256.clone(),
        controller_generation: config.controller_generation,
        runner_generation: config.runner_generation,
        entries: BTreeMap::new(),
    }
}

fn ledger_matches_config(ledger: &ControlLedger, config: &AcceptanceControlConfig) -> bool {
    ledger.activation_id == config.activation_id
        && ledger.activation_package_digest == config.activation_package_digest
        && ledger.scenario_sha256 == config.scenario_sha256
        && ledger.controller_generation == config.controller_generation
        && ledger.runner_generation == config.runner_generation
}

fn load_control_ledger(config: &AcceptanceControlConfig) -> Result<ControlLedger, ControlError> {
    let path = Path::new(CONTROL_LEDGER_PATH);
    if !path.exists() {
        return Ok(new_control_ledger(config));
    }
    let bytes =
        read_secure_file(path, 0, 0, 0o600, MAX_CONFIG_BYTES).map_err(|_| ControlError::Ledger)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::Ledger)?;
    if value.get("schema_version").and_then(|item| item.as_str())
        != Some("buzz-ci-acceptance-control-ledger/v2")
    {
        return Ok(new_control_ledger(config));
    }
    let ledger: ControlLedger = serde_json::from_value(value).map_err(|_| ControlError::Ledger)?;
    if ledger.schema_version != "buzz-ci-acceptance-control-ledger/v2" || ledger.entries.len() > 15
    {
        return Err(ControlError::Ledger);
    }
    if !ledger_matches_config(&ledger, config) {
        return Ok(new_control_ledger(config));
    }
    Ok(ledger)
}

fn persist_control_ledger(ledger: &ControlLedger) -> Result<(), ControlError> {
    use std::os::unix::fs::OpenOptionsExt;

    if ledger.entries.len() > 15 {
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

/// Schema of the rejection frame the root helper writes before it closes a
/// rejected connection, so the driver reads a reason instead of an empty frame.
pub const CONTROL_ERROR_SCHEMA: &str = "buzz-ci-acceptance-control-error/v1";

/// Structured rejection returned by the root helper. It names only the error
/// class; the helper's own journal line carries the same code.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlErrorFrame {
    pub schema_version: String,
    pub code: String,
    pub message: String,
}

impl ControlErrorFrame {
    pub fn new(error: ControlError) -> Self {
        Self {
            schema_version: CONTROL_ERROR_SCHEMA.to_owned(),
            code: error.code().to_owned(),
            message: error.message().to_owned(),
        }
    }

    /// Driver-side classification of a helper rejection.
    pub fn driver_error(&self) -> DriverError {
        match self.code.as_str() {
            "stale_generation" => DriverError::StaleGeneration,
            "binding_mismatch" | "replay_mismatch" | "invalid_config" => {
                DriverError::BindingMismatch
            }
            _ => DriverError::Protocol,
        }
    }
}

/// Parse a helper response: either the bound [`ControlResponse`] or a
/// [`ControlErrorFrame`], which fails closed with its classified error.
fn parse_control_response(bytes: &[u8]) -> Result<ControlResponse, DriverError> {
    if bytes.is_empty() || bytes.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(DriverError::FrameTooLarge);
    }
    if let Ok(frame) = serde_json::from_slice::<ControlErrorFrame>(bytes) {
        if frame.schema_version == CONTROL_ERROR_SCHEMA {
            return Err(frame.driver_error());
        }
    }
    parse_bounded(bytes)
}

impl ControlError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidConfig => "control configuration rejected",
            Self::BindingMismatch => "control binding rejected",
            Self::HostAction => "host action failed",
            Self::ReadbackMismatch => "host readback rejected",
            Self::StaleGeneration => "host generation rejected",
            Self::ReplayMismatch => "operation replay rejected",
            Self::Ledger => "operation ledger unavailable",
        }
    }

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
    use std::{collections::VecDeque, convert::Infallible, path::PathBuf};

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

    fn control_config() -> AcceptanceControlConfig {
        let fixture = fixture();
        AcceptanceControlConfig {
            schema_version: CONTROL_CONFIG_SCHEMA.into(),
            activation_id: fixture.activation_id,
            activation_package_digest: fixture.activation_package_digest,
            integrated_candidate_sha: fixture.integrated_candidate_sha,
            scenario_sha256: hex('9', 64),
            run_id: fixture.run_id,
            job_id: fixture.job_id,
            request_digest: fixture.request_digest,
            manifest_digest: fixture.manifest_digest,
            approval_id: fixture.approval_id,
            grant_event_id: fixture.grant_event_id,
            grant_digest: fixture.grant_digest,
            qualification_uid: 1001,
            qualification_gid: 1001,
            controller_generation: 7,
            runner_generation: 9,
        }
    }

    fn capacity_one_control_request() -> ControlRequest {
        let fixture = fixture();
        let scenario_sha256 = hex('9', 64);
        let request = request(&fixture, &scenario_sha256);
        control_request(&request, &operation_id(&request).unwrap())
    }

    fn fake_zero_proof(readback: &ControlReadback) -> ZeroProof {
        ZeroProof {
            schema_version: ZERO_PROOF_VERSION.into(),
            scenario_sha256: hex('9', 64),
            activation_id: readback.activation_id.clone(),
            activation_package_digest: readback.activation_package_digest.clone(),
            integrated_candidate_sha: readback.integrated_candidate_sha.clone(),
            capacity: 0,
            admission: AdmissionState::Closed,
            controller_generation: readback.controller_generation,
            runner_generation: readback.runner_generation,
            controld_service_active: false,
            controld_acceptance_socket_active: false,
            controld_acceptance_socket_present: false,
        }
    }

    fn fake_host_zero(readback: &ControlReadback) -> HostZeroResult {
        HostZeroResult {
            proof: fake_zero_proof(readback),
            controller_receipt_sha256: hex('7', 64),
        }
    }

    fn fake_host_capacity_one(readback: &ControlReadback) -> HostCapacityOneResult {
        HostCapacityOneResult {
            readback: readback.clone(),
            controller_receipt_sha256: hex('6', 64),
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
            zero_proof: None,
            controller_receipt_sha256: Some(hex('6', 64)),
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

        let mut unproved = control;
        unproved.controller_receipt_sha256 = None;
        let transport = FakeTransport {
            replies: VecDeque::from([serde_json::to_vec(&unproved).unwrap()]),
            endpoints: Vec::new(),
        };
        let mut driver = ProductionDriver::new(driver_config.clone(), transport).unwrap();
        assert_eq!(driver.execute(&request), Err(DriverError::BindingMismatch));
        assert_eq!(
            driver.into_transport().endpoints,
            [AdapterEndpoint::Control]
        );
    }

    #[test]
    fn durable_ledger_scope_is_activation_scenario_and_generation_bound() {
        let driver = config();
        let control = AcceptanceControlConfig {
            schema_version: CONTROL_CONFIG_SCHEMA.into(),
            activation_id: driver.activation_id,
            activation_package_digest: driver.activation_package_digest,
            integrated_candidate_sha: driver.integrated_candidate_sha,
            scenario_sha256: driver.scenario_sha256,
            run_id: driver.run_id,
            job_id: driver.job_id,
            request_digest: driver.request_digest,
            manifest_digest: driver.manifest_digest,
            approval_id: driver.approval_id,
            grant_event_id: driver.grant_event_id,
            grant_digest: driver.grant_digest,
            qualification_uid: driver.qualification_uid,
            qualification_gid: driver.qualification_gid,
            controller_generation: 7,
            runner_generation: 9,
        };
        let ledger = new_control_ledger(&control);
        assert!(ledger_matches_config(&ledger, &control));

        let mut next = control.clone();
        next.scenario_sha256 = hex('a', 64);
        assert!(!ledger_matches_config(&ledger, &next));
        next = control.clone();
        next.controller_generation += 1;
        assert!(!ledger_matches_config(&ledger, &next));
        assert_eq!(ledger.entries.len(), 0);
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
            zero_proof: None,
            controller_receipt_sha256: Some(hex('6', 64)),
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
            fn set_capacity_one(
                &mut self,
                _request: &ControlRequest,
            ) -> Result<HostCapacityOneResult, Self::Error> {
                Ok(fake_host_capacity_one(&self.0))
            }
            fn restart_controller(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn restart_runner(&mut self) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn prepare_capacity_zero(
                &mut self,
                _request: &ControlRequest,
            ) -> Result<ControlReadback, Self::Error> {
                Ok(self.0.clone())
            }
            fn finalize_capacity_zero(
                &mut self,
                _request: &ControlRequest,
            ) -> Result<HostZeroResult, Self::Error> {
                Ok(fake_host_zero(&self.0))
            }
            fn prove_capacity_zero(
                &mut self,
                _request: &ControlRequest,
            ) -> Result<HostZeroResult, Self::Error> {
                Ok(fake_host_zero(&self.0))
            }
            fn emergency_capacity_zero(&mut self) -> Result<ZeroProof, Self::Error> {
                Ok(fake_zero_proof(&self.0))
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
        CapacityActivation,
        WrongManifest,
        UnauthenticatedExport,
        StaleRestart,
        BadCapacity,
    }

    struct ScenarioTransport {
        fault: Fault,
        trace: Vec<(AdapterEndpoint, u32)>,
        control_frames: Vec<(u32, Vec<u8>)>,
        finalize_failures: usize,
    }

    impl AdapterTransport for ScenarioTransport {
        type Error = &'static str;

        fn exchange(
            &mut self,
            endpoint: AdapterEndpoint,
            request: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, Self::Error> {
            let sequence = match endpoint {
                AdapterEndpoint::Control => {
                    serde_json::from_slice::<ControlRequest>(request)
                        .unwrap()
                        .sequence
                }
                AdapterEndpoint::Controld => {
                    serde_json::from_slice::<AdapterRequest>(request)
                        .unwrap()
                        .sequence
                }
            };
            self.trace.push((endpoint, sequence));
            if endpoint == AdapterEndpoint::Control {
                self.control_frames.push((sequence, request.to_vec()));
                if sequence == 2 && self.fault == Fault::CapacityActivation {
                    return Err("capacity-one activation rejected");
                }
                if sequence == 14 && self.finalize_failures > 0 {
                    self.finalize_failures -= 1;
                    return Err("transport lost after durable finalize");
                }
            }
            Ok(match endpoint {
                AdapterEndpoint::Control => {
                    let request: ControlRequest = serde_json::from_slice(request).unwrap();
                    let (mut capacity, mut controller, runner) = match request.sequence {
                        1 => (0, 7, 9),
                        2..=10 => (1, 7, 9),
                        11 => (1, 8, 9),
                        12 => (1, 8, 10),
                        13 => (0, 8, 10),
                        14 | 15 => (
                            0,
                            request.expected_controller_generation.unwrap_or(8),
                            request.expected_runner_generation.unwrap_or(10),
                        ),
                        _ => unreachable!(),
                    };
                    if self.fault == Fault::StaleRestart && request.sequence == 11 {
                        controller = 7;
                    }
                    if self.fault == Fault::BadCapacity && request.sequence == 2 {
                        capacity = 2;
                    }
                    let zero_proof = (request.sequence >= 14).then(|| ZeroProof {
                        schema_version: ZERO_PROOF_VERSION.into(),
                        scenario_sha256: request.scenario_sha256.clone(),
                        activation_id: request.activation_id.clone(),
                        activation_package_digest: request.activation_package_digest.clone(),
                        integrated_candidate_sha: request.integrated_candidate_sha.clone(),
                        capacity: 0,
                        admission: AdmissionState::Closed,
                        controller_generation: controller,
                        runner_generation: runner,
                        controld_service_active: false,
                        controld_acceptance_socket_active: false,
                        controld_acceptance_socket_present: false,
                    });
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
                        zero_proof,
                        controller_receipt_sha256: (request.sequence == 2)
                            .then(|| hex('6', 64))
                            .or_else(|| (request.sequence >= 14).then(|| hex('7', 64))),
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
            schema_version: "buzz-ci-capacity-one-scenario/v2".into(),
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
        let transport = ScenarioTransport {
            fault,
            trace: Vec::new(),
            control_frames: Vec::new(),
            finalize_failures: 0,
        };
        let mut driver = ProductionDriver::new(config, transport).unwrap();
        run_acceptance(&scenario, &mut driver)
    }

    fn run_simulation_with_transport(
        finalize_failures: usize,
    ) -> (crate::acceptance::AcceptanceReceipt, ScenarioTransport) {
        let scenario = scenario();
        let scenario_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&scenario).unwrap()));
        let mut config = config();
        config.scenario_sha256 = scenario_sha256;
        let transport = ScenarioTransport {
            fault: Fault::None,
            trace: Vec::new(),
            control_frames: Vec::new(),
            finalize_failures,
        };
        let mut driver = ProductionDriver::new(config, transport).unwrap();
        let receipt = run_acceptance(&scenario, &mut driver);
        (receipt, driver.into_transport())
    }

    #[test]
    fn full_production_adapter_simulation_passes_all_thirteen_stages() {
        let (receipt, transport) = run_simulation_with_transport(0);
        assert_eq!(receipt.outcome, Outcome::Pass);
        assert_eq!(receipt.checks.len(), 13);
        assert_eq!(
            &transport.trace[transport.trace.len() - 4..],
            &[
                (AdapterEndpoint::Control, 13),
                (AdapterEndpoint::Controld, 13),
                (AdapterEndpoint::Control, 14),
                (AdapterEndpoint::Control, 15),
            ]
        );
    }

    #[test]
    fn lost_finalize_response_retries_byte_identically_without_controld_reactivation() {
        let (receipt, transport) = run_simulation_with_transport(1);
        assert_eq!(receipt.outcome, Outcome::Pass);
        let finalize: Vec<_> = transport
            .control_frames
            .iter()
            .filter(|(sequence, _)| *sequence == 14)
            .collect();
        assert_eq!(finalize.len(), 2);
        assert_eq!(finalize[0].1, finalize[1].1);
        assert_eq!(
            &transport.trace[transport.trace.len() - 5..],
            &[
                (AdapterEndpoint::Control, 13),
                (AdapterEndpoint::Controld, 13),
                (AdapterEndpoint::Control, 14),
                (AdapterEndpoint::Control, 14),
                (AdapterEndpoint::Control, 15),
            ]
        );
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

    #[test]
    fn capacity_one_control_failure_never_reaches_controld_and_compensates_to_zero() {
        let scenario = scenario();
        let scenario_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&scenario).unwrap()));
        let mut config = config();
        config.scenario_sha256 = scenario_sha256;
        let transport = ScenarioTransport {
            fault: Fault::CapacityActivation,
            trace: Vec::new(),
            control_frames: Vec::new(),
            finalize_failures: 0,
        };
        let mut driver = ProductionDriver::new(config, transport).unwrap();
        let receipt = run_acceptance(&scenario, &mut driver);
        let transport = driver.into_transport();
        assert_eq!(receipt.outcome, Outcome::Fail);
        let zero_transition = receipt.zero_transition.as_ref().unwrap();
        assert_eq!(zero_transition.outcome, Outcome::Pass);
        assert_eq!(zero_transition.phases.len(), 2);
        assert_eq!(zero_transition.phases[0].sequence, 14);
        assert_eq!(zero_transition.phases[0].outcome, Outcome::Pass);
        assert_eq!(zero_transition.phases[1].sequence, 15);
        assert_eq!(zero_transition.phases[1].outcome, Outcome::Pass);
        assert_eq!(zero_transition.zero_proof.capacity, 0);
        assert_eq!(zero_transition.zero_proof.admission, AdmissionState::Closed);
        assert!(!zero_transition.zero_proof.controld_service_active);
        assert!(!zero_transition.zero_proof.controld_acceptance_socket_active);
        assert!(
            !zero_transition
                .zero_proof
                .controld_acceptance_socket_present
        );
        assert!(!transport.trace.contains(&(AdapterEndpoint::Controld, 2)));
        assert_eq!(
            &transport.trace[transport.trace.len() - 2..],
            &[
                (AdapterEndpoint::Control, 14),
                (AdapterEndpoint::Control, 15),
            ]
        );
    }

    struct FixtureCapacityOneRuntime {
        controller: PathBuf,
        state: PathBuf,
        receipt: PathBuf,
        mode: &'static str,
        controller_calls: usize,
        post_state: Option<serde_json::Value>,
    }

    impl FixtureCapacityOneRuntime {
        fn state(&self) -> serde_json::Value {
            self.post_state
                .clone()
                .unwrap_or_else(|| serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap())
        }

        fn unit_value(&self, unit: &str, field: &str) -> String {
            self.state()["units"][unit][field]
                .as_str()
                .unwrap()
                .to_owned()
        }
    }

    impl CapacityOneRuntime for FixtureCapacityOneRuntime {
        fn activate(&mut self, input: &[u8], timeout: Duration) -> Result<Vec<u8>, ControlError> {
            self.controller_calls += 1;
            let mut command = Command::new(&self.controller);
            command
                .arg(CapacityOneAction::SetCapacityOne.argument())
                .env("BUZZ_FAKE_SYSTEMD_STATE", &self.state)
                .env("BUZZ_FAKE_ACTIVATION_RECEIPT", &self.receipt)
                .env("BUZZ_FAKE_CAPACITY_ONE_MODE", self.mode);
            let output = run_bounded_controller_command(command, input, timeout)?;
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap();
            // The fake controller models the live transition for the units it
            // knows; the executor pair is layered here with the same shape: an
            // `Accept=no` socket reports `running` once its service is up.
            for unit in [
                EXECD_SERVICE,
                EXECD_SOCKET,
                EXECUTOR_SERVICE,
                EXECUTOR_SOCKET,
            ] {
                state["units"][unit]["state"] = "active".into();
                state["units"][unit]["load_state"] = "loaded".into();
                state["units"][unit]["sub_state"] = "running".into();
            }
            state["units"][EXECD_SERVICE]["invocation_id"] = hex('4', 32).into();
            state["units"][EXECD_SERVICE]["main_pid"] = 404.into();
            state["units"][EXECUTOR_SERVICE]["invocation_id"] = hex('6', 32).into();
            state["units"][EXECUTOR_SERVICE]["main_pid"] = 606.into();
            state["units"][EXECUTOR_SERVICE]["user"] = EXECUTOR_SERVICE_ACCOUNT.into();
            state["units"][EXECUTOR_SERVICE]["group"] = EXECUTOR_SERVICE_ACCOUNT.into();
            state["units"][EXECUTOR_SERVICE]["supplementary_groups"] = "".into();
            state["units"][EXECUTOR_SERVICE]["executable"] = EXECUTOR_PROGRAM.into();
            state["units"][EXECUTOR_SERVICE]["arguments"] =
                serde_json::json!([EXECUTOR_PROGRAM, "--socket-activation"]);
            state["executor_socket"] = serde_json::json!({
                "uid": 0,
                "gid": 0,
                "mode": 0o600,
            });
            match self.mode {
                "missing_executor" => {
                    state["units"][EXECUTOR_SERVICE]["state"] = "inactive".into();
                    state["units"][EXECUTOR_SERVICE]["load_state"] = "not-found".into();
                }
                "wrong_executor_fragment" => {
                    state["units"][EXECUTOR_SERVICE]["fragment_path"] =
                        "/etc/systemd/system/buzz-ci-executor.service".into();
                }
                "stale_executor" => {
                    state["units"][EXECUTOR_SERVICE]["invocation_id"] = "".into();
                    state["units"][EXECUTOR_SERVICE]["main_pid"] = 0.into();
                }
                "stopped_executor_socket" => {
                    state["units"][EXECUTOR_SOCKET]["state"] = "inactive".into();
                    state["units"][EXECUTOR_SOCKET]["sub_state"] = "dead".into();
                }
                "wrong_executor_process" => {
                    state["units"][EXECUTOR_SERVICE]["arguments"] =
                        serde_json::json!([EXECUTOR_PROGRAM, "--standalone"]);
                }
                "wrong_executor_account" => {
                    state["units"][EXECUTOR_SERVICE]["supplementary_groups"] = "wheel".into();
                }
                "wrong_executor_socket_metadata" => {
                    state["executor_socket"]["mode"] = 0o660.into();
                }
                "stale_execd" => {
                    state["units"][EXECD_SERVICE]["invocation_id"] = "".into();
                    state["units"][EXECD_SERVICE]["main_pid"] = 0.into();
                }
                "unloaded_execd_socket" => {
                    state["units"][EXECD_SOCKET]["load_state"] = "not-found".into();
                }
                "listening_execd_socket" => {
                    state["units"][EXECD_SOCKET]["sub_state"] = "listening".into();
                }
                "dead_execd_socket" => {
                    state["units"][EXECD_SOCKET]["sub_state"] = "dead".into();
                }
                "failed_executor_socket" => {
                    state["units"][EXECUTOR_SOCKET]["sub_state"] = "failed".into();
                }
                _ => {}
            }
            self.post_state = Some(state);
            Ok(output)
        }

        fn unit_state(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<UnitState, ControlError> {
            match self.unit_value(unit, "state").as_str() {
                "active" => Ok(UnitState::Active),
                "inactive" => Ok(UnitState::Inactive),
                "failed" => Ok(UnitState::Failed),
                _ => Err(ControlError::ReadbackMismatch),
            }
        }

        fn invocation(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<String, ControlError> {
            let value = self.unit_value(unit, "invocation_id");
            if lower_hex(&value, &[32]) {
                Ok(value)
            } else {
                Err(ControlError::ReadbackMismatch)
            }
        }

        fn optional_invocation(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<String, ControlError> {
            let value = self.unit_value(unit, "invocation_id");
            if value.is_empty() || lower_hex(&value, &[32]) {
                Ok(value)
            } else {
                Err(ControlError::ReadbackMismatch)
            }
        }

        fn fragment_path(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<String, ControlError> {
            Ok(self.unit_value(unit, "fragment_path"))
        }

        fn load_state(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<String, ControlError> {
            Ok(self.unit_value(unit, "load_state"))
        }

        fn sub_state(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<String, ControlError> {
            Ok(self.unit_value(unit, "sub_state"))
        }

        fn main_pid(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<u32, ControlError> {
            self.state()["units"][unit]["main_pid"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(ControlError::ReadbackMismatch)
        }

        fn process_identity(
            &mut self,
            pid: u32,
            _timeout: Duration,
        ) -> Result<ProcessIdentity, ControlError> {
            let state = self.state();
            let unit = &state["units"][EXECUTOR_SERVICE];
            if unit["main_pid"].as_u64() != Some(u64::from(pid)) {
                return Err(ControlError::ReadbackMismatch);
            }
            let arguments = unit["arguments"]
                .as_array()
                .ok_or(ControlError::ReadbackMismatch)?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(|item| item.as_bytes().to_vec())
                        .ok_or(ControlError::ReadbackMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ProcessIdentity {
                executable: PathBuf::from(
                    unit["executable"]
                        .as_str()
                        .ok_or(ControlError::ReadbackMismatch)?,
                ),
                arguments,
            })
        }

        fn service_account(
            &mut self,
            unit: &'static str,
            _timeout: Duration,
        ) -> Result<(String, String, String), ControlError> {
            Ok((
                self.unit_value(unit, "user"),
                self.unit_value(unit, "group"),
                self.unit_value(unit, "supplementary_groups"),
            ))
        }

        fn executor_socket_identity(
            &mut self,
            _timeout: Duration,
        ) -> Result<SocketIdentity, ControlError> {
            let state = self.state();
            let socket = &state["executor_socket"];
            Ok(SocketIdentity {
                uid: socket["uid"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(ControlError::ReadbackMismatch)?,
                gid: socket["gid"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(ControlError::ReadbackMismatch)?,
                mode: socket["mode"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(ControlError::ReadbackMismatch)?,
            })
        }

        fn active_receipt_sha256(
            &mut self,
            config: &AcceptanceControlConfig,
        ) -> Result<String, ControlError> {
            let bytes = fs::read(&self.receipt).map_err(|_| ControlError::ReadbackMismatch)?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ControlError::ReadbackMismatch)?;
            if !bytes.ends_with(b"\n")
                || value["state"] != "active_one"
                || value["activation_id"] != config.activation_id
                || value["package_digest"] != config.activation_package_digest
                || value["scenario_sha256"] != config.scenario_sha256
                || value["source_commit"] != config.integrated_candidate_sha
            {
                return Err(ControlError::BindingMismatch);
            }
            Ok(hex::encode(Sha256::digest(bytes)))
        }

        fn prove_qualified_receipt(
            &mut self,
            config: &AcceptanceControlConfig,
        ) -> Result<(), ControlError> {
            let value: serde_json::Value = serde_json::from_slice(
                &fs::read(&self.receipt).map_err(|_| ControlError::ReadbackMismatch)?,
            )
            .map_err(|_| ControlError::ReadbackMismatch)?;
            if value["state"] == "qualified_closed"
                && value["activation_id"] == config.activation_id
                && value["package_digest"] == config.activation_package_digest
                && value["scenario_sha256"] == config.scenario_sha256
                && value["source_commit"] == config.integrated_candidate_sha
            {
                Ok(())
            } else {
                Err(ControlError::BindingMismatch)
            }
        }
    }

    fn capacity_one_fixture(
        mode: &'static str,
    ) -> (
        tempfile::TempDir,
        FixtureCapacityOneRuntime,
        AcceptanceControlConfig,
        ControlRequest,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("systemd.json");
        let receipt_path = directory.path().join("receipt.json");
        let mut units = serde_json::Map::new();
        let staged_active = [
            "buzz-ci-controld.service",
            "buzz-ci-controld-acceptance.socket",
            "buzz-ci-acceptance-control.socket",
            "buzz-ci-acceptance-control.service",
        ];
        for unit in [
            "buzz-ci-capacity-one.target",
            "buzz-ci-controld.service",
            "buzz-ci-controld-acceptance.socket",
            "buzz-ci-acceptance-control.socket",
            "buzz-ci-acceptance-control.service",
            "buzz-ci-runner.service",
            "buzz-ci-runner.socket",
            EXECD_SERVICE,
            EXECD_SOCKET,
            EXECUTOR_SERVICE,
            EXECUTOR_SOCKET,
            "buzz-ci-keyholder.service",
            "buzz-ci-keyholder.socket",
        ] {
            let fragment_path = match unit {
                "buzz-ci-capacity-one.target" => "/etc/systemd/system/buzz-ci-capacity-one.target",
                "buzz-ci-controld.service" => "/etc/systemd/system/buzz-ci-controld.service",
                "buzz-ci-runner.socket" => "/etc/systemd/system/buzz-ci-runner.socket",
                EXECD_SERVICE => "/usr/lib/systemd/system/buzz-ci-execd.service",
                EXECD_SOCKET => "/usr/lib/systemd/system/buzz-ci-execd.socket",
                EXECUTOR_SERVICE => "/usr/lib/systemd/system/buzz-ci-executor.service",
                EXECUTOR_SOCKET => "/usr/lib/systemd/system/buzz-ci-executor.socket",
                "buzz-ci-keyholder.socket" => "/etc/systemd/system/buzz-ci-keyholder.socket",
                _ => "/etc/systemd/system/fixture-unit",
            };
            units.insert(
                unit.to_owned(),
                serde_json::json!({
                    "state": if staged_active.contains(&unit) { "active" } else { "inactive" },
                    "invocation_id": if unit == "buzz-ci-controld.service" { hex('1', 32) } else { String::new() },
                    "fragment_path": fragment_path,
                    "load_state": "loaded",
                    "sub_state": "dead",
                    "main_pid": 0,
                    "user": "",
                    "group": "",
                    "supplementary_groups": "",
                    "executable": "",
                    "arguments": [],
                }),
            );
        }
        fs::write(
            &state_path,
            serde_json::to_vec(&serde_json::json!({"units": units})).unwrap(),
        )
        .unwrap();
        let config = control_config();
        let mut receipt = serde_json::to_vec(&serde_json::json!({
            "state": "qualified_closed",
            "activation_id": config.activation_id,
            "package_digest": config.activation_package_digest,
            "source_commit": config.integrated_candidate_sha,
            "scenario_sha256": config.scenario_sha256,
            "controller_generation": config.controller_generation,
            "runner_generation": config.runner_generation,
        }))
        .unwrap();
        receipt.push(b'\n');
        fs::write(&receipt_path, receipt).unwrap();
        let runtime = FixtureCapacityOneRuntime {
            controller: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/fake-capacity-one-controller.py"),
            state: state_path,
            receipt: receipt_path,
            mode,
            controller_calls: 0,
            post_state: None,
        };
        let request = capacity_one_control_request();
        (directory, runtime, config, request)
    }

    fn run_capacity_one_fixture(
        mode: &'static str,
    ) -> Result<(CapacityOneTransition, FixtureCapacityOneRuntime), ControlError> {
        let (_directory, mut runtime, config, request) = capacity_one_fixture(mode);
        let result = activate_capacity_one(
            &config,
            &request,
            &hex('1', 32),
            "",
            Duration::from_millis(500),
            &mut runtime,
        )?;
        Ok((result, runtime))
    }

    #[test]
    fn fixed_controller_replaces_staged_processes_before_capacity_one_readback() {
        let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
        let transition = activate_capacity_one(
            &config,
            &request,
            &hex('1', 32),
            "",
            Duration::from_millis(500),
            &mut runtime,
        )
        .unwrap();
        assert_eq!(transition.result.readback.capacity, 1);
        assert_eq!(transition.result.readback.admission, AdmissionState::Open);
        assert_eq!(transition.result.readback.controller_generation, 7);
        assert_eq!(transition.result.readback.runner_generation, 9);
        assert_eq!(transition.controller_invocation, hex('2', 32));
        assert_eq!(transition.runner_invocation, hex('3', 32));
        assert_eq!(runtime.controller_calls, 1);
        let state = runtime.state();
        assert_eq!(state["units"][EXECD_SERVICE]["load_state"], "loaded");
        assert_eq!(state["units"][EXECD_SOCKET]["sub_state"], "running");
        assert_eq!(state["units"][EXECUTOR_SERVICE]["load_state"], "loaded");
        assert_eq!(state["units"][EXECUTOR_SERVICE]["main_pid"], 606);
        assert_eq!(
            state["units"][EXECUTOR_SERVICE]["fragment_path"],
            "/usr/lib/systemd/system/buzz-ci-executor.service"
        );
        assert_eq!(state["units"][EXECUTOR_SOCKET]["sub_state"], "running");
        assert_eq!(state["executor_socket"]["uid"], 0);
        assert_eq!(state["executor_socket"]["gid"], 0);
        assert_eq!(state["executor_socket"]["mode"], 0o600);
        assert!(lower_hex(
            &transition.result.controller_receipt_sha256,
            &[64]
        ));
    }

    #[test]
    fn stale_zero_process_is_rejected_before_controller_invocation() {
        let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
        let mut state = runtime.state();
        state["units"]["buzz-ci-runner.service"]["state"] = "active".into();
        state["units"]["buzz-ci-runner.service"]["invocation_id"] = hex('a', 32).into();
        fs::write(&runtime.state, serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(
            activate_capacity_one(
                &config,
                &request,
                &hex('1', 32),
                "",
                Duration::from_millis(500),
                &mut runtime,
            )
            .map(|_| ()),
            Err(ControlError::ReadbackMismatch)
        );
        assert_eq!(runtime.controller_calls, 0);
    }

    #[test]
    fn retained_invocation_ids_on_dead_units_do_not_block_capacity_one() {
        // systemd 259 keeps a stopped unit's InvocationID until its next stop
        // job. After the closed qualification execd is inactive/dead with
        // MainPID=0 and a retained id; that is not a live process.
        let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
        let mut state = runtime.state();
        for unit in [
            EXECD_SERVICE,
            EXECD_SOCKET,
            EXECUTOR_SOCKET,
            "buzz-ci-runner.service",
        ] {
            state["units"][unit]["invocation_id"] = hex('f', 32).into();
        }
        fs::write(&runtime.state, serde_json::to_vec(&state).unwrap()).unwrap();
        let transition = activate_capacity_one(
            &config,
            &request,
            &hex('1', 32),
            &hex('f', 32),
            Duration::from_millis(500),
            &mut runtime,
        )
        .unwrap();
        assert_eq!(transition.result.readback.capacity, 1);
        assert_eq!(transition.result.readback.admission, AdmissionState::Open);
        assert_eq!(transition.runner_invocation, hex('3', 32));
        assert_eq!(runtime.controller_calls, 1);
    }

    #[test]
    fn dead_unit_with_a_live_substate_or_main_pid_is_stale_before_the_controller_runs() {
        for (field, value) in [
            ("sub_state", serde_json::json!("auto-restart")),
            ("main_pid", serde_json::json!(404)),
        ] {
            let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
            let mut state = runtime.state();
            state["units"][EXECD_SERVICE]["invocation_id"] = hex('f', 32).into();
            state["units"][EXECD_SERVICE][field] = value;
            fs::write(&runtime.state, serde_json::to_vec(&state).unwrap()).unwrap();
            assert_eq!(
                activate_capacity_one(
                    &config,
                    &request,
                    &hex('1', 32),
                    "",
                    Duration::from_millis(500),
                    &mut runtime,
                )
                .map(|_| ()),
                Err(ControlError::StaleGeneration),
                "{field}"
            );
            assert_eq!(runtime.controller_calls, 0, "{field}");
        }
    }

    #[test]
    fn unchanged_invocation_id_after_the_controller_ran_is_stale() {
        // The fixture controller reports hex('4') for execd afterwards; a
        // retained id equal to it means the unit was never restarted.
        let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
        let mut state = runtime.state();
        state["units"][EXECD_SERVICE]["invocation_id"] = hex('4', 32).into();
        fs::write(&runtime.state, serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(
            activate_capacity_one(
                &config,
                &request,
                &hex('1', 32),
                "",
                Duration::from_millis(500),
                &mut runtime,
            )
            .map(|_| ()),
            Err(ControlError::StaleGeneration)
        );
        assert_eq!(runtime.controller_calls, 1);
    }

    #[test]
    fn control_error_frames_are_classified_and_never_parsed_as_responses() {
        let frame = ControlErrorFrame::new(ControlError::StaleGeneration);
        assert_eq!(frame.schema_version, CONTROL_ERROR_SCHEMA);
        assert_eq!(frame.code, "stale_generation");
        assert_eq!(frame.message, "host generation rejected");
        for (error, expected) in [
            (ControlError::StaleGeneration, DriverError::StaleGeneration),
            (ControlError::BindingMismatch, DriverError::BindingMismatch),
            (ControlError::ReplayMismatch, DriverError::BindingMismatch),
            (ControlError::InvalidConfig, DriverError::BindingMismatch),
            (ControlError::HostAction, DriverError::Protocol),
            (ControlError::ReadbackMismatch, DriverError::Protocol),
            (ControlError::Ledger, DriverError::Protocol),
        ] {
            let bytes = serde_json::to_vec(&ControlErrorFrame::new(error)).unwrap();
            assert_eq!(parse_control_response(&bytes).err(), Some(expected));
        }
        assert_eq!(
            parse_control_response(b"").err(),
            Some(DriverError::FrameTooLarge)
        );
        assert_eq!(
            parse_control_response(
                b"{\"schema_version\":\"other\",\"code\":\"x\",\"message\":\"y\"}"
            )
            .err(),
            Some(DriverError::Protocol)
        );
    }

    #[test]
    fn capacity_one_controller_rejects_malformed_drift_and_stale_readback() {
        for (mode, expected) in [
            ("malformed", ControlError::BindingMismatch),
            ("drift_response", ControlError::BindingMismatch),
            ("stale_controller", ControlError::StaleGeneration),
            ("wrong_fragment", ControlError::ReadbackMismatch),
        ] {
            assert_eq!(run_capacity_one_fixture(mode).err().unwrap(), expected);
        }
    }

    #[test]
    fn capacity_one_rejects_hostile_execd_and_executor_readback() {
        for (mode, expected) in [
            ("missing_executor", ControlError::ReadbackMismatch),
            ("wrong_executor_fragment", ControlError::ReadbackMismatch),
            ("stale_executor", ControlError::ReadbackMismatch),
            ("stopped_executor_socket", ControlError::ReadbackMismatch),
            ("wrong_executor_process", ControlError::ReadbackMismatch),
            ("wrong_executor_account", ControlError::ReadbackMismatch),
            (
                "wrong_executor_socket_metadata",
                ControlError::ReadbackMismatch,
            ),
            ("stale_execd", ControlError::ReadbackMismatch),
            ("unloaded_execd_socket", ControlError::ReadbackMismatch),
        ] {
            assert_eq!(
                run_capacity_one_fixture(mode).err().unwrap(),
                expected,
                "mode {mode} must fail closed"
            );
        }
    }

    /// H6 clean host, canary stage 2: the controller returned `active_one`
    /// and `buzz-ci-execd.socket` read back `ActiveState=active
    /// SubState=running` (an `Accept=no` socket whose service is up), which
    /// the helper rejected as a readback mismatch. Both fakes now model that
    /// transition, so the default success path exercises `running`;
    /// `listening` (socket up before its service) stays accepted and
    /// `dead` or `failed` stay rejected.
    #[test]
    fn accept_no_socket_running_with_its_service_is_a_healthy_capacity_one_readback() {
        let (transition, runtime) = run_capacity_one_fixture("success").unwrap();
        let state = runtime.state();
        assert_eq!(state["units"][EXECD_SOCKET]["sub_state"], "running");
        assert_eq!(state["units"][EXECD_SERVICE]["sub_state"], "running");
        assert_eq!(state["units"][EXECUTOR_SOCKET]["sub_state"], "running");
        assert_eq!(
            state["units"]["buzz-ci-runner.socket"]["sub_state"],
            "running"
        );
        assert_eq!(transition.result.readback.capacity, 1);

        let (transition, runtime) = run_capacity_one_fixture("listening_execd_socket").unwrap();
        assert_eq!(
            runtime.state()["units"][EXECD_SOCKET]["sub_state"],
            "listening"
        );
        assert_eq!(transition.result.readback.capacity, 1);

        for mode in ["dead_execd_socket", "failed_executor_socket"] {
            assert_eq!(
                run_capacity_one_fixture(mode).err().unwrap(),
                ControlError::ReadbackMismatch,
                "mode {mode} must fail closed"
            );
        }
        for (sub_state, healthy) in [
            ("listening", true),
            ("running", true),
            ("dead", false),
            ("failed", false),
            ("inactive", false),
            ("", false),
            ("Listening", false),
        ] {
            assert_eq!(
                accept_no_socket_is_healthy(sub_state),
                healthy,
                "{sub_state:?}"
            );
        }
    }

    #[test]
    fn capacity_one_controller_timeout_is_bounded() {
        let (_directory, mut runtime, config, request) = capacity_one_fixture("timeout");
        let started = Instant::now();
        assert_eq!(
            activate_capacity_one(
                &config,
                &request,
                &hex('1', 32),
                "",
                Duration::from_millis(40),
                &mut runtime,
            )
            .map(|_| ()),
            Err(ControlError::HostAction)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn capacity_one_controller_exact_replay_is_idempotent_and_drift_is_rejected() {
        let (_directory, mut runtime, config, request) = capacity_one_fixture("success");
        let body = CapacityOneRequest {
            schema_version: CAPACITY_ONE_REQUEST_SCHEMA,
            action: CapacityOneAction::SetCapacityOne,
            activation_id: &request.activation_id,
            activation_package_digest: &request.activation_package_digest,
            scenario_sha256: &request.scenario_sha256,
            initial_controller_generation: config.controller_generation,
            initial_runner_generation: config.runner_generation,
            operation_id: &request.operation_id,
        };
        let input = serde_json::to_vec(&body).unwrap();
        let first = runtime
            .activate(&input, Duration::from_millis(500))
            .unwrap();
        let replay = runtime
            .activate(&input, Duration::from_millis(500))
            .unwrap();
        assert_eq!(first, replay);

        let mut drift = request.clone();
        drift.operation_id = hex('f', 64);
        let drift = CapacityOneRequest {
            schema_version: CAPACITY_ONE_REQUEST_SCHEMA,
            action: CapacityOneAction::SetCapacityOne,
            activation_id: &drift.activation_id,
            activation_package_digest: &drift.activation_package_digest,
            scenario_sha256: &drift.scenario_sha256,
            initial_controller_generation: config.controller_generation,
            initial_runner_generation: config.runner_generation,
            operation_id: &drift.operation_id,
        };
        assert_eq!(
            runtime
                .activate(
                    &serde_json::to_vec(&drift).unwrap(),
                    Duration::from_millis(500),
                )
                .map(|_| ()),
            Err(ControlError::HostAction)
        );
    }

    #[test]
    fn controller_descendant_retaining_output_pipe_is_killed_without_unbounded_join() {
        let started = Instant::now();
        let result = run_bounded_controller_process(
            "/bin/sh",
            &["-c", "printf '{\"status\":\"ok\"}'; sleep 30 &"],
            b"{}",
            Duration::from_millis(80),
        );
        assert_eq!(result, Err(ControlError::HostAction));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn controller_timeout_kills_term_ignoring_process_group_and_returns_boundedly() {
        let started = Instant::now();
        let result = run_bounded_controller_process(
            "/bin/sh",
            &["-c", "trap '' TERM; (trap '' TERM; sleep 30) & wait"],
            b"{}",
            Duration::from_millis(40),
        );
        assert_eq!(result, Err(ControlError::HostAction));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// The exact advisory systemd 259 prints on a successful
    /// `systemctl stop <service>` while the service's socket still listens
    /// (H6 clean host, diagnostic boot 4, rc 0).
    const STOP_ADVISORY: &str =
        "Stopping 'buzz-ci-runner.service', but its triggering units are still active:\nbuzz-ci-runner.socket\n";

    /// A systemd-259-shaped fake systemctl: `stop` records the unit and prints
    /// the advisory for a service whose socket is still up; `show` answers
    /// ActiveState and SubState from the recorded set and a fixed InvocationID
    /// (`restart` never changes it, so every restart reads back stale). Marker
    /// files switch the failure shapes on: `fail-stop` (rc 1) and
    /// `ignore-stop` (rc 0, unit stays active).
    fn fake_systemctl(directory: &Path) -> Systemctl {
        let dir = directory.display();
        let script = format!(
            r#"#!/bin/sh
dir='{dir}'
printf '%s\n' "$*" >> "$dir/calls"
case "$1" in
  stop)
    unit=$2
    if [ -e "$dir/fail-stop" ]; then
      echo "Failed to stop $unit: refused by fixture" >&2
      exit 1
    fi
    if [ ! -e "$dir/ignore-stop" ]; then
      printf '%s\n' "$unit" >> "$dir/stopped"
    fi
    case "$unit" in
      *.service)
        socket="${{unit%.service}}.socket"
        if ! grep -qxF "$socket" "$dir/stopped" 2>/dev/null; then
          printf "Stopping '%s', but its triggering units are still active:\n%s\n" "$unit" "$socket" >&2
        fi
        ;;
    esac
    exit 0
    ;;
  start|restart)
    unit=$2
    if [ -e "$dir/stopped" ]; then
      grep -vxF "$unit" "$dir/stopped" > "$dir/stopped.new"
      mv "$dir/stopped.new" "$dir/stopped"
    fi
    exit 0
    ;;
  show)
    unit=$4
    stopped=0
    if [ -e "$dir/stopped" ] && grep -qxF "$unit" "$dir/stopped"; then stopped=1; fi
    case "$2" in
      --property=ActiveState) if [ "$stopped" = 1 ]; then echo inactive; else echo active; fi ;;
      --property=SubState) if [ "$stopped" = 1 ]; then echo dead; else echo running; fi ;;
      --property=InvocationID) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
      *) exit 1 ;;
    esac
    exit 0
    ;;
esac
exit 1
"#
        );
        let program = directory.join("systemctl");
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        Systemctl { program }
    }

    /// H6 clean host: every zero path aborted after the first service stop
    /// because `run_bounded_command` treated systemd's advisory stderr as a
    /// failed host action. Stop is now judged by exit status plus the
    /// post-stop readback; the advisory is informational.
    #[test]
    fn systemctl_stop_advisory_stderr_is_informational_and_close_capacity_completes() {
        let directory = tempfile::tempdir().unwrap();
        let systemctl = fake_systemctl(directory.path());
        let timeout = Duration::from_secs(5);

        let output = run_bounded_command(
            &systemctl.program,
            &["stop", "buzz-ci-runner.service"],
            timeout,
        )
        .unwrap();
        assert_eq!(output.stdout, b"");
        assert_eq!(std::str::from_utf8(&output.stderr).unwrap(), STOP_ADVISORY);
        fs::remove_file(directory.path().join("stopped")).unwrap();
        fs::remove_file(directory.path().join("calls")).unwrap();

        systemctl.stop("buzz-ci-runner.service", timeout).unwrap();
        assert_eq!(
            fs::read_to_string(directory.path().join("calls")).unwrap(),
            "stop buzz-ci-runner.service\n\
             show --property=ActiveState --value buzz-ci-runner.service\n\
             show --property=SubState --value buzz-ci-runner.service\n"
        );
        fs::remove_file(directory.path().join("stopped")).unwrap();

        close_capacity(&systemctl, timeout).unwrap();
        let stopped = fs::read_to_string(directory.path().join("stopped")).unwrap();
        assert_eq!(
            stopped.lines().collect::<Vec<_>>(),
            CAPACITY_ONE_STOP_ORDER.to_vec()
        );
        for unit in CAPACITY_ONE_STOP_ORDER {
            assert_eq!(
                systemctl.unit_state(unit, timeout).unwrap(),
                UnitState::Inactive
            );
        }

        systemctl.start("buzz-ci-runner.socket", timeout).unwrap();
        assert_eq!(
            systemctl
                .unit_state("buzz-ci-runner.socket", timeout)
                .unwrap(),
            UnitState::Active
        );
        systemctl.restart("buzz-ci-runner.socket", timeout).unwrap();

        fs::write(directory.path().join("ignore-stop"), b"").unwrap();
        assert_eq!(
            systemctl.stop("buzz-ci-runner.socket", timeout),
            Err(ControlError::HostAction)
        );
        fs::remove_file(directory.path().join("ignore-stop")).unwrap();
        fs::write(directory.path().join("fail-stop"), b"").unwrap();
        assert_eq!(
            systemctl.stop("buzz-ci-runner.socket", timeout),
            Err(ControlError::HostAction)
        );
        assert_eq!(
            close_capacity(&systemctl, timeout),
            Err(ControlError::HostAction)
        );
    }

    /// H10 clean host, boot 8: stage 13's prepare wrote the staged zero
    /// configs and closed capacity, but controld kept running as the
    /// capacity-one service (it reads its capacity once at start), refused
    /// sequence 13 and exited closed. Prepare now reopens controld at staged
    /// zero: socket and service stopped in the finalize order, then started.
    #[test]
    fn prepare_reopens_controld_at_staged_zero_in_the_finalize_order() {
        let directory = tempfile::tempdir().unwrap();
        let systemctl = fake_systemctl(directory.path());
        let timeout = Duration::from_secs(5);
        reopen_controld_at_staged_zero(&systemctl, timeout).unwrap();
        let calls = fs::read_to_string(directory.path().join("calls")).unwrap();
        let transitions: Vec<&str> = calls
            .lines()
            .filter(|line| line.starts_with("stop ") || line.starts_with("start "))
            .collect();
        assert_eq!(
            transitions,
            [
                "stop buzz-ci-controld-acceptance.socket",
                "stop buzz-ci-controld.service",
                "start buzz-ci-controld-acceptance.socket",
                "start buzz-ci-controld.service",
            ]
        );
        for unit in [
            "buzz-ci-controld-acceptance.socket",
            "buzz-ci-controld.service",
        ] {
            assert_eq!(
                systemctl.unit_state(unit, timeout).unwrap(),
                UnitState::Active
            );
        }
        fs::write(directory.path().join("fail-stop"), b"").unwrap();
        assert_eq!(
            reopen_controld_at_staged_zero(&systemctl, timeout),
            Err(ControlError::HostAction)
        );
    }

    /// Sol focus read of head Q, finding 11: a restart that read back a stale
    /// InvocationID discarded the result of `close_capacity` and returned
    /// `StaleGeneration`, so capacity-one units could stay running while the
    /// driver treated the host as closed. The close failure is now the error
    /// surfaced; `StaleGeneration` is returned only after the nine-unit stop
    /// order completed and every unit read back stopped.
    #[test]
    fn stale_restart_generation_surfaces_a_failed_capacity_close() {
        let directory = tempfile::tempdir().unwrap();
        let systemctl = fake_systemctl(directory.path());
        let timeout = Duration::from_secs(5);
        let mut host = SystemdHostControl {
            config: control_config(),
            controller_invocation: String::new(),
            runner_invocation: String::new(),
            controller_generation: 1,
            runner_generation: 1,
            timeout,
            systemctl,
        };

        fs::write(directory.path().join("fail-stop"), b"").unwrap();
        assert_eq!(
            host.restart_controller().err(),
            Some(ControlError::HostAction)
        );
        assert_eq!(host.restart_runner().err(), Some(ControlError::HostAction));
        assert!(!directory.path().join("stopped").exists());
        assert_eq!(host.controller_generation, 1);
        assert_eq!(host.runner_generation, 1);
        assert!(host.controller_invocation.is_empty());
        assert!(host.runner_invocation.is_empty());

        fs::remove_file(directory.path().join("fail-stop")).unwrap();
        fs::remove_file(directory.path().join("calls")).unwrap();
        assert_eq!(
            host.restart_controller().err(),
            Some(ControlError::StaleGeneration)
        );
        let stopped = fs::read_to_string(directory.path().join("stopped")).unwrap();
        assert_eq!(
            stopped.lines().collect::<Vec<_>>(),
            CAPACITY_ONE_STOP_ORDER.to_vec()
        );
        let calls = fs::read_to_string(directory.path().join("calls")).unwrap();
        assert_eq!(
            calls.lines().next(),
            Some("show --property=InvocationID --value buzz-ci-controld.service")
        );
        assert!(calls.contains("restart buzz-ci-controld.service"));
        for unit in CAPACITY_ONE_STOP_ORDER {
            assert_eq!(
                host.systemctl.unit_state(unit, timeout).unwrap(),
                UnitState::Inactive,
                "{unit}"
            );
        }
        assert_eq!(host.controller_generation, 1);
    }

    /// H10 clean host, boot 7: stage 13's prepare succeeded in the controller
    /// (receipt state preparing_zero), capacity closed, controld restarted,
    /// and the readback refused the receipt because preparing_zero was not
    /// a live state, failing the host action closed. The prepare window is
    /// live; the failure states stay refused.
    /// PR6 clean host: the candidate's receipt on a rolled-back host embeds the
    /// retained controller and package module as `prior` payloads (about 524 KB
    /// at e60431ac), so the 128 KiB config bound closed the acceptance host at
    /// startup. The receipt reads under the controller's 1 MiB receipt bound.
    #[test]
    fn activation_receipt_reads_under_the_controller_receipt_bound_not_the_config_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt-v1.json");
        let mut receipt =
            b"{\"state\":\"staged_zero\",\"targets\":[{\"prior\":{\"payload_base64\":\"".to_vec();
        receipt.extend(std::iter::repeat_n(b'A', 600 * 1024));
        receipt.extend_from_slice(b"\"}}]}\n");
        fs::write(&path, &receipt).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let (uid, gid) = (metadata.uid(), metadata.gid());
        assert!(receipt.len() as u64 > MAX_CONFIG_BYTES);
        assert!(matches!(
            read_secure_file(&path, uid, gid, 0o600, MAX_CONFIG_BYTES),
            Err(DriverError::InvalidConfig)
        ));
        assert_eq!(
            read_secure_file(&path, uid, gid, 0o600, MAX_ACTIVATION_RECEIPT_BYTES).unwrap(),
            receipt
        );
    }

    #[test]
    fn live_activation_receipt_accepts_the_zero_prepare_window() {
        let config = control_config();
        let receipt = |state: &str| {
            serde_json::json!({
                "activation_id": config.activation_id,
                "package_digest": config.activation_package_digest,
                "source_commit": config.integrated_candidate_sha,
                "scenario_sha256": config.scenario_sha256,
                "state": state,
            })
        };
        for state in [
            "staged_zero",
            "qualified_closed",
            "activating",
            "active_one",
            "preparing_zero",
        ] {
            assert_eq!(
                validate_live_activation_receipt(&receipt(state), &config),
                Ok(()),
                "{state}"
            );
        }
        for state in [
            "absent",
            "dormant",
            "preparing",
            "qualification_uncertain",
            "rollback_cleanup",
            "rollback_failed",
            "rolled_back",
        ] {
            assert_eq!(
                validate_live_activation_receipt(&receipt(state), &config),
                Err(ControlError::BindingMismatch),
                "{state}"
            );
        }
        let mut foreign = receipt("preparing_zero");
        foreign["activation_id"] = serde_json::json!("buzz-ci-capacity-one-other");
        assert_eq!(
            validate_live_activation_receipt(&foreign, &config),
            Err(ControlError::BindingMismatch)
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod endpoint_identity_tests {
    use std::{
        io::{ErrorKind, Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        thread,
    };

    use super::*;

    const SERVICE_UID: u32 = 1002;
    const SERVICE_GID: u32 = 1002;
    const SYSTEMD: ListenerPeer = ListenerPeer {
        pid: 1,
        uid: 0,
        gid: 0,
    };

    fn own_ids() -> (u32, u32) {
        (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    #[test]
    fn listener_peer_accepts_the_endpoint_service_or_the_systemd_socket_unit() {
        let service = ListenerPeer {
            pid: 4242,
            uid: SERVICE_UID,
            gid: SERVICE_GID,
        };
        assert!(listener_peer_accepted(service, SERVICE_UID, SERVICE_GID));
        assert!(listener_peer_accepted(SYSTEMD, SERVICE_UID, SERVICE_GID));
        assert!(listener_peer_accepted(SYSTEMD, 0, 0));
    }

    #[test]
    fn listener_peer_rejects_every_other_shape() {
        let rejected = [
            ListenerPeer {
                pid: 4242,
                uid: 0,
                gid: 0,
            },
            ListenerPeer {
                pid: 0,
                uid: 0,
                gid: 0,
            },
            ListenerPeer {
                pid: -1,
                uid: 0,
                gid: 0,
            },
            ListenerPeer {
                pid: 1,
                uid: 0,
                gid: SERVICE_GID,
            },
            ListenerPeer {
                pid: 1,
                uid: SERVICE_UID,
                gid: 0,
            },
            ListenerPeer {
                pid: 4242,
                uid: SERVICE_UID,
                gid: 0,
            },
            ListenerPeer {
                pid: 4242,
                uid: 0,
                gid: SERVICE_GID,
            },
            ListenerPeer {
                pid: 4242,
                uid: SERVICE_UID + 1,
                gid: SERVICE_GID,
            },
            ListenerPeer {
                pid: 4242,
                uid: SERVICE_UID,
                gid: SERVICE_GID + 1,
            },
        ];
        for peer in rejected {
            assert!(
                !listener_peer_accepted(peer, SERVICE_UID, SERVICE_GID),
                "{peer:?}"
            );
        }
        let root_not_init = ListenerPeer {
            pid: 4242,
            uid: 0,
            gid: 0,
        };
        assert!(listener_peer_accepted(root_not_init, 0, 0));
        assert!(!listener_peer_accepted(
            ListenerPeer {
                pid: 1,
                uid: 0,
                gid: 1
            },
            0,
            0
        ));
    }

    #[test]
    fn socket_inode_requires_a_root_owned_group_0620_socket() {
        let installed = SocketInode {
            is_socket: true,
            uid: 0,
            gid: SERVICE_GID,
            mode: 0o620,
        };
        assert!(socket_inode_accepted(installed, SERVICE_GID));
        let rejected = [
            SocketInode {
                is_socket: false,
                ..installed
            },
            SocketInode {
                uid: SERVICE_UID,
                ..installed
            },
            SocketInode {
                gid: 0,
                ..installed
            },
            SocketInode {
                gid: SERVICE_GID + 1,
                ..installed
            },
            SocketInode {
                mode: 0o660,
                ..installed
            },
            SocketInode {
                mode: 0o600,
                ..installed
            },
            SocketInode {
                mode: 0o1620,
                ..installed
            },
        ];
        for inode in rejected {
            assert!(!socket_inode_accepted(inode, SERVICE_GID), "{inode:?}");
        }
    }

    #[test]
    fn exchange_connected_accepts_the_listener_credentials_and_rejects_foreign_ones() {
        let (uid, gid) = own_ids();
        let (client, mut server) = UnixStream::pair().unwrap();
        let echo = thread::spawn(move || {
            let mut request = Vec::new();
            server.read_to_end(&mut request).unwrap();
            server.write_all(b"reply:").unwrap();
            server.write_all(&request).unwrap();
        });
        let response = exchange_connected(client, uid, gid, b"ping", Duration::from_secs(2));
        echo.join().unwrap();
        assert_eq!(response, Ok(b"reply:ping".to_vec()));

        let (client, mut server) = UnixStream::pair().unwrap();
        let observed = thread::spawn(move || {
            let mut request = Vec::new();
            server.read_to_end(&mut request).unwrap();
            request
        });
        let response = exchange_connected(
            client,
            uid.checked_add(1).unwrap(),
            gid,
            b"ping",
            Duration::from_secs(2),
        );
        assert_eq!(response, Err(DriverError::WrongPeer));
        assert!(
            observed.join().unwrap().is_empty(),
            "no bytes before peer check"
        );
    }

    #[test]
    fn exchange_unix_rejects_an_unprivileged_socket_before_connecting() {
        let (uid, gid) = own_ids();
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = root.path().join("endpoint.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        let response = exchange_unix(&path, gid, uid, gid, b"ping", Duration::from_secs(2));
        assert_eq!(response, Err(DriverError::WrongPeer));
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert_eq!(
            exchange_unix(
                &root.path().join("absent.sock"),
                gid,
                uid,
                gid,
                b"ping",
                Duration::from_secs(2)
            ),
            Err(DriverError::Transport)
        );
    }
}
