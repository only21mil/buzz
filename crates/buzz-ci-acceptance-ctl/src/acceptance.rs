//! Capacity-one activation qualification state machine.
//!
//! The state machine owns transition order and evidence validation. A driver
//! only performs injected control, observation, export, and process operations.
//! A zero exit from a driver command is never acceptance evidence by itself.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum accepted scenario document size.
pub const MAX_SCENARIO_BYTES: usize = 128 * 1024;
const MAX_DRIVER_OUTPUT_BYTES: usize = 1024 * 1024;
const SCENARIO_VERSION: &str = "buzz-ci-capacity-one-scenario/v2";
pub const DRIVER_VERSION: &str = "buzz-ci-capacity-one-driver/v2";
const RECEIPT_VERSION: &str = "buzz-ci-capacity-one-acceptance-receipt/v2";
pub const ZERO_REQUEST_VERSION: &str = "buzz-ci-capacity-one-zero-request/v1";
pub const ZERO_PROOF_VERSION: &str = "buzz-ci-capacity-one-zero-proof/v1";
pub const ZERO_TRANSITION_VERSION: &str = "buzz-ci-capacity-one-zero-transition/v1";
/// Number of durable provider-facing operations in the closed acceptance sequence.
pub const ACCEPTANCE_STAGE_COUNT: u32 = 16;

/// One executable endpoint. The harness never invokes a shell.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEndpoint {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// Provider adapter and service process controls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverEndpoints {
    pub control: ProcessEndpoint,
    pub observe: ProcessEndpoint,
    pub export: ProcessEndpoint,
    pub controller_process: ProcessEndpoint,
    pub runner_process: ProcessEndpoint,
    pub timeout_seconds: u64,
}

/// One expected evidence object.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObject {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Public, digest-bound selector that makes only Run B attempt 1 fail.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSelector {
    pub schema_version: String,
    pub selector: String,
    pub job_id: String,
    pub run_id: String,
    pub attempt: u32,
    pub sha256: String,
}

pub(crate) fn valid_fixture_selector(
    value: &FixtureSelector,
    failure_run_id: &str,
    job_id: &str,
) -> bool {
    let Ok(run_id) = uuid::Uuid::parse_str(&value.run_id) else {
        return false;
    };
    let encoded = format!(
        "buzz-ci:capacity-one:fixture-selector:v1\n{}\n{}\n{}\n{}\n{}\n",
        value.schema_version,
        value.selector,
        value.job_id,
        run_id.simple(),
        value.attempt,
    );
    value.schema_version == "buzz-ci-capacity-one-fixture-selector/v1"
        && value.selector == "deterministic-failure"
        && value.job_id == job_id
        && value.attempt == 1
        && value.run_id == run_id.hyphenated().to_string()
        && run_id.simple().to_string() == failure_run_id
        && value.sha256 == hex::encode(Sha256::digest(encoded.as_bytes()))
}

/// Immutable fixture identities and expected outputs.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    pub integrated_candidate_sha: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub run_id: String,
    pub failure_run_id: String,
    pub failure_selector: FixtureSelector,
    pub job_id: String,
    pub request_digest: String,
    pub failure_request_digest: String,
    pub manifest_digest: String,
    pub source_oid: String,
    pub approval_id: String,
    pub grant_event_id: String,
    pub grant_digest: String,
    pub approved_by: String,
    pub export_subject: String,
    pub export_generation: u64,
    pub export_authorization_digest: String,
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub expected_log: EvidenceObject,
    pub expected_failure_log: EvidenceObject,
    pub expected_artifacts: Vec<EvidenceObject>,
}

/// Complete capacity-one qualification input.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScenario {
    pub schema_version: String,
    pub fixture: FixtureSpec,
    pub driver: DriverEndpoints,
}

/// Fixed state-machine operations. Drivers cannot add or skip operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ObserveInitial,
    SetCapacityOne,
    SubmitManifest,
    ApproveGrant,
    ResumeGrant,
    AwaitFirstTerminal,
    ExportFirstEvidence,
    SubmitFailureManifest,
    ResumeFailure,
    AwaitFailureTerminal,
    Rerun,
    CancelRerun,
    TombstoneRerun,
    RestartController,
    RestartRunner,
    SetCapacityZero,
}

/// Request written to one injected driver command on standard input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRequest<'a> {
    pub schema_version: &'static str,
    pub scenario_sha256: &'a str,
    pub sequence: u32,
    pub operation: Operation,
    pub fixture: &'a FixtureSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
}

/// Admission posture returned by every observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionState {
    Closed,
    Open,
}

/// Lifecycle of the fixture run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    AwaitingApproval,
    GrantedAwaitingResume,
    Running,
    Terminal,
}

/// Lifecycle of one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Queued,
    Running,
    Terminal,
    Tombstoned,
}

/// Terminal outcome. `none` is valid only before an attempt terminates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    None,
    Success,
    Failure,
    Cancelled,
    TimedOut,
    InfrastructureFailure,
}

/// Approval and explicit resume state bound to the fixture run.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSnapshot {
    pub approval_id: String,
    pub grant_event_id: String,
    pub grant_digest: String,
    pub approved_by: String,
    pub resumed: bool,
}

/// One provider-neutral attempt observation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptSnapshot {
    pub attempt_id: String,
    pub attempt: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attempt_id: Option<String>,
    pub state: AttemptState,
    pub conclusion: Conclusion,
    pub integrated_candidate_sha: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub source_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_set_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<EvidenceObject>,
    #[serde(default)]
    pub artifacts: Vec<EvidenceObject>,
}

/// Fixture run projection returned by the adapter.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSnapshot {
    pub run_id: String,
    pub integrated_candidate_sha: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub source_oid: String,
    pub state: RunState,
    pub aggregate_conclusion: Conclusion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_attempt_id: Option<String>,
    #[serde(default)]
    pub attempts: Vec<AttemptSnapshot>,
}

/// Global and fixture-specific state returned after each operation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSnapshot {
    pub capacity: u32,
    pub admission: AdmissionState,
    pub active_run_count: u32,
    pub active_attempt_count: u32,
    pub controller_generation: u64,
    pub runner_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunSnapshot>,
}

/// Authenticated evidence export returned only by the export endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSnapshot {
    pub authenticated: bool,
    pub subject: String,
    pub generation: u64,
    pub authorization_digest: String,
    pub attempt_id: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub evidence_set_digest: String,
    pub objects: Vec<EvidenceObject>,
}

/// One response read from a driver command's standard output.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverResponse {
    pub schema_version: String,
    pub sequence: u32,
    pub operation: Operation,
    pub snapshot: SystemSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<ExportSnapshot>,
}

/// Root-only compensating request. It never uses the controld adapter socket.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroRequest {
    pub schema_version: String,
    pub scenario_sha256: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub run_id: String,
    pub failed_stage: Stage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_response_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
}

/// Independent root readback after the controld acceptance socket is stopped.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroProof {
    pub schema_version: String,
    pub scenario_sha256: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub capacity: u32,
    pub admission: AdmissionState,
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub controld_service_active: bool,
    pub controld_acceptance_socket_active: bool,
    pub controld_acceptance_socket_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroOperation {
    FinalizeCapacityZero,
    ProveCapacityZero,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroPhaseRequest {
    pub sequence: u32,
    pub operation: ZeroOperation,
    pub operation_id: String,
    pub scenario_sha256: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub integrated_candidate_sha: String,
    pub failed_stage: Stage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_response_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_controller_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_runner_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroPhaseResponse {
    pub operation_id: String,
    pub controller_receipt_sha256: String,
    pub proof: ZeroProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroPhaseReceipt {
    pub sequence: u32,
    pub operation: ZeroOperation,
    pub outcome: Outcome,
    pub attempts: u32,
    pub request_sha256: String,
    pub response_sha256: String,
    pub request: ZeroPhaseRequest,
    pub response: ZeroPhaseResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroTransition {
    pub schema_version: String,
    pub outcome: Outcome,
    pub attempts: u32,
    pub phases: Vec<ZeroPhaseReceipt>,
    pub zero_proof: ZeroProof,
}

/// Stable acceptance check names recorded in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    CapacityZeroClosed,
    CapacityOneOpen,
    ManifestIdentity,
    ApprovalGrant,
    GrantResume,
    FirstAttemptTerminal,
    AuthenticatedExport,
    FailedManifestIdentity,
    FailedAttemptRunning,
    FailedAttemptTerminal,
    RerunSeparation,
    CancellationTerminal,
    TombstoneFolding,
    ControllerRestartRecovery,
    RunnerRestartRecovery,
    PrepareCapacityZero,
}

/// Pass or fail result for the whole receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
}

/// Evidence digest for one completed stage.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageReceipt {
    pub sequence: u32,
    pub stage: Stage,
    pub outcome: Outcome,
    pub evidence_sha256: String,
    pub snapshot: SystemSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<ExportSnapshot>,
}

/// Stable failure detail without raw driver output.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureReceipt {
    pub stage: Stage,
    pub code: String,
    pub message: String,
}

/// Machine-readable qualification receipt.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceReceipt {
    pub schema_version: String,
    pub outcome: Outcome,
    pub scenario_sha256: String,
    pub integrated_candidate_sha: String,
    pub run_id: String,
    pub checks: Vec<StageReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_transition: Option<ZeroTransition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureReceipt>,
}

/// Invalid or ambiguous scenario input.
#[derive(Debug, Error)]
pub enum ScenarioError {
    #[error("scenario exceeds {MAX_SCENARIO_BYTES} bytes")]
    InputTooLarge,
    #[error("malformed scenario: {0}")]
    Malformed(String),
    #[error("unsupported scenario version")]
    UnsupportedVersion,
    #[error("invalid scenario field: {0}")]
    InvalidField(&'static str),
}

impl ScenarioError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::Malformed(_) => "malformed_scenario",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidField(_) => "invalid_field",
        }
    }
}

/// Driver or state validation failure.
#[derive(Debug, Error)]
pub enum AcceptanceError {
    #[error("driver failed: {0}")]
    Driver(String),
    #[error("driver response binding mismatch")]
    DriverBinding,
    #[error("missing evidence: {0}")]
    MissingEvidence(&'static str),
    #[error("ambiguous evidence: {0}")]
    AmbiguousEvidence(&'static str),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(&'static str),
    #[error("invalid transition: {0}")]
    InvalidTransition(&'static str),
    #[error("integrity mismatch: {0}")]
    IntegrityMismatch(&'static str),
}

impl AcceptanceError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Driver(_) => "driver_failure",
            Self::DriverBinding => "driver_binding_mismatch",
            Self::MissingEvidence(_) => "missing_evidence",
            Self::AmbiguousEvidence(_) => "ambiguous_evidence",
            Self::IdentityMismatch(_) => "identity_mismatch",
            Self::InvalidTransition(_) => "invalid_transition",
            Self::IntegrityMismatch(_) => "integrity_mismatch",
        }
    }
}

/// Injected operation driver.
pub trait AcceptanceDriver {
    type Error: std::fmt::Display;

    /// Perform exactly one requested operation and return its observation.
    fn execute(&mut self, request: &DriverRequest<'_>) -> Result<DriverResponse, Self::Error>;

    /// Finalize capacity zero and return an independent root readback.
    fn return_to_zero(&mut self, request: &ZeroRequest) -> Result<ZeroTransition, Self::Error>;
}

/// Parse and validate one complete scenario without invoking a driver.
pub fn parse_scenario(input: &[u8]) -> Result<AcceptanceScenario, ScenarioError> {
    if input.len() > MAX_SCENARIO_BYTES {
        return Err(ScenarioError::InputTooLarge);
    }
    let scenario: AcceptanceScenario = serde_json::from_slice(input)
        .map_err(|error| ScenarioError::Malformed(error.to_string()))?;
    validate_scenario(&scenario)?;
    Ok(scenario)
}

/// Run the fixed qualification sequence and always return a receipt.
pub fn run_acceptance<D: AcceptanceDriver>(
    scenario: &AcceptanceScenario,
    driver: &mut D,
) -> AcceptanceReceipt {
    let scenario_sha256 = match digest_json(scenario) {
        Some(digest) => digest,
        None => {
            return AcceptanceReceipt {
                schema_version: RECEIPT_VERSION.to_owned(),
                outcome: Outcome::Fail,
                scenario_sha256: digest_bytes(b"scenario serialization failure"),
                integrated_candidate_sha: scenario.fixture.integrated_candidate_sha.clone(),
                run_id: scenario.fixture.run_id.clone(),
                checks: Vec::new(),
                zero_transition: None,
                failure: Some(FailureReceipt {
                    stage: Stage::CapacityZeroClosed,
                    code: "integrity_mismatch".to_owned(),
                    message: "integrity mismatch: scenario serialization".to_owned(),
                }),
            };
        }
    };
    let mut receipt = AcceptanceReceipt {
        schema_version: RECEIPT_VERSION.to_owned(),
        outcome: Outcome::Pass,
        scenario_sha256,
        integrated_candidate_sha: scenario.fixture.integrated_candidate_sha.clone(),
        run_id: scenario.fixture.run_id.clone(),
        checks: Vec::new(),
        zero_transition: None,
        failure: None,
    };

    let result = run_sequence(
        scenario,
        &receipt.scenario_sha256,
        driver,
        &mut receipt.checks,
    );
    let failed_stage = result
        .as_ref()
        .err()
        .map_or(Stage::PrepareCapacityZero, |v| v.0);
    if let Err((stage, error)) = result {
        receipt.outcome = Outcome::Fail;
        receipt.failure = Some(FailureReceipt {
            stage,
            code: error.code().to_owned(),
            message: error.to_string(),
        });
    }
    if failed_stage != Stage::CapacityZeroClosed {
        let last = receipt.checks.last();
        let last_trusted = receipt
            .checks
            .iter()
            .rev()
            .find(|check| check.outcome == Outcome::Pass);
        let zero_request = ZeroRequest {
            schema_version: ZERO_REQUEST_VERSION.to_owned(),
            scenario_sha256: receipt.scenario_sha256.clone(),
            activation_id: scenario.fixture.activation_id.clone(),
            activation_package_digest: scenario.fixture.activation_package_digest.clone(),
            integrated_candidate_sha: scenario.fixture.integrated_candidate_sha.clone(),
            run_id: scenario.fixture.run_id.clone(),
            failed_stage,
            final_response_sha256: (receipt.outcome == Outcome::Pass)
                .then(|| last.map(|check| check.evidence_sha256.clone()))
                .flatten(),
            expected_controller_generation: (failed_stage != Stage::ControllerRestartRecovery)
                .then(|| {
                    last_trusted.map_or(scenario.fixture.controller_generation, |check| {
                        check.snapshot.controller_generation
                    })
                }),
            expected_runner_generation: (failed_stage != Stage::RunnerRestartRecovery).then(|| {
                last_trusted.map_or(scenario.fixture.runner_generation, |check| {
                    check.snapshot.runner_generation
                })
            }),
        };
        let mut zero_error = None;
        let mut zero_attempts = 0;
        for _ in 0..2 {
            zero_attempts += 1;
            match driver.return_to_zero(&zero_request) {
                Ok(mut transition) => match validate_zero_transition(&transition, &zero_request) {
                    Ok(()) => {
                        transition.attempts = zero_attempts;
                        receipt.zero_transition = Some(transition);
                        zero_error = None;
                        break;
                    }
                    Err(error) => zero_error = Some(error),
                },
                Err(error) => zero_error = Some(AcceptanceError::Driver(error.to_string())),
            }
        }
        if let Some(error) = zero_error {
            receipt.outcome = Outcome::Fail;
            receipt.failure = Some(FailureReceipt {
                stage: failed_stage,
                code: error.code().to_owned(),
                message: format!("capacity-zero compensation failed: {error}"),
            });
        }
    }
    receipt
}

fn validate_zero_proof(proof: &ZeroProof, request: &ZeroRequest) -> Result<(), AcceptanceError> {
    require(
        proof.schema_version == ZERO_PROOF_VERSION
            && proof.scenario_sha256 == request.scenario_sha256
            && proof.activation_id == request.activation_id
            && proof.activation_package_digest == request.activation_package_digest
            && proof.integrated_candidate_sha == request.integrated_candidate_sha,
        "capacity-zero proof binding mismatch",
    )?;
    require(
        proof.capacity == 0 && proof.admission == AdmissionState::Closed,
        "capacity-zero proof is not closed",
    )?;
    require(
        proof.controller_generation > 0
            && proof.runner_generation > 0
            && request
                .expected_controller_generation
                .is_none_or(|expected| proof.controller_generation == expected)
            && request
                .expected_runner_generation
                .is_none_or(|expected| proof.runner_generation == expected),
        "capacity-zero proof generation mismatch",
    )?;
    require(
        !proof.controld_service_active
            && !proof.controld_acceptance_socket_active
            && !proof.controld_acceptance_socket_present,
        "controld acceptance transport remains active",
    )
}

fn validate_zero_transition(
    transition: &ZeroTransition,
    request: &ZeroRequest,
) -> Result<(), AcceptanceError> {
    if transition.schema_version != ZERO_TRANSITION_VERSION
        || transition.outcome != Outcome::Pass
        || !(1..=2).contains(&transition.attempts)
        || transition.phases.len() != 2
    {
        return Err(AcceptanceError::IntegrityMismatch("zero transition shape"));
    }
    for (index, phase) in transition.phases.iter().enumerate() {
        let (sequence, operation) = if index == 0 {
            (17, ZeroOperation::FinalizeCapacityZero)
        } else {
            (18, ZeroOperation::ProveCapacityZero)
        };
        if phase.sequence != sequence
            || phase.operation != operation
            || phase.outcome != Outcome::Pass
            || !(1..=2).contains(&phase.attempts)
            || phase.request.sequence != sequence
            || phase.request.operation != operation
            || phase.request.operation_id != phase.response.operation_id
            || phase.request.scenario_sha256 != request.scenario_sha256
            || phase.request.activation_id != request.activation_id
            || phase.request.activation_package_digest != request.activation_package_digest
            || phase.request.integrated_candidate_sha != request.integrated_candidate_sha
            || phase.request.failed_stage != request.failed_stage
            || phase.request.final_response_sha256 != request.final_response_sha256
            || phase.request.expected_controller_generation
                != request.expected_controller_generation
            || phase.request.expected_runner_generation != request.expected_runner_generation
            || digest_json(&phase.request).as_deref() != Some(&phase.request_sha256)
            || digest_json(&phase.response).as_deref() != Some(&phase.response_sha256)
        {
            return Err(AcceptanceError::IntegrityMismatch("zero transition phase"));
        }
        require_hex(
            &phase.response.controller_receipt_sha256,
            64,
            "controller zero receipt digest",
        )?;
        validate_zero_proof(&phase.response.proof, request)?;
    }
    require(
        transition.zero_proof == transition.phases[1].response.proof,
        "final zero proof is not the independent prove response",
    )
}

/// Reconstruct and validate all evidence required for a passing receipt.
pub fn validate_receipt(receipt: &AcceptanceReceipt) -> Result<(), AcceptanceError> {
    if receipt.schema_version != RECEIPT_VERSION
        || receipt.outcome != Outcome::Pass
        || receipt.failure.is_some()
        || receipt.checks.len() != 16
    {
        return Err(AcceptanceError::IntegrityMismatch("receipt shape"));
    }
    let expected = [
        Stage::CapacityZeroClosed,
        Stage::CapacityOneOpen,
        Stage::ManifestIdentity,
        Stage::ApprovalGrant,
        Stage::GrantResume,
        Stage::FirstAttemptTerminal,
        Stage::AuthenticatedExport,
        Stage::FailedManifestIdentity,
        Stage::FailedAttemptRunning,
        Stage::FailedAttemptTerminal,
        Stage::RerunSeparation,
        Stage::CancellationTerminal,
        Stage::TombstoneFolding,
        Stage::ControllerRestartRecovery,
        Stage::RunnerRestartRecovery,
        Stage::PrepareCapacityZero,
    ];
    for (index, check) in receipt.checks.iter().enumerate() {
        let sequence = u32::try_from(index + 1)
            .map_err(|_| AcceptanceError::IntegrityMismatch("receipt sequence"))?;
        if check.sequence != sequence
            || check.stage != expected[index]
            || check.outcome != Outcome::Pass
        {
            return Err(AcceptanceError::IntegrityMismatch("receipt stage ordering"));
        }
        let response = DriverResponse {
            schema_version: DRIVER_VERSION.to_owned(),
            sequence,
            operation: expected_operation_for_stage(check.stage),
            snapshot: check.snapshot.clone(),
            export: check.export.clone(),
        };
        if digest_json(&response).as_deref() != Some(&check.evidence_sha256) {
            return Err(AcceptanceError::IntegrityMismatch(
                "receipt evidence digest",
            ));
        }
    }
    let transition = receipt
        .zero_transition
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("capacity-zero transition"))?;
    let proof = &transition.zero_proof;
    if proof.scenario_sha256 != receipt.scenario_sha256
        || proof.integrated_candidate_sha != receipt.integrated_candidate_sha
        || proof.capacity != 0
        || proof.admission != AdmissionState::Closed
        || proof.controld_service_active
        || proof.controld_acceptance_socket_active
        || proof.controld_acceptance_socket_present
    {
        return Err(AcceptanceError::IntegrityMismatch("capacity-zero proof"));
    }
    let request = ZeroRequest {
        schema_version: ZERO_REQUEST_VERSION.to_owned(),
        scenario_sha256: receipt.scenario_sha256.clone(),
        activation_id: proof.activation_id.clone(),
        activation_package_digest: proof.activation_package_digest.clone(),
        integrated_candidate_sha: receipt.integrated_candidate_sha.clone(),
        run_id: receipt.run_id.clone(),
        failed_stage: Stage::PrepareCapacityZero,
        final_response_sha256: receipt
            .checks
            .last()
            .map(|check| check.evidence_sha256.clone()),
        expected_controller_generation: Some(proof.controller_generation),
        expected_runner_generation: Some(proof.runner_generation),
    };
    validate_zero_transition(transition, &request)?;
    Ok(())
}

const fn expected_operation_for_stage(stage: Stage) -> Operation {
    match stage {
        Stage::CapacityZeroClosed => Operation::ObserveInitial,
        Stage::CapacityOneOpen => Operation::SetCapacityOne,
        Stage::ManifestIdentity => Operation::SubmitManifest,
        Stage::ApprovalGrant => Operation::ApproveGrant,
        Stage::GrantResume => Operation::ResumeGrant,
        Stage::FirstAttemptTerminal => Operation::AwaitFirstTerminal,
        Stage::AuthenticatedExport => Operation::ExportFirstEvidence,
        Stage::FailedManifestIdentity => Operation::SubmitFailureManifest,
        Stage::FailedAttemptRunning => Operation::ResumeFailure,
        Stage::FailedAttemptTerminal => Operation::AwaitFailureTerminal,
        Stage::RerunSeparation => Operation::Rerun,
        Stage::CancellationTerminal => Operation::CancelRerun,
        Stage::TombstoneFolding => Operation::TombstoneRerun,
        Stage::ControllerRestartRecovery => Operation::RestartController,
        Stage::RunnerRestartRecovery => Operation::RestartRunner,
        Stage::PrepareCapacityZero => Operation::SetCapacityZero,
    }
}

fn run_sequence<D: AcceptanceDriver>(
    scenario: &AcceptanceScenario,
    scenario_sha256: &str,
    driver: &mut D,
    checks: &mut Vec<StageReceipt>,
) -> Result<(), (Stage, AcceptanceError)> {
    let fixture = &scenario.fixture;
    let initial = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        1,
        Operation::ObserveInitial,
        Stage::CapacityZeroClosed,
        None,
        None,
        |response| validate_initial(&response.snapshot, fixture),
    )?;
    let one = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        2,
        Operation::SetCapacityOne,
        Stage::CapacityOneOpen,
        None,
        Some(&initial),
        |response| validate_capacity_one(&response.snapshot, &initial),
    )?;
    let submitted = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        3,
        Operation::SubmitManifest,
        Stage::ManifestIdentity,
        None,
        Some(&one),
        |response| validate_submitted(&response.snapshot, fixture, &one),
    )?;
    let granted = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        4,
        Operation::ApproveGrant,
        Stage::ApprovalGrant,
        None,
        Some(&submitted),
        |response| validate_granted(&response.snapshot, fixture, &submitted),
    )?;
    let running_one = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        5,
        Operation::ResumeGrant,
        Stage::GrantResume,
        None,
        Some(&granted),
        |response| validate_running_first(&response.snapshot, fixture, &granted),
    )?;
    let attempt_one_id = only_attempt(&running_one)
        .map_err(|error| (Stage::GrantResume, error))?
        .attempt_id
        .clone();
    let terminal_one = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        6,
        Operation::AwaitFirstTerminal,
        Stage::FirstAttemptTerminal,
        Some(&attempt_one_id),
        Some(&running_one),
        |response| {
            validate_terminal_first(&response.snapshot, fixture, &running_one, &attempt_one_id)
        },
    )?;
    let exported = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        7,
        Operation::ExportFirstEvidence,
        Stage::AuthenticatedExport,
        Some(&attempt_one_id),
        Some(&terminal_one),
        |response| validate_export(response, fixture, &terminal_one, &attempt_one_id),
    )?;
    let failed_submitted = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        8,
        Operation::SubmitFailureManifest,
        Stage::FailedManifestIdentity,
        None,
        Some(&exported),
        |response| validate_failure_submitted(&response.snapshot, fixture, &exported),
    )?;
    let failure_running = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        9,
        Operation::ResumeFailure,
        Stage::FailedAttemptRunning,
        None,
        Some(&failed_submitted),
        |response| validate_failure_running(&response.snapshot, fixture, &failed_submitted),
    )?;
    let failure_attempt_id = only_attempt(&failure_running)
        .map_err(|error| (Stage::FailedAttemptRunning, error))?
        .attempt_id
        .clone();
    let failure_terminal = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        10,
        Operation::AwaitFailureTerminal,
        Stage::FailedAttemptTerminal,
        Some(&failure_attempt_id),
        Some(&failure_running),
        |response| {
            validate_failure_terminal(
                &response.snapshot,
                fixture,
                &failure_running,
                &failure_attempt_id,
            )
        },
    )?;
    let rerun = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        11,
        Operation::Rerun,
        Stage::RerunSeparation,
        Some(&failure_attempt_id),
        Some(&failure_terminal),
        |response| {
            validate_rerun(
                &response.snapshot,
                fixture,
                &failure_terminal,
                &failure_attempt_id,
            )
        },
    )?;
    let attempt_two_id = attempt_by_number(&rerun, 2)
        .map_err(|error| (Stage::RerunSeparation, error))?
        .attempt_id
        .clone();
    let cancelled = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        12,
        Operation::CancelRerun,
        Stage::CancellationTerminal,
        Some(&attempt_two_id),
        Some(&rerun),
        |response| {
            validate_cancelled(
                &response.snapshot,
                fixture,
                &rerun,
                &failure_attempt_id,
                &attempt_two_id,
            )
        },
    )?;
    let tombstoned = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        13,
        Operation::TombstoneRerun,
        Stage::TombstoneFolding,
        Some(&attempt_two_id),
        Some(&cancelled),
        |response| {
            validate_tombstoned(
                &response.snapshot,
                fixture,
                &cancelled,
                &failure_attempt_id,
                &attempt_two_id,
            )
        },
    )?;
    let controller_recovered = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        14,
        Operation::RestartController,
        Stage::ControllerRestartRecovery,
        None,
        Some(&tombstoned),
        |response| validate_controller_restart(&response.snapshot, &tombstoned),
    )?;
    let runner_recovered = step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        15,
        Operation::RestartRunner,
        Stage::RunnerRestartRecovery,
        None,
        Some(&controller_recovered),
        |response| validate_runner_restart(&response.snapshot, &controller_recovered),
    )?;
    step(
        driver,
        fixture,
        scenario_sha256,
        checks,
        16,
        Operation::SetCapacityZero,
        Stage::PrepareCapacityZero,
        None,
        Some(&runner_recovered),
        |response| validate_final_zero(&response.snapshot, &runner_recovered),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn step<D, F>(
    driver: &mut D,
    fixture: &FixtureSpec,
    scenario_sha256: &str,
    checks: &mut Vec<StageReceipt>,
    sequence: u32,
    operation: Operation,
    stage: Stage,
    attempt_id: Option<&str>,
    expected: Option<&SystemSnapshot>,
    validate: F,
) -> Result<SystemSnapshot, (Stage, AcceptanceError)>
where
    D: AcceptanceDriver,
    F: FnOnce(&DriverResponse) -> Result<(), AcceptanceError>,
{
    let request = DriverRequest {
        schema_version: DRIVER_VERSION,
        scenario_sha256,
        sequence,
        operation,
        fixture,
        attempt_id,
        expected_controller_generation: expected.map(|value| value.controller_generation),
        expected_runner_generation: expected.map(|value| value.runner_generation),
    };
    let response = driver
        .execute(&request)
        .map_err(|error| (stage, AcceptanceError::Driver(error.to_string())))?;
    if response.schema_version != DRIVER_VERSION
        || response.sequence != sequence
        || response.operation != operation
    {
        return Err((stage, AcceptanceError::DriverBinding));
    }
    let evidence_sha256 = digest_json(&response).ok_or((
        stage,
        AcceptanceError::IntegrityMismatch("driver response serialization"),
    ))?;
    if operation != Operation::ExportFirstEvidence && response.export.is_some() {
        checks.push(StageReceipt {
            sequence,
            stage,
            outcome: Outcome::Fail,
            evidence_sha256,
            snapshot: response.snapshot,
            export: response.export,
        });
        return Err((
            stage,
            AcceptanceError::AmbiguousEvidence("unexpected export evidence"),
        ));
    }
    match validate(&response) {
        Ok(()) => {
            checks.push(StageReceipt {
                sequence,
                stage,
                outcome: Outcome::Pass,
                evidence_sha256,
                snapshot: response.snapshot.clone(),
                export: response.export.clone(),
            });
            Ok(response.snapshot)
        }
        Err(error) => {
            checks.push(StageReceipt {
                sequence,
                stage,
                outcome: Outcome::Fail,
                evidence_sha256,
                snapshot: response.snapshot.clone(),
                export: response.export.clone(),
            });
            Err((stage, error))
        }
    }
}

fn validate_initial(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    require(
        snapshot.controller_generation == fixture.controller_generation,
        "initial controller generation does not match the scenario",
    )?;
    require(
        snapshot.runner_generation == fixture.runner_generation,
        "initial runner generation does not match the scenario",
    )?;
    require(snapshot.capacity == 0, "initial capacity is not zero")?;
    require(
        snapshot.admission == AdmissionState::Closed,
        "initial admission is not closed",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "initial active work exists",
    )?;
    if snapshot.run.is_some() {
        return Err(AcceptanceError::AmbiguousEvidence(
            "fixture run exists before submission",
        ));
    }
    Ok(())
}

fn validate_capacity_one(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    validate_generations(snapshot, prior)?;
    require(snapshot.capacity == 1, "capacity did not become one")?;
    require(
        snapshot.admission == AdmissionState::Open,
        "admission did not open",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "capacity change started work",
    )?;
    if snapshot.run.is_some() {
        return Err(AcceptanceError::AmbiguousEvidence(
            "fixture run exists before submission",
        ));
    }
    Ok(())
}

fn validate_submitted(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_run(snapshot, fixture)?;
    require(
        run.state == RunState::AwaitingApproval,
        "submitted run did not wait for approval",
    )?;
    require(
        run.aggregate_conclusion == Conclusion::None,
        "unrun manifest has a conclusion",
    )?;
    require(run.approval.is_none(), "approval exists before grant")?;
    require(
        run.attempts.is_empty(),
        "attempt exists before grant resume",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "unapproved manifest consumed capacity",
    )?;
    Ok(())
}

fn validate_granted(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_run(snapshot, fixture)?;
    require(
        run.state == RunState::GrantedAwaitingResume,
        "grant did not stop at explicit resume boundary",
    )?;
    let approval = run
        .approval
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("approval grant"))?;
    validate_approval(approval, fixture, false)?;
    require(
        run.attempts.is_empty(),
        "grant started an attempt before resume",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "grant consumed capacity before resume",
    )?;
    Ok(())
}

fn validate_running_first(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_run(snapshot, fixture)?;
    require(run.state == RunState::Running, "resumed run is not running")?;
    let approval = run
        .approval
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("resumed approval"))?;
    validate_approval(approval, fixture, true)?;
    require(
        run.selected_attempt_id.is_none(),
        "running attempt was selected as terminal",
    )?;
    let attempt = only_attempt(snapshot)?;
    validate_attempt_identity(attempt, fixture)?;
    require(attempt.attempt == 1, "first attempt number is not one")?;
    require(
        attempt.parent_attempt_id.is_none(),
        "first attempt has a parent",
    )?;
    require(
        matches!(attempt.state, AttemptState::Queued | AttemptState::Running),
        "first attempt never entered execution",
    )?;
    require(
        attempt.conclusion == Conclusion::None,
        "running attempt has a conclusion",
    )?;
    require(
        snapshot.active_run_count == 1 && snapshot.active_attempt_count == 1,
        "running counters are not exactly one",
    )?;
    Ok(())
}

fn validate_terminal_first(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    attempt_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_run(snapshot, fixture)?;
    require(run.state == RunState::Terminal, "first run is not terminal")?;
    require(
        run.aggregate_conclusion == Conclusion::Success,
        "first run did not succeed",
    )?;
    require(
        run.selected_attempt_id.as_deref() == Some(attempt_id),
        "first terminal selection is ambiguous",
    )?;
    let attempt = attempt_by_id(run, attempt_id)?;
    require(
        run.attempts.len() == 1,
        "first terminal run has extra attempts",
    )?;
    validate_resumed_approval(run, fixture)?;
    validate_attempt_identity(attempt, fixture)?;
    require(
        attempt.state == AttemptState::Terminal,
        "first attempt is not terminal",
    )?;
    require(
        attempt.conclusion == Conclusion::Success,
        "first attempt did not succeed",
    )?;
    validate_attempt_evidence(attempt, fixture)?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "terminal run remains active",
    )?;
    Ok(())
}

fn validate_export(
    response: &DriverResponse,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    attempt_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(&response.snapshot, prior)?;
    require(
        response.snapshot.run == prior.run,
        "evidence export changed run state",
    )?;
    let export = response
        .export
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("authenticated export"))?;
    require(export.authenticated, "export is not authenticated")?;
    exact(&export.subject, &fixture.export_subject, "export subject")?;
    require(
        export.generation == fixture.export_generation,
        "export generation differs",
    )?;
    exact(
        &export.authorization_digest,
        &fixture.export_authorization_digest,
        "export authorization digest",
    )?;
    exact(&export.attempt_id, attempt_id, "export attempt")?;
    exact(
        &export.request_digest,
        &fixture.request_digest,
        "export request digest",
    )?;
    exact(
        &export.manifest_digest,
        &fixture.manifest_digest,
        "export manifest digest",
    )?;
    require_hex(
        &export.evidence_set_digest,
        64,
        "export evidence set digest",
    )?;
    let run = response
        .snapshot
        .run
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("exported run"))?;
    let attempt = attempt_by_id(run, attempt_id)?;
    exact(
        &export.evidence_set_digest,
        attempt
            .evidence_set_digest
            .as_deref()
            .ok_or(AcceptanceError::MissingEvidence(
                "attempt evidence set digest",
            ))?,
        "export evidence set digest",
    )?;
    validate_evidence_set(&export.objects, fixture)?;
    Ok(())
}

fn validate_failure_submitted(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    require(
        run.state == RunState::GrantedAwaitingResume,
        "failed-parent run did not stop at explicit resume boundary",
    )?;
    validate_resumed_state(run, fixture, false)?;
    require(run.attempts.is_empty(), "failed-parent run started early")?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "failed-parent submission consumed capacity",
    )
}

fn validate_failure_running(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    validate_resumed_state(run, fixture, true)?;
    require(
        run.state == RunState::Running,
        "failed-parent attempt is not running",
    )?;
    let attempt = only_attempt(snapshot)?;
    validate_failure_attempt_identity(attempt, fixture)?;
    require(
        attempt.attempt == 1,
        "failed-parent attempt number is not one",
    )?;
    require(
        attempt.parent_attempt_id.is_none(),
        "failed-parent attempt has a parent",
    )?;
    require(
        attempt.conclusion == Conclusion::None,
        "running failed-parent has a conclusion",
    )?;
    require(
        snapshot.active_run_count == 1 && snapshot.active_attempt_count == 1,
        "failed-parent counters are not exactly one",
    )
}

fn validate_failure_terminal(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    attempt_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    validate_resumed_state(run, fixture, true)?;
    require(
        run.state == RunState::Terminal,
        "failed-parent run is not terminal",
    )?;
    require(
        run.aggregate_conclusion == Conclusion::Failure,
        "failed-parent run did not fail",
    )?;
    require(
        run.selected_attempt_id.as_deref() == Some(attempt_id),
        "failed parent is not selected",
    )?;
    require(
        run.attempts.len() == 1,
        "failed-parent run has extra attempts",
    )?;
    let attempt = attempt_by_id(run, attempt_id)?;
    validate_failure_attempt_identity(attempt, fixture)?;
    require(
        attempt.state == AttemptState::Terminal,
        "failed-parent attempt is not terminal",
    )?;
    require(
        attempt.conclusion == Conclusion::Failure,
        "failed-parent attempt did not fail",
    )?;
    validate_failure_attempt_evidence(attempt, fixture)?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "failed-parent run remains active",
    )
}

fn validate_rerun(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    first_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    validate_resumed_approval(run, fixture)?;
    require(run.state == RunState::Running, "rerun is not running")?;
    require(
        run.aggregate_conclusion == Conclusion::None,
        "running rerun has an aggregate conclusion",
    )?;
    require(
        run.attempts.len() == 2,
        "rerun did not produce exactly two attempts",
    )?;
    let first = attempt_by_id(run, first_id)?;
    validate_failure_attempt_evidence(first, fixture)?;
    require(
        first.state == AttemptState::Terminal && first.conclusion == Conclusion::Failure,
        "rerun changed the first attempt",
    )?;
    let second = attempt_by_number(snapshot, 2)?;
    validate_failure_attempt_identity(second, fixture)?;
    require(
        second.attempt_id != first_id,
        "rerun reused the first attempt ID",
    )?;
    require(
        second.parent_attempt_id.as_deref() == Some(first_id),
        "rerun parent does not bind the first attempt",
    )?;
    require(
        matches!(second.state, AttemptState::Queued | AttemptState::Running),
        "rerun never entered execution",
    )?;
    require(
        second.conclusion == Conclusion::None,
        "running rerun has a conclusion",
    )?;
    require(
        snapshot.active_run_count == 1 && snapshot.active_attempt_count == 1,
        "rerun counters are not exactly one",
    )?;
    Ok(())
}

fn validate_cancelled(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    first_id: &str,
    second_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    validate_resumed_approval(run, fixture)?;
    require(
        run.attempts.len() == 2,
        "cancelled run does not have exactly two attempts",
    )?;
    require(
        run.state == RunState::Terminal,
        "cancelled rerun is not terminal",
    )?;
    require(
        run.aggregate_conclusion == Conclusion::Cancelled,
        "cancelled rerun has the wrong aggregate conclusion",
    )?;
    require(
        run.selected_attempt_id.as_deref() == Some(second_id),
        "cancelled attempt is not selected",
    )?;
    let first = attempt_by_id(run, first_id)?;
    require(
        first.state == AttemptState::Terminal && first.conclusion == Conclusion::Failure,
        "cancellation changed the first attempt",
    )?;
    validate_failure_attempt_evidence(first, fixture)?;
    let second = attempt_by_id(run, second_id)?;
    require(
        second.state == AttemptState::Terminal,
        "cancelled attempt is not terminal",
    )?;
    require(
        second.conclusion == Conclusion::Cancelled,
        "attempt is not cancelled",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "cancelled attempt remains active",
    )?;
    Ok(())
}

fn validate_tombstoned(
    snapshot: &SystemSnapshot,
    fixture: &FixtureSpec,
    prior: &SystemSnapshot,
    first_id: &str,
    second_id: &str,
) -> Result<(), AcceptanceError> {
    validate_live_capacity(snapshot, prior)?;
    let run = exact_failure_run(snapshot, fixture)?;
    validate_resumed_approval(run, fixture)?;
    require(
        run.attempts.len() == 2,
        "folded run does not have exactly two attempts",
    )?;
    require(
        run.state == RunState::Terminal,
        "folded run is not terminal",
    )?;
    require(
        run.aggregate_conclusion == Conclusion::Failure,
        "tombstone did not fold back to the failed attempt",
    )?;
    require(
        run.selected_attempt_id.as_deref() == Some(first_id),
        "tombstone did not select the surviving attempt",
    )?;
    let first = attempt_by_id(run, first_id)?;
    require(
        first.state == AttemptState::Terminal && first.conclusion == Conclusion::Failure,
        "tombstone changed the surviving attempt",
    )?;
    validate_failure_attempt_evidence(first, fixture)?;
    let second = attempt_by_id(run, second_id)?;
    require(
        second.state == AttemptState::Tombstoned && second.conclusion == Conclusion::Cancelled,
        "cancelled rerun tombstone is not visible",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "tombstoned run remains active",
    )?;
    Ok(())
}

fn validate_controller_restart(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    require(
        snapshot.controller_generation > prior.controller_generation,
        "controller generation did not advance",
    )?;
    require(
        snapshot.runner_generation >= prior.runner_generation,
        "runner generation regressed during controller restart",
    )?;
    require_same_persistent_state(snapshot, prior)
}

fn validate_runner_restart(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    require(
        snapshot.runner_generation > prior.runner_generation,
        "runner generation did not advance",
    )?;
    require(
        snapshot.controller_generation >= prior.controller_generation,
        "controller generation regressed during runner restart",
    )?;
    require_same_persistent_state(snapshot, prior)
}

fn validate_final_zero(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    validate_generations(snapshot, prior)?;
    require(snapshot.capacity == 0, "final capacity is not zero")?;
    require(
        snapshot.admission == AdmissionState::Closed,
        "final admission is not closed",
    )?;
    require(
        snapshot.active_run_count == 0 && snapshot.active_attempt_count == 0,
        "active work remains after capacity zero",
    )?;
    require(
        snapshot.run == prior.run,
        "capacity zero changed durable run state",
    )?;
    Ok(())
}

fn validate_live_capacity(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    validate_global(snapshot)?;
    validate_generations(snapshot, prior)?;
    require(snapshot.capacity == 1, "capacity is not exactly one")?;
    require(
        snapshot.admission == AdmissionState::Open,
        "admission is not open",
    )
}

fn validate_global(snapshot: &SystemSnapshot) -> Result<(), AcceptanceError> {
    require(snapshot.capacity <= 1, "capacity exceeded one")?;
    require(
        snapshot.controller_generation > 0,
        "controller generation is missing",
    )?;
    require(
        snapshot.runner_generation > 0,
        "runner generation is missing",
    )?;
    if snapshot.active_run_count > 1 || snapshot.active_attempt_count > 1 {
        return Err(AcceptanceError::AmbiguousEvidence(
            "more than one active run or attempt",
        ));
    }
    Ok(())
}

fn validate_generations(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    require(
        snapshot.controller_generation >= prior.controller_generation,
        "controller generation regressed",
    )?;
    require(
        snapshot.runner_generation >= prior.runner_generation,
        "runner generation regressed",
    )
}

fn exact_run<'a>(
    snapshot: &'a SystemSnapshot,
    fixture: &FixtureSpec,
) -> Result<&'a RunSnapshot, AcceptanceError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("fixture run"))?;
    exact(&run.run_id, &fixture.run_id, "run ID")?;
    exact(
        &run.integrated_candidate_sha,
        &fixture.integrated_candidate_sha,
        "integrated candidate",
    )?;
    exact(
        &run.request_digest,
        &fixture.request_digest,
        "request digest",
    )?;
    exact(
        &run.manifest_digest,
        &fixture.manifest_digest,
        "manifest digest",
    )?;
    exact(&run.source_oid, &fixture.source_oid, "source object ID")?;
    let mut ids = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    for attempt in &run.attempts {
        require_hex(&attempt.attempt_id, 32, "attempt ID")?;
        if !ids.insert(attempt.attempt_id.as_str()) || !numbers.insert(attempt.attempt) {
            return Err(AcceptanceError::AmbiguousEvidence("duplicate attempt"));
        }
    }
    Ok(run)
}

fn exact_failure_run<'a>(
    snapshot: &'a SystemSnapshot,
    fixture: &FixtureSpec,
) -> Result<&'a RunSnapshot, AcceptanceError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("failed-parent run"))?;
    exact(&run.run_id, &fixture.failure_run_id, "failed-parent run ID")?;
    exact(
        &run.integrated_candidate_sha,
        &fixture.integrated_candidate_sha,
        "integrated candidate",
    )?;
    exact(
        &run.request_digest,
        &fixture.failure_request_digest,
        "failed-parent request digest",
    )?;
    exact(
        &run.manifest_digest,
        &fixture.manifest_digest,
        "manifest digest",
    )?;
    exact(&run.source_oid, &fixture.source_oid, "source object ID")?;
    let mut ids = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    for attempt in &run.attempts {
        require_hex(&attempt.attempt_id, 32, "attempt ID")?;
        if !ids.insert(attempt.attempt_id.as_str()) || !numbers.insert(attempt.attempt) {
            return Err(AcceptanceError::AmbiguousEvidence("duplicate attempt"));
        }
    }
    Ok(run)
}

fn validate_approval(
    approval: &ApprovalSnapshot,
    fixture: &FixtureSpec,
    resumed: bool,
) -> Result<(), AcceptanceError> {
    exact(&approval.approval_id, &fixture.approval_id, "approval ID")?;
    exact(
        &approval.grant_event_id,
        &fixture.grant_event_id,
        "grant event ID",
    )?;
    exact(
        &approval.grant_digest,
        &fixture.grant_digest,
        "grant digest",
    )?;
    exact(
        &approval.approved_by,
        &fixture.approved_by,
        "grant approver",
    )?;
    require(approval.resumed == resumed, "grant resume state is wrong")
}

fn validate_resumed_approval(
    run: &RunSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    let approval = run
        .approval
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("resumed approval"))?;
    validate_approval(approval, fixture, true)
}

fn validate_resumed_state(
    run: &RunSnapshot,
    fixture: &FixtureSpec,
    resumed: bool,
) -> Result<(), AcceptanceError> {
    let approval = run
        .approval
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("approval grant"))?;
    validate_approval(approval, fixture, resumed)
}

fn validate_attempt_identity(
    attempt: &AttemptSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    exact(
        &attempt.integrated_candidate_sha,
        &fixture.integrated_candidate_sha,
        "attempt candidate",
    )?;
    exact(
        &attempt.request_digest,
        &fixture.request_digest,
        "attempt request digest",
    )?;
    exact(
        &attempt.manifest_digest,
        &fixture.manifest_digest,
        "attempt manifest digest",
    )?;
    exact(
        &attempt.source_oid,
        &fixture.source_oid,
        "attempt source object",
    )
}

fn validate_failure_attempt_identity(
    attempt: &AttemptSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    exact(
        &attempt.integrated_candidate_sha,
        &fixture.integrated_candidate_sha,
        "attempt candidate",
    )?;
    exact(
        &attempt.request_digest,
        &fixture.failure_request_digest,
        "failed-parent attempt request digest",
    )?;
    exact(
        &attempt.manifest_digest,
        &fixture.manifest_digest,
        "attempt manifest digest",
    )?;
    exact(
        &attempt.source_oid,
        &fixture.source_oid,
        "attempt source object",
    )
}

fn validate_failure_attempt_evidence(
    attempt: &AttemptSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    require_hex(
        attempt
            .evidence_set_digest
            .as_deref()
            .ok_or(AcceptanceError::MissingEvidence(
                "failed-parent evidence set digest",
            ))?,
        64,
        "failed-parent evidence set digest",
    )?;
    let log = attempt
        .log
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("failed-parent log"))?;
    exact_evidence(log, &fixture.expected_failure_log)?;
    require(
        attempt.artifacts.is_empty(),
        "failed-parent attempt emitted artifacts",
    )
}

fn validate_attempt_evidence(
    attempt: &AttemptSnapshot,
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    require_hex(
        attempt
            .evidence_set_digest
            .as_deref()
            .ok_or(AcceptanceError::MissingEvidence(
                "attempt evidence set digest",
            ))?,
        64,
        "attempt evidence set digest",
    )?;
    let log = attempt
        .log
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("attempt log"))?;
    exact_evidence(log, &fixture.expected_log)?;
    let mut objects = Vec::with_capacity(1 + attempt.artifacts.len());
    objects.push(log.clone());
    objects.extend(attempt.artifacts.clone());
    validate_evidence_set(&objects, fixture)
}

fn validate_evidence_set(
    objects: &[EvidenceObject],
    fixture: &FixtureSpec,
) -> Result<(), AcceptanceError> {
    let mut expected = BTreeMap::new();
    expected.insert(fixture.expected_log.name.as_str(), &fixture.expected_log);
    for artifact in &fixture.expected_artifacts {
        if expected.insert(artifact.name.as_str(), artifact).is_some() {
            return Err(AcceptanceError::AmbiguousEvidence(
                "duplicate expected evidence object",
            ));
        }
    }
    let mut actual = BTreeMap::new();
    for object in objects {
        if actual.insert(object.name.as_str(), object).is_some() {
            return Err(AcceptanceError::AmbiguousEvidence(
                "duplicate observed evidence object",
            ));
        }
    }
    require(
        actual.len() == expected.len(),
        "evidence object count does not match fixture",
    )?;
    for (name, expected_object) in expected {
        let actual_object = actual
            .get(name)
            .ok_or(AcceptanceError::MissingEvidence("expected evidence object"))?;
        exact_evidence(actual_object, expected_object)?;
    }
    Ok(())
}

fn exact_evidence(
    actual: &EvidenceObject,
    expected: &EvidenceObject,
) -> Result<(), AcceptanceError> {
    exact(&actual.name, &expected.name, "evidence object name")?;
    exact(&actual.sha256, &expected.sha256, "evidence object digest")?;
    require(
        actual.bytes == expected.bytes,
        "evidence object byte length does not match",
    )
}

fn attempt_by_id<'a>(
    run: &'a RunSnapshot,
    attempt_id: &str,
) -> Result<&'a AttemptSnapshot, AcceptanceError> {
    let mut matches = run
        .attempts
        .iter()
        .filter(|attempt| attempt.attempt_id == attempt_id);
    let attempt = matches
        .next()
        .ok_or(AcceptanceError::MissingEvidence("attempt ID"))?;
    if matches.next().is_some() {
        return Err(AcceptanceError::AmbiguousEvidence("attempt ID"));
    }
    Ok(attempt)
}

fn only_attempt(snapshot: &SystemSnapshot) -> Result<&AttemptSnapshot, AcceptanceError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("fixture run"))?;
    if run.attempts.len() != 1 {
        return Err(AcceptanceError::AmbiguousEvidence(
            "expected exactly one attempt",
        ));
    }
    run.attempts
        .first()
        .ok_or(AcceptanceError::MissingEvidence("first attempt"))
}

fn attempt_by_number(
    snapshot: &SystemSnapshot,
    number: u32,
) -> Result<&AttemptSnapshot, AcceptanceError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(AcceptanceError::MissingEvidence("fixture run"))?;
    let mut matches = run
        .attempts
        .iter()
        .filter(|attempt| attempt.attempt == number);
    let attempt = matches
        .next()
        .ok_or(AcceptanceError::MissingEvidence("attempt number"))?;
    if matches.next().is_some() {
        return Err(AcceptanceError::AmbiguousEvidence("attempt number"));
    }
    Ok(attempt)
}

fn require_same_persistent_state(
    snapshot: &SystemSnapshot,
    prior: &SystemSnapshot,
) -> Result<(), AcceptanceError> {
    require(
        snapshot.capacity == prior.capacity,
        "capacity changed during restart",
    )?;
    require(
        snapshot.admission == prior.admission,
        "admission changed during restart",
    )?;
    require(
        snapshot.active_run_count == prior.active_run_count
            && snapshot.active_attempt_count == prior.active_attempt_count,
        "active counters changed during restart",
    )?;
    require(
        snapshot.run == prior.run,
        "durable run state changed during restart",
    )
}

fn require(condition: bool, message: &'static str) -> Result<(), AcceptanceError> {
    if condition {
        Ok(())
    } else {
        Err(AcceptanceError::InvalidTransition(message))
    }
}

fn exact(actual: &str, expected: &str, field: &'static str) -> Result<(), AcceptanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AcceptanceError::IdentityMismatch(field))
    }
}

fn validate_scenario(scenario: &AcceptanceScenario) -> Result<(), ScenarioError> {
    if scenario.schema_version != SCENARIO_VERSION {
        return Err(ScenarioError::UnsupportedVersion);
    }
    let fixture = &scenario.fixture;
    validate_hex_field(
        &fixture.integrated_candidate_sha,
        &[40, 64],
        "fixture.integrated_candidate_sha",
    )?;
    for (value, field, lengths) in [
        (
            &fixture.activation_package_digest,
            "fixture.activation_package_digest",
            &[64][..],
        ),
        (&fixture.run_id, "fixture.run_id", &[32][..]),
        (&fixture.failure_run_id, "fixture.failure_run_id", &[32][..]),
        (&fixture.request_digest, "fixture.request_digest", &[64][..]),
        (
            &fixture.failure_request_digest,
            "fixture.failure_request_digest",
            &[64][..],
        ),
        (
            &fixture.manifest_digest,
            "fixture.manifest_digest",
            &[64][..],
        ),
        (&fixture.source_oid, "fixture.source_oid", &[40, 64][..]),
        (&fixture.approval_id, "fixture.approval_id", &[32][..]),
        (&fixture.grant_event_id, "fixture.grant_event_id", &[64][..]),
        (&fixture.grant_digest, "fixture.grant_digest", &[64][..]),
        (&fixture.approved_by, "fixture.approved_by", &[64][..]),
        (&fixture.export_subject, "fixture.export_subject", &[64][..]),
        (
            &fixture.export_authorization_digest,
            "fixture.export_authorization_digest",
            &[64][..],
        ),
    ] {
        validate_hex_field(value, lengths, field)?;
    }
    if fixture.run_id == fixture.failure_run_id
        || fixture.request_digest == fixture.failure_request_digest
    {
        return Err(ScenarioError::InvalidField("fixture.failure_run_id"));
    }
    let run_uuid = uuid::Uuid::parse_str(&fixture.run_id)
        .map_err(|_| ScenarioError::InvalidField("fixture.run_id"))?;
    let failure_uuid = uuid::Uuid::parse_str(&fixture.failure_run_id)
        .map_err(|_| ScenarioError::InvalidField("fixture.failure_run_id"))?;
    if run_uuid.get_version_num() != 5
        || failure_uuid.get_version_num() != 5
        || !valid_fixture_selector(
            &fixture.failure_selector,
            &fixture.failure_run_id,
            &fixture.job_id,
        )
    {
        return Err(ScenarioError::InvalidField("fixture.failure_selector"));
    }
    if fixture.activation_id.is_empty()
        || fixture.activation_id.len() > 128
        || !fixture
            .activation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ScenarioError::InvalidField("fixture.activation_id"));
    }
    let mut job_bytes = fixture.job_id.bytes();
    if !job_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || fixture.job_id.len() > 64
        || !job_bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ScenarioError::InvalidField("fixture.job_id"));
    }
    if fixture.export_generation == 0 || fixture.export_generation > 9_007_199_254_740_991 {
        return Err(ScenarioError::InvalidField("fixture.export_generation"));
    }
    if fixture.controller_generation == 0 || fixture.runner_generation == 0 {
        return Err(ScenarioError::InvalidField("fixture.service_generation"));
    }
    validate_expected_evidence(&fixture.expected_log, "fixture.expected_log")?;
    validate_expected_evidence(
        &fixture.expected_failure_log,
        "fixture.expected_failure_log",
    )?;
    if fixture.expected_artifacts.len() != 1 {
        return Err(ScenarioError::InvalidField("fixture.expected_artifacts"));
    }
    let mut names = BTreeSet::new();
    names.insert(fixture.expected_log.name.as_str());
    for artifact in &fixture.expected_artifacts {
        validate_expected_evidence(artifact, "fixture.expected_artifacts")?;
        if !names.insert(artifact.name.as_str()) {
            return Err(ScenarioError::InvalidField("fixture.expected_artifacts"));
        }
    }
    if !(1..=300).contains(&scenario.driver.timeout_seconds) {
        return Err(ScenarioError::InvalidField("driver.timeout_seconds"));
    }
    for endpoint in [
        &scenario.driver.control,
        &scenario.driver.observe,
        &scenario.driver.export,
        &scenario.driver.controller_process,
        &scenario.driver.runner_process,
    ] {
        validate_endpoint(endpoint)?;
    }
    Ok(())
}

fn validate_expected_evidence(
    evidence: &EvidenceObject,
    field: &'static str,
) -> Result<(), ScenarioError> {
    if evidence.name.is_empty()
        || evidence.name.len() > 255
        || evidence.name.contains('/')
        || evidence.name.contains('\\')
        || evidence.bytes == 0
    {
        return Err(ScenarioError::InvalidField(field));
    }
    validate_hex_field(&evidence.sha256, &[64], field)
}

fn validate_endpoint(endpoint: &ProcessEndpoint) -> Result<(), ScenarioError> {
    if endpoint.program != "/usr/libexec/buzz-ci-capacity-one-driver"
        || !Path::new(&endpoint.program).is_absolute()
        || !endpoint.args.is_empty()
    {
        return Err(ScenarioError::InvalidField("driver endpoint"));
    }
    Ok(())
}

fn validate_hex_field(
    value: &str,
    lengths: &[usize],
    field: &'static str,
) -> Result<(), ScenarioError> {
    if lengths.contains(&value.len())
        && is_normalized_hex(value)
        && !value.bytes().all(|b| b == b'0')
    {
        Ok(())
    } else {
        Err(ScenarioError::InvalidField(field))
    }
}

fn require_hex(value: &str, length: usize, field: &'static str) -> Result<(), AcceptanceError> {
    if value.len() == length && is_normalized_hex(value) && !value.bytes().all(|b| b == b'0') {
        Ok(())
    } else {
        Err(AcceptanceError::IntegrityMismatch(field))
    }
}

fn is_normalized_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_json(value: &impl Serialize) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|encoded| digest_bytes(&encoded))
}

fn digest_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Subprocess-backed driver using the scenario's injected endpoints.
pub struct CommandAcceptanceDriver {
    endpoints: DriverEndpoints,
}

impl CommandAcceptanceDriver {
    /// Construct a driver from validated injected endpoints.
    pub const fn new(endpoints: DriverEndpoints) -> Self {
        Self { endpoints }
    }

    fn endpoint(&self, operation: Operation) -> &ProcessEndpoint {
        match operation {
            Operation::ObserveInitial => &self.endpoints.observe,
            Operation::ExportFirstEvidence => &self.endpoints.export,
            Operation::RestartController => &self.endpoints.controller_process,
            Operation::RestartRunner => &self.endpoints.runner_process,
            Operation::SetCapacityOne
            | Operation::SubmitManifest
            | Operation::ApproveGrant
            | Operation::ResumeGrant
            | Operation::AwaitFirstTerminal
            | Operation::SubmitFailureManifest
            | Operation::ResumeFailure
            | Operation::AwaitFailureTerminal
            | Operation::Rerun
            | Operation::CancelRerun
            | Operation::TombstoneRerun
            | Operation::SetCapacityZero => &self.endpoints.control,
        }
    }

    fn invoke<I: Serialize, O: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &ProcessEndpoint,
        request: &I,
    ) -> Result<O, CommandDriverError> {
        let mut child = Command::new(&endpoint.program)
            .args(&endpoint.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| CommandDriverError::Spawn)?;
        let mut stdin = child.stdin.take().ok_or(CommandDriverError::Spawn)?;
        let write_result = serde_json::to_writer(&mut stdin, request)
            .map_err(|_| CommandDriverError::RequestWrite)
            .and_then(|()| {
                stdin
                    .write_all(b"\n")
                    .map_err(|_| CommandDriverError::RequestWrite)
            });
        drop(stdin);
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        let stdout = child.stdout.take().ok_or(CommandDriverError::OutputRead)?;
        let stderr = child.stderr.take().ok_or(CommandDriverError::OutputRead)?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));
        let deadline = Instant::now() + Duration::from_secs(self.endpoints.timeout_seconds);
        let status = loop {
            match child
                .try_wait()
                .map_err(|_| CommandDriverError::OutputRead)?
            {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(CommandDriverError::Timeout);
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| CommandDriverError::OutputRead)??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| CommandDriverError::OutputRead)??;
        if stdout.len() > MAX_DRIVER_OUTPUT_BYTES || stderr.len() > MAX_DRIVER_OUTPUT_BYTES {
            return Err(CommandDriverError::OutputTooLarge);
        }
        if !status.success() {
            return Err(CommandDriverError::Unsuccessful);
        }
        serde_json::from_slice(&stdout).map_err(|_| CommandDriverError::MalformedResponse)
    }
}

/// Stable subprocess adapter failure. Raw output is never copied into receipts.
#[derive(Debug, Error)]
pub enum CommandDriverError {
    #[error("could not start driver endpoint")]
    Spawn,
    #[error("could not write driver request")]
    RequestWrite,
    #[error("driver endpoint timed out")]
    Timeout,
    #[error("driver endpoint output exceeded the limit")]
    OutputTooLarge,
    #[error("driver endpoint exited unsuccessfully")]
    Unsuccessful,
    #[error("driver endpoint returned malformed JSON")]
    MalformedResponse,
    #[error("could not collect driver endpoint output")]
    OutputRead,
}

impl AcceptanceDriver for CommandAcceptanceDriver {
    type Error = CommandDriverError;

    fn execute(&mut self, request: &DriverRequest<'_>) -> Result<DriverResponse, Self::Error> {
        let endpoint = self.endpoint(request.operation);
        self.invoke(endpoint, request)
    }

    fn return_to_zero(&mut self, request: &ZeroRequest) -> Result<ZeroTransition, Self::Error> {
        self.invoke(&self.endpoints.control, request)
    }
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, CommandDriverError> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take((MAX_DRIVER_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| CommandDriverError::OutputRead)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    struct ScriptedDriver {
        responses: Vec<DriverResponse>,
        index: usize,
    }

    impl AcceptanceDriver for ScriptedDriver {
        type Error = Infallible;

        fn execute(&mut self, _request: &DriverRequest<'_>) -> Result<DriverResponse, Self::Error> {
            let response = self.responses[self.index].clone();
            self.index += 1;
            Ok(response)
        }

        fn return_to_zero(&mut self, request: &ZeroRequest) -> Result<ZeroTransition, Self::Error> {
            Ok(zero_transition_for(request, false))
        }
    }

    struct FaultDriver {
        responses: Vec<DriverResponse>,
        fail_sequence: u32,
        zero_failures: usize,
        zero_requests: Vec<ZeroRequest>,
        wrong_zero: bool,
    }

    impl AcceptanceDriver for FaultDriver {
        type Error = &'static str;

        fn execute(&mut self, request: &DriverRequest<'_>) -> Result<DriverResponse, Self::Error> {
            if request.sequence == self.fail_sequence {
                Err("transport unavailable or timed out")
            } else {
                Ok(self.responses[request.sequence as usize - 1].clone())
            }
        }

        fn return_to_zero(&mut self, request: &ZeroRequest) -> Result<ZeroTransition, Self::Error> {
            self.zero_requests.push(request.clone());
            if self.zero_failures > 0 {
                self.zero_failures -= 1;
                return Err("transport unavailable or timed out");
            }
            Ok(zero_transition_for(request, self.wrong_zero))
        }
    }

    fn zero_proof_for(request: &ZeroRequest) -> ZeroProof {
        ZeroProof {
            schema_version: ZERO_PROOF_VERSION.to_owned(),
            scenario_sha256: request.scenario_sha256.clone(),
            activation_id: request.activation_id.clone(),
            activation_package_digest: request.activation_package_digest.clone(),
            integrated_candidate_sha: request.integrated_candidate_sha.clone(),
            capacity: 0,
            admission: AdmissionState::Closed,
            controller_generation: request.expected_controller_generation.unwrap_or(2),
            runner_generation: request.expected_runner_generation.unwrap_or(2),
            controld_service_active: false,
            controld_acceptance_socket_active: false,
            controld_acceptance_socket_present: false,
        }
    }

    fn zero_transition_for(request: &ZeroRequest, wrong: bool) -> ZeroTransition {
        let mut proof = zero_proof_for(request);
        if wrong {
            proof.controld_acceptance_socket_present = true;
        }
        let phases = [
            (17, ZeroOperation::FinalizeCapacityZero),
            (18, ZeroOperation::ProveCapacityZero),
        ]
        .into_iter()
        .map(|(sequence, operation)| {
            let phase_request = ZeroPhaseRequest {
                sequence,
                operation,
                operation_id: digest_bytes(format!("zero-{sequence}").as_bytes()),
                scenario_sha256: request.scenario_sha256.clone(),
                activation_id: request.activation_id.clone(),
                activation_package_digest: request.activation_package_digest.clone(),
                integrated_candidate_sha: request.integrated_candidate_sha.clone(),
                failed_stage: request.failed_stage,
                final_response_sha256: request.final_response_sha256.clone(),
                expected_controller_generation: request.expected_controller_generation,
                expected_runner_generation: request.expected_runner_generation,
            };
            let phase_response = ZeroPhaseResponse {
                operation_id: phase_request.operation_id.clone(),
                controller_receipt_sha256: digest_bytes(b"controller-zero-receipt"),
                proof: proof.clone(),
            };
            ZeroPhaseReceipt {
                sequence,
                operation,
                outcome: Outcome::Pass,
                attempts: 1,
                request_sha256: digest_json(&phase_request).unwrap(),
                response_sha256: digest_json(&phase_response).unwrap(),
                request: phase_request,
                response: phase_response,
            }
        })
        .collect();
        ZeroTransition {
            schema_version: ZERO_TRANSITION_VERSION.to_owned(),
            outcome: Outcome::Pass,
            attempts: 1,
            phases,
            zero_proof: proof,
        }
    }

    fn hex(byte: char, length: usize) -> String {
        std::iter::repeat_n(byte, length).collect()
    }

    fn evidence(name: &str, byte: char, bytes: u64) -> EvidenceObject {
        EvidenceObject {
            name: name.to_owned(),
            sha256: hex(byte, 64),
            bytes,
        }
    }

    fn selector(run_id: &str, job_id: &str) -> FixtureSelector {
        let parsed = uuid::Uuid::parse_str(run_id).unwrap();
        let encoded = format!(
            "buzz-ci:capacity-one:fixture-selector:v1\nbuzz-ci-capacity-one-fixture-selector/v1\ndeterministic-failure\n{job_id}\n{}\n1\n",
            parsed.simple(),
        );
        FixtureSelector {
            schema_version: "buzz-ci-capacity-one-fixture-selector/v1".into(),
            selector: "deterministic-failure".into(),
            job_id: job_id.into(),
            run_id: parsed.hyphenated().to_string(),
            attempt: 1,
            sha256: hex::encode(Sha256::digest(encoded.as_bytes())),
        }
    }

    fn scenario() -> AcceptanceScenario {
        let endpoint = ProcessEndpoint {
            program: "/usr/libexec/buzz-ci-capacity-one-driver".to_owned(),
            args: Vec::new(),
        };
        AcceptanceScenario {
            schema_version: SCENARIO_VERSION.to_owned(),
            fixture: FixtureSpec {
                integrated_candidate_sha: hex('a', 40),
                activation_id: "buzz-ci-capacity-one-test".to_owned(),
                activation_package_digest: hex('8', 64),
                run_id: "bbbbbbbbbbbb5bbb9bbbbbbbbbbbbbbb".into(),
                failure_run_id: "cccccccccccc5ccc9ccccccccccccccc".into(),
                failure_selector: selector("cccccccc-cccc-5ccc-9ccc-cccccccccccc", "fixture"),
                job_id: "fixture".to_owned(),
                request_digest: hex('c', 64),
                failure_request_digest: hex('f', 64),
                manifest_digest: hex('d', 64),
                source_oid: hex('e', 40),
                approval_id: hex('1', 32),
                grant_event_id: hex('9', 64),
                grant_digest: hex('2', 64),
                approved_by: hex('3', 64),
                export_subject: hex('4', 64),
                export_generation: 6,
                export_authorization_digest: hex('5', 64),
                controller_generation: 1,
                runner_generation: 1,
                expected_log: evidence("job.log", '6', 12),
                expected_failure_log: evidence("job.log", '5', 18),
                expected_artifacts: vec![evidence("result.json", '7', 24)],
            },
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

    fn approval(fixture: &FixtureSpec, resumed: bool) -> ApprovalSnapshot {
        ApprovalSnapshot {
            approval_id: fixture.approval_id.clone(),
            grant_event_id: fixture.grant_event_id.clone(),
            grant_digest: fixture.grant_digest.clone(),
            approved_by: fixture.approved_by.clone(),
            resumed,
        }
    }

    fn attempt(
        fixture: &FixtureSpec,
        id: char,
        number: u32,
        parent: Option<char>,
        state: AttemptState,
        conclusion: Conclusion,
        with_evidence: bool,
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
            evidence_set_digest: with_evidence.then(|| hex('8', 64)),
            log: with_evidence.then(|| fixture.expected_log.clone()),
            artifacts: if with_evidence {
                fixture.expected_artifacts.clone()
            } else {
                Vec::new()
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

    fn failure_attempt(
        fixture: &FixtureSpec,
        id: char,
        number: u32,
        parent: Option<char>,
        state: AttemptState,
        conclusion: Conclusion,
        with_evidence: bool,
    ) -> AttemptSnapshot {
        let mut value = attempt(fixture, id, number, parent, state, conclusion, false);
        value.request_digest = fixture.failure_request_digest.clone();
        if with_evidence {
            value.evidence_set_digest = Some(hex('8', 64));
            value.log = Some(fixture.expected_failure_log.clone());
        }
        value
    }

    fn failure_run(
        fixture: &FixtureSpec,
        state: RunState,
        conclusion: Conclusion,
        approval: Option<ApprovalSnapshot>,
        selected: Option<char>,
        attempts: Vec<AttemptSnapshot>,
    ) -> RunSnapshot {
        let mut value = run(fixture, state, conclusion, approval, selected, attempts);
        value.run_id = fixture.failure_run_id.clone();
        value.request_digest = fixture.failure_request_digest.clone();
        value
    }

    fn snapshot(
        capacity: u32,
        active: u32,
        controller_generation: u64,
        runner_generation: u64,
        run: Option<RunSnapshot>,
    ) -> SystemSnapshot {
        SystemSnapshot {
            capacity,
            admission: if capacity == 0 {
                AdmissionState::Closed
            } else {
                AdmissionState::Open
            },
            active_run_count: active,
            active_attempt_count: active,
            controller_generation,
            runner_generation,
            run,
        }
    }

    fn response(
        sequence: u32,
        operation: Operation,
        snapshot: SystemSnapshot,
        export: Option<ExportSnapshot>,
    ) -> DriverResponse {
        DriverResponse {
            schema_version: DRIVER_VERSION.to_owned(),
            sequence,
            operation,
            snapshot,
            export,
        }
    }

    fn passing_responses(scenario: &AcceptanceScenario) -> Vec<DriverResponse> {
        let fixture = &scenario.fixture;
        let first_running = attempt(
            fixture,
            '9',
            1,
            None,
            AttemptState::Running,
            Conclusion::None,
            false,
        );
        let first_terminal = attempt(
            fixture,
            '9',
            1,
            None,
            AttemptState::Terminal,
            Conclusion::Success,
            true,
        );
        let failed_running = failure_attempt(
            fixture,
            'b',
            1,
            None,
            AttemptState::Running,
            Conclusion::None,
            false,
        );
        let failed_terminal = failure_attempt(
            fixture,
            'b',
            1,
            None,
            AttemptState::Terminal,
            Conclusion::Failure,
            true,
        );
        let second_running = failure_attempt(
            fixture,
            'a',
            2,
            Some('b'),
            AttemptState::Running,
            Conclusion::None,
            false,
        );
        let second_cancelled = failure_attempt(
            fixture,
            'a',
            2,
            Some('b'),
            AttemptState::Terminal,
            Conclusion::Cancelled,
            false,
        );
        let second_tombstoned = failure_attempt(
            fixture,
            'a',
            2,
            Some('b'),
            AttemptState::Tombstoned,
            Conclusion::Cancelled,
            false,
        );
        let submitted = run(
            fixture,
            RunState::AwaitingApproval,
            Conclusion::None,
            None,
            None,
            Vec::new(),
        );
        let granted = run(
            fixture,
            RunState::GrantedAwaitingResume,
            Conclusion::None,
            Some(approval(fixture, false)),
            None,
            Vec::new(),
        );
        let running_one = run(
            fixture,
            RunState::Running,
            Conclusion::None,
            Some(approval(fixture, true)),
            None,
            vec![first_running],
        );
        let terminal_one = run(
            fixture,
            RunState::Terminal,
            Conclusion::Success,
            Some(approval(fixture, true)),
            Some('9'),
            vec![first_terminal.clone()],
        );
        let failure_submitted = failure_run(
            fixture,
            RunState::GrantedAwaitingResume,
            Conclusion::None,
            Some(approval(fixture, false)),
            None,
            Vec::new(),
        );
        let failure_running = failure_run(
            fixture,
            RunState::Running,
            Conclusion::None,
            Some(approval(fixture, true)),
            None,
            vec![failed_running],
        );
        let failure_terminal = failure_run(
            fixture,
            RunState::Terminal,
            Conclusion::Failure,
            Some(approval(fixture, true)),
            Some('b'),
            vec![failed_terminal.clone()],
        );
        let rerun = failure_run(
            fixture,
            RunState::Running,
            Conclusion::None,
            Some(approval(fixture, true)),
            None,
            vec![failed_terminal.clone(), second_running],
        );
        let cancelled = failure_run(
            fixture,
            RunState::Terminal,
            Conclusion::Cancelled,
            Some(approval(fixture, true)),
            Some('a'),
            vec![failed_terminal.clone(), second_cancelled],
        );
        let folded = failure_run(
            fixture,
            RunState::Terminal,
            Conclusion::Failure,
            Some(approval(fixture, true)),
            Some('b'),
            vec![failed_terminal, second_tombstoned],
        );
        let export = ExportSnapshot {
            authenticated: true,
            subject: fixture.export_subject.clone(),
            generation: fixture.export_generation,
            authorization_digest: fixture.export_authorization_digest.clone(),
            attempt_id: hex('9', 32),
            request_digest: fixture.request_digest.clone(),
            manifest_digest: fixture.manifest_digest.clone(),
            evidence_set_digest: hex('8', 64),
            objects: vec![
                fixture.expected_log.clone(),
                fixture.expected_artifacts[0].clone(),
            ],
        };
        vec![
            response(
                1,
                Operation::ObserveInitial,
                snapshot(0, 0, 1, 1, None),
                None,
            ),
            response(
                2,
                Operation::SetCapacityOne,
                snapshot(1, 0, 1, 1, None),
                None,
            ),
            response(
                3,
                Operation::SubmitManifest,
                snapshot(1, 0, 1, 1, Some(submitted)),
                None,
            ),
            response(
                4,
                Operation::ApproveGrant,
                snapshot(1, 0, 1, 1, Some(granted)),
                None,
            ),
            response(
                5,
                Operation::ResumeGrant,
                snapshot(1, 1, 1, 1, Some(running_one)),
                None,
            ),
            response(
                6,
                Operation::AwaitFirstTerminal,
                snapshot(1, 0, 1, 1, Some(terminal_one.clone())),
                None,
            ),
            response(
                7,
                Operation::ExportFirstEvidence,
                snapshot(1, 0, 1, 1, Some(terminal_one)),
                Some(export),
            ),
            response(
                8,
                Operation::SubmitFailureManifest,
                snapshot(1, 0, 1, 1, Some(failure_submitted)),
                None,
            ),
            response(
                9,
                Operation::ResumeFailure,
                snapshot(1, 1, 1, 1, Some(failure_running)),
                None,
            ),
            response(
                10,
                Operation::AwaitFailureTerminal,
                snapshot(1, 0, 1, 1, Some(failure_terminal)),
                None,
            ),
            response(
                11,
                Operation::Rerun,
                snapshot(1, 1, 1, 1, Some(rerun)),
                None,
            ),
            response(
                12,
                Operation::CancelRerun,
                snapshot(1, 0, 1, 1, Some(cancelled)),
                None,
            ),
            response(
                13,
                Operation::TombstoneRerun,
                snapshot(1, 0, 1, 1, Some(folded.clone())),
                None,
            ),
            response(
                14,
                Operation::RestartController,
                snapshot(1, 0, 2, 1, Some(folded.clone())),
                None,
            ),
            response(
                15,
                Operation::RestartRunner,
                snapshot(1, 0, 2, 2, Some(folded.clone())),
                None,
            ),
            response(
                16,
                Operation::SetCapacityZero,
                snapshot(0, 0, 2, 2, Some(folded)),
                None,
            ),
        ]
    }

    #[test]
    fn complete_capacity_one_sequence_passes_and_returns_to_zero() {
        let scenario = scenario();
        validate_scenario(&scenario).unwrap();
        let mut driver = ScriptedDriver {
            responses: passing_responses(&scenario),
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Pass);
        assert_eq!(receipt.checks.len(), 16);
        assert!(receipt.failure.is_none());
        validate_receipt(&receipt).unwrap();
        assert_eq!(driver.index, 16);
    }

    #[test]
    fn every_error_after_capacity_one_compensates_and_proves_zero() {
        let scenario = scenario();
        for sequence in 2..=16 {
            let mut driver = FaultDriver {
                responses: passing_responses(&scenario),
                fail_sequence: sequence,
                zero_failures: 0,
                zero_requests: Vec::new(),
                wrong_zero: false,
            };
            let receipt = run_acceptance(&scenario, &mut driver);
            assert_eq!(receipt.outcome, Outcome::Fail, "sequence {sequence}");
            assert_eq!(receipt.zero_transition.as_ref().unwrap().attempts, 1);
            let request = &driver.zero_requests[0];
            assert_eq!(
                request.expected_controller_generation.is_none(),
                sequence == 14
            );
            assert_eq!(request.expected_runner_generation.is_none(), sequence == 15);
            assert_eq!(driver.zero_requests.len(), 1, "sequence {sequence}");
        }
    }

    #[test]
    fn compensation_retries_identical_request_after_transport_loss() {
        let scenario = scenario();
        let mut driver = FaultDriver {
            responses: passing_responses(&scenario),
            fail_sequence: 4,
            zero_failures: 1,
            zero_requests: Vec::new(),
            wrong_zero: false,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(receipt.zero_transition.as_ref().unwrap().attempts, 2);
        assert_eq!(driver.zero_requests.len(), 2);
        assert_eq!(driver.zero_requests[0], driver.zero_requests[1]);
    }

    #[test]
    fn ambiguous_zero_readback_fails_closed_after_bounded_retry() {
        let scenario = scenario();
        let mut driver = FaultDriver {
            responses: passing_responses(&scenario),
            fail_sequence: 5,
            zero_failures: 0,
            zero_requests: Vec::new(),
            wrong_zero: true,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert!(receipt.zero_transition.is_none());
        assert!(receipt
            .failure
            .unwrap()
            .message
            .starts_with("capacity-zero compensation failed:"));
    }

    #[test]
    fn pass_receipt_verifier_rejects_reordering_and_digest_tampering() {
        let scenario = scenario();
        let mut driver = ScriptedDriver {
            responses: passing_responses(&scenario),
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        validate_receipt(&receipt).unwrap();

        let mut reordered = receipt.clone();
        reordered.checks.swap(5, 6);
        assert!(validate_receipt(&reordered).is_err());

        let mut tampered = receipt;
        tampered.checks[6].export.as_mut().unwrap().authenticated = false;
        assert!(validate_receipt(&tampered).is_err());
    }

    #[test]
    fn wrong_manifest_fails_closed_before_grant() {
        let scenario = scenario();
        let mut responses = passing_responses(&scenario);
        responses[2].snapshot.run.as_mut().unwrap().manifest_digest = hex('f', 64);
        let mut driver = ScriptedDriver {
            responses,
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(receipt.checks.len(), 3);
        assert_eq!(receipt.failure.unwrap().stage, Stage::ManifestIdentity);
        assert_eq!(driver.index, 3);
    }

    #[test]
    fn unauthenticated_export_fails_closed_before_rerun() {
        let scenario = scenario();
        let mut responses = passing_responses(&scenario);
        responses[6].export.as_mut().unwrap().authenticated = false;
        let mut driver = ScriptedDriver {
            responses,
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(receipt.failure.unwrap().stage, Stage::AuthenticatedExport);
        assert_eq!(driver.index, 7);
    }

    #[test]
    fn wrong_export_generation_fails_closed_before_rerun() {
        let scenario = scenario();
        let mut responses = passing_responses(&scenario);
        responses[6].export.as_mut().unwrap().generation += 1;
        let mut driver = ScriptedDriver {
            responses,
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(receipt.failure.unwrap().stage, Stage::AuthenticatedExport);
        assert_eq!(driver.index, 7);
    }

    #[test]
    fn reused_attempt_id_fails_closed() {
        let scenario = scenario();
        let mut responses = passing_responses(&scenario);
        let run = responses[10].snapshot.run.as_mut().unwrap();
        run.attempts[1].attempt_id = hex('b', 32);
        let mut driver = ScriptedDriver {
            responses,
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(receipt.failure.unwrap().stage, Stage::RerunSeparation);
        assert_eq!(driver.index, 11);
    }

    #[test]
    fn restart_state_loss_fails_closed() {
        let scenario = scenario();
        let mut responses = passing_responses(&scenario);
        responses[13].snapshot.run.as_mut().unwrap().attempts.pop();
        let mut driver = ScriptedDriver {
            responses,
            index: 0,
        };
        let receipt = run_acceptance(&scenario, &mut driver);
        assert_eq!(receipt.outcome, Outcome::Fail);
        assert_eq!(
            receipt.failure.unwrap().stage,
            Stage::ControllerRestartRecovery
        );
        assert_eq!(driver.index, 14);
    }

    #[test]
    fn runner_restart_corruption_fails_closed() {
        let scenario = scenario();
        for fault in [
            "runner generation",
            "controller generation",
            "persistent state",
        ] {
            let mut responses = passing_responses(&scenario);
            match fault {
                "runner generation" => responses[14].snapshot.runner_generation = 1,
                "controller generation" => responses[14].snapshot.controller_generation = 1,
                "persistent state" => {
                    responses[14].snapshot.run.as_mut().unwrap().attempts.pop();
                }
                _ => unreachable!(),
            }
            let mut driver = ScriptedDriver {
                responses,
                index: 0,
            };
            let receipt = run_acceptance(&scenario, &mut driver);
            assert_eq!(receipt.outcome, Outcome::Fail, "{fault}");
            assert_eq!(
                receipt.failure.unwrap().stage,
                Stage::RunnerRestartRecovery,
                "{fault}"
            );
            assert_eq!(driver.index, 15, "{fault}");
        }
    }

    #[test]
    fn scenario_requires_absolute_non_shell_endpoints() {
        let mut scenario = scenario();
        scenario.driver.control.program = "adapter".to_owned();
        assert!(matches!(
            validate_scenario(&scenario),
            Err(ScenarioError::InvalidField("driver endpoint"))
        ));
    }

    #[test]
    fn scenario_rejects_export_generation_and_extra_artifact_drift() {
        let mut invalid_generation = scenario();
        invalid_generation.fixture.export_generation = 0;
        assert!(matches!(
            validate_scenario(&invalid_generation),
            Err(ScenarioError::InvalidField("fixture.export_generation"))
        ));

        let mut extra_artifact = scenario();
        extra_artifact
            .fixture
            .expected_artifacts
            .push(evidence("extra.json", '8', 1));
        assert!(matches!(
            validate_scenario(&extra_artifact),
            Err(ScenarioError::InvalidField("fixture.expected_artifacts"))
        ));

        for job_id in [".bad", "1bad", "bad.name"] {
            let mut invalid_job = scenario();
            invalid_job.fixture.job_id = job_id.to_owned();
            assert!(validate_scenario(&invalid_job).is_err());
        }
    }
}
