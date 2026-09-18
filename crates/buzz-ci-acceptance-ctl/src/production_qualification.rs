//! Closed production-v2 qualification probe used before capacity activation.
//!
//! This is deliberately separate from the capacity-one acceptance canary. It
//! can send only one fixed, path-free qualification operation to execd and it
//! accepts only a response that echoes every activation and host binding.

use std::{
    fmt,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use buzz_ci_broker_protocol::{
    v2::{
        decode_production_qualification_response, encode_request,
        production_qualification_receipt_digest, production_qualification_request_frame_digest,
        FrameHeader, ProductionQualificationRequest, Request,
        PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE,
    },
    GitOid, Operation, ResponseCode, HEADER_SIZE, MAX_SAFE_INTEGER,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::response_code_name;

pub const REQUEST_SCHEMA: &str = "buzz-ci-production-qualification-request/v2";
pub const RESPONSE_SCHEMA: &str = "buzz-ci-production-qualification-response/v2";
pub const EXECD_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Exact byte length of the version 2 qualification response frame.
const RESPONSE_FRAME_SIZE: usize = HEADER_SIZE + PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationInput {
    pub schema_version: String,
    pub request_id: String,
    pub integrated_candidate_sha: String,
    pub activation_package_digest: String,
    pub fixture_digest: String,
    pub principal_digest: String,
    pub lane_manifest_digest: String,
    pub broker_build_identity_digest: String,
    pub host_profile_digest: String,
    pub suite_digest: String,
    pub isolation_profile_digest: String,
    pub seccomp_profile_digest: String,
    pub executor_program_digest: String,
    pub executor_provenance_digest: String,
    pub nonce: String,
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationReceipt {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub disposition: &'static str,
    pub request_id: String,
    pub request_frame_digest: String,
    pub qualification_receipt_digest: String,
    pub integrated_candidate_sha: String,
    pub activation_package_digest: String,
    pub fixture_digest: String,
    pub principal_digest: String,
    pub lane_manifest_digest: String,
    pub broker_build_identity_digest: String,
    pub host_profile_digest: String,
    pub suite_digest: String,
    pub isolation_profile_digest: String,
    pub seccomp_profile_digest: String,
    pub seccomp_install_receipt_digest: String,
    pub executor_program_digest: String,
    pub executor_provenance_digest: String,
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub qualified_at: u64,
    pub request_expires_at: u64,
}

/// One parsed input together with its exact version 2 frame contents.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedRequest {
    input: ProductionQualificationInput,
    header: FrameHeader,
    request: ProductionQualificationRequest,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum InputError {
    #[error("input exceeds the fixed qualification limit")]
    TooLarge,
    #[error("input is not the closed qualification JSON object")]
    Malformed,
    #[error("unsupported qualification schema")]
    Schema,
    #[error("invalid field: {0}")]
    Field(&'static str),
    #[error("qualification request is outside its validity interval")]
    Deadline,
}

impl InputError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "input_too_large",
            Self::Malformed => "malformed_input",
            Self::Schema => "unsupported_schema",
            Self::Field(_) => "invalid_field",
            Self::Deadline => "invalid_deadline",
        }
    }

    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::Schema => Some("schema_version"),
            Self::Field(field) => Some(field),
            Self::Deadline => Some("issued_at/expires_at"),
            Self::TooLarge | Self::Malformed => None,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ExchangeError {
    #[error("execd qualification socket is unavailable")]
    Unavailable,
    #[error("execd qualification exchange timed out")]
    Timeout,
    #[error("execd qualification transport failed")]
    Transport,
    #[error("execd returned a malformed production-v2 response")]
    MalformedResponse,
    #[error("execd refused production qualification: {0}")]
    Refused(&'static str),
    #[error("execd qualification response drifted from the exact request")]
    BindingMismatch,
}

impl ExchangeError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "execd_unavailable",
            Self::Timeout => "execd_timeout",
            Self::Transport => "transport_failure",
            Self::MalformedResponse => "malformed_response",
            Self::Refused(_) => "qualification_refused",
            Self::BindingMismatch => "binding_mismatch",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DispatchError {
    #[error(transparent)]
    Input(#[from] InputError),
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
}

pub trait ProductionQualificationTransport {
    fn exchange(&mut self, request_frame: &[u8]) -> Result<Vec<u8>, ExchangeError>;
}

pub struct UnixProductionQualificationTransport {
    socket_path: PathBuf,
    timeout: Duration,
}

impl UnixProductionQualificationTransport {
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(EXECD_SOCKET_PATH),
            timeout: IO_TIMEOUT,
        }
    }

    #[doc(hidden)]
    pub fn at_path(socket_path: PathBuf, timeout: Duration) -> Self {
        Self {
            socket_path,
            timeout,
        }
    }
}

impl Default for UnixProductionQualificationTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductionQualificationTransport for UnixProductionQualificationTransport {
    fn exchange(&mut self, request_frame: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        exchange_unix(&self.socket_path, self.timeout, request_frame)
    }
}

pub fn dispatch<T: ProductionQualificationTransport>(
    input: &[u8],
    now: u64,
    transport: &mut T,
) -> Result<ProductionQualificationReceipt, DispatchError> {
    let request = parse_and_validate(input, now)?;
    let frame = encode_request(
        request.header.request_id,
        Request::AdmitQualification(request.request),
    );
    let response = transport.exchange(frame.as_bytes())?;
    decode_and_validate_response(&request, &response).map_err(DispatchError::Exchange)
}

fn parse_and_validate(input: &[u8], now: u64) -> Result<ValidatedRequest, InputError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(InputError::TooLarge);
    }
    let value: ProductionQualificationInput =
        serde_json::from_slice(input).map_err(|_| InputError::Malformed)?;
    if value.schema_version != REQUEST_SCHEMA {
        return Err(InputError::Schema);
    }
    let request_id = parse_hex::<16>(&value.request_id, "request_id")?;
    require_nonzero(&request_id, "request_id")?;
    let integrated_candidate_sha = parse_candidate(&value.integrated_candidate_sha)?;
    let digest = |encoded: &str, field: &'static str| -> Result<[u8; 32], InputError> {
        let decoded = parse_hex::<32>(encoded, field)?;
        require_nonzero(&decoded, field)?;
        Ok(decoded)
    };
    for (field, number) in [
        ("controller_generation", value.controller_generation),
        ("runner_generation", value.runner_generation),
        ("lane_epoch", value.lane_epoch),
        ("admission_key_generation", value.admission_key_generation),
        ("issued_at", value.issued_at),
        ("expires_at", value.expires_at),
    ] {
        if number == 0 || number > MAX_SAFE_INTEGER {
            return Err(InputError::Field(field));
        }
    }
    let mut request = ProductionQualificationRequest {
        integrated_candidate_sha,
        activation_package_digest: digest(
            &value.activation_package_digest,
            "activation_package_digest",
        )?,
        fixture_digest: digest(&value.fixture_digest, "fixture_digest")?,
        principal_digest: digest(&value.principal_digest, "principal_digest")?,
        lane_manifest_digest: digest(&value.lane_manifest_digest, "lane_manifest_digest")?,
        broker_build_identity: digest(
            &value.broker_build_identity_digest,
            "broker_build_identity_digest",
        )?,
        host_profile_digest: digest(&value.host_profile_digest, "host_profile_digest")?,
        suite_identity: digest(&value.suite_digest, "suite_digest")?,
        isolation_profile_digest: digest(
            &value.isolation_profile_digest,
            "isolation_profile_digest",
        )?,
        seccomp_profile_digest: digest(&value.seccomp_profile_digest, "seccomp_profile_digest")?,
        executor_program_digest: digest(&value.executor_program_digest, "executor_program_digest")?,
        executor_provenance_digest: digest(
            &value.executor_provenance_digest,
            "executor_provenance_digest",
        )?,
        nonce: digest(&value.nonce, "nonce")?,
        controller_generation: value.controller_generation,
        runner_generation: value.runner_generation,
        lane_epoch: value.lane_epoch,
        admission_key_generation: value.admission_key_generation,
        issued_at: value.issued_at,
        expires_at: value.expires_at,
        request_frame_digest: [0; 32],
    };
    if value.issued_at > now
        || now >= value.expires_at
        || value.expires_at.checked_sub(value.issued_at) != Some(60)
    {
        return Err(InputError::Deadline);
    }
    let header = FrameHeader {
        operation: Operation::AdmitQualification,
        request_id,
    };
    // The digest is `None` only for a non-qualification operation; the header
    // above is fixed, so this branch cannot be reached with valid input.
    request.request_frame_digest = production_qualification_request_frame_digest(header, &request)
        .ok_or(InputError::Malformed)?;
    Ok(ValidatedRequest {
        input: value,
        header,
        request,
    })
}

fn decode_and_validate_response(
    request: &ValidatedRequest,
    response: &[u8],
) -> Result<ProductionQualificationReceipt, ExchangeError> {
    let response = decode_production_qualification_response(request.header, response)
        .map_err(|_| ExchangeError::MalformedResponse)?;
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing) {
        return Err(ExchangeError::Refused(response_code_name(response.code)));
    }
    if response.retry_after_millis != 0 {
        return Err(ExchangeError::MalformedResponse);
    }
    let sent = &request.request;
    if response.request_frame_digest != sent.request_frame_digest
        || production_qualification_receipt_digest(&response)
            != response.qualification_receipt_digest
        || response.integrated_candidate_sha != sent.integrated_candidate_sha
        || response.activation_package_digest != sent.activation_package_digest
        || response.fixture_digest != sent.fixture_digest
        || response.principal_digest != sent.principal_digest
        || response.lane_manifest_digest != sent.lane_manifest_digest
        || response.broker_build_identity != sent.broker_build_identity
        || response.host_profile_digest != sent.host_profile_digest
        || response.suite_identity != sent.suite_identity
        || response.isolation_profile_digest != sent.isolation_profile_digest
        || response.seccomp_profile_digest != sent.seccomp_profile_digest
        || response.executor_program_digest != sent.executor_program_digest
        || response.executor_provenance_digest != sent.executor_provenance_digest
        || response.controller_generation != sent.controller_generation
        || response.runner_generation != sent.runner_generation
        || response.lane_epoch != sent.lane_epoch
        || response.admission_key_generation != sent.admission_key_generation
        || response.qualified_at < sent.issued_at
        || response.qualified_at >= sent.expires_at
        || response.request_expires_at != sent.expires_at
    {
        return Err(ExchangeError::BindingMismatch);
    }
    let input = &request.input;
    Ok(ProductionQualificationReceipt {
        schema_version: RESPONSE_SCHEMA,
        status: "qualified_closed",
        disposition: if response.code == ResponseCode::Ok {
            "created"
        } else {
            "existing"
        },
        request_id: input.request_id.clone(),
        request_frame_digest: hex::encode(sent.request_frame_digest),
        qualification_receipt_digest: hex::encode(response.qualification_receipt_digest),
        integrated_candidate_sha: input.integrated_candidate_sha.clone(),
        activation_package_digest: input.activation_package_digest.clone(),
        fixture_digest: input.fixture_digest.clone(),
        principal_digest: input.principal_digest.clone(),
        lane_manifest_digest: input.lane_manifest_digest.clone(),
        broker_build_identity_digest: input.broker_build_identity_digest.clone(),
        host_profile_digest: input.host_profile_digest.clone(),
        suite_digest: input.suite_digest.clone(),
        isolation_profile_digest: input.isolation_profile_digest.clone(),
        seccomp_profile_digest: input.seccomp_profile_digest.clone(),
        seccomp_install_receipt_digest: hex::encode(response.seccomp_install_receipt_digest),
        executor_program_digest: input.executor_program_digest.clone(),
        executor_provenance_digest: input.executor_provenance_digest.clone(),
        controller_generation: response.controller_generation,
        runner_generation: response.runner_generation,
        lane_epoch: response.lane_epoch,
        admission_key_generation: response.admission_key_generation,
        qualified_at: response.qualified_at,
        request_expires_at: response.request_expires_at,
    })
}

fn exchange_unix(path: &Path, timeout: Duration, request: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    let mut stream = UnixStream::connect(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ExchangeError::Timeout,
        _ => ExchangeError::Unavailable,
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| ExchangeError::Transport)?;
    stream.write_all(request).map_err(map_io_error)?;
    stream.shutdown(Shutdown::Write).map_err(map_io_error)?;
    let mut response = Vec::with_capacity(RESPONSE_FRAME_SIZE + 1);
    stream
        .take((RESPONSE_FRAME_SIZE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(map_io_error)?;
    if response.len() != RESPONSE_FRAME_SIZE {
        return Err(ExchangeError::MalformedResponse);
    }
    Ok(response)
}

fn map_io_error(error: std::io::Error) -> ExchangeError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ExchangeError::Timeout,
        _ => ExchangeError::Transport,
    }
}

fn parse_candidate(value: &str) -> Result<GitOid, InputError> {
    let result = match value.len() {
        40 => GitOid::Sha1(parse_hex::<20>(value, "integrated_candidate_sha")?),
        64 => GitOid::Sha256(parse_hex::<32>(value, "integrated_candidate_sha")?),
        _ => return Err(InputError::Field("integrated_candidate_sha")),
    };
    match result {
        GitOid::Sha1(bytes) if bytes == [0; 20] => {
            Err(InputError::Field("integrated_candidate_sha"))
        }
        GitOid::Sha256(bytes) if bytes == [0; 32] => {
            Err(InputError::Field("integrated_candidate_sha"))
        }
        _ => Ok(result),
    }
}

fn parse_hex<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], InputError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InputError::Field(field));
    }
    let decoded = hex::decode(value).map_err(|_| InputError::Field(field))?;
    decoded.try_into().map_err(|_| InputError::Field(field))
}

fn require_nonzero<const N: usize>(value: &[u8; N], field: &'static str) -> Result<(), InputError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(InputError::Field(field))
    } else {
        Ok(())
    }
}

impl fmt::Debug for UnixProductionQualificationTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixProductionQualificationTransport")
            .field("socket_path", &self.socket_path)
            .field("timeout", &self.timeout)
            .finish()
    }
}
