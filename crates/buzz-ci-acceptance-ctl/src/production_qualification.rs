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
    v2::{production_qualification_receipt_digest, ProductionQualificationResponse},
    GitOid as ProtocolGitOid, ResponseCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::GitOid;

pub const REQUEST_SCHEMA: &str = "buzz-ci-production-qualification-request/v2";
pub const RESPONSE_SCHEMA: &str = "buzz-ci-production-qualification-response/v2";
pub const EXECD_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

const MAGIC: &[u8; 4] = b"BZCI";
const PROTOCOL_VERSION: u16 = 2;
const OPERATION: u16 = 5;
const RESPONSE_OPERATION: u16 = OPERATION | 0x8000;
const HEADER_SIZE: usize = 32;
const REQUEST_BODY_SIZE: usize = 640;
const RESPONSE_BODY_SIZE: usize = 576;
const REQUEST_FRAME_SIZE: usize = HEADER_SIZE + REQUEST_BODY_SIZE;
const RESPONSE_FRAME_SIZE: usize = HEADER_SIZE + RESPONSE_BODY_SIZE;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"buzz-ci-execd:production-qualification-request:v1\0";

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedRequest {
    input: ProductionQualificationInput,
    request_id: [u8; 16],
    candidate: GitOid,
    digests: [[u8; 32]; 11],
    nonce: [u8; 32],
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
    let frame = encode_request(&request);
    let response = transport.exchange(&frame)?;
    decode_and_validate_response(&request, &frame, &response).map_err(DispatchError::Exchange)
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
    let candidate = parse_candidate(&value.integrated_candidate_sha)?;
    let digest_values = [
        (
            &value.activation_package_digest,
            "activation_package_digest",
        ),
        (&value.fixture_digest, "fixture_digest"),
        (&value.principal_digest, "principal_digest"),
        (&value.lane_manifest_digest, "lane_manifest_digest"),
        (
            &value.broker_build_identity_digest,
            "broker_build_identity_digest",
        ),
        (&value.host_profile_digest, "host_profile_digest"),
        (&value.suite_digest, "suite_digest"),
        (&value.isolation_profile_digest, "isolation_profile_digest"),
        (&value.seccomp_profile_digest, "seccomp_profile_digest"),
        (&value.executor_program_digest, "executor_program_digest"),
        (
            &value.executor_provenance_digest,
            "executor_provenance_digest",
        ),
    ];
    let mut digests = [[0; 32]; 11];
    for (slot, (encoded, field)) in digests.iter_mut().zip(digest_values) {
        *slot = parse_hex::<32>(encoded, field)?;
        require_nonzero(slot, field)?;
    }
    let nonce = parse_hex::<32>(&value.nonce, "nonce")?;
    require_nonzero(&nonce, "nonce")?;
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
    if value.issued_at > now
        || now >= value.expires_at
        || value.expires_at.checked_sub(value.issued_at) != Some(60)
    {
        return Err(InputError::Deadline);
    }
    Ok(ValidatedRequest {
        input: value,
        request_id,
        candidate,
        digests,
        nonce,
    })
}

fn encode_request(request: &ValidatedRequest) -> Vec<u8> {
    let mut frame = vec![0; REQUEST_FRAME_SIZE];
    encode_header(
        &mut frame[..HEADER_SIZE],
        OPERATION,
        REQUEST_BODY_SIZE,
        request.request_id,
    );
    {
        let body = &mut frame[HEADER_SIZE..];
        encode_oid(&mut body[0..33], request.candidate);
        for (index, digest) in request.digests.iter().enumerate() {
            let start = 33 + index * 32;
            body[start..start + 32].copy_from_slice(digest);
        }
        body[385..417].copy_from_slice(&request.nonce);
        for (offset, value) in [
            (417, request.input.controller_generation),
            (425, request.input.runner_generation),
            (433, request.input.lane_epoch),
            (441, request.input.admission_key_generation),
            (449, request.input.issued_at),
            (457, request.input.expires_at),
        ] {
            body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
    }
    let digest = request_frame_digest(&frame);
    frame[HEADER_SIZE + 465..HEADER_SIZE + 497].copy_from_slice(&digest);
    frame
}

fn request_frame_digest(frame: &[u8]) -> [u8; 32] {
    let mut canonical = frame.to_vec();
    canonical[HEADER_SIZE + 465..HEADER_SIZE + 497].fill(0);
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update(OPERATION.to_be_bytes());
    hasher.update(&canonical[16..32]);
    hasher.update(&canonical[HEADER_SIZE..]);
    hasher.finalize().into()
}

fn decode_and_validate_response(
    request: &ValidatedRequest,
    request_frame: &[u8],
    response: &[u8],
) -> Result<ProductionQualificationReceipt, ExchangeError> {
    if response.len() != RESPONSE_FRAME_SIZE
        || &response[..4] != MAGIC
        || u16_at(response, 4) != PROTOCOL_VERSION
        || u16_at(response, 6) != RESPONSE_OPERATION
        || u32_at(response, 8) != 0
        || usize::try_from(u32_at(response, 12)).ok() != Some(RESPONSE_BODY_SIZE)
        || response[16..32] != request.request_id
    {
        return Err(ExchangeError::MalformedResponse);
    }
    let body = &response[HEADER_SIZE..];
    if body[535..].iter().any(|byte| *byte != 0) {
        return Err(ExchangeError::MalformedResponse);
    }
    let code =
        ResponseCode::try_from(u16_at(body, 0)).map_err(|_| ExchangeError::MalformedResponse)?;
    if !matches!(code, ResponseCode::Ok | ResponseCode::Existing) {
        return Err(ExchangeError::Refused(response_code_name(code)));
    }
    if u32_at(body, 2) != 0 {
        return Err(ExchangeError::MalformedResponse);
    }
    let expected_frame_digest = request_frame_digest(request_frame);
    let response_frame_digest: [u8; 32] = body[6..38]
        .try_into()
        .map_err(|_| ExchangeError::MalformedResponse)?;
    let qualification_receipt_digest: [u8; 32] = body[38..70]
        .try_into()
        .map_err(|_| ExchangeError::MalformedResponse)?;
    let candidate = decode_oid(&body[70..103]).ok_or(ExchangeError::MalformedResponse)?;
    let offsets = [103, 135, 167, 199, 231, 263, 295, 327, 359, 423, 455];
    let mut echoed = [[0; 32]; 11];
    for (slot, offset) in echoed.iter_mut().zip(offsets) {
        slot.copy_from_slice(&body[offset..offset + 32]);
    }
    let seccomp_install_receipt_digest: [u8; 32] = body[391..423]
        .try_into()
        .map_err(|_| ExchangeError::MalformedResponse)?;
    let generations = [
        u64_at(body, 487),
        u64_at(body, 495),
        u64_at(body, 503),
        u64_at(body, 511),
    ];
    let expected_generations = [
        request.input.controller_generation,
        request.input.runner_generation,
        request.input.lane_epoch,
        request.input.admission_key_generation,
    ];
    let qualified_at = u64_at(body, 519);
    let request_expires_at = u64_at(body, 527);
    let shared_response = ProductionQualificationResponse {
        code,
        retry_after_millis: u32_at(body, 2),
        request_frame_digest: response_frame_digest,
        qualification_receipt_digest,
        integrated_candidate_sha: protocol_oid(candidate),
        activation_package_digest: echoed[0],
        fixture_digest: echoed[1],
        principal_digest: echoed[2],
        lane_manifest_digest: echoed[3],
        broker_build_identity: echoed[4],
        host_profile_digest: echoed[5],
        suite_identity: echoed[6],
        isolation_profile_digest: echoed[7],
        seccomp_profile_digest: echoed[8],
        seccomp_install_receipt_digest,
        executor_program_digest: echoed[9],
        executor_provenance_digest: echoed[10],
        controller_generation: generations[0],
        runner_generation: generations[1],
        lane_epoch: generations[2],
        admission_key_generation: generations[3],
        qualified_at,
        request_expires_at,
    };
    if response_frame_digest != expected_frame_digest
        || qualification_receipt_digest == [0; 32]
        || production_qualification_receipt_digest(&shared_response) != qualification_receipt_digest
        || candidate != request.candidate
        || echoed != request.digests
        || seccomp_install_receipt_digest == [0; 32]
        || generations != expected_generations
        || qualified_at < request.input.issued_at
        || qualified_at >= request.input.expires_at
        || request_expires_at != request.input.expires_at
    {
        return Err(ExchangeError::BindingMismatch);
    }
    Ok(ProductionQualificationReceipt {
        schema_version: RESPONSE_SCHEMA,
        status: "qualified_closed",
        disposition: if code == ResponseCode::Ok {
            "created"
        } else {
            "existing"
        },
        request_id: request.input.request_id.clone(),
        request_frame_digest: hex(&expected_frame_digest),
        qualification_receipt_digest: hex(&qualification_receipt_digest),
        integrated_candidate_sha: request.input.integrated_candidate_sha.clone(),
        activation_package_digest: request.input.activation_package_digest.clone(),
        fixture_digest: request.input.fixture_digest.clone(),
        principal_digest: request.input.principal_digest.clone(),
        lane_manifest_digest: request.input.lane_manifest_digest.clone(),
        broker_build_identity_digest: request.input.broker_build_identity_digest.clone(),
        host_profile_digest: request.input.host_profile_digest.clone(),
        suite_digest: request.input.suite_digest.clone(),
        isolation_profile_digest: request.input.isolation_profile_digest.clone(),
        seccomp_profile_digest: request.input.seccomp_profile_digest.clone(),
        seccomp_install_receipt_digest: hex(&seccomp_install_receipt_digest),
        executor_program_digest: request.input.executor_program_digest.clone(),
        executor_provenance_digest: request.input.executor_provenance_digest.clone(),
        controller_generation: generations[0],
        runner_generation: generations[1],
        lane_epoch: generations[2],
        admission_key_generation: generations[3],
        qualified_at,
        request_expires_at,
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

fn encode_header(output: &mut [u8], operation: u16, body_size: usize, request_id: [u8; 16]) {
    output[..4].copy_from_slice(MAGIC);
    output[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    output[6..8].copy_from_slice(&operation.to_be_bytes());
    output[8..12].fill(0);
    output[12..16].copy_from_slice(&(body_size as u32).to_be_bytes());
    output[16..32].copy_from_slice(&request_id);
}

fn encode_oid(output: &mut [u8], oid: GitOid) {
    match oid {
        GitOid::Sha1(bytes) => {
            output[0] = 1;
            output[1..21].copy_from_slice(&bytes);
            output[21..].fill(0);
        }
        GitOid::Sha256(bytes) => {
            output[0] = 2;
            output[1..].copy_from_slice(&bytes);
        }
    }
}

fn decode_oid(input: &[u8]) -> Option<GitOid> {
    match input.first().copied()? {
        1 if input[21..].iter().all(|byte| *byte == 0) => {
            Some(GitOid::Sha1(input[1..21].try_into().ok()?))
        }
        2 => Some(GitOid::Sha256(input[1..33].try_into().ok()?)),
        _ => None,
    }
}

fn protocol_oid(oid: GitOid) -> ProtocolGitOid {
    match oid {
        GitOid::Sha1(bytes) => ProtocolGitOid::Sha1(bytes),
        GitOid::Sha256(bytes) => ProtocolGitOid::Sha256(bytes),
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

fn u16_at(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(input[offset..offset + 2].try_into().expect("fixed offset"))
}

fn u32_at(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().expect("fixed offset"))
}

fn u64_at(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(input[offset..offset + 8].try_into().expect("fixed offset"))
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

const fn response_code_name(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::Ok => "ok",
        ResponseCode::Existing => "existing",
        ResponseCode::BadFrame => "bad_frame",
        ResponseCode::UnsupportedVersion => "unsupported_version",
        ResponseCode::UnknownOperation => "unknown_operation",
        ResponseCode::InvalidField => "invalid_field",
        ResponseCode::UnauthorizedPeer => "unauthorized_peer",
        ResponseCode::PolicyDenied => "policy_denied",
        ResponseCode::ReplayConflict => "replay_conflict",
        ResponseCode::NoCapacity => "no_capacity",
        ResponseCode::NotProvisioned => "not_provisioned",
        ResponseCode::NotFound => "not_found",
        ResponseCode::StateConflict => "state_conflict",
        ResponseCode::Reconciling => "reconciling",
        ResponseCode::StorageUnavailable => "storage_unavailable",
        ResponseCode::InternalFailure => "internal_failure",
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
