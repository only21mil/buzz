//! Strict qualification-only input and transport boundary.
//!
//! Authentication happens outside this crate. Signer fields are non-zero
//! claims bound into the request, never proof that a signer authenticated.

pub mod acceptance;

use std::{
    fmt,
    io::{Read, Write},
    time::Duration,
};

use buzz_ci_broker_protocol::{
    decode_response, encode_request, BrokerResponse, FrameHeader, GitOid as ProtocolGitOid,
    QualificationDirective as ProtocolDirective,
    QualificationRequest as ProtocolQualificationRequest, Request, ResponseCode, HEADER_SIZE,
    RESPONSE_BODY_SIZE,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Maximum accepted standard-input document size.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Fixed root-broker socket selected by the deployment contract.
pub const BROKER_SOCKET_PATH: &str = "/run/buzzci/execd.sock";

const RESPONSE_FRAME_SIZE: usize = HEADER_SIZE + RESPONSE_BODY_SIZE;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// One normalized 32-byte digest or signer identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hex32([u8; 32]);

impl Hex32 {
    /// Return the decoded bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl Serialize for Hex32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        decode_hex::<32>(&value)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// Supported Git object ID algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitOidAlgorithm {
    Sha1,
    Sha256,
}

/// One normalized Git object ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitOid {
    /// Return the object ID algorithm.
    pub const fn algorithm(self) -> GitOidAlgorithm {
        match self {
            Self::Sha1(_) => GitOidAlgorithm::Sha1,
            Self::Sha256(_) => GitOidAlgorithm::Sha256,
        }
    }

    fn is_zero(self) -> bool {
        match self {
            Self::Sha1(bytes) => bytes == [0; 20],
            Self::Sha256(bytes) => bytes == [0; 32],
        }
    }
}

impl Serialize for GitOid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct WireOid<'a> {
            algorithm: GitOidAlgorithm,
            hex: &'a str,
        }

        let hex = match self {
            Self::Sha1(bytes) => encode_hex(bytes),
            Self::Sha256(bytes) => encode_hex(bytes),
        };
        WireOid {
            algorithm: self.algorithm(),
            hex: &hex,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GitOid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireOid {
            algorithm: String,
            hex: String,
        }

        let wire = WireOid::deserialize(deserializer)?;
        match wire.algorithm.as_str() {
            "sha1" => decode_hex::<20>(&wire.hex)
                .map(Self::Sha1)
                .map_err(de::Error::custom),
            "sha256" => decode_hex::<32>(&wire.hex)
                .map(Self::Sha256)
                .map_err(de::Error::custom),
            _ => Err(de::Error::custom("unsupported Git object ID algorithm")),
        }
    }
}

/// Immutable host and integrated-build coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCoordinates {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: Hex32,
    pub host_profile_digest: Hex32,
    pub suite_identity: Hex32,
}

/// Exact coordinates of the qualification fixture job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureJobCoordinates {
    pub request_digest: Hex32,
    pub manifest_digest: Hex32,
    pub isolation_profile_digest: Hex32,
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub test_identity: Hex32,
}

/// Root-authorized qualification permit fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPermitInput {
    pub authorized_by: Hex32,
    pub host: HostCoordinates,
    pub fixture_job: FixtureJobCoordinates,
    pub fixture_identity: Hex32,
    pub fixture_signer: Hex32,
    pub nonce: Hex32,
    pub not_before: u64,
    pub expires_at: u64,
}

/// Trust class presented by the authenticated admission boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionTrustClass {
    QualificationFixture,
    AcceptedReviewed,
    Unaccepted,
}

/// One authenticated qualification admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAdmissionInput {
    pub host: HostCoordinates,
    pub fixture_job: FixtureJobCoordinates,
    pub fixture_identity: Hex32,
    pub signer: Hex32,
    pub nonce: Hex32,
    pub trust_class: AdmissionTrustClass,
}

/// The sole qualification-only behavior directive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationDirective {
    TeardownFailure,
}

/// Closed standard-input grammar for one qualification exchange.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationExchangeInput {
    pub version: String,
    pub permit: QualificationPermitInput,
    pub admission: QualificationAdmissionInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directive: Option<QualificationDirective>,
}

/// Flattened qualification request passed to the parent transport.
///
/// Root authority, qualification trust, and current time come from the
/// service-owned control path. They are deliberately absent from this payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QualificationRequest {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: Hex32,
    pub host_profile_digest: Hex32,
    pub suite_identity: Hex32,
    pub fixture_signer: Hex32,
    pub request_digest: Hex32,
    pub manifest_digest: Hex32,
    pub isolation_profile_digest: Hex32,
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub job_identity: Hex32,
    pub fixture_identity: Hex32,
    pub nonce: Hex32,
    pub not_before: u64,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directive: Option<QualificationDirective>,
}

/// A request that passed every local qualification check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedQualificationExchange {
    input: QualificationExchangeInput,
    request: QualificationRequest,
}

impl ValidatedQualificationExchange {
    /// Read the validated fixed fields for protocol conversion.
    pub const fn as_input(&self) -> &QualificationExchangeInput {
        &self.input
    }

    /// Read the flattened request for the qualification protocol lane.
    pub const fn as_request(&self) -> &QualificationRequest {
        &self.request
    }
}

/// Stable input rejection returned before the transport runs.
#[derive(Debug, Error)]
pub enum InputError {
    #[error("input exceeds {MAX_INPUT_BYTES} bytes")]
    InputTooLarge,
    #[error("malformed input: {0}")]
    Malformed(String),
    #[error("unsupported input version")]
    UnsupportedVersion,
    #[error("zero value is forbidden for {0}")]
    ZeroField(&'static str),
    #[error("qualification trust is required")]
    UnacceptedTrustClass,
    #[error("invalid permit time window")]
    InvalidTimeWindow,
    #[error("permit and admission mismatch at {0}")]
    BindingMismatch(&'static str),
}

impl InputError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::Malformed(_) => "malformed_input",
            Self::UnsupportedVersion => "unsupported_version",
            Self::ZeroField(_) => "zero_field",
            Self::UnacceptedTrustClass => "unaccepted_trust_class",
            Self::InvalidTimeWindow => "invalid_time_window",
            Self::BindingMismatch(_) => "binding_mismatch",
        }
    }

    /// Field involved in a field-specific rejection.
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::ZeroField(field) | Self::BindingMismatch(field) => Some(field),
            _ => None,
        }
    }
}

/// Parent-owned exchange seam for the qualification protocol lane.
pub trait QualificationTransport {
    type Error;

    /// Exchange one fully validated qualification request.
    fn exchange(&mut self, request: &QualificationRequest) -> Result<(), Self::Error>;
}

/// Dispatch failure split between local validation and parent transport.
#[derive(Debug)]
pub enum DispatchError<E> {
    Input(InputError),
    Transport(E),
}

impl<E: fmt::Display> fmt::Display for DispatchError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(formatter),
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for DispatchError<E> {}

/// Parse and validate one complete JSON input without performing transport I/O.
pub fn parse_and_validate(input: &[u8]) -> Result<ValidatedQualificationExchange, InputError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(InputError::InputTooLarge);
    }
    let request: QualificationExchangeInput =
        serde_json::from_slice(input).map_err(|error| InputError::Malformed(error.to_string()))?;
    validate(request)
}

/// Validate first, then invoke the transport exactly once.
pub fn dispatch<T: QualificationTransport>(
    input: &[u8],
    transport: &mut T,
) -> Result<(), DispatchError<T::Error>> {
    let request = parse_and_validate(input).map_err(DispatchError::Input)?;
    transport
        .exchange(request.as_request())
        .map_err(DispatchError::Transport)
}

/// JSON-line transport used by the standalone binary.
pub struct JsonLineTransport<W> {
    writer: W,
}

impl<W> JsonLineTransport<W> {
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }
}

/// Failure while writing a validated exchange.
#[derive(Debug, Error)]
pub enum JsonLineTransportError {
    #[error("could not serialize exchange: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("could not finish exchange line: {0}")]
    Write(#[from] std::io::Error),
}

impl<W: Write> QualificationTransport for JsonLineTransport<W> {
    type Error = JsonLineTransportError;

    fn exchange(&mut self, request: &QualificationRequest) -> Result<(), Self::Error> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            r#type: &'static str,
            request: &'a QualificationRequest,
        }

        serde_json::to_writer(
            &mut self.writer,
            &Envelope {
                r#type: "qualification_exchange",
                request,
            },
        )?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }
}

/// Fixed-socket transport used by the installed qualification binary.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixQualificationTransport {
    response: Option<BrokerResponse>,
}

impl UnixQualificationTransport {
    /// Construct an empty transport. A response appears only after one exchange.
    pub const fn new() -> Self {
        Self { response: None }
    }

    /// Return the response from the completed successful exchange.
    pub const fn response(&self) -> Option<BrokerResponse> {
        self.response
    }
}

/// Stable failure from the fixed qualification transport.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum QualificationExchangeError {
    #[error("qualification broker is unavailable")]
    BrokerUnavailable,
    #[error("qualification transport failed")]
    TransportFailure,
    #[error("qualification broker response was invalid")]
    InvalidBrokerResponse,
    #[error("qualification broker refused the request")]
    Refused(ResponseCode),
}

impl QualificationExchangeError {
    /// Stable machine-readable failure code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BrokerUnavailable => "broker_unavailable",
            Self::TransportFailure => "transport_failure",
            Self::InvalidBrokerResponse => "invalid_broker_response",
            Self::Refused(code) => response_code_name(code),
        }
    }
}

impl QualificationTransport for UnixQualificationTransport {
    type Error = QualificationExchangeError;

    fn exchange(&mut self, request: &QualificationRequest) -> Result<(), Self::Error> {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixStream;

            let mut stream = UnixStream::connect(BROKER_SOCKET_PATH)
                .map_err(|_| QualificationExchangeError::BrokerUnavailable)?;
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
                .map_err(|_| QualificationExchangeError::TransportFailure)?;
            exchange_stream(&mut stream, request, &mut self.response)
        }
        #[cfg(not(unix))]
        {
            let _ = request;
            Err(QualificationExchangeError::BrokerUnavailable)
        }
    }
}

trait QualificationStream: Read + Write {
    fn shutdown_write(&mut self) -> std::io::Result<()>;
}

#[cfg(unix)]
impl QualificationStream for std::os::unix::net::UnixStream {
    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

fn exchange_stream(
    stream: &mut impl QualificationStream,
    request: &QualificationRequest,
    response_slot: &mut Option<BrokerResponse>,
) -> Result<(), QualificationExchangeError> {
    let request_id = request_id(request);
    let request = Request::AdmitQualification(to_protocol_request(request));
    let encoded = encode_request(request_id, request);
    stream
        .write_all(encoded.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| QualificationExchangeError::TransportFailure)?;
    stream
        .shutdown_write()
        .map_err(|_| QualificationExchangeError::TransportFailure)?;

    let mut response = Vec::with_capacity(RESPONSE_FRAME_SIZE);
    stream
        .take((RESPONSE_FRAME_SIZE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| QualificationExchangeError::TransportFailure)?;
    if response.len() != RESPONSE_FRAME_SIZE {
        return Err(QualificationExchangeError::InvalidBrokerResponse);
    }
    let decoded = decode_response(
        FrameHeader {
            operation: request.operation(),
            request_id,
        },
        &response,
    )
    .map_err(|_| QualificationExchangeError::InvalidBrokerResponse)?;
    *response_slot = Some(decoded);
    if decoded.code == ResponseCode::Ok {
        Ok(())
    } else {
        Err(QualificationExchangeError::Refused(decoded.code))
    }
}

fn request_id(request: &QualificationRequest) -> [u8; 16] {
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&request.nonce.as_bytes()[..16]);
    request_id
}

fn to_protocol_request(request: &QualificationRequest) -> ProtocolQualificationRequest {
    ProtocolQualificationRequest {
        integrated_candidate_sha: protocol_oid(request.integrated_candidate_sha),
        broker_build_identity: *request.broker_build_identity.as_bytes(),
        host_profile_digest: *request.host_profile_digest.as_bytes(),
        suite_identity: *request.suite_identity.as_bytes(),
        fixture_signer: *request.fixture_signer.as_bytes(),
        request_digest: *request.request_digest.as_bytes(),
        manifest_digest: *request.manifest_digest.as_bytes(),
        isolation_profile_digest: *request.isolation_profile_digest.as_bytes(),
        source_oid: protocol_oid(request.source_oid),
        base_oid: protocol_oid(request.base_oid),
        job_identity: *request.job_identity.as_bytes(),
        fixture_identity: *request.fixture_identity.as_bytes(),
        nonce: *request.nonce.as_bytes(),
        not_before: request.not_before,
        expires_at: request.expires_at,
        directive: request.directive.map(|directive| match directive {
            QualificationDirective::TeardownFailure => ProtocolDirective::TeardownFailure,
        }),
    }
}

const fn protocol_oid(oid: GitOid) -> ProtocolGitOid {
    match oid {
        GitOid::Sha1(bytes) => ProtocolGitOid::Sha1(bytes),
        GitOid::Sha256(bytes) => ProtocolGitOid::Sha256(bytes),
    }
}

/// Stable lowercase name for a broker response code.
pub const fn response_code_name(code: ResponseCode) -> &'static str {
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

fn validate(
    request: QualificationExchangeInput,
) -> Result<ValidatedQualificationExchange, InputError> {
    if request.version != "qualification_v1" {
        return Err(InputError::UnsupportedVersion);
    }

    validate_permit(&request.permit)?;
    validate_admission(&request.admission)?;

    if request.permit.not_before >= request.permit.expires_at {
        return Err(InputError::InvalidTimeWindow);
    }
    if request.admission.trust_class != AdmissionTrustClass::QualificationFixture {
        return Err(InputError::UnacceptedTrustClass);
    }

    require_equal(
        request.permit.host.integrated_candidate_sha,
        request.admission.host.integrated_candidate_sha,
        "host.integrated_candidate_sha",
    )?;
    require_equal(
        request.permit.host.broker_build_identity,
        request.admission.host.broker_build_identity,
        "host.broker_build_identity",
    )?;
    require_equal(
        request.permit.host.host_profile_digest,
        request.admission.host.host_profile_digest,
        "host.host_profile_digest",
    )?;
    require_equal(
        request.permit.host.suite_identity,
        request.admission.host.suite_identity,
        "host.suite_identity",
    )?;
    require_equal(
        request.permit.fixture_job.request_digest,
        request.admission.fixture_job.request_digest,
        "fixture_job.request_digest",
    )?;
    require_equal(
        request.permit.fixture_job.manifest_digest,
        request.admission.fixture_job.manifest_digest,
        "fixture_job.manifest_digest",
    )?;
    require_equal(
        request.permit.fixture_job.isolation_profile_digest,
        request.admission.fixture_job.isolation_profile_digest,
        "fixture_job.isolation_profile_digest",
    )?;
    require_equal(
        request.permit.fixture_job.source_oid,
        request.admission.fixture_job.source_oid,
        "fixture_job.source_oid",
    )?;
    require_equal(
        request.permit.fixture_job.base_oid,
        request.admission.fixture_job.base_oid,
        "fixture_job.base_oid",
    )?;
    require_equal(
        request.permit.fixture_job.test_identity,
        request.admission.fixture_job.test_identity,
        "fixture_job.test_identity",
    )?;
    require_equal(
        request.permit.fixture_identity,
        request.admission.fixture_identity,
        "fixture_identity",
    )?;
    require_equal(
        request.permit.fixture_signer,
        request.admission.signer,
        "fixture_signer",
    )?;
    require_equal(request.permit.nonce, request.admission.nonce, "nonce")?;

    let protocol_request = QualificationRequest {
        integrated_candidate_sha: request.permit.host.integrated_candidate_sha,
        broker_build_identity: request.permit.host.broker_build_identity,
        host_profile_digest: request.permit.host.host_profile_digest,
        suite_identity: request.permit.host.suite_identity,
        fixture_signer: request.permit.fixture_signer,
        request_digest: request.permit.fixture_job.request_digest,
        manifest_digest: request.permit.fixture_job.manifest_digest,
        isolation_profile_digest: request.permit.fixture_job.isolation_profile_digest,
        source_oid: request.permit.fixture_job.source_oid,
        base_oid: request.permit.fixture_job.base_oid,
        job_identity: request.permit.fixture_job.test_identity,
        fixture_identity: request.permit.fixture_identity,
        nonce: request.permit.nonce,
        not_before: request.permit.not_before,
        expires_at: request.permit.expires_at,
        directive: request.directive,
    };
    Ok(ValidatedQualificationExchange {
        input: request,
        request: protocol_request,
    })
}

fn validate_permit(permit: &QualificationPermitInput) -> Result<(), InputError> {
    require_nonzero_hex(permit.authorized_by, "permit.authorized_by")?;
    validate_host(&permit.host, "permit")?;
    validate_fixture_job(&permit.fixture_job, "permit")?;
    require_nonzero_hex(permit.fixture_identity, "permit.fixture_identity")?;
    require_nonzero_hex(permit.fixture_signer, "permit.fixture_signer")?;
    require_nonzero_hex(permit.nonce, "permit.nonce")?;
    if permit.not_before == 0 {
        return Err(InputError::ZeroField("permit.not_before"));
    }
    if permit.expires_at == 0 {
        return Err(InputError::ZeroField("permit.expires_at"));
    }
    Ok(())
}

fn validate_admission(admission: &QualificationAdmissionInput) -> Result<(), InputError> {
    validate_host(&admission.host, "admission")?;
    validate_fixture_job(&admission.fixture_job, "admission")?;
    require_nonzero_hex(admission.fixture_identity, "admission.fixture_identity")?;
    require_nonzero_hex(admission.signer, "admission.signer")?;
    require_nonzero_hex(admission.nonce, "admission.nonce")
}

fn validate_host(host: &HostCoordinates, prefix: &'static str) -> Result<(), InputError> {
    let fields = if prefix == "permit" {
        [
            (
                host.broker_build_identity,
                "permit.host.broker_build_identity",
            ),
            (host.host_profile_digest, "permit.host.host_profile_digest"),
            (host.suite_identity, "permit.host.suite_identity"),
        ]
    } else {
        [
            (
                host.broker_build_identity,
                "admission.host.broker_build_identity",
            ),
            (
                host.host_profile_digest,
                "admission.host.host_profile_digest",
            ),
            (host.suite_identity, "admission.host.suite_identity"),
        ]
    };
    for (value, field) in fields {
        require_nonzero_hex(value, field)?;
    }
    let oid_field = if prefix == "permit" {
        "permit.host.integrated_candidate_sha"
    } else {
        "admission.host.integrated_candidate_sha"
    };
    require_nonzero_oid(host.integrated_candidate_sha, oid_field)
}

fn validate_fixture_job(
    job: &FixtureJobCoordinates,
    prefix: &'static str,
) -> Result<(), InputError> {
    let fields = if prefix == "permit" {
        [
            (job.request_digest, "permit.fixture_job.request_digest"),
            (job.manifest_digest, "permit.fixture_job.manifest_digest"),
            (
                job.isolation_profile_digest,
                "permit.fixture_job.isolation_profile_digest",
            ),
            (job.test_identity, "permit.fixture_job.test_identity"),
        ]
    } else {
        [
            (job.request_digest, "admission.fixture_job.request_digest"),
            (job.manifest_digest, "admission.fixture_job.manifest_digest"),
            (
                job.isolation_profile_digest,
                "admission.fixture_job.isolation_profile_digest",
            ),
            (job.test_identity, "admission.fixture_job.test_identity"),
        ]
    };
    for (value, field) in fields {
        require_nonzero_hex(value, field)?;
    }
    let (source, base) = if prefix == "permit" {
        (
            "permit.fixture_job.source_oid",
            "permit.fixture_job.base_oid",
        )
    } else {
        (
            "admission.fixture_job.source_oid",
            "admission.fixture_job.base_oid",
        )
    };
    require_nonzero_oid(job.source_oid, source)?;
    require_nonzero_oid(job.base_oid, base)
}

fn require_nonzero_hex(value: Hex32, field: &'static str) -> Result<(), InputError> {
    if value.is_zero() {
        Err(InputError::ZeroField(field))
    } else {
        Ok(())
    }
}

fn require_nonzero_oid(value: GitOid, field: &'static str) -> Result<(), InputError> {
    if value.is_zero() {
        Err(InputError::ZeroField(field))
    } else {
        Ok(())
    }
}

fn require_equal<T: Eq>(left: T, right: T, field: &'static str) -> Result<(), InputError> {
    if left == right {
        Ok(())
    } else {
        Err(InputError::BindingMismatch(field))
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 {
        return Err("hex value has the wrong length");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("hex value must use normalized lowercase ASCII");
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("decode_hex validates every nibble"),
    }
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

#[cfg(test)]
mod transport_tests {
    use std::io::{Cursor, Read, Write};

    use buzz_ci_broker_protocol::{
        decode_request, encode_response, BrokerState, Conclusion, GitOid as ProtocolGitOid,
        Operation,
    };

    use super::*;

    struct ScriptedStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        shutdown: bool,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(output)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl QualificationStream for ScriptedStream {
        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.shutdown = true;
            Ok(())
        }
    }

    fn request() -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: GitOid::Sha256([2; 32]),
            broker_build_identity: Hex32([3; 32]),
            host_profile_digest: Hex32([4; 32]),
            suite_identity: Hex32([5; 32]),
            fixture_signer: Hex32([6; 32]),
            request_digest: Hex32([7; 32]),
            manifest_digest: Hex32([8; 32]),
            isolation_profile_digest: Hex32([9; 32]),
            source_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha1([11; 20]),
            job_identity: Hex32([12; 32]),
            fixture_identity: Hex32([13; 32]),
            nonce: Hex32([14; 32]),
            not_before: 100,
            expires_at: 200,
            directive: Some(QualificationDirective::TeardownFailure),
        }
    }

    fn response(code: ResponseCode) -> BrokerResponse {
        BrokerResponse {
            code,
            retry_after_millis: 0,
            attempt_id: [13; 16],
            run_id: [0; 16],
            accepted_request_digest: [7; 32],
            job_manifest_digest: [8; 32],
            tip_oid: None,
            broker_state: BrokerState::Reconciling,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: 1,
            accepted_at: 100,
            updated_at: 100,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 0,
        }
    }

    fn stream(code: ResponseCode) -> ScriptedStream {
        let header = FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [14; 16],
        };
        ScriptedStream {
            input: Cursor::new(encode_response(header, response(code)).as_bytes().to_vec()),
            output: Vec::new(),
            shutdown: false,
        }
    }

    #[test]
    fn fixed_transport_emits_the_exact_qualification_frame() {
        let request = request();
        let mut stream = stream(ResponseCode::Ok);
        let mut response_slot = None;
        exchange_stream(&mut stream, &request, &mut response_slot).unwrap();
        assert!(stream.shutdown);
        let (header, decoded) = decode_request(&stream.output).unwrap();
        assert_eq!(header.operation, Operation::AdmitQualification);
        assert_eq!(header.request_id, [14; 16]);
        assert_eq!(
            decoded,
            Request::AdmitQualification(ProtocolQualificationRequest {
                integrated_candidate_sha: ProtocolGitOid::Sha256([2; 32]),
                broker_build_identity: [3; 32],
                host_profile_digest: [4; 32],
                suite_identity: [5; 32],
                fixture_signer: [6; 32],
                request_digest: [7; 32],
                manifest_digest: [8; 32],
                isolation_profile_digest: [9; 32],
                source_oid: ProtocolGitOid::Sha256([10; 32]),
                base_oid: ProtocolGitOid::Sha1([11; 20]),
                job_identity: [12; 32],
                fixture_identity: [13; 32],
                nonce: [14; 32],
                not_before: 100,
                expires_at: 200,
                directive: Some(ProtocolDirective::TeardownFailure),
            })
        );
        assert_eq!(response_slot, Some(response(ResponseCode::Ok)));
    }

    #[test]
    fn fixed_transport_preserves_stable_broker_refusals() {
        let mut stream = stream(ResponseCode::ReplayConflict);
        let error = exchange_stream(&mut stream, &request(), &mut None).unwrap_err();
        assert_eq!(
            error,
            QualificationExchangeError::Refused(ResponseCode::ReplayConflict)
        );
        assert_eq!(error.code(), "replay_conflict");
    }
}
