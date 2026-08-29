//! Fixed-width IPC between the unprivileged Buzz CI control process and the
//! privileged resource broker.
//!
//! This protocol is deliberately independent from the public Nostr CI
//! envelopes. It can represent only normalized identifiers, digests, counters,
//! deadlines, and closed enums. It cannot represent repository content,
//! commands, paths, environment variables, logs, artifacts, or credentials.

#![forbid(unsafe_code)]

/// Version 2 protocol types and codecs.
///
/// Version 2 is a separate wire contract. Its codecs never reinterpret a
/// version 1 frame, and the legacy top-level API remains frozen at version 1.
pub mod v2;

pub const MAGIC: [u8; 4] = *b"BZCI";
pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 32;
pub const HELLO_BODY_SIZE: usize = 64;
pub const ADMIT_ATTEMPT_BODY_SIZE: usize = 376;
pub const ADMIT_QUALIFICATION_BODY_SIZE: usize = 440;
pub const CANCEL_ATTEMPT_BODY_SIZE: usize = 128;
pub const GET_ATTEMPT_BODY_SIZE: usize = 32;
pub const COMPLETE_ATTEMPT_BODY_SIZE: usize = 160;
pub const RESPONSE_BODY_SIZE: usize = 256;
pub const MAX_BODY_SIZE: usize = ADMIT_QUALIFICATION_BODY_SIZE;
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_BODY_SIZE;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const OP_RESPONSE_BIT: u16 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    Hello = 1,
    AdmitAttempt = 2,
    CancelAttempt = 3,
    GetAttempt = 4,
    AdmitQualification = 5,
    CompleteAttempt = 6,
}

impl Operation {
    fn from_u16(value: u16) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::AdmitAttempt),
            3 => Ok(Self::CancelAttempt),
            4 => Ok(Self::GetAttempt),
            5 => Ok(Self::AdmitQualification),
            6 => Ok(Self::CompleteAttempt),
            _ => Err(DecodeError::UnknownOperation),
        }
    }

    const fn body_size(self) -> usize {
        match self {
            Self::Hello => HELLO_BODY_SIZE,
            Self::AdmitAttempt => ADMIT_ATTEMPT_BODY_SIZE,
            Self::CancelAttempt => CANCEL_ATTEMPT_BODY_SIZE,
            Self::GetAttempt => GET_ATTEMPT_BODY_SIZE,
            Self::AdmitQualification => ADMIT_QUALIFICATION_BODY_SIZE,
            Self::CompleteAttempt => COMPLETE_ATTEMPT_BODY_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub operation: Operation,
    pub request_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitOid {
    fn encode_into(self, output: &mut [u8]) {
        debug_assert_eq!(output.len(), 33);
        match self {
            Self::Sha1(bytes) => {
                output[0] = 1;
                output[1..21].copy_from_slice(&bytes);
                output[21..].fill(0);
            }
            Self::Sha256(bytes) => {
                output[0] = 2;
                output[1..].copy_from_slice(&bytes);
            }
        }
    }

    fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() != 33 {
            return Err(DecodeError::WrongBodyLength);
        }
        match input[0] {
            1 => {
                if input[21..].iter().any(|byte| *byte != 0) {
                    return Err(DecodeError::NonCanonicalOid);
                }
                let mut bytes = [0_u8; 20];
                bytes.copy_from_slice(&input[1..21]);
                if is_zero(&bytes) {
                    return Err(DecodeError::ZeroField);
                }
                Ok(Self::Sha1(bytes))
            }
            2 => {
                let mut bytes = [0_u8; 32];
                bytes.copy_from_slice(&input[1..]);
                if is_zero(&bytes) {
                    return Err(DecodeError::ZeroField);
                }
                Ok(Self::Sha256(bytes))
            }
            _ => Err(DecodeError::UnknownOidAlgorithm),
        }
    }

    fn encode_optional(value: Option<Self>, output: &mut [u8]) {
        match value {
            Some(oid) => oid.encode_into(output),
            None => output.fill(0),
        }
    }

    fn decode_optional(input: &[u8]) -> Result<Option<Self>, DecodeError> {
        if input.len() == 33 && input.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        Self::decode(input).map(Some)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TrustClass {
    AcceptedReviewed = 1,
}

impl TryFrom<u8> for TrustClass {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AcceptedReviewed),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CancelReason {
    UserRequest = 1,
    SignedPolicy = 2,
    Shutdown = 3,
}

impl TryFrom<u16> for CancelReason {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UserRequest),
            2 => Ok(Self::SignedPolicy),
            3 => Ok(Self::Shutdown),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// The only privileged fault behavior available to a qualification fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum QualificationDirective {
    TeardownFailure = 1,
}

impl QualificationDirective {
    fn decode_optional(value: u8) -> Result<Option<Self>, DecodeError> {
        match value {
            0 => Ok(None),
            _ => Self::try_from(value).map(Some),
        }
    }
}

impl TryFrom<u8> for QualificationDirective {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TeardownFailure),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloRequest {
    pub controller_instance: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmitAttemptRequest {
    pub signed_request_digest: [u8; 32],
    pub actor_pubkey: [u8; 32],
    pub audience_digest: [u8; 32],
    pub idempotency_digest: [u8; 32],
    pub source_pin_event_id: [u8; 32],
    pub workflow_digest: [u8; 32],
    pub job_manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub run_id: [u8; 16],
    pub tip_oid: GitOid,
    pub base_oid: GitOid,
    pub issued_at: u64,
    pub expires_at: u64,
    pub wall_timeout_seconds: u32,
    pub attempt: u32,
    pub parent_attempt: u32,
    pub trust_class: TrustClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelAttemptRequest {
    pub attempt_id: [u8; 16],
    pub actor_pubkey: [u8; 32],
    pub cancel_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub expected_generation: u64,
    pub reason: CancelReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetAttemptRequest {
    pub attempt_id: [u8; 16],
}

/// Authenticated completion claim for one exact admitted lease.
///
/// `signer_pubkey` remains a claim on the wire. The service-owned boundary must
/// authenticate it and compare it to the admitted actor before using this
/// request to mutate lifecycle state. The conclusion is advisory; durable
/// evidence and teardown decide final state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteAttemptRequest {
    pub signer_pubkey: [u8; 32],
    pub signed_request_digest: [u8; 32],
    pub run_id: [u8; 16],
    pub attempt: u32,
    pub lease_id: [u8; 16],
    pub lease_generation: u64,
    pub advisory_conclusion: Conclusion,
    pub evidence_set_digest: [u8; 32],
    pub terminal_at: u64,
}

/// One root-permitted qualification fixture request.
///
/// `fixture_signer` is a claimed identity. The service-owned authentication
/// adapter must verify it before constructing its trusted signer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationRequest {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub fixture_signer: [u8; 32],
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub job_identity: [u8; 32],
    pub fixture_identity: [u8; 32],
    pub nonce: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub directive: Option<QualificationDirective>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Keeping every request inline is deliberate: the root broker accepts only
// bounded fixed-width frames and never allocates from attacker-selected data.
#[allow(clippy::large_enum_variant)]
pub enum Request {
    Hello(HelloRequest),
    AdmitAttempt(AdmitAttemptRequest),
    CancelAttempt(CancelAttemptRequest),
    GetAttempt(GetAttemptRequest),
    AdmitQualification(QualificationRequest),
    CompleteAttempt(CompleteAttemptRequest),
}

impl Request {
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Hello(_) => Operation::Hello,
            Self::AdmitAttempt(_) => Operation::AdmitAttempt,
            Self::CancelAttempt(_) => Operation::CancelAttempt,
            Self::GetAttempt(_) => Operation::GetAttempt,
            Self::AdmitQualification(_) => Operation::AdmitQualification,
            Self::CompleteAttempt(_) => Operation::CompleteAttempt,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ResponseCode {
    Ok = 0,
    Existing = 1,
    BadFrame = 100,
    UnsupportedVersion = 101,
    UnknownOperation = 102,
    InvalidField = 103,
    UnauthorizedPeer = 104,
    PolicyDenied = 105,
    ReplayConflict = 106,
    NoCapacity = 107,
    NotProvisioned = 108,
    NotFound = 109,
    StateConflict = 110,
    Reconciling = 111,
    StorageUnavailable = 112,
    InternalFailure = 113,
}

impl TryFrom<u16> for ResponseCode {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Existing),
            100 => Ok(Self::BadFrame),
            101 => Ok(Self::UnsupportedVersion),
            102 => Ok(Self::UnknownOperation),
            103 => Ok(Self::InvalidField),
            104 => Ok(Self::UnauthorizedPeer),
            105 => Ok(Self::PolicyDenied),
            106 => Ok(Self::ReplayConflict),
            107 => Ok(Self::NoCapacity),
            108 => Ok(Self::NotProvisioned),
            109 => Ok(Self::NotFound),
            110 => Ok(Self::StateConflict),
            111 => Ok(Self::Reconciling),
            112 => Ok(Self::StorageUnavailable),
            113 => Ok(Self::InternalFailure),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BrokerState {
    Booting = 1,
    Reconciling = 2,
    Ready = 3,
    Draining = 4,
    Quarantined = 5,
    Terminal = 6,
    Leased = 7,
}

impl TryFrom<u8> for BrokerState {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Booting),
            2 => Ok(Self::Reconciling),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Draining),
            5 => Ok(Self::Quarantined),
            6 => Ok(Self::Terminal),
            7 => Ok(Self::Leased),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Conclusion {
    None = 0,
    Success = 1,
    Failure = 2,
    Cancelled = 3,
    TimedOut = 4,
    InfrastructureFailure = 5,
}

impl TryFrom<u8> for Conclusion {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Success),
            2 => Ok(Self::Failure),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::InfrastructureFailure),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerResponse {
    pub code: ResponseCode,
    pub retry_after_millis: u32,
    pub attempt_id: [u8; 16],
    pub run_id: [u8; 16],
    pub accepted_request_digest: [u8; 32],
    pub job_manifest_digest: [u8; 32],
    pub tip_oid: Option<GitOid>,
    pub broker_state: BrokerState,
    pub conclusion: Conclusion,
    pub terminal_reason: u16,
    pub generation: u64,
    pub accepted_at: u64,
    pub updated_at: u64,
    pub lease_generation: u64,
    pub evidence_set_digest: [u8; 32],
    pub teardown_digest: [u8; 32],
    pub attempt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    bytes: [u8; MAX_FRAME_SIZE],
    len: usize,
}

impl EncodedFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Validates an exact request header before a stream reader allocates or reads
/// the body. The returned length is a protocol constant for the decoded
/// operation, never an attacker-selected size.
pub fn decode_request_header(input: &[u8]) -> Result<(FrameHeader, usize), DecodeError> {
    if input.len() < HEADER_SIZE {
        return Err(DecodeError::FrameTooShort);
    }
    if input.len() > HEADER_SIZE {
        return Err(DecodeError::TrailingBytes);
    }
    if input[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if get_u16(input, 4) != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let operation = Operation::from_u16(get_u16(input, 6))?;
    if get_u32(input, 8) != 0 {
        return Err(DecodeError::NonZeroFlags);
    }
    let declared = usize::try_from(get_u32(input, 12)).map_err(|_| DecodeError::WrongBodyLength)?;
    let expected = operation.body_size();
    if declared != expected {
        return Err(DecodeError::WrongBodyLength);
    }
    Ok((
        FrameHeader {
            operation,
            request_id: array(&input[16..32]),
        },
        expected,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    FrameTooShort,
    BadMagic,
    UnsupportedVersion,
    UnknownOperation,
    NonZeroFlags,
    WrongBodyLength,
    TrailingBytes,
    NonZeroReserved,
    UnknownOidAlgorithm,
    NonCanonicalOid,
    UnknownEnum,
    ZeroField,
    InvalidAttemptLineage,
    InvalidDeadline,
    UnsafeInteger,
}

pub fn encode_request(request_id: [u8; 16], request: Request) -> EncodedFrame {
    let operation = request.operation();
    let body_size = operation.body_size();
    let mut encoded = EncodedFrame {
        bytes: [0_u8; MAX_FRAME_SIZE],
        len: HEADER_SIZE + body_size,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        operation as u16,
        body_size,
        request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    match request {
        Request::Hello(value) => encode_hello(body, value),
        Request::AdmitAttempt(value) => encode_admit(body, value),
        Request::CancelAttempt(value) => encode_cancel(body, value),
        Request::GetAttempt(value) => body[..16].copy_from_slice(&value.attempt_id),
        Request::AdmitQualification(value) => encode_qualification(body, value),
        Request::CompleteAttempt(value) => encode_complete(body, value),
    }
    encoded
}

pub fn decode_request(frame: &[u8]) -> Result<(FrameHeader, Request), DecodeError> {
    if frame.len() < HEADER_SIZE {
        return Err(DecodeError::FrameTooShort);
    }
    let (header, body_size) = decode_request_header(&frame[..HEADER_SIZE])?;
    let expected_len = HEADER_SIZE + body_size;
    if frame.len() < expected_len {
        return Err(DecodeError::WrongBodyLength);
    }
    if frame.len() > expected_len {
        return Err(DecodeError::TrailingBytes);
    }
    let operation = header.operation;
    let body = &frame[HEADER_SIZE..];
    if body.len() != operation.body_size() {
        return Err(DecodeError::WrongBodyLength);
    }
    let request = match operation {
        Operation::Hello => Request::Hello(decode_hello(body)?),
        Operation::AdmitAttempt => Request::AdmitAttempt(decode_admit(body)?),
        Operation::CancelAttempt => Request::CancelAttempt(decode_cancel(body)?),
        Operation::GetAttempt => {
            require_zero(&body[16..])?;
            Request::GetAttempt(GetAttemptRequest {
                attempt_id: nonzero_array(&body[..16])?,
            })
        }
        Operation::AdmitQualification => Request::AdmitQualification(decode_qualification(body)?),
        Operation::CompleteAttempt => Request::CompleteAttempt(decode_complete(body)?),
    };
    Ok((header, request))
}

pub fn encode_response(request_header: FrameHeader, response: BrokerResponse) -> EncodedFrame {
    let mut encoded = EncodedFrame {
        bytes: [0_u8; MAX_FRAME_SIZE],
        len: HEADER_SIZE + RESPONSE_BODY_SIZE,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        (request_header.operation as u16) | OP_RESPONSE_BIT,
        RESPONSE_BODY_SIZE,
        request_header.request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    put_u16(body, 0, response.code as u16);
    put_u32(body, 2, response.retry_after_millis);
    body[6..22].copy_from_slice(&response.attempt_id);
    body[22..38].copy_from_slice(&response.run_id);
    body[38..70].copy_from_slice(&response.accepted_request_digest);
    body[70..102].copy_from_slice(&response.job_manifest_digest);
    GitOid::encode_optional(response.tip_oid, &mut body[102..135]);
    body[135] = response.broker_state as u8;
    body[136] = response.conclusion as u8;
    put_u16(body, 137, response.terminal_reason);
    put_u64(body, 139, response.generation);
    put_u64(body, 147, response.accepted_at);
    put_u64(body, 155, response.updated_at);
    put_u64(body, 163, response.lease_generation);
    body[171..203].copy_from_slice(&response.evidence_set_digest);
    body[203..235].copy_from_slice(&response.teardown_digest);
    put_u32(body, 235, response.attempt);
    encoded
}

pub fn decode_response(expected: FrameHeader, frame: &[u8]) -> Result<BrokerResponse, DecodeError> {
    let (operation, request_id, body) = decode_header(frame, true)?;
    if operation != (expected.operation as u16) | OP_RESPONSE_BIT
        || request_id != expected.request_id
    {
        return Err(DecodeError::UnknownOperation);
    }
    if body.len() != RESPONSE_BODY_SIZE {
        return Err(DecodeError::WrongBodyLength);
    }
    require_zero(&body[239..])?;
    let response = BrokerResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        retry_after_millis: get_u32(body, 2),
        attempt_id: array(&body[6..22]),
        run_id: array(&body[22..38]),
        accepted_request_digest: array(&body[38..70]),
        job_manifest_digest: array(&body[70..102]),
        tip_oid: GitOid::decode_optional(&body[102..135])?,
        broker_state: BrokerState::try_from(body[135])?,
        conclusion: Conclusion::try_from(body[136])?,
        terminal_reason: get_u16(body, 137),
        generation: get_u64(body, 139),
        accepted_at: get_u64(body, 147),
        updated_at: get_u64(body, 155),
        lease_generation: get_u64(body, 163),
        evidence_set_digest: array(&body[171..203]),
        teardown_digest: array(&body[203..235]),
        attempt: get_u32(body, 235),
    };
    validate_safe(response.accepted_at)?;
    validate_safe(response.updated_at)?;
    Ok(response)
}

fn encode_header(output: &mut [u8], operation: u16, body_size: usize, request_id: [u8; 16]) {
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, PROTOCOL_VERSION);
    put_u16(output, 6, operation);
    put_u32(output, 8, 0);
    put_u32(
        output,
        12,
        u32::try_from(body_size).expect("fixed body size fits u32"),
    );
    output[16..32].copy_from_slice(&request_id);
}

fn decode_header(frame: &[u8], response: bool) -> Result<(u16, [u8; 16], &[u8]), DecodeError> {
    if frame.len() < HEADER_SIZE {
        return Err(DecodeError::FrameTooShort);
    }
    if frame[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if get_u16(frame, 4) != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let operation = get_u16(frame, 6);
    if response != (operation & OP_RESPONSE_BIT != 0) {
        return Err(DecodeError::UnknownOperation);
    }
    if get_u32(frame, 8) != 0 {
        return Err(DecodeError::NonZeroFlags);
    }
    let body_len = usize::try_from(get_u32(frame, 12)).map_err(|_| DecodeError::WrongBodyLength)?;
    if body_len > MAX_BODY_SIZE {
        return Err(DecodeError::WrongBodyLength);
    }
    let expected_len = HEADER_SIZE
        .checked_add(body_len)
        .ok_or(DecodeError::WrongBodyLength)?;
    if frame.len() < expected_len {
        return Err(DecodeError::WrongBodyLength);
    }
    if frame.len() > expected_len {
        return Err(DecodeError::TrailingBytes);
    }
    Ok((operation, array(&frame[16..32]), &frame[HEADER_SIZE..]))
}

fn encode_hello(body: &mut [u8], value: HelloRequest) {
    body[..32].copy_from_slice(&value.controller_instance);
    body[32..64].copy_from_slice(&value.nonce);
}

fn decode_hello(body: &[u8]) -> Result<HelloRequest, DecodeError> {
    Ok(HelloRequest {
        controller_instance: nonzero_array(&body[..32])?,
        nonce: nonzero_array(&body[32..64])?,
    })
}

fn encode_admit(body: &mut [u8], value: AdmitAttemptRequest) {
    let digests = [
        value.signed_request_digest,
        value.actor_pubkey,
        value.audience_digest,
        value.idempotency_digest,
        value.source_pin_event_id,
        value.workflow_digest,
        value.job_manifest_digest,
        value.isolation_profile_digest,
    ];
    for (index, digest) in digests.into_iter().enumerate() {
        let start = index * 32;
        body[start..start + 32].copy_from_slice(&digest);
    }
    body[256..272].copy_from_slice(&value.run_id);
    value.tip_oid.encode_into(&mut body[272..305]);
    value.base_oid.encode_into(&mut body[305..338]);
    put_u64(body, 338, value.issued_at);
    put_u64(body, 346, value.expires_at);
    put_u32(body, 354, value.wall_timeout_seconds);
    put_u32(body, 358, value.attempt);
    put_u32(body, 362, value.parent_attempt);
    body[366] = value.trust_class as u8;
}

fn decode_admit(body: &[u8]) -> Result<AdmitAttemptRequest, DecodeError> {
    require_zero(&body[367..])?;
    let value = AdmitAttemptRequest {
        signed_request_digest: nonzero_array(&body[0..32])?,
        actor_pubkey: nonzero_array(&body[32..64])?,
        audience_digest: nonzero_array(&body[64..96])?,
        idempotency_digest: nonzero_array(&body[96..128])?,
        source_pin_event_id: nonzero_array(&body[128..160])?,
        workflow_digest: nonzero_array(&body[160..192])?,
        job_manifest_digest: nonzero_array(&body[192..224])?,
        isolation_profile_digest: nonzero_array(&body[224..256])?,
        run_id: nonzero_array(&body[256..272])?,
        tip_oid: GitOid::decode(&body[272..305])?,
        base_oid: GitOid::decode(&body[305..338])?,
        issued_at: get_u64(body, 338),
        expires_at: get_u64(body, 346),
        wall_timeout_seconds: get_u32(body, 354),
        attempt: get_u32(body, 358),
        parent_attempt: get_u32(body, 362),
        trust_class: TrustClass::try_from(body[366])?,
    };
    validate_safe(value.issued_at)?;
    validate_safe(value.expires_at)?;
    if value.expires_at <= value.issued_at || value.wall_timeout_seconds == 0 {
        return Err(DecodeError::InvalidDeadline);
    }
    if value.attempt == 0
        || (value.attempt == 1 && value.parent_attempt != 0)
        || (value.attempt > 1 && value.parent_attempt.checked_add(1) != Some(value.attempt))
    {
        return Err(DecodeError::InvalidAttemptLineage);
    }
    Ok(value)
}

fn encode_qualification(body: &mut [u8], value: QualificationRequest) {
    value.integrated_candidate_sha.encode_into(&mut body[0..33]);
    body[33..65].copy_from_slice(&value.broker_build_identity);
    body[65..97].copy_from_slice(&value.host_profile_digest);
    body[97..129].copy_from_slice(&value.suite_identity);
    body[129..161].copy_from_slice(&value.fixture_signer);
    body[161..193].copy_from_slice(&value.request_digest);
    body[193..225].copy_from_slice(&value.manifest_digest);
    body[225..257].copy_from_slice(&value.isolation_profile_digest);
    value.source_oid.encode_into(&mut body[257..290]);
    value.base_oid.encode_into(&mut body[290..323]);
    body[323..355].copy_from_slice(&value.job_identity);
    body[355..387].copy_from_slice(&value.fixture_identity);
    body[387..419].copy_from_slice(&value.nonce);
    put_u64(body, 419, value.not_before);
    put_u64(body, 427, value.expires_at);
    body[435] = value.directive.map_or(0, |directive| directive as u8);
}

fn decode_qualification(body: &[u8]) -> Result<QualificationRequest, DecodeError> {
    require_zero(&body[436..])?;
    let value = QualificationRequest {
        integrated_candidate_sha: GitOid::decode(&body[0..33])?,
        broker_build_identity: nonzero_array(&body[33..65])?,
        host_profile_digest: nonzero_array(&body[65..97])?,
        suite_identity: nonzero_array(&body[97..129])?,
        fixture_signer: nonzero_array(&body[129..161])?,
        request_digest: nonzero_array(&body[161..193])?,
        manifest_digest: nonzero_array(&body[193..225])?,
        isolation_profile_digest: nonzero_array(&body[225..257])?,
        source_oid: GitOid::decode(&body[257..290])?,
        base_oid: GitOid::decode(&body[290..323])?,
        job_identity: nonzero_array(&body[323..355])?,
        fixture_identity: nonzero_array(&body[355..387])?,
        nonce: nonzero_array(&body[387..419])?,
        not_before: get_u64(body, 419),
        expires_at: get_u64(body, 427),
        directive: QualificationDirective::decode_optional(body[435])?,
    };
    validate_safe(value.not_before)?;
    validate_safe(value.expires_at)?;
    if value.not_before >= value.expires_at {
        return Err(DecodeError::InvalidDeadline);
    }
    Ok(value)
}

fn encode_cancel(body: &mut [u8], value: CancelAttemptRequest) {
    body[..16].copy_from_slice(&value.attempt_id);
    body[16..48].copy_from_slice(&value.actor_pubkey);
    body[48..80].copy_from_slice(&value.cancel_digest);
    put_u64(body, 80, value.issued_at);
    put_u64(body, 88, value.expires_at);
    put_u64(body, 96, value.expected_generation);
    put_u16(body, 104, value.reason as u16);
}

fn decode_cancel(body: &[u8]) -> Result<CancelAttemptRequest, DecodeError> {
    require_zero(&body[106..])?;
    let value = CancelAttemptRequest {
        attempt_id: nonzero_array(&body[..16])?,
        actor_pubkey: nonzero_array(&body[16..48])?,
        cancel_digest: nonzero_array(&body[48..80])?,
        issued_at: get_u64(body, 80),
        expires_at: get_u64(body, 88),
        expected_generation: get_u64(body, 96),
        reason: CancelReason::try_from(get_u16(body, 104))?,
    };
    validate_safe(value.issued_at)?;
    validate_safe(value.expires_at)?;
    if value.expires_at <= value.issued_at {
        return Err(DecodeError::InvalidDeadline);
    }
    Ok(value)
}

fn encode_complete(body: &mut [u8], value: CompleteAttemptRequest) {
    body[0..32].copy_from_slice(&value.signer_pubkey);
    body[32..64].copy_from_slice(&value.signed_request_digest);
    body[64..80].copy_from_slice(&value.run_id);
    put_u32(body, 80, value.attempt);
    body[84..100].copy_from_slice(&value.lease_id);
    put_u64(body, 100, value.lease_generation);
    body[108] = value.advisory_conclusion as u8;
    body[109..141].copy_from_slice(&value.evidence_set_digest);
    put_u64(body, 141, value.terminal_at);
}

fn decode_complete(body: &[u8]) -> Result<CompleteAttemptRequest, DecodeError> {
    require_zero(&body[149..])?;
    let value = CompleteAttemptRequest {
        signer_pubkey: nonzero_array(&body[0..32])?,
        signed_request_digest: nonzero_array(&body[32..64])?,
        run_id: nonzero_array(&body[64..80])?,
        attempt: get_u32(body, 80),
        lease_id: nonzero_array(&body[84..100])?,
        lease_generation: get_u64(body, 100),
        advisory_conclusion: Conclusion::try_from(body[108])?,
        evidence_set_digest: nonzero_array(&body[109..141])?,
        terminal_at: get_u64(body, 141),
    };
    if value.attempt == 0
        || value.lease_generation == 0
        || value.advisory_conclusion == Conclusion::None
        || value.terminal_at == 0
    {
        return Err(DecodeError::ZeroField);
    }
    validate_safe(value.terminal_at)?;
    Ok(value)
}

fn require_zero(input: &[u8]) -> Result<(), DecodeError> {
    if input.iter().any(|byte| *byte != 0) {
        return Err(DecodeError::NonZeroReserved);
    }
    Ok(())
}

fn validate_safe(value: u64) -> Result<(), DecodeError> {
    if value > MAX_SAFE_INTEGER {
        return Err(DecodeError::UnsafeInteger);
    }
    Ok(())
}

fn nonzero_array<const N: usize>(input: &[u8]) -> Result<[u8; N], DecodeError> {
    let value = array(input);
    if is_zero(&value) {
        return Err(DecodeError::ZeroField);
    }
    Ok(value)
}

fn array<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(input);
    value
}

fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(array(&input[offset..offset + 2]))
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(array(&input[offset..offset + 4]))
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(array(&input[offset..offset + 8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn oid() -> GitOid {
        GitOid::Sha256(digest(11))
    }

    fn admit() -> AdmitAttemptRequest {
        AdmitAttemptRequest {
            signed_request_digest: digest(1),
            actor_pubkey: digest(2),
            audience_digest: digest(3),
            idempotency_digest: digest(4),
            source_pin_event_id: digest(5),
            workflow_digest: digest(6),
            job_manifest_digest: digest(7),
            isolation_profile_digest: digest(8),
            run_id: [9; 16],
            tip_oid: oid(),
            base_oid: GitOid::Sha1([10; 20]),
            issued_at: 100,
            expires_at: 200,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    fn qualification(directive: Option<QualificationDirective>) -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: GitOid::Sha256(digest(12)),
            broker_build_identity: digest(13),
            host_profile_digest: digest(14),
            suite_identity: digest(15),
            fixture_signer: digest(16),
            request_digest: digest(17),
            manifest_digest: digest(18),
            isolation_profile_digest: digest(19),
            source_oid: GitOid::Sha256(digest(20)),
            base_oid: GitOid::Sha1([21; 20]),
            job_identity: digest(22),
            fixture_identity: digest(23),
            nonce: digest(24),
            not_before: 100,
            expires_at: 200,
            directive,
        }
    }

    fn complete() -> CompleteAttemptRequest {
        CompleteAttemptRequest {
            signer_pubkey: digest(25),
            signed_request_digest: digest(26),
            run_id: [27; 16],
            attempt: 28,
            lease_id: [29; 16],
            lease_generation: 30,
            advisory_conclusion: Conclusion::Success,
            evidence_set_digest: digest(31),
            terminal_at: 300,
        }
    }

    fn legacy_fingerprint(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }

    #[test]
    fn legacy_frame_fingerprints_are_frozen() {
        let requests = [
            Request::Hello(HelloRequest {
                controller_instance: digest(1),
                nonce: digest(2),
            }),
            Request::AdmitAttempt(admit()),
            Request::CancelAttempt(CancelAttemptRequest {
                attempt_id: [3; 16],
                actor_pubkey: digest(4),
                cancel_digest: digest(5),
                issued_at: 100,
                expires_at: 200,
                expected_generation: 7,
                reason: CancelReason::SignedPolicy,
            }),
            Request::GetAttempt(GetAttemptRequest {
                attempt_id: [6; 16],
            }),
            Request::AdmitQualification(qualification(None)),
            Request::AdmitQualification(qualification(Some(
                QualificationDirective::TeardownFailure,
            ))),
        ];
        let fingerprints = requests
            .map(|request| legacy_fingerprint(encode_request([42; 16], request).as_bytes()));
        assert_eq!(
            fingerprints,
            [
                "fdcc4db112dd807e89376b0393ea51aa3647802d5e82adf1ee64ae3e74d6b332",
                "ace88f9c024a0fd5d05b195e654070b1cc70f0a1b908f7eb5bdb97e2af8a6378",
                "5c30309d9c54caaf8326455f5dd50ea6932da6ede7ce4154449f8ce9274f2c4a",
                "baaf58b3790f65d84c7a23371d78f41b4d1bd0f6720083fdfef1dc15110adc06",
                "c37dbe68b9268287a47f4409ba711f4a565a4433156df6eebfbf23d3a1220476",
                "40999559bb1b66b47ba55a7367d16a9ae605f1d16284b6ceb1dbc307ae753470",
            ]
        );
        let response = BrokerResponse {
            code: ResponseCode::NotProvisioned,
            retry_after_millis: 0,
            attempt_id: [8; 16],
            run_id: [9; 16],
            accepted_request_digest: digest(10),
            job_manifest_digest: digest(11),
            tip_oid: Some(oid()),
            broker_state: BrokerState::Reconciling,
            conclusion: Conclusion::InfrastructureFailure,
            terminal_reason: 2,
            generation: 3,
            accepted_at: 100,
            updated_at: 101,
            lease_generation: 4,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 1,
        };
        let response_fingerprints = [
            Operation::Hello,
            Operation::AdmitAttempt,
            Operation::CancelAttempt,
            Operation::GetAttempt,
            Operation::AdmitQualification,
        ]
        .map(|operation| {
            legacy_fingerprint(
                encode_response(
                    FrameHeader {
                        operation,
                        request_id: [42; 16],
                    },
                    response,
                )
                .as_bytes(),
            )
        });
        assert_eq!(
            response_fingerprints,
            [
                "cc96c5915cf176ddcdabdf3896286422b6a96696c9ca93ab9b7a009dcfa1e810",
                "a25a9177e94470942ad719b9512fcbd99dec17a7384ca2a1c4ba8ec42cf859d7",
                "98f75c52d40d8f8c5e9e9bb75543c73ccda6bac823bfe52cc55d57964a34d6f0",
                "e61aefcf81faccc4d32eda5679e26403a9f737edac4e51d26cfb13308c693956",
                "98108352cd166e83977ec25aca9fb3c8321710e3254317b6a4a75d5017a0ec51",
            ]
        );
    }

    #[test]
    fn complete_attempt_frame_fingerprints_are_frozen() {
        let request_id = [42; 16];
        let request = encode_request(request_id, Request::CompleteAttempt(complete()));
        assert_eq!(
            legacy_fingerprint(request.as_bytes()),
            "6ed3264e960fe632d23c31d26bdcd64f966e56ad54d1a87d3bcdaf3126514c3f"
        );

        let response = BrokerResponse {
            code: ResponseCode::NotProvisioned,
            retry_after_millis: 0,
            attempt_id: [8; 16],
            run_id: [9; 16],
            accepted_request_digest: digest(10),
            job_manifest_digest: digest(11),
            tip_oid: Some(oid()),
            broker_state: BrokerState::Reconciling,
            conclusion: Conclusion::InfrastructureFailure,
            terminal_reason: 2,
            generation: 3,
            accepted_at: 100,
            updated_at: 101,
            lease_generation: 4,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 1,
        };
        let response = encode_response(
            FrameHeader {
                operation: Operation::CompleteAttempt,
                request_id,
            },
            response,
        );
        assert_eq!(get_u16(response.as_bytes(), 6), 0x8006);
        assert_eq!(
            legacy_fingerprint(response.as_bytes()),
            "f149611278ea4d836de62d8c792c5b68a394b34def63c35714c9787b1f505d5c"
        );
    }

    #[test]
    fn every_request_round_trips() {
        let requests = [
            Request::Hello(HelloRequest {
                controller_instance: digest(1),
                nonce: digest(2),
            }),
            Request::AdmitAttempt(admit()),
            Request::CancelAttempt(CancelAttemptRequest {
                attempt_id: [3; 16],
                actor_pubkey: digest(4),
                cancel_digest: digest(5),
                issued_at: 100,
                expires_at: 200,
                expected_generation: 7,
                reason: CancelReason::SignedPolicy,
            }),
            Request::GetAttempt(GetAttemptRequest {
                attempt_id: [6; 16],
            }),
            Request::AdmitQualification(qualification(None)),
            Request::AdmitQualification(qualification(Some(
                QualificationDirective::TeardownFailure,
            ))),
            Request::CompleteAttempt(complete()),
        ];
        for request in requests {
            let encoded = encode_request([42; 16], request);
            let (header, decoded) = decode_request(encoded.as_bytes()).expect("valid frame");
            assert_eq!(header.request_id, [42; 16]);
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn response_round_trips_and_binds_request() {
        let header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [7; 16],
        };
        let response = BrokerResponse {
            code: ResponseCode::NotProvisioned,
            retry_after_millis: 0,
            attempt_id: [8; 16],
            run_id: [9; 16],
            accepted_request_digest: digest(10),
            job_manifest_digest: digest(11),
            tip_oid: Some(oid()),
            broker_state: BrokerState::Reconciling,
            conclusion: Conclusion::InfrastructureFailure,
            terminal_reason: 2,
            generation: 3,
            accepted_at: 100,
            updated_at: 101,
            lease_generation: 4,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 1,
        };
        let encoded = encode_response(header, response);
        assert_eq!(decode_response(header, encoded.as_bytes()), Ok(response));
        let wrong_header = FrameHeader {
            request_id: [6; 16],
            ..header
        };
        assert_eq!(
            decode_response(wrong_header, encoded.as_bytes()),
            Err(DecodeError::UnknownOperation)
        );
    }

    #[test]
    fn malformed_headers_and_trailing_frames_fail_closed() {
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        let original = encoded.as_bytes();
        let mut cases = Vec::new();
        cases.push(original[..HEADER_SIZE - 1].to_vec());
        let mut bad_magic = original.to_vec();
        bad_magic[0] ^= 1;
        cases.push(bad_magic);
        let mut bad_version = original.to_vec();
        bad_version[5] = 2;
        cases.push(bad_version);
        let mut bad_flags = original.to_vec();
        bad_flags[11] = 1;
        cases.push(bad_flags);
        let mut trailing = original.to_vec();
        trailing.push(0);
        cases.push(trailing);
        for case in cases {
            assert!(decode_request(&case).is_err());
        }
    }

    #[test]
    fn stream_header_validation_never_trusts_declared_length() {
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        let header = &encoded.as_bytes()[..HEADER_SIZE];
        assert_eq!(
            decode_request_header(header),
            Ok((
                FrameHeader {
                    operation: Operation::AdmitAttempt,
                    request_id: [1; 16],
                },
                ADMIT_ATTEMPT_BODY_SIZE,
            ))
        );

        let mut oversized = header.to_vec();
        put_u32(&mut oversized, 12, u32::MAX);
        assert_eq!(
            decode_request_header(&oversized),
            Err(DecodeError::WrongBodyLength)
        );
    }

    #[test]
    fn hostile_body_mutations_fail_before_admission() {
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        let original = encoded.as_bytes();
        let body = HEADER_SIZE;

        let mut zero_digest = original.to_vec();
        zero_digest[body..body + 32].fill(0);
        assert_eq!(decode_request(&zero_digest), Err(DecodeError::ZeroField));

        let mut bad_oid = original.to_vec();
        bad_oid[body + 272] = 9;
        assert_eq!(
            decode_request(&bad_oid),
            Err(DecodeError::UnknownOidAlgorithm)
        );

        let mut bad_lineage = original.to_vec();
        put_u32(&mut bad_lineage, body + 358, 2);
        assert_eq!(
            decode_request(&bad_lineage),
            Err(DecodeError::InvalidAttemptLineage)
        );

        let mut reserved = original.to_vec();
        reserved[body + 375] = 1;
        assert_eq!(decode_request(&reserved), Err(DecodeError::NonZeroReserved));
    }

    #[test]
    fn qualification_decode_rejects_unknown_directives_invalid_fields_and_shape() {
        let encoded = encode_request(
            [1; 16],
            Request::AdmitQualification(qualification(Some(
                QualificationDirective::TeardownFailure,
            ))),
        );
        let original = encoded.as_bytes();
        let body = HEADER_SIZE;

        let mut unknown_directive = original.to_vec();
        unknown_directive[body + 435] = 2;
        assert_eq!(
            decode_request(&unknown_directive),
            Err(DecodeError::UnknownEnum)
        );

        let mut unknown_operation = original.to_vec();
        put_u16(&mut unknown_operation, 6, 7);
        assert_eq!(
            decode_request(&unknown_operation),
            Err(DecodeError::UnknownOperation)
        );

        let mut zero_signer = original.to_vec();
        zero_signer[body + 129..body + 161].fill(0);
        assert_eq!(decode_request(&zero_signer), Err(DecodeError::ZeroField));

        let mut invalid_expiry = original.to_vec();
        put_u64(&mut invalid_expiry, body + 427, 100);
        assert_eq!(
            decode_request(&invalid_expiry),
            Err(DecodeError::InvalidDeadline)
        );

        let mut nonzero_reserved = original.to_vec();
        nonzero_reserved[body + 439] = 1;
        assert_eq!(
            decode_request(&nonzero_reserved),
            Err(DecodeError::NonZeroReserved)
        );

        assert_eq!(
            decode_request(&original[..original.len() - 1]),
            Err(DecodeError::WrongBodyLength)
        );
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn frame_shape_has_no_content_bearing_fields() {
        assert_eq!(ADMIT_ATTEMPT_BODY_SIZE, 376);
        assert_eq!(ADMIT_QUALIFICATION_BODY_SIZE, 440);
        assert_eq!(COMPLETE_ATTEMPT_BODY_SIZE, 160);
        assert_eq!(MAX_FRAME_SIZE, 472);
        assert!(!std::mem::needs_drop::<AdmitAttemptRequest>());
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        assert_eq!(
            encoded.as_bytes().len(),
            HEADER_SIZE + ADMIT_ATTEMPT_BODY_SIZE
        );
        assert_eq!(get_u16(encoded.as_bytes(), 6), 2);
        assert_eq!(get_u32(encoded.as_bytes(), 12), 376);
        assert_eq!(Operation::Hello as u16, 1);
        assert_eq!(Operation::AdmitAttempt as u16, 2);
        assert_eq!(Operation::CancelAttempt as u16, 3);
        assert_eq!(Operation::GetAttempt as u16, 4);
        assert_eq!(Operation::AdmitQualification as u16, 5);
        assert_eq!(Operation::CompleteAttempt as u16, 6);
        assert_eq!(BrokerState::Leased as u8, 7);
    }

    #[test]
    fn complete_attempt_has_canonical_fixed_width_encoding() {
        let request = complete();
        let encoded = encode_request([42; 16], Request::CompleteAttempt(request));
        let bytes = encoded.as_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE + COMPLETE_ATTEMPT_BODY_SIZE);
        assert_eq!(get_u16(bytes, 6), 6);
        assert_eq!(get_u32(bytes, 12), 160);
        assert_eq!(&bytes[HEADER_SIZE + 149..], &[0; 11]);
        assert_eq!(
            decode_request(bytes),
            Ok((
                FrameHeader {
                    operation: Operation::CompleteAttempt,
                    request_id: [42; 16],
                },
                Request::CompleteAttempt(request),
            ))
        );
    }

    #[test]
    fn complete_attempt_rejects_hostile_fields_and_shape() {
        let encoded = encode_request([1; 16], Request::CompleteAttempt(complete()));
        let original = encoded.as_bytes();
        let body = HEADER_SIZE;
        for range in [0..32, 32..64, 64..80, 84..100, 109..141] {
            let mut zero = original.to_vec();
            zero[body + range.start..body + range.end].fill(0);
            assert_eq!(decode_request(&zero), Err(DecodeError::ZeroField));
        }

        let mut zero_attempt = original.to_vec();
        put_u32(&mut zero_attempt, body + 80, 0);
        assert_eq!(decode_request(&zero_attempt), Err(DecodeError::ZeroField));

        let mut zero_generation = original.to_vec();
        put_u64(&mut zero_generation, body + 100, 0);
        assert_eq!(
            decode_request(&zero_generation),
            Err(DecodeError::ZeroField)
        );

        let mut no_conclusion = original.to_vec();
        no_conclusion[body + 108] = Conclusion::None as u8;
        assert_eq!(decode_request(&no_conclusion), Err(DecodeError::ZeroField));
        let mut unknown_conclusion = original.to_vec();
        unknown_conclusion[body + 108] = 6;
        assert_eq!(
            decode_request(&unknown_conclusion),
            Err(DecodeError::UnknownEnum)
        );

        let mut zero_terminal = original.to_vec();
        put_u64(&mut zero_terminal, body + 141, 0);
        assert_eq!(decode_request(&zero_terminal), Err(DecodeError::ZeroField));
        let mut unsafe_terminal = original.to_vec();
        put_u64(&mut unsafe_terminal, body + 141, MAX_SAFE_INTEGER + 1);
        assert_eq!(
            decode_request(&unsafe_terminal),
            Err(DecodeError::UnsafeInteger)
        );

        let mut reserved = original.to_vec();
        reserved[body + 159] = 1;
        assert_eq!(decode_request(&reserved), Err(DecodeError::NonZeroReserved));
        assert_eq!(
            decode_request(&original[..original.len() - 1]),
            Err(DecodeError::WrongBodyLength)
        );
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(DecodeError::TrailingBytes));
    }

    proptest! {
        #[test]
        fn arbitrary_frames_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = decode_request(&bytes);
        }

        #[test]
        fn arbitrary_response_frames_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            let expected = FrameHeader {
                operation: Operation::AdmitAttempt,
                request_id: [1; 16],
            };
            let _ = decode_response(expected, &bytes);
        }
    }
}
