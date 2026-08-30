//! Version 2 fixed-width broker protocol.
//!
//! Version 2 separates pre-admission job intent from broker-owned execution
//! binding. A signed admission carries only immutable request coordinates, a
//! LaneActivationManifestV1 digest and epoch, and a detached signature. Every
//! post-admission mutation carries the broker-issued execution-binding digest.
//! Paths, commands, environment variables, and lease material remain outside
//! this protocol.

use super::{
    array, get_u16, get_u32, get_u64, nonzero_array, put_u16, put_u32, put_u64, require_zero,
    validate_safe, BrokerState, CancelReason, Conclusion, DecodeError, GitOid, HelloRequest,
    Operation, QualificationRequest, ResponseCode, TrustClass, HEADER_SIZE, MAGIC, OP_RESPONSE_BIT,
};

/// Exact version accepted by the version 2 codecs.
pub const PROTOCOL_VERSION: u16 = 2;
/// Domain for canonical JobIntentV2 digests compiled outside this crate.
pub const JOB_INTENT_DIGEST_DOMAIN: &[u8] = b"buzz-ci:job-intent:v2\0";
/// Domain for canonical LaneActivationManifestV1 digests.
pub const LANE_ACTIVATION_MANIFEST_V1_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci:lane-activation-manifest:v1\0";
/// Domain prepended to the canonical detached-admission signature message.
pub const ADMISSION_SIGNATURE_DOMAIN: &[u8] = b"buzz-ci-broker:admission-signature:v2\0";
/// Domain for broker-owned post-admission execution binding digests.
pub const EXECUTION_BINDING_DIGEST_DOMAIN: &[u8] = b"buzz-ci-broker:execution-binding:v2\0";

/// Version 2 admit-attempt body length.
pub const ADMIT_ATTEMPT_BODY_SIZE: usize = 480;
/// Version 2 cancel-attempt body length.
pub const CANCEL_ATTEMPT_BODY_SIZE: usize = 160;
/// Version 2 get-attempt body length.
pub const GET_ATTEMPT_BODY_SIZE: usize = 64;
/// Version 2 complete-attempt body length.
pub const COMPLETE_ATTEMPT_BODY_SIZE: usize = 192;
/// Version 2 response body length.
pub const RESPONSE_BODY_SIZE: usize = 288;
/// Largest version 2 request body.
pub const MAX_BODY_SIZE: usize = ADMIT_ATTEMPT_BODY_SIZE;
/// Largest complete version 2 frame.
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_BODY_SIZE;

const ADMISSION_SIGNATURE_START: usize = 288;
const ADMISSION_SIGNATURE_END: usize = 352;
const ADMISSION_SIGNED_END: usize = 471;

/// Version 2 request header.
///
/// A distinct type prevents a version 1 request header from being passed to a
/// version 2 response codec by accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    /// Closed operation identifier.
    pub operation: Operation,
    /// Caller-selected replay identifier.
    pub request_id: [u8; 16],
}

/// Version 2 pre-admission request.
///
/// The detached signature covers every field except `admission_signature`.
/// The LaneActivationManifestV1 identified by `lane_manifest_digest` and
/// `lane_epoch` supplies the verification key and policy bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmitAttemptRequest {
    /// Digest established by signed public-request verification.
    pub signed_request_digest: [u8; 32],
    /// Claimed actor public key, checked by the service-owned authority.
    pub actor_pubkey: [u8; 32],
    /// Digest of the allowed publication audience.
    pub audience_digest: [u8; 32],
    /// Digest of the public request idempotency key.
    pub idempotency_digest: [u8; 32],
    /// Exact immutable source-pin event identifier.
    pub source_pin_event_id: [u8; 32],
    /// Digest of the reviewed workflow definition.
    pub workflow_digest: [u8; 32],
    /// Domain-separated digest of canonical JobIntentV2 bytes.
    pub job_intent_digest: [u8; 32],
    /// Digest of the complete allowed isolation profile.
    pub isolation_profile_digest: [u8; 32],
    /// Domain-separated digest of the root-owned LaneActivationManifestV1.
    pub lane_manifest_digest: [u8; 32],
    /// Detached Ed25519 signature over [`admission_signature_message`].
    pub admission_signature: [u8; 64],
    /// Public CI run identifier.
    pub run_id: [u8; 16],
    /// Immutable source object identifier.
    pub tip_oid: GitOid,
    /// Trusted base object identifier.
    pub base_oid: GitOid,
    /// Request issuance time.
    pub issued_at: u64,
    /// Request expiry time.
    pub expires_at: u64,
    /// Exact root-owned lane authority epoch.
    pub lane_epoch: u64,
    /// Wall-clock execution ceiling.
    pub wall_timeout_seconds: u32,
    /// One-based attempt number.
    pub attempt: u32,
    /// Prior attempt, or zero for the first attempt.
    pub parent_attempt: u32,
    /// Closed accepted trust class.
    pub trust_class: TrustClass,
}

/// Version 2 cancellation bound to one exact execution binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelAttemptRequest {
    /// Broker-issued attempt identifier.
    pub attempt_id: [u8; 16],
    /// Broker-issued digest of the post-admission execution binding.
    pub execution_binding_digest: [u8; 32],
    /// Claimed actor public key, checked by the service-owned authority.
    pub actor_pubkey: [u8; 32],
    /// Digest of the authenticated cancellation statement.
    pub cancel_digest: [u8; 32],
    /// Cancellation issuance time.
    pub issued_at: u64,
    /// Cancellation expiry time.
    pub expires_at: u64,
    /// Expected broker generation.
    pub expected_generation: u64,
    /// Closed cancellation reason.
    pub reason: CancelReason,
}

/// Version 2 state read bound to one exact execution binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetAttemptRequest {
    /// Broker-issued attempt identifier.
    pub attempt_id: [u8; 16],
    /// Broker-issued digest of the post-admission execution binding.
    pub execution_binding_digest: [u8; 32],
}

/// Version 2 completion claim bound to one exact execution binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteAttemptRequest {
    /// Claimed signer public key, checked by the service-owned authority.
    pub signer_pubkey: [u8; 32],
    /// Digest established by signed public-request verification.
    pub signed_request_digest: [u8; 32],
    /// Public CI run identifier.
    pub run_id: [u8; 16],
    /// One-based attempt number.
    pub attempt: u32,
    /// Broker-issued lease identifier.
    pub lease_id: [u8; 16],
    /// Broker-issued lease generation.
    pub lease_generation: u64,
    /// Broker-issued digest of the post-admission execution binding.
    pub execution_binding_digest: [u8; 32],
    /// Advisory job conclusion. Root-owned evidence remains authoritative.
    pub advisory_conclusion: Conclusion,
    /// Digest of bounded terminal evidence.
    pub evidence_set_digest: [u8; 32],
    /// Terminal observation time.
    pub terminal_at: u64,
}

/// Version 2 request set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    /// Version negotiation probe.
    Hello(HelloRequest),
    /// Pre-admission job intent.
    AdmitAttempt(AdmitAttemptRequest),
    /// Bound cancellation request.
    CancelAttempt(CancelAttemptRequest),
    /// Bound state read.
    GetAttempt(GetAttemptRequest),
    /// Existing fixed qualification request under a version 2 frame.
    AdmitQualification(QualificationRequest),
    /// Bound completion request.
    CompleteAttempt(CompleteAttemptRequest),
}

impl Request {
    /// Return the closed operation identifier.
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

/// Version 2 broker response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerResponse {
    /// Closed response status.
    pub code: ResponseCode,
    /// Bounded retry delay.
    pub retry_after_millis: u32,
    /// Broker-issued attempt identifier.
    pub attempt_id: [u8; 16],
    /// Public CI run identifier.
    pub run_id: [u8; 16],
    /// Accepted signed public-request digest.
    pub accepted_request_digest: [u8; 32],
    /// Accepted domain-separated JobIntentV2 digest.
    pub job_intent_digest: [u8; 32],
    /// Broker-issued post-admission execution-binding digest.
    pub execution_binding_digest: [u8; 32],
    /// Accepted immutable source object.
    pub tip_oid: Option<GitOid>,
    /// Broker lifecycle state.
    pub broker_state: BrokerState,
    /// Root-observed conclusion.
    pub conclusion: Conclusion,
    /// Closed terminal reason.
    pub terminal_reason: u16,
    /// Broker state generation.
    pub generation: u64,
    /// Durable admission time.
    pub accepted_at: u64,
    /// Last durable update time.
    pub updated_at: u64,
    /// Broker-issued lease generation.
    pub lease_generation: u64,
    /// Root-observed evidence set digest.
    pub evidence_set_digest: [u8; 32],
    /// Root-observed teardown digest.
    pub teardown_digest: [u8; 32],
    /// One-based request attempt.
    pub attempt: u32,
}

/// Bounded version 2 frame bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    bytes: [u8; MAX_FRAME_SIZE],
    len: usize,
}

impl EncodedFrame {
    /// Borrow the exact encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Return the exact domain-separated bytes covered by `admission_signature`.
///
/// Signature bytes and reserved bytes are excluded. Every other meaningful
/// AdmitAttemptV2 field is included in canonical wire order.
pub fn admission_signature_message(value: &AdmitAttemptRequest) -> Vec<u8> {
    let mut body = [0_u8; ADMIT_ATTEMPT_BODY_SIZE];
    encode_admit(&mut body, *value);
    let mut message = Vec::with_capacity(
        ADMISSION_SIGNATURE_DOMAIN.len() + ADMISSION_SIGNATURE_START + ADMISSION_SIGNED_END
            - ADMISSION_SIGNATURE_END,
    );
    message.extend_from_slice(ADMISSION_SIGNATURE_DOMAIN);
    message.extend_from_slice(&body[..ADMISSION_SIGNATURE_START]);
    message.extend_from_slice(&body[ADMISSION_SIGNATURE_END..ADMISSION_SIGNED_END]);
    message
}

/// Validate an exact version 2 request header before reading its body.
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
    let expected = body_size(operation);
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

/// Encode one version 2 request.
pub fn encode_request(request_id: [u8; 16], request: Request) -> EncodedFrame {
    let operation = request.operation();
    let body_size = body_size(operation);
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
        Request::Hello(value) => super::encode_hello(body, value),
        Request::AdmitAttempt(value) => encode_admit(body, value),
        Request::CancelAttempt(value) => encode_cancel(body, value),
        Request::GetAttempt(value) => encode_get(body, value),
        Request::AdmitQualification(value) => super::encode_qualification(body, value),
        Request::CompleteAttempt(value) => encode_complete(body, value),
    }
    encoded
}

/// Decode one exact version 2 request.
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
    let body = &frame[HEADER_SIZE..];
    let request = match header.operation {
        Operation::Hello => Request::Hello(super::decode_hello(body)?),
        Operation::AdmitAttempt => Request::AdmitAttempt(decode_admit(body)?),
        Operation::CancelAttempt => Request::CancelAttempt(decode_cancel(body)?),
        Operation::GetAttempt => Request::GetAttempt(decode_get(body)?),
        Operation::AdmitQualification => {
            Request::AdmitQualification(super::decode_qualification(body)?)
        }
        Operation::CompleteAttempt => Request::CompleteAttempt(decode_complete(body)?),
    };
    Ok((header, request))
}

/// Encode a response to one exact version 2 request header.
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
    body[70..102].copy_from_slice(&response.job_intent_digest);
    body[102..134].copy_from_slice(&response.execution_binding_digest);
    GitOid::encode_optional(response.tip_oid, &mut body[134..167]);
    body[167] = response.broker_state as u8;
    body[168] = response.conclusion as u8;
    put_u16(body, 169, response.terminal_reason);
    put_u64(body, 171, response.generation);
    put_u64(body, 179, response.accepted_at);
    put_u64(body, 187, response.updated_at);
    put_u64(body, 195, response.lease_generation);
    body[203..235].copy_from_slice(&response.evidence_set_digest);
    body[235..267].copy_from_slice(&response.teardown_digest);
    put_u32(body, 267, response.attempt);
    encoded
}

/// Decode a response bound to one exact version 2 request header.
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
    require_zero(&body[271..])?;
    let response = BrokerResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        retry_after_millis: get_u32(body, 2),
        attempt_id: array(&body[6..22]),
        run_id: array(&body[22..38]),
        accepted_request_digest: array(&body[38..70]),
        job_intent_digest: array(&body[70..102]),
        execution_binding_digest: array(&body[102..134]),
        tip_oid: GitOid::decode_optional(&body[134..167])?,
        broker_state: BrokerState::try_from(body[167])?,
        conclusion: Conclusion::try_from(body[168])?,
        terminal_reason: get_u16(body, 169),
        generation: get_u64(body, 171),
        accepted_at: get_u64(body, 179),
        updated_at: get_u64(body, 187),
        lease_generation: get_u64(body, 195),
        evidence_set_digest: array(&body[203..235]),
        teardown_digest: array(&body[235..267]),
        attempt: get_u32(body, 267),
    };
    validate_safe(response.accepted_at)?;
    validate_safe(response.updated_at)?;
    Ok(response)
}

const fn body_size(operation: Operation) -> usize {
    match operation {
        Operation::Hello => super::HELLO_BODY_SIZE,
        Operation::AdmitAttempt => ADMIT_ATTEMPT_BODY_SIZE,
        Operation::CancelAttempt => CANCEL_ATTEMPT_BODY_SIZE,
        Operation::GetAttempt => GET_ATTEMPT_BODY_SIZE,
        Operation::AdmitQualification => super::ADMIT_QUALIFICATION_BODY_SIZE,
        Operation::CompleteAttempt => COMPLETE_ATTEMPT_BODY_SIZE,
    }
}

fn encode_header(output: &mut [u8], operation: u16, body_size: usize, request_id: [u8; 16]) {
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, PROTOCOL_VERSION);
    put_u16(output, 6, operation);
    put_u32(output, 8, 0);
    debug_assert!(u32::try_from(body_size).is_ok());
    put_u32(output, 12, body_size as u32);
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

fn encode_admit(body: &mut [u8], value: AdmitAttemptRequest) {
    let digests = [
        value.signed_request_digest,
        value.actor_pubkey,
        value.audience_digest,
        value.idempotency_digest,
        value.source_pin_event_id,
        value.workflow_digest,
        value.job_intent_digest,
        value.isolation_profile_digest,
        value.lane_manifest_digest,
    ];
    for (index, digest) in digests.into_iter().enumerate() {
        let start = index * 32;
        body[start..start + 32].copy_from_slice(&digest);
    }
    body[288..352].copy_from_slice(&value.admission_signature);
    body[352..368].copy_from_slice(&value.run_id);
    value.tip_oid.encode_into(&mut body[368..401]);
    value.base_oid.encode_into(&mut body[401..434]);
    put_u64(body, 434, value.issued_at);
    put_u64(body, 442, value.expires_at);
    put_u64(body, 450, value.lane_epoch);
    put_u32(body, 458, value.wall_timeout_seconds);
    put_u32(body, 462, value.attempt);
    put_u32(body, 466, value.parent_attempt);
    body[470] = value.trust_class as u8;
}

fn decode_admit(body: &[u8]) -> Result<AdmitAttemptRequest, DecodeError> {
    require_zero(&body[471..])?;
    let value = AdmitAttemptRequest {
        signed_request_digest: nonzero_array(&body[0..32])?,
        actor_pubkey: nonzero_array(&body[32..64])?,
        audience_digest: nonzero_array(&body[64..96])?,
        idempotency_digest: nonzero_array(&body[96..128])?,
        source_pin_event_id: nonzero_array(&body[128..160])?,
        workflow_digest: nonzero_array(&body[160..192])?,
        job_intent_digest: nonzero_array(&body[192..224])?,
        isolation_profile_digest: nonzero_array(&body[224..256])?,
        lane_manifest_digest: nonzero_array(&body[256..288])?,
        admission_signature: nonzero_array(&body[288..352])?,
        run_id: nonzero_array(&body[352..368])?,
        tip_oid: GitOid::decode(&body[368..401])?,
        base_oid: GitOid::decode(&body[401..434])?,
        issued_at: get_u64(body, 434),
        expires_at: get_u64(body, 442),
        lane_epoch: get_u64(body, 450),
        wall_timeout_seconds: get_u32(body, 458),
        attempt: get_u32(body, 462),
        parent_attempt: get_u32(body, 466),
        trust_class: TrustClass::try_from(body[470])?,
    };
    validate_safe(value.issued_at)?;
    validate_safe(value.expires_at)?;
    validate_safe(value.lane_epoch)?;
    if value.lane_epoch == 0 {
        return Err(DecodeError::ZeroField);
    }
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

fn encode_cancel(body: &mut [u8], value: CancelAttemptRequest) {
    body[0..16].copy_from_slice(&value.attempt_id);
    body[16..48].copy_from_slice(&value.execution_binding_digest);
    body[48..80].copy_from_slice(&value.actor_pubkey);
    body[80..112].copy_from_slice(&value.cancel_digest);
    put_u64(body, 112, value.issued_at);
    put_u64(body, 120, value.expires_at);
    put_u64(body, 128, value.expected_generation);
    put_u16(body, 136, value.reason as u16);
}

fn decode_cancel(body: &[u8]) -> Result<CancelAttemptRequest, DecodeError> {
    require_zero(&body[138..])?;
    let value = CancelAttemptRequest {
        attempt_id: nonzero_array(&body[0..16])?,
        execution_binding_digest: nonzero_array(&body[16..48])?,
        actor_pubkey: nonzero_array(&body[48..80])?,
        cancel_digest: nonzero_array(&body[80..112])?,
        issued_at: get_u64(body, 112),
        expires_at: get_u64(body, 120),
        expected_generation: get_u64(body, 128),
        reason: CancelReason::try_from(get_u16(body, 136))?,
    };
    validate_safe(value.issued_at)?;
    validate_safe(value.expires_at)?;
    if value.expected_generation == 0 {
        return Err(DecodeError::ZeroField);
    }
    if value.expires_at <= value.issued_at {
        return Err(DecodeError::InvalidDeadline);
    }
    Ok(value)
}

fn encode_get(body: &mut [u8], value: GetAttemptRequest) {
    body[0..16].copy_from_slice(&value.attempt_id);
    body[16..48].copy_from_slice(&value.execution_binding_digest);
}

fn decode_get(body: &[u8]) -> Result<GetAttemptRequest, DecodeError> {
    require_zero(&body[48..])?;
    Ok(GetAttemptRequest {
        attempt_id: nonzero_array(&body[0..16])?,
        execution_binding_digest: nonzero_array(&body[16..48])?,
    })
}

fn encode_complete(body: &mut [u8], value: CompleteAttemptRequest) {
    body[0..32].copy_from_slice(&value.signer_pubkey);
    body[32..64].copy_from_slice(&value.signed_request_digest);
    body[64..80].copy_from_slice(&value.run_id);
    put_u32(body, 80, value.attempt);
    body[84..100].copy_from_slice(&value.lease_id);
    put_u64(body, 100, value.lease_generation);
    body[108..140].copy_from_slice(&value.execution_binding_digest);
    body[140] = value.advisory_conclusion as u8;
    body[141..173].copy_from_slice(&value.evidence_set_digest);
    put_u64(body, 173, value.terminal_at);
}

fn decode_complete(body: &[u8]) -> Result<CompleteAttemptRequest, DecodeError> {
    require_zero(&body[181..])?;
    let value = CompleteAttemptRequest {
        signer_pubkey: nonzero_array(&body[0..32])?,
        signed_request_digest: nonzero_array(&body[32..64])?,
        run_id: nonzero_array(&body[64..80])?,
        attempt: get_u32(body, 80),
        lease_id: nonzero_array(&body[84..100])?,
        lease_generation: get_u64(body, 100),
        execution_binding_digest: nonzero_array(&body[108..140])?,
        advisory_conclusion: Conclusion::try_from(body[140])?,
        evidence_set_digest: nonzero_array(&body[141..173])?,
        terminal_at: get_u64(body, 173),
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn oid() -> GitOid {
        GitOid::Sha1([21; 20])
    }

    fn admit() -> AdmitAttemptRequest {
        AdmitAttemptRequest {
            signed_request_digest: digest(1),
            actor_pubkey: digest(2),
            audience_digest: digest(3),
            idempotency_digest: digest(4),
            source_pin_event_id: digest(5),
            workflow_digest: digest(6),
            job_intent_digest: digest(7),
            isolation_profile_digest: digest(8),
            lane_manifest_digest: digest(9),
            admission_signature: [10; 64],
            run_id: [11; 16],
            tip_oid: oid(),
            base_oid: GitOid::Sha256(digest(12)),
            issued_at: 100,
            expires_at: 200,
            lane_epoch: 3,
            wall_timeout_seconds: 60,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    fn qualification() -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: oid(),
            broker_build_identity: digest(12),
            host_profile_digest: digest(13),
            suite_identity: digest(14),
            fixture_signer: digest(15),
            request_digest: digest(16),
            manifest_digest: digest(17),
            isolation_profile_digest: digest(18),
            source_oid: GitOid::Sha256(digest(19)),
            base_oid: oid(),
            job_identity: digest(20),
            fixture_identity: digest(21),
            nonce: digest(22),
            not_before: 100,
            expires_at: 200,
            directive: None,
        }
    }

    fn cancel() -> CancelAttemptRequest {
        CancelAttemptRequest {
            attempt_id: [1; 16],
            execution_binding_digest: digest(2),
            actor_pubkey: digest(3),
            cancel_digest: digest(4),
            issued_at: 100,
            expires_at: 200,
            expected_generation: 2,
            reason: CancelReason::SignedPolicy,
        }
    }

    fn get() -> GetAttemptRequest {
        GetAttemptRequest {
            attempt_id: [1; 16],
            execution_binding_digest: digest(2),
        }
    }

    fn complete() -> CompleteAttemptRequest {
        CompleteAttemptRequest {
            signer_pubkey: digest(1),
            signed_request_digest: digest(2),
            run_id: [3; 16],
            attempt: 1,
            lease_id: [4; 16],
            lease_generation: 5,
            execution_binding_digest: digest(6),
            advisory_conclusion: Conclusion::Success,
            evidence_set_digest: digest(7),
            terminal_at: 100,
        }
    }

    fn response() -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: [1; 16],
            run_id: [2; 16],
            accepted_request_digest: digest(3),
            job_intent_digest: digest(4),
            execution_binding_digest: digest(5),
            tip_oid: Some(oid()),
            broker_state: BrokerState::Leased,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: 1,
            accepted_at: 100,
            updated_at: 100,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 1,
        }
    }

    #[test]
    fn version_two_round_trips_every_request_and_response() {
        let requests = [
            Request::Hello(HelloRequest {
                controller_instance: digest(1),
                nonce: digest(2),
            }),
            Request::AdmitAttempt(admit()),
            Request::CancelAttempt(cancel()),
            Request::GetAttempt(get()),
            Request::AdmitQualification(qualification()),
            Request::CompleteAttempt(complete()),
        ];
        for request in requests {
            let encoded = encode_request([42; 16], request);
            let (header, decoded) = decode_request(encoded.as_bytes()).expect("valid v2 frame");
            assert_eq!(header.request_id, [42; 16]);
            assert_eq!(decoded, request);
        }

        let header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [42; 16],
        };
        let encoded = encode_response(header, response());
        assert_eq!(decode_response(header, encoded.as_bytes()), Ok(response()));
    }

    #[test]
    fn versions_are_explicit_and_never_reinterpreted() {
        let v2 = encode_request([42; 16], Request::AdmitAttempt(admit()));
        assert_eq!(
            super::super::decode_request(v2.as_bytes()),
            Err(DecodeError::UnsupportedVersion)
        );

        let v1 = super::super::encode_request(
            [42; 16],
            super::super::Request::Hello(HelloRequest {
                controller_instance: digest(1),
                nonce: digest(2),
            }),
        );
        assert_eq!(
            decode_request(v1.as_bytes()),
            Err(DecodeError::UnsupportedVersion)
        );
        assert_eq!(get_u16(v2.as_bytes(), 4), PROTOCOL_VERSION);
        assert_eq!(get_u16(v1.as_bytes(), 4), super::super::PROTOCOL_VERSION);
    }

    #[test]
    fn detached_signature_message_is_domain_separated_and_excludes_signature() {
        let first = admit();
        let mut second = first;
        second.admission_signature = [99; 64];
        assert_eq!(
            admission_signature_message(&first),
            admission_signature_message(&second)
        );

        second = first;
        second.lane_epoch += 1;
        assert_ne!(
            admission_signature_message(&first),
            admission_signature_message(&second)
        );
        second = first;
        second.job_intent_digest[0] ^= 1;
        assert_ne!(
            admission_signature_message(&first),
            admission_signature_message(&second)
        );

        let message = admission_signature_message(&first);
        assert!(message.starts_with(ADMISSION_SIGNATURE_DOMAIN));
        assert_eq!(message.len(), ADMISSION_SIGNATURE_DOMAIN.len() + 407);
    }

    #[test]
    fn digest_and_signature_domains_are_distinct_and_artifact_versioned() {
        let domains: [&[u8]; 4] = [
            JOB_INTENT_DIGEST_DOMAIN,
            LANE_ACTIVATION_MANIFEST_V1_DIGEST_DOMAIN,
            ADMISSION_SIGNATURE_DOMAIN,
            EXECUTION_BINDING_DIGEST_DOMAIN,
        ];
        for (index, domain) in domains.iter().enumerate() {
            for other in domains.iter().skip(index + 1) {
                assert_ne!(domain, other);
            }
        }
        assert!(JOB_INTENT_DIGEST_DOMAIN.ends_with(b":v2\0"));
        assert!(LANE_ACTIVATION_MANIFEST_V1_DIGEST_DOMAIN.ends_with(b":v1\0"));
        assert!(ADMISSION_SIGNATURE_DOMAIN.ends_with(b":v2\0"));
        assert!(EXECUTION_BINDING_DIGEST_DOMAIN.ends_with(b":v2\0"));
    }

    #[test]
    fn version_two_frame_shapes_are_fixed() {
        assert_eq!(ADMIT_ATTEMPT_BODY_SIZE, 480);
        assert_eq!(CANCEL_ATTEMPT_BODY_SIZE, 160);
        assert_eq!(GET_ATTEMPT_BODY_SIZE, 64);
        assert_eq!(COMPLETE_ATTEMPT_BODY_SIZE, 192);
        assert_eq!(RESPONSE_BODY_SIZE, 288);
        assert_eq!(MAX_FRAME_SIZE, 512);
        assert!(!std::mem::needs_drop::<AdmitAttemptRequest>());
        assert!(!std::mem::needs_drop::<CompleteAttemptRequest>());

        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        assert_eq!(
            encoded.as_bytes().len(),
            HEADER_SIZE + ADMIT_ATTEMPT_BODY_SIZE
        );
        assert_eq!(get_u16(encoded.as_bytes(), 4), PROTOCOL_VERSION);
        assert_eq!(
            get_u32(encoded.as_bytes(), 12),
            ADMIT_ATTEMPT_BODY_SIZE as u32
        );
    }

    #[test]
    fn new_admission_coordinates_are_required_before_decode() {
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        let original = encoded.as_bytes();
        let body = HEADER_SIZE;
        for range in [192..224, 256..288, 288..352] {
            let mut zero = original.to_vec();
            zero[body + range.start..body + range.end].fill(0);
            assert_eq!(decode_request(&zero), Err(DecodeError::ZeroField));
        }

        let mut zero_epoch = original.to_vec();
        put_u64(&mut zero_epoch, body + 450, 0);
        assert_eq!(decode_request(&zero_epoch), Err(DecodeError::ZeroField));

        let mut reserved = original.to_vec();
        reserved[body + 479] = 1;
        assert_eq!(decode_request(&reserved), Err(DecodeError::NonZeroReserved));
    }

    #[test]
    fn every_post_admission_operation_requires_execution_binding_digest() {
        for request in [
            Request::CancelAttempt(cancel()),
            Request::GetAttempt(get()),
            Request::CompleteAttempt(complete()),
        ] {
            let encoded = encode_request([1; 16], request);
            let mut bytes = encoded.as_bytes().to_vec();
            let offset = match request {
                Request::CancelAttempt(_) | Request::GetAttempt(_) => 16,
                Request::CompleteAttempt(_) => 108,
                _ => unreachable!(),
            };
            bytes[HEADER_SIZE + offset..HEADER_SIZE + offset + 32].fill(0);
            assert_eq!(decode_request(&bytes), Err(DecodeError::ZeroField));
        }
    }

    #[test]
    fn version_two_fingerprints_are_frozen() {
        let request = encode_request([42; 16], Request::AdmitAttempt(admit()));
        let signing_message = admission_signature_message(&admit());
        let response = encode_response(
            FrameHeader {
                operation: Operation::AdmitAttempt,
                request_id: [42; 16],
            },
            response(),
        );
        assert_eq!(
            hex_digest(request.as_bytes()),
            "d236bafb7938a809ba607b04f6f22e8e39bd598148241129c8dc66e6ca689d45"
        );
        assert_eq!(
            hex_digest(&signing_message),
            "c982b84efe95b862cc72667d27b71ddd1d825364b3d913cdbbde259927a7d478"
        );
        assert_eq!(
            hex_digest(response.as_bytes()),
            "c1ac6e82fd54e57102c453aa9de6284f71cfd74092108b7f985d153fe1f772c9"
        );
    }

    fn hex_digest(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut output = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    fn header_bytes(operation: u16, declared_body_size: u32) -> [u8; HEADER_SIZE] {
        let mut header = [0_u8; HEADER_SIZE];
        header[..4].copy_from_slice(&MAGIC);
        put_u16(&mut header, 4, PROTOCOL_VERSION);
        put_u16(&mut header, 6, operation);
        put_u32(&mut header, 12, declared_body_size);
        header
    }

    #[test]
    fn request_headers_reject_version_magic_operation_and_length_drift() {
        let exact = header_bytes(Operation::GetAttempt as u16, GET_ATTEMPT_BODY_SIZE as u32);
        assert_eq!(
            decode_request_header(&exact),
            Ok((
                FrameHeader {
                    operation: Operation::GetAttempt,
                    request_id: [0; 16]
                },
                GET_ATTEMPT_BODY_SIZE
            ))
        );

        let mut bad_magic = header_bytes(Operation::Hello as u16, 64_u32);
        bad_magic[0] = b'X';
        assert_eq!(
            decode_request_header(&bad_magic),
            Err(DecodeError::BadMagic)
        );

        for version in [0_u16, 1, 3] {
            let mut drifted = header_bytes(Operation::Hello as u16, 64_u32);
            put_u16(&mut drifted, 4, version);
            assert_eq!(
                decode_request_header(&drifted),
                Err(DecodeError::UnsupportedVersion)
            );
        }

        for operation in [0_u16, 7, Operation::Hello as u16 | OP_RESPONSE_BIT] {
            let header = header_bytes(operation, 64_u32);
            assert_eq!(
                decode_request_header(&header),
                Err(DecodeError::UnknownOperation)
            );
        }

        let mut flagged = header_bytes(Operation::Hello as u16, 64_u32);
        put_u32(&mut flagged, 8, 1);
        assert_eq!(
            decode_request_header(&flagged),
            Err(DecodeError::NonZeroFlags)
        );

        for (operation, declared) in [
            (Operation::Hello, super::super::HELLO_BODY_SIZE + 1),
            // The version 1 admit body size is never a version 2 body length.
            (Operation::AdmitAttempt, 376),
            (Operation::CancelAttempt, CANCEL_ATTEMPT_BODY_SIZE - 1),
            (Operation::GetAttempt, 0),
            (
                Operation::AdmitQualification,
                super::super::ADMIT_QUALIFICATION_BODY_SIZE - 1,
            ),
            (Operation::CompleteAttempt, COMPLETE_ATTEMPT_BODY_SIZE + 1),
        ] {
            let header = header_bytes(operation as u16, declared as u32);
            assert_eq!(
                decode_request_header(&header),
                Err(DecodeError::WrongBodyLength)
            );
        }
    }

    #[test]
    fn truncated_and_overlong_frames_never_decode() {
        let encoded = encode_request([7; 16], Request::GetAttempt(get()));
        let bytes = encoded.as_bytes();
        assert_eq!(
            decode_request(&bytes[..HEADER_SIZE - 1]),
            Err(DecodeError::FrameTooShort)
        );
        assert_eq!(
            decode_request(&bytes[..HEADER_SIZE]),
            Err(DecodeError::WrongBodyLength)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn admit_deadlines_lineage_and_closed_enums_are_enforced() {
        let encoded = encode_request([1; 16], Request::AdmitAttempt(admit()));
        let at = |offset: usize| HEADER_SIZE + offset;

        for expires_at in [100_u64, 99] {
            let mut frame = encoded.as_bytes().to_vec();
            put_u64(&mut frame, at(442), expires_at);
            assert_eq!(decode_request(&frame), Err(DecodeError::InvalidDeadline));
        }

        let mut zero_timeout = encoded.as_bytes().to_vec();
        put_u32(&mut zero_timeout, at(458), 0);
        assert_eq!(
            decode_request(&zero_timeout),
            Err(DecodeError::InvalidDeadline)
        );

        let drift = |attempt: u32, parent_attempt: u32| {
            let mut frame = encoded.as_bytes().to_vec();
            put_u32(&mut frame, at(462), attempt);
            put_u32(&mut frame, at(466), parent_attempt);
            decode_request(&frame).map(|(_, request)| request)
        };
        assert_eq!(drift(0, 0), Err(DecodeError::InvalidAttemptLineage));
        assert_eq!(drift(1, 1), Err(DecodeError::InvalidAttemptLineage));
        assert_eq!(
            drift(u32::MAX, u32::MAX - 1),
            Ok(Request::AdmitAttempt(AdmitAttemptRequest {
                attempt: u32::MAX,
                parent_attempt: u32::MAX - 1,
                ..admit()
            }))
        );

        for offset in [434, 442, 450] {
            let mut unsafe_time = encoded.as_bytes().to_vec();
            put_u64(
                &mut unsafe_time,
                at(offset),
                super::super::MAX_SAFE_INTEGER + 1,
            );
            assert_eq!(
                decode_request(&unsafe_time),
                Err(DecodeError::UnsafeInteger)
            );
        }

        let mut unknown_trust = encoded.as_bytes().to_vec();
        unknown_trust[at(470)] = 7;
        assert_eq!(
            decode_request(&unknown_trust),
            Err(DecodeError::UnknownEnum)
        );

        // OIDs stay canonical: unknown algorithms and padded Sha1 digests drift.
        let mut unknown_oid = encoded.as_bytes().to_vec();
        unknown_oid[at(368)] = 3;
        assert_eq!(
            decode_request(&unknown_oid),
            Err(DecodeError::UnknownOidAlgorithm)
        );
        let mut padded_oid = encoded.as_bytes().to_vec();
        padded_oid[at(389)] = 1;
        assert_eq!(
            decode_request(&padded_oid),
            Err(DecodeError::NonCanonicalOid)
        );
    }

    #[test]
    fn cancel_get_and_complete_field_drift_is_rejected() {
        let cancel_encoded = encode_request([1; 16], Request::CancelAttempt(cancel()));
        let mut frame = cancel_encoded.as_bytes().to_vec();
        put_u64(&mut frame, HEADER_SIZE + 128, 0);
        assert_eq!(decode_request(&frame), Err(DecodeError::ZeroField));

        let mut equal_deadline = cancel_encoded.as_bytes().to_vec();
        put_u64(&mut equal_deadline, HEADER_SIZE + 120, 100);
        assert_eq!(
            decode_request(&equal_deadline),
            Err(DecodeError::InvalidDeadline)
        );

        let mut unsafe_time = cancel_encoded.as_bytes().to_vec();
        put_u64(
            &mut unsafe_time,
            HEADER_SIZE + 112,
            super::super::MAX_SAFE_INTEGER + 1,
        );
        assert_eq!(
            decode_request(&unsafe_time),
            Err(DecodeError::UnsafeInteger)
        );

        let mut cancel_reserved = cancel_encoded.as_bytes().to_vec();
        cancel_reserved[HEADER_SIZE + 138] = 1;
        assert_eq!(
            decode_request(&cancel_reserved),
            Err(DecodeError::NonZeroReserved)
        );

        let get_encoded = encode_request([1; 16], Request::GetAttempt(get()));
        let mut get_reserved = get_encoded.as_bytes().to_vec();
        get_reserved[HEADER_SIZE + 48] = 1;
        assert_eq!(
            decode_request(&get_reserved),
            Err(DecodeError::NonZeroReserved)
        );

        let mut zero_attempt_id = get_encoded.as_bytes().to_vec();
        zero_attempt_id[HEADER_SIZE..HEADER_SIZE + 16].fill(0);
        assert_eq!(
            decode_request(&zero_attempt_id),
            Err(DecodeError::ZeroField)
        );

        let complete_encoded = encode_request([1; 16], Request::CompleteAttempt(complete()));
        let complete_bytes = complete_encoded.as_bytes();
        let mut zero_attempt = complete_bytes.to_vec();
        put_u32(&mut zero_attempt, HEADER_SIZE + 80, 0);
        assert_eq!(decode_request(&zero_attempt), Err(DecodeError::ZeroField));

        let mut zero_generation = complete_bytes.to_vec();
        put_u64(&mut zero_generation, HEADER_SIZE + 100, 0);
        assert_eq!(
            decode_request(&zero_generation),
            Err(DecodeError::ZeroField)
        );

        let mut zero_terminal = complete_bytes.to_vec();
        put_u64(&mut zero_terminal, HEADER_SIZE + 173, 0);
        assert_eq!(decode_request(&zero_terminal), Err(DecodeError::ZeroField));

        let mut blank_evidence = complete_bytes.to_vec();
        blank_evidence[HEADER_SIZE + 140] = 0;
        assert_eq!(decode_request(&blank_evidence), Err(DecodeError::ZeroField));

        let mut unknown_conclusion = complete_bytes.to_vec();
        unknown_conclusion[HEADER_SIZE + 140] = 9;
        assert_eq!(
            decode_request(&unknown_conclusion),
            Err(DecodeError::UnknownEnum)
        );

        let mut unsafe_terminal = complete_bytes.to_vec();
        put_u64(
            &mut unsafe_terminal,
            HEADER_SIZE + 173,
            super::super::MAX_SAFE_INTEGER + 1,
        );
        assert_eq!(
            decode_request(&unsafe_terminal),
            Err(DecodeError::UnsafeInteger)
        );

        let mut complete_reserved = complete_bytes.to_vec();
        complete_reserved[HEADER_SIZE + 181] = 1;
        assert_eq!(
            decode_request(&complete_reserved),
            Err(DecodeError::NonZeroReserved)
        );
    }

    #[test]
    fn responses_decode_only_for_the_exact_bound_header() {
        let header = FrameHeader {
            operation: Operation::CancelAttempt,
            request_id: [9; 16],
        };
        let encoded = encode_response(header, response());
        let bytes = encoded.as_bytes();

        let drifted_id = FrameHeader {
            operation: header.operation,
            request_id: [10; 16],
        };
        assert_eq!(
            decode_response(drifted_id, bytes),
            Err(DecodeError::UnknownOperation)
        );
        let drifted_operation = FrameHeader {
            operation: Operation::GetAttempt,
            request_id: header.request_id,
        };
        assert_eq!(
            decode_response(drifted_operation, bytes),
            Err(DecodeError::UnknownOperation)
        );

        // A response frame with the response bit cleared is not a response.
        let mut unmarked = bytes.to_vec();
        put_u16(&mut unmarked, 6, header.operation as u16);
        assert_eq!(
            decode_response(header, &unmarked),
            Err(DecodeError::UnknownOperation)
        );

        assert_eq!(
            decode_response(header, &bytes[..bytes.len() - 1]),
            Err(DecodeError::WrongBodyLength)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_response(header, &trailing),
            Err(DecodeError::TrailingBytes)
        );

        let body = HEADER_SIZE;
        let mut invalid_code = bytes.to_vec();
        put_u16(&mut invalid_code, body, 0xFFFF);
        assert_eq!(
            decode_response(header, &invalid_code),
            Err(DecodeError::UnknownEnum)
        );
        let mut unknown_state = bytes.to_vec();
        unknown_state[body + 167] = 0;
        assert_eq!(
            decode_response(header, &unknown_state),
            Err(DecodeError::UnknownEnum)
        );
        let mut unknown_conclusion = bytes.to_vec();
        unknown_conclusion[body + 168] = 6;
        assert_eq!(
            decode_response(header, &unknown_conclusion),
            Err(DecodeError::UnknownEnum)
        );
        let mut unknown_oid = bytes.to_vec();
        unknown_oid[body + 134] = 3;
        assert_eq!(
            decode_response(header, &unknown_oid),
            Err(DecodeError::UnknownOidAlgorithm)
        );
        for offset in [179, 187] {
            let mut unsafe_time = bytes.to_vec();
            put_u64(
                &mut unsafe_time,
                body + offset,
                super::super::MAX_SAFE_INTEGER + 1,
            );
            assert_eq!(
                decode_response(header, &unsafe_time),
                Err(DecodeError::UnsafeInteger)
            );
        }
        let mut reserved = bytes.to_vec();
        reserved[body + 280] = 1;
        assert_eq!(
            decode_response(header, &reserved),
            Err(DecodeError::NonZeroReserved)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_version_two_frames_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = decode_request(&bytes);
        }

        #[test]
        fn arbitrary_version_two_response_frames_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            let expected = FrameHeader {
                operation: Operation::AdmitAttempt,
                request_id: [1; 16],
            };
            let _ = decode_response(expected, &bytes);
        }

        #[test]
        fn truncated_admit_frames_are_never_accepted(
            len in 0..(HEADER_SIZE + ADMIT_ATTEMPT_BODY_SIZE),
        ) {
            let encoded = encode_request([7; 16], Request::AdmitAttempt(admit()));
            let truncated = &encoded.as_bytes()[..len];
            match decode_request(truncated) {
                Err(DecodeError::FrameTooShort | DecodeError::WrongBodyLength) => {}
                other => panic!("truncated frame decoded as {other:?}"),
            }
        }

        #[test]
        fn arbitrary_admit_lineage_and_timing_round_trip(
            request_id in prop::array::uniform16(any::<u8>()),
            attempt in 1_u32..,
            issued_at in 0_u64..=9_007_199_254_740_991_u64 - 65_536,
            wall_timeout_seconds in 1_u32..=65_535,
            lane_epoch in 1_u64..=1_048_576,
            tag in prop::array::uniform32(any::<u8>()),
        ) {
            let mut request = admit();
            request.attempt = attempt;
            request.parent_attempt = if attempt == 1 { 0 } else { attempt - 1 };
            request.issued_at = issued_at;
            request.expires_at = issued_at + u64::from(wall_timeout_seconds);
            request.wall_timeout_seconds = wall_timeout_seconds;
            request.lane_epoch = lane_epoch;
            request.job_intent_digest = tag.map(|byte| byte | 1);

            let encoded = encode_request(request_id, Request::AdmitAttempt(request));
            let (header, decoded) = decode_request(encoded.as_bytes())
                .unwrap_or_else(|error| panic!("round trip failed: {error:?}"));
            prop_assert_eq!(header.request_id, request_id);
            prop_assert_eq!(decoded, Request::AdmitAttempt(request));
        }
    }
}
