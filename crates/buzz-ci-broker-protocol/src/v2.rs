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
use sha2::{Digest, Sha256};

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
/// Version 2 evidence description request length.
pub const DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE: usize = 256;
/// Version 2 evidence chunk request length.
pub const READ_ATTEMPT_EVIDENCE_BODY_SIZE: usize = 288;
/// Version 2 response body length.
pub const RESPONSE_BODY_SIZE: usize = 288;
/// Maximum number of sealed evidence items returned for one attempt.
pub const MAX_EVIDENCE_ITEMS: usize = 4;
/// Maximum bytes returned by one evidence read.
pub const MAX_EVIDENCE_CHUNK_SIZE: usize = 4096;
/// Fixed evidence description response length.
pub const EVIDENCE_DESCRIPTION_BODY_SIZE: usize = 768;
/// Fixed evidence chunk response length.
pub const EVIDENCE_CHUNK_BODY_SIZE: usize = 4224;
/// Largest version 2 request or response body.
pub const MAX_BODY_SIZE: usize = EVIDENCE_CHUNK_BODY_SIZE;
/// Largest complete version 2 frame.
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_BODY_SIZE;

const ADMISSION_SIGNATURE_START: usize = 288;
const ADMISSION_SIGNATURE_END: usize = 352;
const ADMISSION_SIGNED_END: usize = 480;
/// Exact length of the canonical admission signature message.
pub const ADMISSION_SIGNATURE_MESSAGE_SIZE: usize =
    ADMISSION_SIGNATURE_DOMAIN.len() + ADMISSION_SIGNATURE_START + ADMISSION_SIGNED_END
        - ADMISSION_SIGNATURE_END;

/// Closed signature algorithm accepted by version 2 admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionSignatureAlgorithm {
    /// BIP-340 Schnorr over secp256k1 and a SHA-256 message digest.
    Bip340Secp256k1Sha256 = 1,
}

impl TryFrom<u8> for AdmissionSignatureAlgorithm {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bip340Secp256k1Sha256),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

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
    /// Detached BIP-340 signature over the SHA-256 digest of
    /// [`admission_signature_message`].
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
    /// Exact manifest key generation used for this signature.
    pub admission_key_generation: u64,
    /// Wall-clock execution ceiling.
    pub wall_timeout_seconds: u32,
    /// One-based attempt number.
    pub attempt: u32,
    /// Prior attempt, or zero for the first attempt.
    pub parent_attempt: u32,
    /// Closed accepted trust class.
    pub trust_class: TrustClass,
    /// Closed admission signature algorithm.
    pub admission_signature_algorithm: AdmissionSignatureAlgorithm,
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

/// Coordinates that bind every evidence operation to one exact admitted attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptEvidenceCoordinates {
    pub signed_request_digest: [u8; 32],
    pub run_id: [u8; 16],
    pub workflow_digest: [u8; 32],
    pub job_intent_digest: [u8; 32],
    pub attempt: u32,
    pub attempt_id: [u8; 16],
    pub execution_binding_digest: [u8; 32],
    pub expected_generation: u64,
}

/// Describe all sealed evidence owned by execd for one exact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescribeAttemptEvidenceRequest {
    pub coordinates: AttemptEvidenceCoordinates,
    pub idempotency_digest: [u8; 32],
    /// Domain-separated digest of the header and every other request field.
    pub request_frame_digest: [u8; 32],
}

/// Closed evidence kinds. No filesystem path is representable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvidenceKind {
    Stdout = 1,
    Stderr = 2,
    Artifact = 3,
    Teardown = 4,
}

impl TryFrom<u8> for EvidenceKind {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stdout),
            2 => Ok(Self::Stderr),
            3 => Ok(Self::Artifact),
            4 => Ok(Self::Teardown),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// Read one bounded chunk from a descriptor returned by describe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadAttemptEvidenceRequest {
    pub coordinates: AttemptEvidenceCoordinates,
    pub idempotency_digest: [u8; 32],
    pub request_frame_digest: [u8; 32],
    pub kind: EvidenceKind,
    pub item_index: u8,
    pub descriptor_digest: [u8; 32],
    pub offset: u32,
    pub max_length: u32,
}

/// One verified, path-free sealed evidence descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceDescriptor {
    pub kind: EvidenceKind,
    pub digest: [u8; 32],
    pub length: u32,
    pub artifact_name_digest: [u8; 32],
    pub artifact_media_type_digest: [u8; 32],
    pub teardown_lease_id: [u8; 16],
    pub teardown_lease_generation: u64,
    pub teardown_attestation_digest: [u8; 32],
}

/// Result of describing one exact sealed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceDescriptionResponse {
    pub code: ResponseCode,
    pub execution_binding_digest: [u8; 32],
    pub generation: u64,
    pub request_frame_digest: [u8; 32],
    pub descriptor_set_digest: [u8; 32],
    pub item_count: u8,
    pub items: [Option<EvidenceDescriptor>; MAX_EVIDENCE_ITEMS],
}

/// Result of one bounded evidence read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceChunkResponse {
    pub code: ResponseCode,
    pub execution_binding_digest: [u8; 32],
    pub generation: u64,
    pub request_frame_digest: [u8; 32],
    pub kind: EvidenceKind,
    pub item_index: u8,
    pub descriptor_digest: [u8; 32],
    pub offset: u32,
    pub total_length: u32,
    pub bytes: Vec<u8>,
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
    DescribeAttemptEvidence(DescribeAttemptEvidenceRequest),
    ReadAttemptEvidence(ReadAttemptEvidenceRequest),
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
            Self::DescribeAttemptEvidence(_) => Operation::DescribeAttemptEvidence,
            Self::ReadAttemptEvidence(_) => Operation::ReadAttemptEvidence,
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

/// Decode and validate one canonical admission signature message.
///
/// The returned signature is a nonzero placeholder because signatures are not
/// part of this message. Every signed request field is decoded by the ordinary
/// version 2 request validator.
pub fn decode_admission_signature_message(
    message: &[u8],
) -> Result<AdmitAttemptRequest, DecodeError> {
    if message.len() != ADMISSION_SIGNATURE_MESSAGE_SIZE
        || !message.starts_with(ADMISSION_SIGNATURE_DOMAIN)
    {
        return Err(DecodeError::WrongBodyLength);
    }
    let signed = &message[ADMISSION_SIGNATURE_DOMAIN.len()..];
    let mut body = [0_u8; ADMIT_ATTEMPT_BODY_SIZE];
    body[..ADMISSION_SIGNATURE_START].copy_from_slice(&signed[..ADMISSION_SIGNATURE_START]);
    body[ADMISSION_SIGNATURE_START..ADMISSION_SIGNATURE_END].fill(1);
    body[ADMISSION_SIGNATURE_END..ADMISSION_SIGNED_END]
        .copy_from_slice(&signed[ADMISSION_SIGNATURE_START..]);
    decode_admit(&body)
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
    let operation = Operation::from_u16_v2(get_u16(input, 6))?;
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
        Request::DescribeAttemptEvidence(value) => encode_describe_evidence(body, value),
        Request::ReadAttemptEvidence(value) => encode_read_evidence(body, value),
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
        Operation::DescribeAttemptEvidence => {
            Request::DescribeAttemptEvidence(decode_describe_evidence(body)?)
        }
        Operation::ReadAttemptEvidence => Request::ReadAttemptEvidence(decode_read_evidence(body)?),
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
        Operation::DescribeAttemptEvidence => DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE,
        Operation::ReadAttemptEvidence => READ_ATTEMPT_EVIDENCE_BODY_SIZE,
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
    put_u64(body, 471, value.admission_key_generation);
    body[479] = value.admission_signature_algorithm as u8;
}

fn decode_admit(body: &[u8]) -> Result<AdmitAttemptRequest, DecodeError> {
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
        admission_key_generation: get_u64(body, 471),
        wall_timeout_seconds: get_u32(body, 458),
        attempt: get_u32(body, 462),
        parent_attempt: get_u32(body, 466),
        trust_class: TrustClass::try_from(body[470])?,
        admission_signature_algorithm: AdmissionSignatureAlgorithm::try_from(body[479])?,
    };
    validate_safe(value.issued_at)?;
    validate_safe(value.expires_at)?;
    validate_safe(value.lane_epoch)?;
    validate_safe(value.admission_key_generation)?;
    if value.lane_epoch == 0 || value.admission_key_generation == 0 {
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

fn encode_coordinates(body: &mut [u8], value: AttemptEvidenceCoordinates) {
    body[0..32].copy_from_slice(&value.signed_request_digest);
    body[32..48].copy_from_slice(&value.run_id);
    body[48..80].copy_from_slice(&value.workflow_digest);
    body[80..112].copy_from_slice(&value.job_intent_digest);
    put_u32(body, 112, value.attempt);
    body[116..132].copy_from_slice(&value.attempt_id);
    body[132..164].copy_from_slice(&value.execution_binding_digest);
    put_u64(body, 164, value.expected_generation);
}

fn decode_coordinates(body: &[u8]) -> Result<AttemptEvidenceCoordinates, DecodeError> {
    let value = AttemptEvidenceCoordinates {
        signed_request_digest: nonzero_array(&body[0..32])?,
        run_id: nonzero_array(&body[32..48])?,
        workflow_digest: nonzero_array(&body[48..80])?,
        job_intent_digest: nonzero_array(&body[80..112])?,
        attempt: get_u32(body, 112),
        attempt_id: nonzero_array(&body[116..132])?,
        execution_binding_digest: nonzero_array(&body[132..164])?,
        expected_generation: get_u64(body, 164),
    };
    if value.attempt == 0 || value.expected_generation == 0 {
        return Err(DecodeError::ZeroField);
    }
    validate_safe(value.expected_generation)?;
    Ok(value)
}

fn encode_describe_evidence(body: &mut [u8], value: DescribeAttemptEvidenceRequest) {
    encode_coordinates(body, value.coordinates);
    body[172..204].copy_from_slice(&value.idempotency_digest);
    body[204..236].copy_from_slice(&value.request_frame_digest);
}

fn decode_describe_evidence(body: &[u8]) -> Result<DescribeAttemptEvidenceRequest, DecodeError> {
    require_zero(&body[236..])?;
    Ok(DescribeAttemptEvidenceRequest {
        coordinates: decode_coordinates(body)?,
        idempotency_digest: nonzero_array(&body[172..204])?,
        request_frame_digest: nonzero_array(&body[204..236])?,
    })
}

fn encode_read_evidence(body: &mut [u8], value: ReadAttemptEvidenceRequest) {
    encode_coordinates(body, value.coordinates);
    body[172..204].copy_from_slice(&value.idempotency_digest);
    body[204..236].copy_from_slice(&value.request_frame_digest);
    body[236] = value.kind as u8;
    body[237] = value.item_index;
    body[238..270].copy_from_slice(&value.descriptor_digest);
    put_u32(body, 270, value.offset);
    put_u32(body, 274, value.max_length);
}

fn decode_read_evidence(body: &[u8]) -> Result<ReadAttemptEvidenceRequest, DecodeError> {
    require_zero(&body[278..])?;
    let value = ReadAttemptEvidenceRequest {
        coordinates: decode_coordinates(body)?,
        idempotency_digest: nonzero_array(&body[172..204])?,
        request_frame_digest: nonzero_array(&body[204..236])?,
        kind: EvidenceKind::try_from(body[236])?,
        item_index: body[237],
        descriptor_digest: nonzero_array(&body[238..270])?,
        offset: get_u32(body, 270),
        max_length: get_u32(body, 274),
    };
    if usize::from(value.item_index) >= MAX_EVIDENCE_ITEMS
        || value.max_length == 0
        || value.max_length as usize > MAX_EVIDENCE_CHUNK_SIZE
    {
        return Err(DecodeError::WrongBodyLength);
    }
    Ok(value)
}

/// Compute the digest carried by an evidence request, binding request id and
/// canonical fields without introducing a self-reference.
pub fn evidence_request_frame_digest(header: FrameHeader, request: &Request) -> Option<[u8; 32]> {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(b"buzz-ci-broker:evidence-request-frame:v2\0");
    bytes.extend_from_slice(&(header.operation as u16).to_be_bytes());
    bytes.extend_from_slice(&header.request_id);
    let (coordinates, idempotency) = match request {
        Request::DescribeAttemptEvidence(value) => (value.coordinates, value.idempotency_digest),
        Request::ReadAttemptEvidence(value) => (value.coordinates, value.idempotency_digest),
        _ => return None,
    };
    bytes.extend_from_slice(&coordinates.signed_request_digest);
    bytes.extend_from_slice(&coordinates.run_id);
    bytes.extend_from_slice(&coordinates.workflow_digest);
    bytes.extend_from_slice(&coordinates.job_intent_digest);
    bytes.extend_from_slice(&coordinates.attempt.to_be_bytes());
    bytes.extend_from_slice(&coordinates.attempt_id);
    bytes.extend_from_slice(&coordinates.execution_binding_digest);
    bytes.extend_from_slice(&coordinates.expected_generation.to_be_bytes());
    bytes.extend_from_slice(&idempotency);
    if let Request::ReadAttemptEvidence(value) = request {
        bytes.push(value.kind as u8);
        bytes.push(value.item_index);
        bytes.extend_from_slice(&value.descriptor_digest);
        bytes.extend_from_slice(&value.offset.to_be_bytes());
        bytes.extend_from_slice(&value.max_length.to_be_bytes());
    }
    Some(Sha256::digest(bytes).into())
}

/// Encode a path-free description response.
pub fn encode_evidence_description_response(
    header: FrameHeader,
    response: EvidenceDescriptionResponse,
) -> EncodedFrame {
    let mut encoded = EncodedFrame {
        bytes: [0; MAX_FRAME_SIZE],
        len: HEADER_SIZE + EVIDENCE_DESCRIPTION_BODY_SIZE,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        (header.operation as u16) | OP_RESPONSE_BIT,
        EVIDENCE_DESCRIPTION_BODY_SIZE,
        header.request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    put_u16(body, 0, response.code as u16);
    body[2] = response.item_count;
    body[3..35].copy_from_slice(&response.execution_binding_digest);
    put_u64(body, 35, response.generation);
    body[43..75].copy_from_slice(&response.request_frame_digest);
    body[75..107].copy_from_slice(&response.descriptor_set_digest);
    for (index, item) in response.items.iter().enumerate() {
        if let Some(item) = item {
            let start = 108 + index * 160;
            body[start] = item.kind as u8;
            body[start + 4..start + 36].copy_from_slice(&item.digest);
            put_u32(body, start + 36, item.length);
            body[start + 40..start + 72].copy_from_slice(&item.artifact_name_digest);
            body[start + 72..start + 104].copy_from_slice(&item.artifact_media_type_digest);
            body[start + 104..start + 120].copy_from_slice(&item.teardown_lease_id);
            put_u64(body, start + 120, item.teardown_lease_generation);
            body[start + 128..start + 160].copy_from_slice(&item.teardown_attestation_digest);
        }
    }
    encoded
}

/// Decode a path-free description response.
pub fn decode_evidence_description_response(
    expected: FrameHeader,
    frame: &[u8],
) -> Result<EvidenceDescriptionResponse, DecodeError> {
    let (operation, request_id, body) = decode_header(frame, true)?;
    if operation != (expected.operation as u16) | OP_RESPONSE_BIT
        || request_id != expected.request_id
        || body.len() != EVIDENCE_DESCRIPTION_BODY_SIZE
    {
        return Err(DecodeError::WrongBodyLength);
    }
    let item_count = body[2];
    if usize::from(item_count) > MAX_EVIDENCE_ITEMS {
        return Err(DecodeError::WrongBodyLength);
    }
    let mut items = [None; MAX_EVIDENCE_ITEMS];
    for (index, slot) in items.iter_mut().enumerate() {
        let start = 108 + index * 160;
        if index < usize::from(item_count) {
            require_zero(&body[start + 1..start + 4])?;
            *slot = Some(EvidenceDescriptor {
                kind: EvidenceKind::try_from(body[start])?,
                digest: nonzero_array(&body[start + 4..start + 36])?,
                length: get_u32(body, start + 36),
                artifact_name_digest: array(&body[start + 40..start + 72]),
                artifact_media_type_digest: array(&body[start + 72..start + 104]),
                teardown_lease_id: array(&body[start + 104..start + 120]),
                teardown_lease_generation: get_u64(body, start + 120),
                teardown_attestation_digest: array(&body[start + 128..start + 160]),
            });
        } else {
            require_zero(&body[start..start + 160])?;
        }
    }
    require_zero(&body[107..108])?;
    require_zero(&body[748..])?;
    Ok(EvidenceDescriptionResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        execution_binding_digest: array(&body[3..35]),
        generation: get_u64(body, 35),
        request_frame_digest: array(&body[43..75]),
        descriptor_set_digest: array(&body[75..107]),
        item_count,
        items,
    })
}

/// Encode one bounded evidence chunk response.
pub fn encode_evidence_chunk_response(
    header: FrameHeader,
    response: &EvidenceChunkResponse,
) -> EncodedFrame {
    assert!(response.bytes.len() <= MAX_EVIDENCE_CHUNK_SIZE);
    let mut encoded = EncodedFrame {
        bytes: [0; MAX_FRAME_SIZE],
        len: HEADER_SIZE + EVIDENCE_CHUNK_BODY_SIZE,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        (header.operation as u16) | OP_RESPONSE_BIT,
        EVIDENCE_CHUNK_BODY_SIZE,
        header.request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    put_u16(body, 0, response.code as u16);
    body[2] = response.kind as u8;
    body[3] = response.item_index;
    put_u32(body, 4, response.offset);
    put_u32(body, 8, response.total_length);
    put_u32(body, 12, response.bytes.len() as u32);
    body[16..48].copy_from_slice(&response.descriptor_digest);
    body[48..80].copy_from_slice(&response.execution_binding_digest);
    put_u64(body, 80, response.generation);
    body[88..120].copy_from_slice(&response.request_frame_digest);
    body[120..120 + response.bytes.len()].copy_from_slice(&response.bytes);
    encoded
}

/// Decode one bounded evidence chunk response.
pub fn decode_evidence_chunk_response(
    expected: FrameHeader,
    frame: &[u8],
) -> Result<EvidenceChunkResponse, DecodeError> {
    let (operation, request_id, body) = decode_header(frame, true)?;
    if operation != (expected.operation as u16) | OP_RESPONSE_BIT
        || request_id != expected.request_id
        || body.len() != EVIDENCE_CHUNK_BODY_SIZE
    {
        return Err(DecodeError::WrongBodyLength);
    }
    let length = get_u32(body, 12) as usize;
    if length > MAX_EVIDENCE_CHUNK_SIZE {
        return Err(DecodeError::WrongBodyLength);
    }
    require_zero(&body[120 + length..])?;
    Ok(EvidenceChunkResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        kind: EvidenceKind::try_from(body[2])?,
        item_index: body[3],
        offset: get_u32(body, 4),
        total_length: get_u32(body, 8),
        bytes: body[120..120 + length].to_vec(),
        descriptor_digest: array(&body[16..48]),
        execution_binding_digest: array(&body[48..80]),
        generation: get_u64(body, 80),
        request_frame_digest: array(&body[88..120]),
    })
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
            admission_key_generation: 4,
            wall_timeout_seconds: 60,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
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

    fn coordinates() -> AttemptEvidenceCoordinates {
        AttemptEvidenceCoordinates {
            signed_request_digest: digest(1),
            run_id: [2; 16],
            workflow_digest: digest(3),
            job_intent_digest: digest(4),
            attempt: 1,
            attempt_id: [5; 16],
            execution_binding_digest: digest(6),
            expected_generation: 4,
        }
    }

    fn describe() -> DescribeAttemptEvidenceRequest {
        let header = FrameHeader {
            operation: Operation::DescribeAttemptEvidence,
            request_id: [9; 16],
        };
        let mut value = DescribeAttemptEvidenceRequest {
            coordinates: coordinates(),
            idempotency_digest: digest(7),
            request_frame_digest: digest(8),
        };
        value.request_frame_digest =
            evidence_request_frame_digest(header, &Request::DescribeAttemptEvidence(value))
                .unwrap();
        value
    }

    fn read() -> ReadAttemptEvidenceRequest {
        let header = FrameHeader {
            operation: Operation::ReadAttemptEvidence,
            request_id: [9; 16],
        };
        let mut value = ReadAttemptEvidenceRequest {
            coordinates: coordinates(),
            idempotency_digest: digest(7),
            request_frame_digest: digest(8),
            kind: EvidenceKind::Stdout,
            item_index: 0,
            descriptor_digest: digest(10),
            offset: 3,
            max_length: 17,
        };
        value.request_frame_digest =
            evidence_request_frame_digest(header, &Request::ReadAttemptEvidence(value)).unwrap();
        value
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
            Request::DescribeAttemptEvidence(describe()),
            Request::ReadAttemptEvidence(read()),
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
        assert_eq!(message.len(), ADMISSION_SIGNATURE_MESSAGE_SIZE);
        let decoded = decode_admission_signature_message(&message).expect("canonical message");
        assert_eq!(decoded.admission_signature, [1; 64]);
        assert_eq!(admission_signature_message(&decoded), message);
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
        assert_eq!(DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE, 256);
        assert_eq!(READ_ATTEMPT_EVIDENCE_BODY_SIZE, 288);
        assert_eq!(RESPONSE_BODY_SIZE, 288);
        assert_eq!(MAX_FRAME_SIZE, 4256);
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
    fn evidence_responses_round_trip_and_reject_trailing_or_oversized_content() {
        let descriptor = EvidenceDescriptor {
            kind: EvidenceKind::Teardown,
            digest: digest(1),
            length: 6,
            artifact_name_digest: [0; 32],
            artifact_media_type_digest: [0; 32],
            teardown_lease_id: [2; 16],
            teardown_lease_generation: 3,
            teardown_attestation_digest: digest(4),
        };
        let header = FrameHeader {
            operation: Operation::DescribeAttemptEvidence,
            request_id: [5; 16],
        };
        let description = EvidenceDescriptionResponse {
            code: ResponseCode::Ok,
            execution_binding_digest: digest(6),
            generation: 7,
            request_frame_digest: digest(8),
            descriptor_set_digest: digest(9),
            item_count: 1,
            items: [Some(descriptor), None, None, None],
        };
        let encoded = encode_evidence_description_response(header, description);
        assert_eq!(
            decode_evidence_description_response(header, encoded.as_bytes()),
            Ok(description)
        );

        let chunk_header = FrameHeader {
            operation: Operation::ReadAttemptEvidence,
            request_id: [10; 16],
        };
        let chunk = EvidenceChunkResponse {
            code: ResponseCode::Ok,
            execution_binding_digest: digest(6),
            generation: 7,
            request_frame_digest: digest(11),
            kind: EvidenceKind::Teardown,
            item_index: 0,
            descriptor_digest: digest(1),
            offset: 0,
            total_length: 6,
            bytes: b"sealed".to_vec(),
        };
        let encoded = encode_evidence_chunk_response(chunk_header, &chunk);
        assert_eq!(
            decode_evidence_chunk_response(chunk_header, encoded.as_bytes()),
            Ok(chunk)
        );

        let mut hostile = encode_request([9; 16], Request::ReadAttemptEvidence(read()))
            .as_bytes()
            .to_vec();
        hostile[HEADER_SIZE + 274..HEADER_SIZE + 278]
            .copy_from_slice(&((MAX_EVIDENCE_CHUNK_SIZE as u32) + 1).to_be_bytes());
        assert!(decode_request(&hostile).is_err());
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

        let mut zero_generation = original.to_vec();
        put_u64(&mut zero_generation, body + 471, 0);
        assert_eq!(
            decode_request(&zero_generation),
            Err(DecodeError::ZeroField)
        );

        let mut unknown_algorithm = original.to_vec();
        unknown_algorithm[body + 479] = 2;
        assert_eq!(
            decode_request(&unknown_algorithm),
            Err(DecodeError::UnknownEnum)
        );
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
            "b0ddfb8532e880a4a410592423e62a66d168413399d46f7a097ec8fea70a507e"
        );
        assert_eq!(
            hex_digest(&signing_message),
            "628ff200305bf8be825798c6543b996940abf1ad97795fb5a26b707473223fa0"
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
    }
}
