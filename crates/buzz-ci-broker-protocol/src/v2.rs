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
    Operation, ResponseCode, TrustClass, HEADER_SIZE, MAGIC, OP_RESPONSE_BIT,
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
pub const DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE: usize = 416;
/// Version 2 evidence chunk request length.
pub const READ_ATTEMPT_EVIDENCE_BODY_SIZE: usize = 448;
/// Version 2 dynamic JobIntent registration body length.
pub const REGISTER_JOB_INTENT_BODY_SIZE: usize = 960;
/// Closed production qualification request length.
pub const PRODUCTION_QUALIFICATION_BODY_SIZE: usize = 640;
/// Version 2 response body length.
pub const RESPONSE_BODY_SIZE: usize = 288;
/// Maximum number of sealed evidence items returned for one attempt.
pub const MAX_EVIDENCE_ITEMS: usize = 4;
/// Maximum bytes returned by one evidence read.
pub const MAX_EVIDENCE_CHUNK_SIZE: usize = 4096;
/// Fixed evidence description response length.
pub const EVIDENCE_DESCRIPTION_BODY_SIZE: usize = 1888;
/// Fixed evidence chunk response length.
pub const EVIDENCE_CHUNK_BODY_SIZE: usize = 4448;
/// Fixed JobIntent registration response length.
pub const INTENT_REGISTRATION_RESPONSE_BODY_SIZE: usize = 288;
/// Closed production qualification response length.
pub const PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE: usize = 576;
/// Largest version 2 request or response body.
pub const MAX_BODY_SIZE: usize = EVIDENCE_CHUNK_BODY_SIZE;
/// Largest complete version 2 frame.
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_BODY_SIZE;
/// Maximum declared artifacts in one registered JobIntent.
pub const MAX_JOB_INTENT_ARTIFACTS: usize = 1;
/// Maximum bytes accepted for one declared artifact.
pub const MAX_JOB_INTENT_ARTIFACT_BYTES: u32 = 32 * 1024;
/// Maximum lifetime of one production qualification frame.
pub const MAX_PRODUCTION_QUALIFICATION_LIFETIME_SECONDS: u64 = 300;

const INTENT_REGISTRATION_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:intent-registration-request:v1\0";
const INTENT_REGISTRATION_KEY_DIGEST_DOMAIN: &[u8] = b"buzz-ci-execd:intent-registration-key:v1\0";
const PRODUCTION_QUALIFICATION_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:production-qualification-request:v1\0";
const PRODUCTION_QUALIFICATION_KEY_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:production-qualification-key:v1\0";
const PRODUCTION_QUALIFICATION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:production-qualification-receipt:v1\0";
const PRODUCTION_QUALIFICATION_PRINCIPAL_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:production-qualification-principal:v1\0";
const PRODUCTION_QUALIFICATION_EXECUTOR_PROVENANCE_DIGEST_DOMAIN: &[u8] =
    b"buzz-ci-execd:production-qualification-executor-provenance:v1\0";

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
    pub request_event_id: [u8; 32],
    pub workflow_id: WireText64,
    pub job_id: WireText64,
}

/// Canonical bounded ASCII text used where callers must reconstruct public
/// evidence without reversing a digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireText64 {
    pub len: u8,
    pub bytes: [u8; 64],
}

impl WireText64 {
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; 64],
    };

    pub fn from_ascii(value: &str) -> Result<Self, DecodeError> {
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(DecodeError::UnknownEnum);
        }
        let mut bytes = [0; 64];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            len: value.len() as u8,
            bytes,
        })
    }

    pub fn as_str(&self) -> Result<&str, DecodeError> {
        let len = usize::from(self.len);
        if len == 0 || len > 64 || self.bytes[len..].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::UnknownEnum);
        }
        if !self.bytes[..len]
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err(DecodeError::UnknownEnum);
        }
        std::str::from_utf8(&self.bytes[..len]).map_err(|_| DecodeError::UnknownEnum)
    }
}

/// One path-free artifact declaration in a registered JobIntentV2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobArtifactDeclaration {
    pub artifact_id: WireText64,
    pub name: WireText64,
    pub media_type: WireText64,
    pub relative_name: WireText64,
    pub max_bytes: u32,
}

/// Authenticated create-once registration of the exact existing JobIntentV2
/// preimage. The embedded admission signature binds `job_intent_digest`, and
/// the request-frame digest binds the signature and every literal preimage
/// field to one byte-identical transport retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterJobIntentRequest {
    pub admission: AdmitAttemptRequest,
    pub request_event_id: [u8; 32],
    pub workflow_id: WireText64,
    pub job_id: WireText64,
    pub artifact_count: u8,
    pub artifacts: [Option<JobArtifactDeclaration>; MAX_JOB_INTENT_ARTIFACTS],
    pub request_frame_digest: [u8; 32],
}

/// Result of create-once JobIntent registration. This response exposes no
/// execution binding or lease; it only echoes authenticated registration
/// coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentRegistrationResponse {
    pub code: ResponseCode,
    pub retry_after_millis: u32,
    pub signed_request_digest: [u8; 32],
    pub job_intent_digest: [u8; 32],
    pub request_frame_digest: [u8; 32],
    pub admission_message_digest: [u8; 32],
    pub registration_key_digest: [u8; 32],
    pub lane_manifest_digest: [u8; 32],
    pub run_id: [u8; 16],
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub attempt: u32,
}

/// One closed production qualification request. It carries no command, job,
/// path, environment, or execution directive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionQualificationRequest {
    pub integrated_candidate_sha: GitOid,
    pub activation_package_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    pub principal_digest: [u8; 32],
    pub lane_manifest_digest: [u8; 32],
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub seccomp_profile_digest: [u8; 32],
    pub executor_program_digest: [u8; 32],
    pub executor_provenance_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub request_frame_digest: [u8; 32],
}

/// Execd-owned proof of one create-once closed production qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionQualificationResponse {
    pub code: ResponseCode,
    pub retry_after_millis: u32,
    pub request_frame_digest: [u8; 32],
    pub qualification_receipt_digest: [u8; 32],
    pub integrated_candidate_sha: GitOid,
    pub activation_package_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    pub principal_digest: [u8; 32],
    pub lane_manifest_digest: [u8; 32],
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub seccomp_profile_digest: [u8; 32],
    pub seccomp_install_receipt_digest: [u8; 32],
    pub executor_program_digest: [u8; 32],
    pub executor_provenance_digest: [u8; 32],
    pub controller_generation: u64,
    pub runner_generation: u64,
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub qualified_at: u64,
    pub request_expires_at: u64,
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
    pub artifact_id: WireText64,
    pub artifact_name: WireText64,
    pub artifact_media_type: WireText64,
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
    pub request_event_id: [u8; 32],
    pub run_id: [u8; 16],
    pub workflow_id: WireText64,
    pub workflow_digest: [u8; 32],
    pub job_id: WireText64,
    pub attempt: u32,
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
    pub request_event_id: [u8; 32],
    pub run_id: [u8; 16],
    pub workflow_id: WireText64,
    pub workflow_digest: [u8; 32],
    pub job_id: WireText64,
    pub attempt: u32,
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
    /// Closed production qualification request under a version 2 frame.
    AdmitQualification(ProductionQualificationRequest),
    /// Bound completion request.
    CompleteAttempt(CompleteAttemptRequest),
    DescribeAttemptEvidence(DescribeAttemptEvidenceRequest),
    ReadAttemptEvidence(ReadAttemptEvidenceRequest),
    RegisterJobIntent(RegisterJobIntentRequest),
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
            Self::RegisterJobIntent(_) => Operation::RegisterJobIntent,
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
        Request::AdmitQualification(value) => encode_production_qualification(body, value),
        Request::CompleteAttempt(value) => encode_complete(body, value),
        Request::DescribeAttemptEvidence(value) => encode_describe_evidence(body, value),
        Request::ReadAttemptEvidence(value) => encode_read_evidence(body, value),
        Request::RegisterJobIntent(value) => encode_register_job_intent(body, value),
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
            Request::AdmitQualification(decode_production_qualification(body)?)
        }
        Operation::CompleteAttempt => Request::CompleteAttempt(decode_complete(body)?),
        Operation::DescribeAttemptEvidence => {
            Request::DescribeAttemptEvidence(decode_describe_evidence(body)?)
        }
        Operation::ReadAttemptEvidence => Request::ReadAttemptEvidence(decode_read_evidence(body)?),
        Operation::RegisterJobIntent => {
            Request::RegisterJobIntent(decode_register_job_intent(body)?)
        }
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

/// Encode an operation-specific response to RegisterJobIntent.
pub fn encode_intent_registration_response(
    request_header: FrameHeader,
    response: IntentRegistrationResponse,
) -> EncodedFrame {
    assert_eq!(request_header.operation, Operation::RegisterJobIntent);
    let mut encoded = EncodedFrame {
        bytes: [0_u8; MAX_FRAME_SIZE],
        len: HEADER_SIZE + INTENT_REGISTRATION_RESPONSE_BODY_SIZE,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        (request_header.operation as u16) | OP_RESPONSE_BIT,
        INTENT_REGISTRATION_RESPONSE_BODY_SIZE,
        request_header.request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    put_u16(body, 0, response.code as u16);
    put_u32(body, 2, response.retry_after_millis);
    body[6..38].copy_from_slice(&response.signed_request_digest);
    body[38..70].copy_from_slice(&response.job_intent_digest);
    body[70..102].copy_from_slice(&response.request_frame_digest);
    body[102..134].copy_from_slice(&response.admission_message_digest);
    body[134..166].copy_from_slice(&response.registration_key_digest);
    body[166..198].copy_from_slice(&response.lane_manifest_digest);
    body[198..214].copy_from_slice(&response.run_id);
    put_u64(body, 214, response.lane_epoch);
    put_u64(body, 222, response.admission_key_generation);
    put_u64(body, 230, response.issued_at);
    put_u64(body, 238, response.expires_at);
    put_u32(body, 246, response.attempt);
    encoded
}

/// Decode an operation-specific response bound to RegisterJobIntent.
pub fn decode_intent_registration_response(
    expected: FrameHeader,
    frame: &[u8],
) -> Result<IntentRegistrationResponse, DecodeError> {
    if expected.operation != Operation::RegisterJobIntent {
        return Err(DecodeError::UnknownOperation);
    }
    let (operation, request_id, body) = decode_header(frame, true)?;
    if operation != (Operation::RegisterJobIntent as u16) | OP_RESPONSE_BIT
        || request_id != expected.request_id
        || body.len() != INTENT_REGISTRATION_RESPONSE_BODY_SIZE
    {
        return Err(DecodeError::UnknownOperation);
    }
    require_zero(&body[250..])?;
    let response = IntentRegistrationResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        retry_after_millis: get_u32(body, 2),
        signed_request_digest: nonzero_array(&body[6..38])?,
        job_intent_digest: nonzero_array(&body[38..70])?,
        request_frame_digest: nonzero_array(&body[70..102])?,
        admission_message_digest: nonzero_array(&body[102..134])?,
        registration_key_digest: nonzero_array(&body[134..166])?,
        lane_manifest_digest: nonzero_array(&body[166..198])?,
        run_id: nonzero_array(&body[198..214])?,
        lane_epoch: get_u64(body, 214),
        admission_key_generation: get_u64(body, 222),
        issued_at: get_u64(body, 230),
        expires_at: get_u64(body, 238),
        attempt: get_u32(body, 246),
    };
    validate_safe(response.lane_epoch)?;
    validate_safe(response.admission_key_generation)?;
    validate_safe(response.issued_at)?;
    validate_safe(response.expires_at)?;
    if response.lane_epoch == 0
        || response.admission_key_generation == 0
        || response.issued_at == 0
        || response.expires_at <= response.issued_at
        || response.attempt == 0
    {
        return Err(DecodeError::ZeroField);
    }
    Ok(response)
}

/// Encode the operation-specific response to one closed production qualification.
pub fn encode_production_qualification_response(
    request_header: FrameHeader,
    response: ProductionQualificationResponse,
) -> EncodedFrame {
    assert_eq!(request_header.operation, Operation::AdmitQualification);
    let mut encoded = EncodedFrame {
        bytes: [0_u8; MAX_FRAME_SIZE],
        len: HEADER_SIZE + PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE,
    };
    encode_header(
        &mut encoded.bytes[..HEADER_SIZE],
        (request_header.operation as u16) | OP_RESPONSE_BIT,
        PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE,
        request_header.request_id,
    );
    let body = &mut encoded.bytes[HEADER_SIZE..encoded.len];
    put_u16(body, 0, response.code as u16);
    put_u32(body, 2, response.retry_after_millis);
    body[6..38].copy_from_slice(&response.request_frame_digest);
    body[38..70].copy_from_slice(&response.qualification_receipt_digest);
    response
        .integrated_candidate_sha
        .encode_into(&mut body[70..103]);
    body[103..135].copy_from_slice(&response.activation_package_digest);
    body[135..167].copy_from_slice(&response.fixture_digest);
    body[167..199].copy_from_slice(&response.principal_digest);
    body[199..231].copy_from_slice(&response.lane_manifest_digest);
    body[231..263].copy_from_slice(&response.broker_build_identity);
    body[263..295].copy_from_slice(&response.host_profile_digest);
    body[295..327].copy_from_slice(&response.suite_identity);
    body[327..359].copy_from_slice(&response.isolation_profile_digest);
    body[359..391].copy_from_slice(&response.seccomp_profile_digest);
    body[391..423].copy_from_slice(&response.seccomp_install_receipt_digest);
    body[423..455].copy_from_slice(&response.executor_program_digest);
    body[455..487].copy_from_slice(&response.executor_provenance_digest);
    put_u64(body, 487, response.controller_generation);
    put_u64(body, 495, response.runner_generation);
    put_u64(body, 503, response.lane_epoch);
    put_u64(body, 511, response.admission_key_generation);
    put_u64(body, 519, response.qualified_at);
    put_u64(body, 527, response.request_expires_at);
    encoded
}

/// Decode a closed production qualification response bound to its request.
pub fn decode_production_qualification_response(
    expected: FrameHeader,
    frame: &[u8],
) -> Result<ProductionQualificationResponse, DecodeError> {
    if expected.operation != Operation::AdmitQualification {
        return Err(DecodeError::UnknownOperation);
    }
    let (operation, request_id, body) = decode_header(frame, true)?;
    if operation != (Operation::AdmitQualification as u16) | OP_RESPONSE_BIT
        || request_id != expected.request_id
        || body.len() != PRODUCTION_QUALIFICATION_RESPONSE_BODY_SIZE
    {
        return Err(DecodeError::UnknownOperation);
    }
    require_zero(&body[535..])?;
    let response = ProductionQualificationResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        retry_after_millis: get_u32(body, 2),
        request_frame_digest: nonzero_array(&body[6..38])?,
        qualification_receipt_digest: nonzero_array(&body[38..70])?,
        integrated_candidate_sha: GitOid::decode(&body[70..103])?,
        activation_package_digest: nonzero_array(&body[103..135])?,
        fixture_digest: nonzero_array(&body[135..167])?,
        principal_digest: nonzero_array(&body[167..199])?,
        lane_manifest_digest: nonzero_array(&body[199..231])?,
        broker_build_identity: nonzero_array(&body[231..263])?,
        host_profile_digest: nonzero_array(&body[263..295])?,
        suite_identity: nonzero_array(&body[295..327])?,
        isolation_profile_digest: nonzero_array(&body[327..359])?,
        seccomp_profile_digest: nonzero_array(&body[359..391])?,
        seccomp_install_receipt_digest: nonzero_array(&body[391..423])?,
        executor_program_digest: nonzero_array(&body[423..455])?,
        executor_provenance_digest: nonzero_array(&body[455..487])?,
        controller_generation: get_u64(body, 487),
        runner_generation: get_u64(body, 495),
        lane_epoch: get_u64(body, 503),
        admission_key_generation: get_u64(body, 511),
        qualified_at: get_u64(body, 519),
        request_expires_at: get_u64(body, 527),
    };
    for value in [
        response.controller_generation,
        response.runner_generation,
        response.lane_epoch,
        response.admission_key_generation,
        response.qualified_at,
        response.request_expires_at,
    ] {
        validate_safe(value)?;
    }
    if response.controller_generation == 0
        || response.runner_generation == 0
        || response.lane_epoch == 0
        || response.admission_key_generation == 0
        || response.qualified_at == 0
        || response.request_expires_at < response.qualified_at
        || response.request_expires_at - response.qualified_at
            > MAX_PRODUCTION_QUALIFICATION_LIFETIME_SECONDS
    {
        return Err(DecodeError::InvalidDeadline);
    }
    Ok(response)
}

/// Digest the immutable success receipt. `Ok` and `Existing` share this digest.
pub fn production_qualification_receipt_digest(
    response: &ProductionQualificationResponse,
) -> [u8; 32] {
    let mut canonical = *response;
    canonical.code = ResponseCode::Ok;
    canonical.retry_after_millis = 0;
    canonical.qualification_receipt_digest = [0; 32];
    let frame = encode_production_qualification_response(
        FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [0; 16],
        },
        canonical,
    );
    let body = &frame.bytes[HEADER_SIZE..frame.len];
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_QUALIFICATION_RECEIPT_DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

const fn body_size(operation: Operation) -> usize {
    match operation {
        Operation::Hello => super::HELLO_BODY_SIZE,
        Operation::AdmitAttempt => ADMIT_ATTEMPT_BODY_SIZE,
        Operation::CancelAttempt => CANCEL_ATTEMPT_BODY_SIZE,
        Operation::GetAttempt => GET_ATTEMPT_BODY_SIZE,
        Operation::AdmitQualification => PRODUCTION_QUALIFICATION_BODY_SIZE,
        Operation::CompleteAttempt => COMPLETE_ATTEMPT_BODY_SIZE,
        Operation::DescribeAttemptEvidence => DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE,
        Operation::ReadAttemptEvidence => READ_ATTEMPT_EVIDENCE_BODY_SIZE,
        Operation::RegisterJobIntent => REGISTER_JOB_INTENT_BODY_SIZE,
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

fn encode_register_job_intent(body: &mut [u8], value: RegisterJobIntentRequest) {
    encode_admit(&mut body[..ADMIT_ATTEMPT_BODY_SIZE], value.admission);
    body[480..512].copy_from_slice(&value.request_event_id);
    encode_text(&mut body[512..577], value.workflow_id);
    encode_text(&mut body[577..642], value.job_id);
    body[642] = value.artifact_count;
    if let Some(artifact) = value.artifacts[0] {
        body[643] = 1;
        encode_text(&mut body[644..709], artifact.artifact_id);
        encode_text(&mut body[709..774], artifact.name);
        encode_text(&mut body[774..839], artifact.media_type);
        encode_text(&mut body[839..904], artifact.relative_name);
        put_u32(body, 904, artifact.max_bytes);
    }
    body[908..940].copy_from_slice(&value.request_frame_digest);
}

fn decode_register_job_intent(body: &[u8]) -> Result<RegisterJobIntentRequest, DecodeError> {
    let artifact_count = body[642];
    let artifact = match (artifact_count, body[643]) {
        (0, 0) => {
            require_zero(&body[644..908])?;
            None
        }
        (1, 1) => {
            let artifact = JobArtifactDeclaration {
                artifact_id: decode_text(&body[644..709], false)?,
                name: decode_text(&body[709..774], false)?,
                media_type: decode_text(&body[774..839], false)?,
                relative_name: decode_text(&body[839..904], false)?,
                max_bytes: get_u32(body, 904),
            };
            if artifact.max_bytes == 0 || artifact.max_bytes > MAX_JOB_INTENT_ARTIFACT_BYTES {
                return Err(DecodeError::WrongBodyLength);
            }
            Some(artifact)
        }
        _ => return Err(DecodeError::WrongBodyLength),
    };
    require_zero(&body[940..])?;
    Ok(RegisterJobIntentRequest {
        admission: decode_admit(&body[..ADMIT_ATTEMPT_BODY_SIZE])?,
        request_event_id: nonzero_array(&body[480..512])?,
        workflow_id: decode_text(&body[512..577], false)?,
        job_id: decode_text(&body[577..642], false)?,
        artifact_count,
        artifacts: [artifact],
        request_frame_digest: nonzero_array(&body[908..940])?,
    })
}

/// Digest the complete canonical registration frame except its self-digest.
pub fn intent_registration_request_frame_digest(
    header: FrameHeader,
    value: &RegisterJobIntentRequest,
) -> Option<[u8; 32]> {
    if header.operation != Operation::RegisterJobIntent {
        return None;
    }
    let mut canonical = *value;
    canonical.request_frame_digest = [0; 32];
    let mut body = [0; REGISTER_JOB_INTENT_BODY_SIZE];
    encode_register_job_intent(&mut body, canonical);
    let mut hasher = Sha256::new();
    hasher.update(INTENT_REGISTRATION_REQUEST_DIGEST_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update((Operation::RegisterJobIntent as u16).to_be_bytes());
    hasher.update(header.request_id);
    hasher.update(body);
    Some(hasher.finalize().into())
}

/// Durable pre-admission replay coordinate for one exact logical attempt.
pub fn intent_registration_key_digest(value: &RegisterJobIntentRequest) -> [u8; 32] {
    intent_registration_key_digest_for_admission(value.admission)
}

/// Durable pre-admission replay coordinate derived from the signed admission.
pub fn intent_registration_key_digest_for_admission(admission: AdmitAttemptRequest) -> [u8; 32] {
    intent_registration_key_digest_parts(
        admission.lane_manifest_digest,
        admission.idempotency_digest,
        admission.run_id,
        admission.attempt,
    )
}

/// Durable pre-admission replay coordinate from its canonical components.
pub fn intent_registration_key_digest_parts(
    lane_manifest_digest: [u8; 32],
    idempotency_digest: [u8; 32],
    run_id: [u8; 16],
    attempt: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_REGISTRATION_KEY_DIGEST_DOMAIN);
    hasher.update(lane_manifest_digest);
    hasher.update(idempotency_digest);
    hasher.update(run_id);
    hasher.update(attempt.to_be_bytes());
    hasher.finalize().into()
}

fn encode_production_qualification(body: &mut [u8], value: ProductionQualificationRequest) {
    value.integrated_candidate_sha.encode_into(&mut body[0..33]);
    body[33..65].copy_from_slice(&value.activation_package_digest);
    body[65..97].copy_from_slice(&value.fixture_digest);
    body[97..129].copy_from_slice(&value.principal_digest);
    body[129..161].copy_from_slice(&value.lane_manifest_digest);
    body[161..193].copy_from_slice(&value.broker_build_identity);
    body[193..225].copy_from_slice(&value.host_profile_digest);
    body[225..257].copy_from_slice(&value.suite_identity);
    body[257..289].copy_from_slice(&value.isolation_profile_digest);
    body[289..321].copy_from_slice(&value.seccomp_profile_digest);
    body[321..353].copy_from_slice(&value.executor_program_digest);
    body[353..385].copy_from_slice(&value.executor_provenance_digest);
    body[385..417].copy_from_slice(&value.nonce);
    put_u64(body, 417, value.controller_generation);
    put_u64(body, 425, value.runner_generation);
    put_u64(body, 433, value.lane_epoch);
    put_u64(body, 441, value.admission_key_generation);
    put_u64(body, 449, value.issued_at);
    put_u64(body, 457, value.expires_at);
    body[465..497].copy_from_slice(&value.request_frame_digest);
}

fn decode_production_qualification(
    body: &[u8],
) -> Result<ProductionQualificationRequest, DecodeError> {
    require_zero(&body[497..])?;
    let value = ProductionQualificationRequest {
        integrated_candidate_sha: GitOid::decode(&body[0..33])?,
        activation_package_digest: nonzero_array(&body[33..65])?,
        fixture_digest: nonzero_array(&body[65..97])?,
        principal_digest: nonzero_array(&body[97..129])?,
        lane_manifest_digest: nonzero_array(&body[129..161])?,
        broker_build_identity: nonzero_array(&body[161..193])?,
        host_profile_digest: nonzero_array(&body[193..225])?,
        suite_identity: nonzero_array(&body[225..257])?,
        isolation_profile_digest: nonzero_array(&body[257..289])?,
        seccomp_profile_digest: nonzero_array(&body[289..321])?,
        executor_program_digest: nonzero_array(&body[321..353])?,
        executor_provenance_digest: nonzero_array(&body[353..385])?,
        nonce: nonzero_array(&body[385..417])?,
        controller_generation: get_u64(body, 417),
        runner_generation: get_u64(body, 425),
        lane_epoch: get_u64(body, 433),
        admission_key_generation: get_u64(body, 441),
        issued_at: get_u64(body, 449),
        expires_at: get_u64(body, 457),
        request_frame_digest: nonzero_array(&body[465..497])?,
    };
    for generation in [
        value.controller_generation,
        value.runner_generation,
        value.lane_epoch,
        value.admission_key_generation,
        value.issued_at,
        value.expires_at,
    ] {
        validate_safe(generation)?;
    }
    if value.controller_generation == 0
        || value.runner_generation == 0
        || value.lane_epoch == 0
        || value.admission_key_generation == 0
        || value.issued_at == 0
        || value.expires_at <= value.issued_at
        || value.expires_at - value.issued_at > MAX_PRODUCTION_QUALIFICATION_LIFETIME_SECONDS
    {
        return Err(DecodeError::InvalidDeadline);
    }
    Ok(value)
}

/// Digest the complete canonical qualification frame except its self-digest.
pub fn production_qualification_request_frame_digest(
    header: FrameHeader,
    value: &ProductionQualificationRequest,
) -> Option<[u8; 32]> {
    if header.operation != Operation::AdmitQualification {
        return None;
    }
    let mut canonical = *value;
    canonical.request_frame_digest = [0; 32];
    let mut body = [0; PRODUCTION_QUALIFICATION_BODY_SIZE];
    encode_production_qualification(&mut body, canonical);
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_QUALIFICATION_REQUEST_DIGEST_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update((Operation::AdmitQualification as u16).to_be_bytes());
    hasher.update(header.request_id);
    hasher.update(body);
    Some(hasher.finalize().into())
}

/// Durable create-once key for one package fixture and generation pair.
pub fn production_qualification_key_digest(value: &ProductionQualificationRequest) -> [u8; 32] {
    let mut candidate = [0; 33];
    value.integrated_candidate_sha.encode_into(&mut candidate);
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_QUALIFICATION_KEY_DIGEST_DOMAIN);
    hasher.update(candidate);
    hasher.update(value.activation_package_digest);
    hasher.update(value.fixture_digest);
    hasher.update(value.controller_generation.to_be_bytes());
    hasher.update(value.runner_generation.to_be_bytes());
    hasher.finalize().into()
}

/// Digest the exact configured qualification account contract.
pub fn production_qualification_principal_digest(
    user: &str,
    group: &str,
    uid: u32,
    gid: u32,
    home: &str,
    shell: &str,
    supplementary_groups: &[String],
) -> Option<[u8; 32]> {
    if uid == 0
        || gid == 0
        || supplementary_groups.is_empty()
        || [user, group, home, shell]
            .iter()
            .any(|value| value.is_empty() || value.len() > u16::MAX as usize || !value.is_ascii())
        || supplementary_groups
            .iter()
            .any(|value| value.is_empty() || value.len() > u16::MAX as usize || !value.is_ascii())
    {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_QUALIFICATION_PRINCIPAL_DIGEST_DOMAIN);
    for value in [user, group] {
        hasher.update((value.len() as u16).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(uid.to_be_bytes());
    hasher.update(gid.to_be_bytes());
    for value in [home, shell] {
        hasher.update((value.len() as u16).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update((supplementary_groups.len() as u16).to_be_bytes());
    for value in supplementary_groups {
        hasher.update((value.len() as u16).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Some(hasher.finalize().into())
}

/// Digest the package-bound executor program provenance.
pub fn production_qualification_executor_provenance_digest(
    path: &str,
    program_digest: [u8; 32],
    source_commit: GitOid,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Option<[u8; 32]> {
    if path.is_empty()
        || path.len() > u16::MAX as usize
        || !path.is_ascii()
        || program_digest == [0; 32]
        || mode == 0
    {
        return None;
    }
    let mut encoded_source = [0; 33];
    source_commit.encode_into(&mut encoded_source);
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_QUALIFICATION_EXECUTOR_PROVENANCE_DIGEST_DOMAIN);
    hasher.update((path.len() as u16).to_be_bytes());
    hasher.update(path.as_bytes());
    hasher.update(program_digest);
    hasher.update(encoded_source);
    hasher.update(uid.to_be_bytes());
    hasher.update(gid.to_be_bytes());
    hasher.update(mode.to_be_bytes());
    Some(hasher.finalize().into())
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
    body[172..204].copy_from_slice(&value.request_event_id);
    encode_text(&mut body[204..269], value.workflow_id);
    encode_text(&mut body[269..334], value.job_id);
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
        request_event_id: nonzero_array(&body[172..204])?,
        workflow_id: decode_text(&body[204..269], false)?,
        job_id: decode_text(&body[269..334], false)?,
    };
    if value.attempt == 0 || value.expected_generation == 0 {
        return Err(DecodeError::ZeroField);
    }
    validate_safe(value.expected_generation)?;
    Ok(value)
}

fn encode_text(body: &mut [u8], value: WireText64) {
    body[0] = value.len;
    body[1..65].copy_from_slice(&value.bytes);
}

fn decode_text(body: &[u8], allow_empty: bool) -> Result<WireText64, DecodeError> {
    let value = WireText64 {
        len: body[0],
        bytes: array(&body[1..65]),
    };
    if value.len == 0 && allow_empty && value.bytes == [0; 64] {
        return Ok(value);
    }
    value.as_str()?;
    Ok(value)
}

fn encode_describe_evidence(body: &mut [u8], value: DescribeAttemptEvidenceRequest) {
    encode_coordinates(body, value.coordinates);
    body[334..366].copy_from_slice(&value.idempotency_digest);
    body[366..398].copy_from_slice(&value.request_frame_digest);
}

fn decode_describe_evidence(body: &[u8]) -> Result<DescribeAttemptEvidenceRequest, DecodeError> {
    require_zero(&body[398..])?;
    Ok(DescribeAttemptEvidenceRequest {
        coordinates: decode_coordinates(body)?,
        idempotency_digest: nonzero_array(&body[334..366])?,
        request_frame_digest: nonzero_array(&body[366..398])?,
    })
}

fn encode_read_evidence(body: &mut [u8], value: ReadAttemptEvidenceRequest) {
    encode_coordinates(body, value.coordinates);
    body[334..366].copy_from_slice(&value.idempotency_digest);
    body[366..398].copy_from_slice(&value.request_frame_digest);
    body[398] = value.kind as u8;
    body[399] = value.item_index;
    body[400..432].copy_from_slice(&value.descriptor_digest);
    put_u32(body, 432, value.offset);
    put_u32(body, 436, value.max_length);
}

fn decode_read_evidence(body: &[u8]) -> Result<ReadAttemptEvidenceRequest, DecodeError> {
    require_zero(&body[440..])?;
    let value = ReadAttemptEvidenceRequest {
        coordinates: decode_coordinates(body)?,
        idempotency_digest: nonzero_array(&body[334..366])?,
        request_frame_digest: nonzero_array(&body[366..398])?,
        kind: EvidenceKind::try_from(body[398])?,
        item_index: body[399],
        descriptor_digest: nonzero_array(&body[400..432])?,
        offset: get_u32(body, 432),
        max_length: get_u32(body, 436),
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
    bytes.extend_from_slice(&coordinates.request_event_id);
    bytes.push(coordinates.workflow_id.len);
    bytes.extend_from_slice(&coordinates.workflow_id.bytes);
    bytes.push(coordinates.job_id.len);
    bytes.extend_from_slice(&coordinates.job_id.bytes);
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
    body[107..139].copy_from_slice(&response.request_event_id);
    body[139..155].copy_from_slice(&response.run_id);
    encode_text(&mut body[155..220], response.workflow_id);
    body[220..252].copy_from_slice(&response.workflow_digest);
    encode_text(&mut body[252..317], response.job_id);
    put_u32(body, 317, response.attempt);
    for (index, item) in response.items.iter().enumerate() {
        if let Some(item) = item {
            let start = 336 + index * 384;
            body[start] = item.kind as u8;
            body[start + 4..start + 36].copy_from_slice(&item.digest);
            put_u32(body, start + 36, item.length);
            body[start + 40..start + 72].copy_from_slice(&item.artifact_name_digest);
            body[start + 72..start + 104].copy_from_slice(&item.artifact_media_type_digest);
            body[start + 104..start + 120].copy_from_slice(&item.teardown_lease_id);
            put_u64(body, start + 120, item.teardown_lease_generation);
            body[start + 128..start + 160].copy_from_slice(&item.teardown_attestation_digest);
            encode_text(&mut body[start + 160..start + 225], item.artifact_id);
            encode_text(&mut body[start + 225..start + 290], item.artifact_name);
            encode_text(
                &mut body[start + 290..start + 355],
                item.artifact_media_type,
            );
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
        let start = 336 + index * 384;
        if index < usize::from(item_count) {
            require_zero(&body[start + 1..start + 4])?;
            let descriptor = EvidenceDescriptor {
                kind: EvidenceKind::try_from(body[start])?,
                digest: nonzero_array(&body[start + 4..start + 36])?,
                length: get_u32(body, start + 36),
                artifact_name_digest: array(&body[start + 40..start + 72]),
                artifact_media_type_digest: array(&body[start + 72..start + 104]),
                teardown_lease_id: array(&body[start + 104..start + 120]),
                teardown_lease_generation: get_u64(body, start + 120),
                teardown_attestation_digest: array(&body[start + 128..start + 160]),
                artifact_id: decode_text(&body[start + 160..start + 225], true)?,
                artifact_name: decode_text(&body[start + 225..start + 290], true)?,
                artifact_media_type: decode_text(&body[start + 290..start + 355], true)?,
            };
            let has_artifact_metadata = descriptor.artifact_id.len > 0
                && descriptor.artifact_name.len > 0
                && descriptor.artifact_media_type.len > 0
                && descriptor.artifact_name_digest != [0; 32]
                && descriptor.artifact_media_type_digest != [0; 32];
            let has_no_artifact_metadata = descriptor.artifact_id == WireText64::EMPTY
                && descriptor.artifact_name == WireText64::EMPTY
                && descriptor.artifact_media_type == WireText64::EMPTY
                && descriptor.artifact_name_digest == [0; 32]
                && descriptor.artifact_media_type_digest == [0; 32];
            let has_teardown_coordinates = descriptor.teardown_lease_id != [0; 16]
                && descriptor.teardown_lease_generation > 0
                && descriptor.teardown_attestation_digest != [0; 32];
            let has_no_teardown_coordinates = descriptor.teardown_lease_id == [0; 16]
                && descriptor.teardown_lease_generation == 0
                && descriptor.teardown_attestation_digest == [0; 32];
            let valid_kind = match descriptor.kind {
                EvidenceKind::Artifact => has_artifact_metadata && has_no_teardown_coordinates,
                EvidenceKind::Teardown => has_no_artifact_metadata && has_teardown_coordinates,
                EvidenceKind::Stdout | EvidenceKind::Stderr => {
                    has_no_artifact_metadata && has_no_teardown_coordinates
                }
            };
            if !valid_kind {
                return Err(DecodeError::UnknownEnum);
            }
            *slot = Some(descriptor);
            require_zero(&body[start + 355..start + 384])?;
        } else {
            require_zero(&body[start..start + 384])?;
        }
    }
    require_zero(&body[321..336])?;
    require_zero(&body[1872..])?;
    Ok(EvidenceDescriptionResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        execution_binding_digest: array(&body[3..35]),
        generation: get_u64(body, 35),
        request_frame_digest: array(&body[43..75]),
        descriptor_set_digest: array(&body[75..107]),
        item_count,
        items,
        request_event_id: nonzero_array(&body[107..139])?,
        run_id: nonzero_array(&body[139..155])?,
        workflow_id: decode_text(&body[155..220], false)?,
        workflow_digest: nonzero_array(&body[220..252])?,
        job_id: decode_text(&body[252..317], false)?,
        attempt: get_u32(body, 317),
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
    body[120..152].copy_from_slice(&response.request_event_id);
    body[152..168].copy_from_slice(&response.run_id);
    encode_text(&mut body[168..233], response.workflow_id);
    body[233..265].copy_from_slice(&response.workflow_digest);
    encode_text(&mut body[265..330], response.job_id);
    put_u32(body, 330, response.attempt);
    body[336..336 + response.bytes.len()].copy_from_slice(&response.bytes);
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
    require_zero(&body[334..336])?;
    require_zero(&body[336 + length..])?;
    Ok(EvidenceChunkResponse {
        code: ResponseCode::try_from(get_u16(body, 0))?,
        kind: EvidenceKind::try_from(body[2])?,
        item_index: body[3],
        offset: get_u32(body, 4),
        total_length: get_u32(body, 8),
        bytes: body[336..336 + length].to_vec(),
        descriptor_digest: array(&body[16..48]),
        execution_binding_digest: array(&body[48..80]),
        generation: get_u64(body, 80),
        request_frame_digest: array(&body[88..120]),
        request_event_id: nonzero_array(&body[120..152])?,
        run_id: nonzero_array(&body[152..168])?,
        workflow_id: decode_text(&body[168..233], false)?,
        workflow_digest: nonzero_array(&body[233..265])?,
        job_id: decode_text(&body[265..330], false)?,
        attempt: get_u32(body, 330),
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

    fn lowercase_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
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

    fn qualification(request_id: [u8; 16]) -> ProductionQualificationRequest {
        let mut value = ProductionQualificationRequest {
            integrated_candidate_sha: oid(),
            activation_package_digest: digest(12),
            fixture_digest: digest(13),
            principal_digest: digest(14),
            lane_manifest_digest: digest(15),
            broker_build_identity: digest(16),
            host_profile_digest: digest(17),
            suite_identity: digest(18),
            isolation_profile_digest: digest(19),
            seccomp_profile_digest: digest(20),
            executor_program_digest: digest(21),
            executor_provenance_digest: digest(22),
            nonce: digest(23),
            controller_generation: 1,
            runner_generation: 2,
            lane_epoch: 3,
            admission_key_generation: 4,
            issued_at: 100,
            expires_at: 160,
            request_frame_digest: [0; 32],
        };
        value.request_frame_digest = production_qualification_request_frame_digest(
            FrameHeader {
                operation: Operation::AdmitQualification,
                request_id,
            },
            &value,
        )
        .unwrap();
        value
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
            request_event_id: digest(12),
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
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

    fn register() -> RegisterJobIntentRequest {
        let header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: [9; 16],
        };
        let mut value = RegisterJobIntentRequest {
            admission: admit(),
            request_event_id: digest(1),
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
            artifact_count: 1,
            artifacts: [Some(JobArtifactDeclaration {
                artifact_id: WireText64::from_ascii("report").unwrap(),
                name: WireText64::from_ascii("report.txt").unwrap(),
                media_type: WireText64::from_ascii("text/plain").unwrap(),
                relative_name: WireText64::from_ascii("report.txt").unwrap(),
                max_bytes: 4096,
            })],
            request_frame_digest: digest(20),
        };
        value.request_frame_digest =
            intent_registration_request_frame_digest(header, &value).unwrap();
        value
    }

    fn registration_response(request: RegisterJobIntentRequest) -> IntentRegistrationResponse {
        IntentRegistrationResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            signed_request_digest: request.admission.signed_request_digest,
            job_intent_digest: request.admission.job_intent_digest,
            request_frame_digest: request.request_frame_digest,
            admission_message_digest: Sha256::digest(admission_signature_message(
                &request.admission,
            ))
            .into(),
            registration_key_digest: intent_registration_key_digest(&request),
            lane_manifest_digest: request.admission.lane_manifest_digest,
            run_id: request.admission.run_id,
            lane_epoch: request.admission.lane_epoch,
            admission_key_generation: request.admission.admission_key_generation,
            issued_at: request.admission.issued_at,
            expires_at: request.admission.expires_at,
            attempt: request.admission.attempt,
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

    fn qualification_response(
        request: ProductionQualificationRequest,
    ) -> ProductionQualificationResponse {
        ProductionQualificationResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            request_frame_digest: request.request_frame_digest,
            qualification_receipt_digest: digest(31),
            integrated_candidate_sha: request.integrated_candidate_sha,
            activation_package_digest: request.activation_package_digest,
            fixture_digest: request.fixture_digest,
            principal_digest: request.principal_digest,
            lane_manifest_digest: request.lane_manifest_digest,
            broker_build_identity: request.broker_build_identity,
            host_profile_digest: request.host_profile_digest,
            suite_identity: request.suite_identity,
            isolation_profile_digest: request.isolation_profile_digest,
            seccomp_profile_digest: request.seccomp_profile_digest,
            seccomp_install_receipt_digest: digest(32),
            executor_program_digest: request.executor_program_digest,
            executor_provenance_digest: request.executor_provenance_digest,
            controller_generation: request.controller_generation,
            runner_generation: request.runner_generation,
            lane_epoch: request.lane_epoch,
            admission_key_generation: request.admission_key_generation,
            qualified_at: 150,
            request_expires_at: request.expires_at,
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
            Request::AdmitQualification(qualification([42; 16])),
            Request::CompleteAttempt(complete()),
            Request::DescribeAttemptEvidence(describe()),
            Request::ReadAttemptEvidence(read()),
            Request::RegisterJobIntent(register()),
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

        let qualification_header = FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [42; 16],
        };
        let qualification = qualification([42; 16]);
        let response = qualification_response(qualification);
        let encoded = encode_production_qualification_response(qualification_header, response);
        assert_eq!(
            decode_production_qualification_response(qualification_header, encoded.as_bytes()),
            Ok(response)
        );

        let header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: [9; 16],
        };
        let request = register();
        let response = registration_response(request);
        let encoded = encode_intent_registration_response(header, response);
        assert_eq!(
            decode_intent_registration_response(header, encoded.as_bytes()),
            Ok(response)
        );
    }

    #[test]
    fn production_qualification_matches_acceptance_client_compatibility_fixture() {
        let header = FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [0x10; 16],
        };
        let mut request = ProductionQualificationRequest {
            integrated_candidate_sha: GitOid::Sha1([0x11; 20]),
            activation_package_digest: [0x12; 32],
            fixture_digest: [0x13; 32],
            principal_digest: [0x14; 32],
            lane_manifest_digest: [0x15; 32],
            broker_build_identity: [0x16; 32],
            host_profile_digest: [0x17; 32],
            suite_identity: [0x18; 32],
            isolation_profile_digest: [0x19; 32],
            seccomp_profile_digest: [0x1a; 32],
            executor_program_digest: [0x1b; 32],
            executor_provenance_digest: [0x1c; 32],
            nonce: [0x1d; 32],
            controller_generation: 21,
            runner_generation: 22,
            lane_epoch: 23,
            admission_key_generation: 24,
            issued_at: 100,
            expires_at: 160,
            request_frame_digest: [0; 32],
        };
        request.request_frame_digest =
            production_qualification_request_frame_digest(header, &request).unwrap();
        assert_eq!(
            lowercase_hex(request.request_frame_digest),
            "17b4b3615a49c9a62270f97d96fa95223743b36df5bbc3245b00017ec2b485f3"
        );
        let frame = encode_request(header.request_id, Request::AdmitQualification(request));
        assert_eq!(frame.as_bytes().len(), 672);
        assert_eq!(
            lowercase_hex(Sha256::digest(frame.as_bytes())),
            "5b7966fdb0dcc635d7315f1ea92401975e6c4e63da2713e8a0e0fb99ba5a5c8d"
        );

        let mut response = qualification_response(request);
        response.seccomp_install_receipt_digest = [0x72; 32];
        response.qualification_receipt_digest = production_qualification_receipt_digest(&response);
        assert_eq!(
            lowercase_hex(response.qualification_receipt_digest),
            "7fcaa7478a07d9352b885f5db12b40c4bc719680d2bf282b1a4ca5b0975f93ad"
        );
        let frame = encode_production_qualification_response(header, response);
        assert_eq!(frame.as_bytes().len(), 608);
        assert_eq!(
            decode_production_qualification_response(header, frame.as_bytes()),
            Ok(response)
        );
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
        assert_eq!(DESCRIBE_ATTEMPT_EVIDENCE_BODY_SIZE, 416);
        assert_eq!(READ_ATTEMPT_EVIDENCE_BODY_SIZE, 448);
        assert_eq!(REGISTER_JOB_INTENT_BODY_SIZE, 960);
        assert_eq!(RESPONSE_BODY_SIZE, 288);
        assert_eq!(INTENT_REGISTRATION_RESPONSE_BODY_SIZE, 288);
        assert_eq!(MAX_FRAME_SIZE, 4480);
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
    fn registration_frame_binds_exact_literals_and_rejects_hostile_shapes() {
        let header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: [9; 16],
        };
        let request = register();
        assert_eq!(
            intent_registration_request_frame_digest(header, &request),
            Some(request.request_frame_digest)
        );
        let mut changed = request;
        changed.artifacts[0].as_mut().unwrap().name = WireText64::from_ascii("other.txt").unwrap();
        assert_ne!(
            intent_registration_request_frame_digest(header, &changed),
            Some(request.request_frame_digest)
        );

        let encoded = encode_request([9; 16], Request::RegisterJobIntent(request));
        let mut zero_digest = encoded.as_bytes().to_vec();
        zero_digest[HEADER_SIZE + 908..HEADER_SIZE + 940].fill(0);
        assert_eq!(decode_request(&zero_digest), Err(DecodeError::ZeroField));

        let mut extra_artifact = encoded.as_bytes().to_vec();
        extra_artifact[HEADER_SIZE + 642] = 2;
        assert!(decode_request(&extra_artifact).is_err());

        let mut padding = encoded.as_bytes().to_vec();
        padding[HEADER_SIZE + 940] = 1;
        assert_eq!(decode_request(&padding), Err(DecodeError::NonZeroReserved));
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
            artifact_id: WireText64::EMPTY,
            artifact_name: WireText64::EMPTY,
            artifact_media_type: WireText64::EMPTY,
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
            request_event_id: digest(12),
            run_id: [13; 16],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            workflow_digest: digest(14),
            job_id: WireText64::from_ascii("job").unwrap(),
            attempt: 1,
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
            request_event_id: digest(12),
            run_id: [13; 16],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            workflow_digest: digest(14),
            job_id: WireText64::from_ascii("job").unwrap(),
            attempt: 1,
        };
        let encoded = encode_evidence_chunk_response(chunk_header, &chunk);
        assert_eq!(
            decode_evidence_chunk_response(chunk_header, encoded.as_bytes()),
            Ok(chunk)
        );

        let mut hostile = encode_request([9; 16], Request::ReadAttemptEvidence(read()))
            .as_bytes()
            .to_vec();
        hostile[HEADER_SIZE + 436..HEADER_SIZE + 440]
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
        let registration_request = register();
        let registration_frame =
            encode_request([9; 16], Request::RegisterJobIntent(registration_request));
        let registration_response = encode_intent_registration_response(
            FrameHeader {
                operation: Operation::RegisterJobIntent,
                request_id: [9; 16],
            },
            registration_response(registration_request),
        );
        assert_eq!(
            hex_digest(registration_frame.as_bytes()),
            "06e022cdde38b2e575e275de8f06a98422873f58d2c3f2d3c004fcce2ba36ce3"
        );
        assert_eq!(
            hex_digest(registration_response.as_bytes()),
            "2b1a30e1a1e48e8062233838dc63e78face60d7c266c1ad4a0b01b2272889d16"
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
