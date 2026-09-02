//! Version 2 production admission and execd-owned execution bindings.
//!
//! The runner supplies a signed pre-admission intent. Execd verifies that intent
//! against one static lane manifest, creates the post-admission binding, commits
//! it before host work, and remains the only caller of privileged host seams.

use std::collections::BTreeMap;

use buzz_ci_broker_protocol::v2::{
    admission_signature_message, evidence_request_frame_digest,
    intent_registration_key_digest_for_admission, intent_registration_key_digest_parts,
    intent_registration_request_frame_digest, AdmissionSignatureAlgorithm, AdmitAttemptRequest,
    AttemptEvidenceCoordinates, BrokerResponse, CancelAttemptRequest, CompleteAttemptRequest,
    DescribeAttemptEvidenceRequest, EvidenceChunkResponse, EvidenceDescriptionResponse,
    EvidenceDescriptor, FrameHeader, GetAttemptRequest, IntentRegistrationResponse,
    ReadAttemptEvidenceRequest, RegisterJobIntentRequest, Request, WireText64,
    EXECUTION_BINDING_DIGEST_DOMAIN, JOB_INTENT_DIGEST_DOMAIN,
    LANE_ACTIVATION_MANIFEST_V1_DIGEST_DOMAIN, MAX_EVIDENCE_CHUNK_SIZE, MAX_EVIDENCE_ITEMS,
};
use buzz_ci_broker_protocol::{BrokerState, Conclusion, GitOid, ResponseCode, TrustClass};
use nostr::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use sha2::{Digest, Sha256};

/// Frozen lane-manifest schema.
pub const LANE_ACTIVATION_MANIFEST_SCHEMA_V1: u16 = 1;
/// Frozen job-intent schema.
pub const JOB_INTENT_SCHEMA_V2: u16 = 2;
/// Frozen execd-owned execution-binding schema.
pub const EXECUTION_BINDING_SCHEMA_V1: u16 = 1;
pub const MAX_DECLARED_ARTIFACTS: usize = 1;
pub const MAX_ARTIFACT_BYTES: u32 = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactDeclarationV1 {
    pub artifact_id: WireText64,
    pub name: WireText64,
    pub media_type: WireText64,
    pub relative_name: WireText64,
    pub max_bytes: u32,
}

impl ArtifactDeclarationV1 {
    pub(crate) fn validate(self) -> bool {
        self.artifact_id.as_str().is_ok_and(safe_artifact_name)
            && self.name.as_str().is_ok_and(safe_artifact_name)
            && self.media_type.as_str().is_ok_and(|value| {
                value.contains('/')
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'.' | b'-')
                    })
            })
            && self.relative_name.as_str().is_ok_and(safe_artifact_name)
            && self.max_bytes > 0
            && self.max_bytes <= MAX_ARTIFACT_BYTES
    }
}

fn safe_artifact_name(value: &str) -> bool {
    !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Host identities measured by execd, never supplied by the runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostIdentity {
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
}

/// Static root-owned authority for one execution lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneActivationManifestV1 {
    pub schema_version: u16,
    pub lane_id: [u8; 32],
    pub lane_epoch: u64,
    pub admission_signature_algorithm: AdmissionSignatureAlgorithm,
    pub admission_verifying_key: [u8; 32],
    pub admission_key_generation: u64,
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub max_wall_timeout_seconds: u32,
}

impl LaneActivationManifestV1 {
    /// Return the canonical domain-separated manifest digest.
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(300);
        bytes.extend_from_slice(LANE_ACTIVATION_MANIFEST_V1_DIGEST_DOMAIN);
        put_u16(&mut bytes, self.schema_version);
        bytes.extend_from_slice(&self.lane_id);
        put_u64(&mut bytes, self.lane_epoch);
        bytes.push(self.admission_signature_algorithm as u8);
        bytes.extend_from_slice(&self.admission_verifying_key);
        put_u64(&mut bytes, self.admission_key_generation);
        bytes.extend_from_slice(&self.broker_build_identity);
        bytes.extend_from_slice(&self.host_profile_digest);
        bytes.extend_from_slice(&self.suite_identity);
        bytes.extend_from_slice(&self.isolation_profile_digest);
        put_u64(&mut bytes, self.not_before);
        put_u64(&mut bytes, self.expires_at);
        put_u32(&mut bytes, self.max_wall_timeout_seconds);
        sha256(&bytes)
    }

    fn validate(
        self,
        request: AdmitAttemptRequest,
        measured: HostIdentity,
        time_reference: u64,
    ) -> Result<(), BindingError> {
        if self.schema_version != LANE_ACTIVATION_MANIFEST_SCHEMA_V1
            || manifest_fields(self).contains(&[0; 32])
            || self.lane_epoch == 0
            || self.admission_key_generation == 0
            || self.not_before == 0
            || request.lane_epoch != self.lane_epoch
            || request.admission_signature_algorithm != self.admission_signature_algorithm
            || request.admission_key_generation != self.admission_key_generation
            || request.lane_manifest_digest != self.digest()
            || request.isolation_profile_digest != self.isolation_profile_digest
            || request.wall_timeout_seconds == 0
            || request.wall_timeout_seconds > self.max_wall_timeout_seconds
            || measured.broker_build_identity != self.broker_build_identity
            || measured.host_profile_digest != self.host_profile_digest
            || measured.suite_identity != self.suite_identity
        {
            return Err(BindingError::ManifestRefused);
        }
        validate_window(self.not_before, self.expires_at, time_reference)?;
        Ok(())
    }
}

fn manifest_fields(value: LaneActivationManifestV1) -> [[u8; 32]; 7] {
    [
        value.lane_id,
        value.admission_verifying_key,
        value.broker_build_identity,
        value.host_profile_digest,
        value.suite_identity,
        value.isolation_profile_digest,
        value.digest(),
    ]
}

/// Immutable pre-admission job intent resolved by its v2 digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobIntentV2 {
    pub schema_version: u16,
    pub signed_request_digest: [u8; 32],
    pub actor_pubkey: [u8; 32],
    pub audience_digest: [u8; 32],
    pub idempotency_digest: [u8; 32],
    pub source_pin_event_id: [u8; 32],
    pub workflow_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub lane_manifest_digest: [u8; 32],
    pub lane_epoch: u64,
    pub admission_signature_algorithm: AdmissionSignatureAlgorithm,
    pub admission_key_generation: u64,
    pub run_id: [u8; 16],
    pub tip_oid: GitOid,
    pub base_oid: GitOid,
    pub issued_at: u64,
    pub expires_at: u64,
    pub wall_timeout_seconds: u32,
    pub attempt: u32,
    pub parent_attempt: u32,
    pub trust_class: TrustClass,
    pub request_event_id: [u8; 32],
    pub workflow_id: WireText64,
    pub job_id: WireText64,
    pub artifact_count: u8,
    pub artifacts: [Option<ArtifactDeclarationV1>; MAX_DECLARED_ARTIFACTS],
}

impl JobIntentV2 {
    pub(crate) fn from_registration(value: RegisterJobIntentRequest) -> Self {
        let admission = value.admission;
        Self {
            schema_version: JOB_INTENT_SCHEMA_V2,
            signed_request_digest: admission.signed_request_digest,
            actor_pubkey: admission.actor_pubkey,
            audience_digest: admission.audience_digest,
            idempotency_digest: admission.idempotency_digest,
            source_pin_event_id: admission.source_pin_event_id,
            workflow_digest: admission.workflow_digest,
            isolation_profile_digest: admission.isolation_profile_digest,
            lane_manifest_digest: admission.lane_manifest_digest,
            lane_epoch: admission.lane_epoch,
            admission_signature_algorithm: admission.admission_signature_algorithm,
            admission_key_generation: admission.admission_key_generation,
            run_id: admission.run_id,
            tip_oid: admission.tip_oid,
            base_oid: admission.base_oid,
            issued_at: admission.issued_at,
            expires_at: admission.expires_at,
            wall_timeout_seconds: admission.wall_timeout_seconds,
            attempt: admission.attempt,
            parent_attempt: admission.parent_attempt,
            trust_class: admission.trust_class,
            request_event_id: value.request_event_id,
            workflow_id: value.workflow_id,
            job_id: value.job_id,
            artifact_count: value.artifact_count,
            artifacts: value.artifacts.map(|artifact| {
                artifact.map(|artifact| ArtifactDeclarationV1 {
                    artifact_id: artifact.artifact_id,
                    name: artifact.name,
                    media_type: artifact.media_type,
                    relative_name: artifact.relative_name,
                    max_bytes: artifact.max_bytes,
                })
            }),
        }
    }

    /// Return the canonical domain-separated intent digest.
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(360);
        bytes.extend_from_slice(JOB_INTENT_DIGEST_DOMAIN);
        put_u16(&mut bytes, self.schema_version);
        bytes.extend_from_slice(&self.signed_request_digest);
        bytes.extend_from_slice(&self.actor_pubkey);
        bytes.extend_from_slice(&self.audience_digest);
        bytes.extend_from_slice(&self.idempotency_digest);
        bytes.extend_from_slice(&self.source_pin_event_id);
        bytes.extend_from_slice(&self.workflow_digest);
        bytes.extend_from_slice(&self.isolation_profile_digest);
        bytes.extend_from_slice(&self.lane_manifest_digest);
        put_u64(&mut bytes, self.lane_epoch);
        bytes.push(self.admission_signature_algorithm as u8);
        put_u64(&mut bytes, self.admission_key_generation);
        bytes.extend_from_slice(&self.run_id);
        put_oid(&mut bytes, self.tip_oid);
        put_oid(&mut bytes, self.base_oid);
        put_u64(&mut bytes, self.issued_at);
        put_u64(&mut bytes, self.expires_at);
        put_u32(&mut bytes, self.wall_timeout_seconds);
        put_u32(&mut bytes, self.attempt);
        put_u32(&mut bytes, self.parent_attempt);
        bytes.push(self.trust_class as u8);
        bytes.extend_from_slice(&self.request_event_id);
        put_text(&mut bytes, self.workflow_id);
        put_text(&mut bytes, self.job_id);
        bytes.push(self.artifact_count);
        for artifact in self.artifacts {
            match artifact {
                Some(artifact) => {
                    bytes.push(1);
                    put_text(&mut bytes, artifact.artifact_id);
                    put_text(&mut bytes, artifact.name);
                    put_text(&mut bytes, artifact.media_type);
                    put_text(&mut bytes, artifact.relative_name);
                    put_u32(&mut bytes, artifact.max_bytes);
                }
                None => bytes.push(0),
            }
        }
        sha256(&bytes)
    }

    fn validate(
        self,
        request: AdmitAttemptRequest,
        time_reference: u64,
    ) -> Result<(), BindingError> {
        if self.schema_version != JOB_INTENT_SCHEMA_V2
            || self.digest() != request.job_intent_digest
            || self.signed_request_digest != request.signed_request_digest
            || self.actor_pubkey != request.actor_pubkey
            || self.audience_digest != request.audience_digest
            || self.idempotency_digest != request.idempotency_digest
            || self.source_pin_event_id != request.source_pin_event_id
            || self.workflow_digest != request.workflow_digest
            || self.isolation_profile_digest != request.isolation_profile_digest
            || self.lane_manifest_digest != request.lane_manifest_digest
            || self.lane_epoch != request.lane_epoch
            || self.admission_signature_algorithm != request.admission_signature_algorithm
            || self.admission_key_generation != request.admission_key_generation
            || self.run_id != request.run_id
            || self.tip_oid != request.tip_oid
            || self.base_oid != request.base_oid
            || self.issued_at != request.issued_at
            || self.expires_at != request.expires_at
            || self.wall_timeout_seconds != request.wall_timeout_seconds
            || self.attempt != request.attempt
            || self.parent_attempt != request.parent_attempt
            || self.trust_class != request.trust_class
            || self.request_event_id != request.signed_request_digest
            || self.workflow_id.as_str().is_err()
            || !self.job_id.as_str().is_ok_and(safe_artifact_name)
            || usize::from(self.artifact_count) > MAX_DECLARED_ARTIFACTS
            || usize::from(self.artifact_count)
                != self.artifacts.iter().filter(|item| item.is_some()).count()
            || self.artifacts.iter().flatten().any(|item| !item.validate())
            || request.issued_at == 0
            || request.attempt == 0
            || (request.attempt == 1 && request.parent_attempt != 0)
            || (request.attempt > 1
                && request.parent_attempt.checked_add(1) != Some(request.attempt))
        {
            return Err(BindingError::IntentRefused);
        }
        validate_window(request.issued_at, request.expires_at, time_reference)
    }
}

pub(crate) fn registration_from_intent(
    admission: AdmitAttemptRequest,
    intent: JobIntentV2,
) -> RegisterJobIntentRequest {
    RegisterJobIntentRequest {
        admission,
        request_event_id: intent.request_event_id,
        workflow_id: intent.workflow_id,
        job_id: intent.job_id,
        artifact_count: intent.artifact_count,
        artifacts: intent.artifacts.map(|artifact| {
            artifact.map(
                |artifact| buzz_ci_broker_protocol::v2::JobArtifactDeclaration {
                    artifact_id: artifact.artifact_id,
                    name: artifact.name,
                    media_type: artifact.media_type,
                    relative_name: artifact.relative_name,
                    max_bytes: artifact.max_bytes,
                },
            )
        }),
        request_frame_digest: [1; 32],
    }
}

/// Static lane-manifest lookup used by production composition.
pub trait LaneManifestSource {
    fn load(
        &mut self,
        digest: [u8; 32],
        epoch: u64,
    ) -> Result<LaneActivationManifestV1, BindingError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentRegistrationWrite {
    Written,
    Existing,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredJobIntent {
    pub admission: AdmitAttemptRequest,
    pub intent: JobIntentV2,
}

/// Execd-owned create-once intent registry. The key binds one logical attempt;
/// implementations must persist exact canonical bytes and reject drift.
pub trait JobIntentSource {
    fn register(
        &mut self,
        header: FrameHeader,
        request: RegisterJobIntentRequest,
        intent: JobIntentV2,
    ) -> Result<IntentRegistrationWrite, BindingError>;

    fn load(
        &mut self,
        registration_key_digest: [u8; 32],
        job_intent_digest: [u8; 32],
    ) -> Result<RegisteredJobIntent, BindingError>;
}

/// One immutable manifest. A digest or epoch mismatch never falls back.
#[derive(Clone, Copy, Debug)]
pub struct StaticLaneManifest {
    manifest: LaneActivationManifestV1,
}

impl StaticLaneManifest {
    pub const fn new(manifest: LaneActivationManifestV1) -> Self {
        Self { manifest }
    }
}

impl LaneManifestSource for StaticLaneManifest {
    fn load(
        &mut self,
        digest: [u8; 32],
        epoch: u64,
    ) -> Result<LaneActivationManifestV1, BindingError> {
        (self.manifest.digest() == digest && self.manifest.lane_epoch == epoch)
            .then_some(self.manifest)
            .ok_or(BindingError::ManifestRefused)
    }
}

/// In-memory exact-intent source useful for startup assembly and tests.
#[derive(Default)]
pub struct StaticJobIntents {
    intents: BTreeMap<[u8; 32], MemoryIntentEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemoryIntentEntry {
    header: FrameHeader,
    request: RegisterJobIntentRequest,
    registered: RegisteredJobIntent,
}

impl StaticJobIntents {
    pub fn insert(
        &mut self,
        admission: AdmitAttemptRequest,
        intent: JobIntentV2,
    ) -> Result<(), BindingError> {
        let key = intent_registration_key_digest_parts(
            intent.lane_manifest_digest,
            intent.idempotency_digest,
            intent.run_id,
            intent.attempt,
        );
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::RegisterJobIntent,
            request_id: [0xff; 16],
        };
        let mut request = registration_from_intent(admission, intent);
        request.request_frame_digest = intent_registration_request_frame_digest(header, &request)
            .ok_or(BindingError::IntentRefused)?;
        let entry = MemoryIntentEntry {
            header,
            request,
            registered: RegisteredJobIntent { admission, intent },
        };
        if intent.digest() != admission.job_intent_digest
            || self.intents.insert(key, entry).is_some()
        {
            return Err(BindingError::IntentRefused);
        }
        Ok(())
    }
}

impl JobIntentSource for StaticJobIntents {
    fn register(
        &mut self,
        header: FrameHeader,
        request: RegisterJobIntentRequest,
        intent: JobIntentV2,
    ) -> Result<IntentRegistrationWrite, BindingError> {
        let registration_key_digest =
            intent_registration_key_digest_for_admission(request.admission);
        let entry = MemoryIntentEntry {
            header,
            request,
            registered: RegisteredJobIntent {
                admission: request.admission,
                intent,
            },
        };
        match self.intents.get(&registration_key_digest) {
            Some(existing) if *existing == entry => Ok(IntentRegistrationWrite::Existing),
            Some(_) => Ok(IntentRegistrationWrite::Conflict),
            None => {
                self.intents.insert(registration_key_digest, entry);
                Ok(IntentRegistrationWrite::Written)
            }
        }
    }

    fn load(
        &mut self,
        registration_key_digest: [u8; 32],
        job_intent_digest: [u8; 32],
    ) -> Result<RegisteredJobIntent, BindingError> {
        self.intents
            .get(&registration_key_digest)
            .map(|entry| entry.registered)
            .and_then(|registered| {
                (registered.intent.digest() == job_intent_digest).then_some(registered)
            })
            .ok_or(BindingError::IntentRefused)
    }
}

/// Execd-owned post-admission identity. The digest covers every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBindingV1 {
    pub schema_version: u16,
    pub lane_manifest_digest: [u8; 32],
    pub lane_epoch: u64,
    pub job_intent_digest: [u8; 32],
    pub admission_message_digest: [u8; 32],
    pub signed_request_digest: [u8; 32],
    pub actor_pubkey: [u8; 32],
    pub idempotency_digest: [u8; 32],
    pub run_id: [u8; 16],
    pub attempt: u32,
    pub attempt_id: [u8; 16],
    pub lease_id: [u8; 16],
    pub lease_generation: u64,
    pub tip_oid: GitOid,
    pub base_oid: GitOid,
    pub admitted_at: u64,
    pub deadline_at: u64,
    pub execution_binding_digest: [u8; 32],
    pub request_event_id: [u8; 32],
    pub workflow_digest: [u8; 32],
    pub workflow_id: WireText64,
    pub job_id: WireText64,
    pub artifact_count: u8,
    pub artifacts: [Option<ArtifactDeclarationV1>; MAX_DECLARED_ARTIFACTS],
}

impl ExecutionBindingV1 {
    fn create(
        request: AdmitAttemptRequest,
        intent: JobIntentV2,
        admitted_at: u64,
    ) -> Result<Self, BindingError> {
        // The admission window is a package constant judged against the
        // package time reference, so it bounds the run by its length rather
        // than by its absolute expiry: a run may not outlive its window.
        let window = request
            .expires_at
            .checked_sub(request.issued_at)
            .filter(|window| *window > 0)
            .ok_or(BindingError::IntentRefused)?;
        let deadline_at = admitted_at
            .checked_add(u64::from(request.wall_timeout_seconds).min(window))
            .filter(|deadline| *deadline > admitted_at)
            .ok_or(BindingError::IntentRefused)?;
        let admission_message_digest = sha256(&admission_signature_message(&request));
        let attempt_id = derive_id(
            b"buzz-ci-execd:attempt-id:v1\0",
            &[
                &request.lane_manifest_digest,
                &request.idempotency_digest,
                &request.run_id,
                &request.attempt.to_be_bytes(),
            ],
        );
        let lease_id = derive_id(
            b"buzz-ci-execd:lease-id:v1\0",
            &[
                &attempt_id,
                &request.job_intent_digest,
                &admitted_at.to_be_bytes(),
            ],
        );
        let mut binding = Self {
            schema_version: EXECUTION_BINDING_SCHEMA_V1,
            lane_manifest_digest: request.lane_manifest_digest,
            lane_epoch: request.lane_epoch,
            job_intent_digest: request.job_intent_digest,
            admission_message_digest,
            signed_request_digest: request.signed_request_digest,
            actor_pubkey: request.actor_pubkey,
            idempotency_digest: request.idempotency_digest,
            run_id: request.run_id,
            attempt: request.attempt,
            attempt_id,
            lease_id,
            lease_generation: 1,
            tip_oid: request.tip_oid,
            base_oid: request.base_oid,
            admitted_at,
            deadline_at,
            execution_binding_digest: [0; 32],
            request_event_id: intent.request_event_id,
            workflow_digest: intent.workflow_digest,
            workflow_id: intent.workflow_id,
            job_id: intent.job_id,
            artifact_count: intent.artifact_count,
            artifacts: intent.artifacts,
        };
        binding.execution_binding_digest = binding.computed_digest();
        Ok(binding)
    }

    /// Recompute the exact domain-separated binding digest.
    pub fn computed_digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(400);
        bytes.extend_from_slice(EXECUTION_BINDING_DIGEST_DOMAIN);
        put_u16(&mut bytes, self.schema_version);
        bytes.extend_from_slice(&self.lane_manifest_digest);
        put_u64(&mut bytes, self.lane_epoch);
        bytes.extend_from_slice(&self.job_intent_digest);
        bytes.extend_from_slice(&self.admission_message_digest);
        bytes.extend_from_slice(&self.signed_request_digest);
        bytes.extend_from_slice(&self.actor_pubkey);
        bytes.extend_from_slice(&self.idempotency_digest);
        bytes.extend_from_slice(&self.run_id);
        put_u32(&mut bytes, self.attempt);
        bytes.extend_from_slice(&self.attempt_id);
        bytes.extend_from_slice(&self.lease_id);
        put_u64(&mut bytes, self.lease_generation);
        put_oid(&mut bytes, self.tip_oid);
        put_oid(&mut bytes, self.base_oid);
        put_u64(&mut bytes, self.admitted_at);
        put_u64(&mut bytes, self.deadline_at);
        bytes.extend_from_slice(&self.request_event_id);
        bytes.extend_from_slice(&self.workflow_digest);
        put_text(&mut bytes, self.workflow_id);
        put_text(&mut bytes, self.job_id);
        bytes.push(self.artifact_count);
        for artifact in self.artifacts {
            match artifact {
                Some(artifact) => {
                    bytes.push(1);
                    put_text(&mut bytes, artifact.artifact_id);
                    put_text(&mut bytes, artifact.name);
                    put_text(&mut bytes, artifact.media_type);
                    put_text(&mut bytes, artifact.relative_name);
                    put_u32(&mut bytes, artifact.max_bytes);
                }
                None => bytes.push(0),
            }
        }
        sha256(&bytes)
    }

    fn matches_request(self, request: AdmitAttemptRequest) -> bool {
        self.schema_version == EXECUTION_BINDING_SCHEMA_V1
            && self.execution_binding_digest == self.computed_digest()
            && self.lane_manifest_digest == request.lane_manifest_digest
            && self.lane_epoch == request.lane_epoch
            && self.job_intent_digest == request.job_intent_digest
            && self.admission_message_digest == sha256(&admission_signature_message(&request))
            && self.signed_request_digest == request.signed_request_digest
            && self.actor_pubkey == request.actor_pubkey
            && self.idempotency_digest == request.idempotency_digest
            && self.run_id == request.run_id
            && self.attempt == request.attempt
            && self.tip_oid == request.tip_oid
            && self.base_oid == request.base_oid
            && self.workflow_digest == request.workflow_digest
    }
}

/// Durable lifecycle attached to one exact execution binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingPhase {
    Admitted,
    Running,
    Draining,
    Terminal,
    CapacityReturned,
    Quarantined,
}

/// Complete durable state for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBindingRecord {
    pub binding: ExecutionBindingV1,
    pub phase: BindingPhase,
    pub generation: u64,
    pub updated_at: u64,
    pub conclusion: Conclusion,
    pub host_receipt_digest: [u8; 32],
    pub evidence_set_digest: [u8; 32],
    pub teardown_digest: [u8; 32],
}

impl ExecutionBindingRecord {
    fn admitted(binding: ExecutionBindingV1, now: u64) -> Self {
        Self {
            binding,
            phase: BindingPhase::Admitted,
            generation: 1,
            updated_at: now,
            conclusion: Conclusion::None,
            host_receipt_digest: [0; 32],
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
        }
    }

    fn advance(&mut self, next: BindingPhase, now: u64) -> Result<(), BindingError> {
        let legal = matches!(
            (self.phase, next),
            (BindingPhase::Admitted, BindingPhase::Running)
                | (BindingPhase::Admitted, BindingPhase::Draining)
                | (BindingPhase::Admitted, BindingPhase::Quarantined)
                | (BindingPhase::Running, BindingPhase::Draining)
                | (BindingPhase::Running, BindingPhase::Terminal)
                | (BindingPhase::Running, BindingPhase::Quarantined)
                | (BindingPhase::Draining, BindingPhase::Terminal)
                | (BindingPhase::Draining, BindingPhase::Quarantined)
                | (BindingPhase::Terminal, BindingPhase::CapacityReturned)
                | (BindingPhase::Terminal, BindingPhase::Quarantined)
        );
        if !legal || now < self.updated_at || self.generation == u64::MAX {
            return Err(BindingError::StateConflict);
        }
        self.phase = next;
        self.generation += 1;
        self.updated_at = now;
        Ok(())
    }

    fn needs_recovery(self) -> bool {
        !matches!(
            self.phase,
            BindingPhase::CapacityReturned | BindingPhase::Quarantined
        )
    }

    fn holds_capacity(self) -> bool {
        self.phase != BindingPhase::CapacityReturned
    }
}

/// CAS result from the durable execution-binding journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalWrite {
    Written,
    Conflict,
}

/// Durable journal used before and after every host effect.
pub trait ExecutionBindingJournal {
    fn load(
        &mut self,
        attempt_id: [u8; 16],
    ) -> Result<Option<ExecutionBindingRecord>, BindingError>;
    fn list(&mut self) -> Result<Vec<ExecutionBindingRecord>, BindingError>;
    fn insert(&mut self, record: ExecutionBindingRecord) -> Result<JournalWrite, BindingError>;
    fn replace(
        &mut self,
        expected_generation: u64,
        record: ExecutionBindingRecord,
    ) -> Result<JournalWrite, BindingError>;
}

/// Deterministic journal implementation used by adapter tests and embedders.
#[derive(Default)]
pub struct MemoryExecutionBindingJournal {
    records: BTreeMap<[u8; 16], ExecutionBindingRecord>,
}

impl ExecutionBindingJournal for MemoryExecutionBindingJournal {
    fn load(
        &mut self,
        attempt_id: [u8; 16],
    ) -> Result<Option<ExecutionBindingRecord>, BindingError> {
        Ok(self.records.get(&attempt_id).copied())
    }

    fn list(&mut self) -> Result<Vec<ExecutionBindingRecord>, BindingError> {
        Ok(self.records.values().copied().collect())
    }

    fn insert(&mut self, record: ExecutionBindingRecord) -> Result<JournalWrite, BindingError> {
        if self.records.contains_key(&record.binding.attempt_id) {
            return Ok(JournalWrite::Conflict);
        }
        self.records.insert(record.binding.attempt_id, record);
        Ok(JournalWrite::Written)
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        record: ExecutionBindingRecord,
    ) -> Result<JournalWrite, BindingError> {
        let Some(current) = self.records.get(&record.binding.attempt_id) else {
            return Ok(JournalWrite::Conflict);
        };
        if current.generation != expected_generation
            || current.binding.execution_binding_digest != record.binding.execution_binding_digest
        {
            return Ok(JournalWrite::Conflict);
        }
        self.records.insert(record.binding.attempt_id, record);
        Ok(JournalWrite::Written)
    }
}

/// Receipt from one exact host seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostStepReceipt {
    pub execution_binding_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
}

/// Root-observed terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostTerminalReceipt {
    pub execution_binding_digest: [u8; 32],
    pub conclusion: Conclusion,
    pub evidence_set_digest: [u8; 32],
    pub teardown_digest: [u8; 32],
}

/// Closed reason sent to the host teardown adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostStopReason {
    Cancelled,
    Completed,
    Expired,
    Recovery,
}

/// Result of crash recovery for an open binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRecoveryReceipt {
    CapacityReturned(HostTerminalReceipt),
    Quarantine,
}

/// Verified sealed bytes and their path-free descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEvidenceItem {
    pub descriptor: EvidenceDescriptor,
    pub bytes: Vec<u8>,
}

/// Seven privileged seams. Production implementations receive only bindings
/// created and verified by execd.
pub trait PrivilegedHostSystem {
    fn identity(&mut self) -> Result<HostIdentity, BindingError>;
    fn executor_unit_handoff(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<HostStepReceipt, BindingError>;
    fn runtime_descriptor_provider(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<HostStepReceipt, BindingError>;
    fn materialization_input_provider(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<HostStepReceipt, BindingError>;
    fn proxy_input_and_lease_provider(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<HostStepReceipt, BindingError>;
    fn terminal_evidence_collector(
        &mut self,
        binding: ExecutionBindingV1,
        claimed_evidence_digest: [u8; 32],
    ) -> Result<HostStepReceipt, BindingError>;
    fn teardown_provider(
        &mut self,
        binding: ExecutionBindingV1,
        reason: HostStopReason,
    ) -> Result<HostTerminalReceipt, BindingError>;
    fn crash_recovery_coordinator(
        &mut self,
        binding: ExecutionBindingV1,
        phase: BindingPhase,
    ) -> Result<HostRecoveryReceipt, BindingError>;

    /// Reconcile a broker-owned running process without trusting the runner to
    /// manufacture terminal evidence. `None` means the fixed process group is
    /// still live; a receipt is returned only after execd has sealed evidence
    /// and teardown for the exact binding.
    fn poll_terminal(
        &mut self,
        _binding: ExecutionBindingV1,
    ) -> Result<Option<HostTerminalReceipt>, BindingError> {
        Ok(None)
    }

    /// Reopen and verify create-once receipts before exporting any bytes.
    fn sealed_attempt_evidence(
        &mut self,
        _binding: ExecutionBindingV1,
    ) -> Result<Vec<HostEvidenceItem>, BindingError> {
        Err(BindingError::HostRefused)
    }
}

/// Concrete ordering and binding checks around the injected host system.
pub struct ConcreteHostAdapters<S> {
    system: S,
}

impl<S> ConcreteHostAdapters<S> {
    pub const fn new(system: S) -> Self {
        Self { system }
    }
}

impl<S: PrivilegedHostSystem> ConcreteHostAdapters<S> {
    fn identity(&mut self) -> Result<HostIdentity, BindingError> {
        self.system.identity()
    }

    fn start(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<[u8; 32], BindingError> {
        let receipts = [
            self.system.executor_unit_handoff(binding, intent)?,
            self.system.runtime_descriptor_provider(binding)?,
            self.system
                .materialization_input_provider(binding, intent)?,
            self.system.proxy_input_and_lease_provider(binding)?,
        ];
        validate_host_receipts(binding, &receipts)?;
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(b"buzz-ci-execd:host-start-receipts:v1\0");
        bytes.extend_from_slice(&binding.execution_binding_digest);
        receipts
            .iter()
            .for_each(|receipt| bytes.extend_from_slice(&receipt.receipt_digest));
        Ok(sha256(&bytes))
    }

    fn finish(
        &mut self,
        binding: ExecutionBindingV1,
        evidence_digest: [u8; 32],
        reason: HostStopReason,
    ) -> Result<HostTerminalReceipt, BindingError> {
        let evidence = self
            .system
            .terminal_evidence_collector(binding, evidence_digest)?;
        validate_host_receipts(binding, &[evidence])?;
        if evidence.receipt_digest != evidence_digest {
            return Err(BindingError::HostRefused);
        }
        let terminal = self.system.teardown_provider(binding, reason)?;
        validate_terminal(binding, terminal)?;
        if terminal.evidence_set_digest != evidence_digest {
            return Err(BindingError::HostRefused);
        }
        Ok(terminal)
    }

    fn stop(
        &mut self,
        binding: ExecutionBindingV1,
        reason: HostStopReason,
    ) -> Result<HostTerminalReceipt, BindingError> {
        let terminal = self.system.teardown_provider(binding, reason)?;
        validate_terminal(binding, terminal)?;
        Ok(terminal)
    }

    fn recover(
        &mut self,
        record: ExecutionBindingRecord,
    ) -> Result<HostRecoveryReceipt, BindingError> {
        let receipt = self
            .system
            .crash_recovery_coordinator(record.binding, record.phase)?;
        if let HostRecoveryReceipt::CapacityReturned(terminal) = receipt {
            validate_terminal(record.binding, terminal)?;
        }
        Ok(receipt)
    }

    fn poll_terminal(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Option<HostTerminalReceipt>, BindingError> {
        let receipt = self.system.poll_terminal(binding)?;
        if let Some(terminal) = receipt {
            validate_terminal(binding, terminal)?;
        }
        Ok(receipt)
    }

    fn sealed_evidence(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Vec<HostEvidenceItem>, BindingError> {
        let items = self.system.sealed_attempt_evidence(binding)?;
        if items.is_empty() || items.len() > MAX_EVIDENCE_ITEMS {
            return Err(BindingError::HostRefused);
        }
        for item in &items {
            if item.descriptor.length as usize != item.bytes.len()
                || sha256(&item.bytes) != item.descriptor.digest
            {
                return Err(BindingError::HostRefused);
            }
        }
        Ok(items)
    }
}

/// Fail-closed refusal from manifest, state, or host binding.
/// Judge a request window against the package's bound time reference.
///
/// The lane manifest window and the frozen acceptance fixture's admission
/// and cancel windows are package constants, so they are compared with the
/// reference the freezer recorded (`acceptance_time_reference`), never with
/// the wall clock; the two failures are named apart from a refused intent.
pub fn validate_window(
    issued_at: u64,
    expires_at: u64,
    time_reference: u64,
) -> Result<(), BindingError> {
    if issued_at > time_reference {
        return Err(BindingError::IssuedAfterTimeReference);
    }
    if time_reference >= expires_at {
        return Err(BindingError::ExpiredAtTimeReference);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    ManifestRefused,
    IntentRefused,
    /// The request window opens after the package time reference.
    IssuedAfterTimeReference,
    /// The request window closed at or before the package time reference.
    ExpiredAtTimeReference,
    SignatureRefused,
    StorageUnavailable,
    NotFound,
    ReplayConflict,
    StateConflict,
    HostRefused,
}

/// Version 2 broker foundation. It owns admission, lifecycle state, and every
/// call into the host adapter.
pub struct ProductionBindingController<M, I, J, S> {
    manifests: M,
    intents: I,
    journal: J,
    host: ConcreteHostAdapters<S>,
    recovery_complete: bool,
    /// Package time reference every admission, lane, and cancel window is
    /// judged against; `now` only stamps records and deadlines.
    time_reference: u64,
}

impl<M, I, J, S> ProductionBindingController<M, I, J, S> {
    pub const fn new(manifests: M, intents: I, journal: J, system: S, time_reference: u64) -> Self {
        Self {
            manifests,
            intents,
            journal,
            host: ConcreteHostAdapters::new(system),
            recovery_complete: false,
            time_reference,
        }
    }
}

impl<M, I, J, S> ProductionBindingController<M, I, J, S>
where
    M: LaneManifestSource,
    I: JobIntentSource,
    J: ExecutionBindingJournal,
    S: PrivilegedHostSystem,
{
    /// Dispatch one decoded version 2 request.
    pub fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        if header.operation != request.operation() {
            return empty_response(ResponseCode::BadFrame, now);
        }
        if !self.recovery_complete {
            return empty_response(ResponseCode::Reconciling, now);
        }
        match request {
            Request::AdmitAttempt(request) => self.admit(request, now),
            Request::CancelAttempt(request) => self.cancel(request, now),
            Request::GetAttempt(request) => self.get(request, now),
            Request::CompleteAttempt(request) => self.complete(request, now),
            Request::DescribeAttemptEvidence(_) | Request::ReadAttemptEvidence(_) => {
                empty_response(ResponseCode::BadFrame, now)
            }
            Request::RegisterJobIntent(_) => empty_response(ResponseCode::BadFrame, now),
            Request::Hello(_) | Request::AdmitQualification(_) => {
                empty_response(ResponseCode::NotProvisioned, now)
            }
        }
    }

    fn validate_evidence_coordinates(
        &mut self,
        coordinates: AttemptEvidenceCoordinates,
        idempotency_digest: [u8; 32],
    ) -> Result<ExecutionBindingRecord, BindingError> {
        let record =
            self.load_bound(coordinates.attempt_id, coordinates.execution_binding_digest)?;
        let registration_key = intent_registration_key_digest_parts(
            record.binding.lane_manifest_digest,
            record.binding.idempotency_digest,
            record.binding.run_id,
            record.binding.attempt,
        );
        let intent = self
            .intents
            .load(registration_key, record.binding.job_intent_digest)?
            .intent;
        if record.phase != BindingPhase::CapacityReturned
            || record.generation != coordinates.expected_generation
            || record.evidence_set_digest == [0; 32]
            || record.teardown_digest == [0; 32]
            || coordinates.signed_request_digest != record.binding.signed_request_digest
            || coordinates.run_id != record.binding.run_id
            || coordinates.workflow_digest != intent.workflow_digest
            || coordinates.request_event_id != record.binding.request_event_id
            || coordinates.workflow_id != record.binding.workflow_id
            || coordinates.job_id != record.binding.job_id
            || coordinates.job_intent_digest != record.binding.job_intent_digest
            || coordinates.attempt != record.binding.attempt
            || idempotency_digest != record.binding.idempotency_digest
        {
            return Err(BindingError::StateConflict);
        }
        Ok(record)
    }

    fn describe_evidence(
        &mut self,
        header: FrameHeader,
        request: DescribeAttemptEvidenceRequest,
    ) -> Result<EvidenceDescriptionResponse, BindingError> {
        if evidence_request_frame_digest(header, &Request::DescribeAttemptEvidence(request))
            != Some(request.request_frame_digest)
        {
            return Err(BindingError::ReplayConflict);
        }
        let record =
            self.validate_evidence_coordinates(request.coordinates, request.idempotency_digest)?;
        let items = self.host.sealed_evidence(record.binding)?;
        if items[0].descriptor.digest != record.evidence_set_digest
            || items.last().map(|item| item.descriptor.digest) != Some(record.teardown_digest)
        {
            return Err(BindingError::HostRefused);
        }
        let mut descriptors = [None; MAX_EVIDENCE_ITEMS];
        let mut digest_material = Vec::with_capacity(items.len() * 160 + 64);
        digest_material.extend_from_slice(b"buzz-ci-execd:evidence-descriptor-set:v2\0");
        digest_material.extend_from_slice(&record.binding.execution_binding_digest);
        for (slot, item) in descriptors.iter_mut().zip(&items) {
            *slot = Some(item.descriptor);
            descriptor_digest_material(&mut digest_material, item.descriptor);
        }
        Ok(EvidenceDescriptionResponse {
            code: ResponseCode::Ok,
            execution_binding_digest: record.binding.execution_binding_digest,
            generation: record.generation,
            request_frame_digest: request.request_frame_digest,
            descriptor_set_digest: sha256(&digest_material),
            item_count: items.len() as u8,
            items: descriptors,
            request_event_id: record.binding.request_event_id,
            run_id: record.binding.run_id,
            workflow_id: record.binding.workflow_id,
            workflow_digest: record.binding.workflow_digest,
            job_id: record.binding.job_id,
            attempt: record.binding.attempt,
        })
    }

    fn read_evidence(
        &mut self,
        header: FrameHeader,
        request: ReadAttemptEvidenceRequest,
    ) -> Result<EvidenceChunkResponse, BindingError> {
        if evidence_request_frame_digest(header, &Request::ReadAttemptEvidence(request))
            != Some(request.request_frame_digest)
        {
            return Err(BindingError::ReplayConflict);
        }
        let record =
            self.validate_evidence_coordinates(request.coordinates, request.idempotency_digest)?;
        let items = self.host.sealed_evidence(record.binding)?;
        let item = items
            .get(usize::from(request.item_index))
            .filter(|item| item.descriptor.kind == request.kind)
            .filter(|item| item.descriptor.digest == request.descriptor_digest)
            .ok_or(BindingError::ReplayConflict)?;
        let offset = request.offset as usize;
        if offset > item.bytes.len()
            || request.max_length == 0
            || request.max_length as usize > MAX_EVIDENCE_CHUNK_SIZE
        {
            return Err(BindingError::StateConflict);
        }
        let end = offset
            .saturating_add(request.max_length as usize)
            .min(item.bytes.len());
        Ok(EvidenceChunkResponse {
            code: ResponseCode::Ok,
            execution_binding_digest: record.binding.execution_binding_digest,
            generation: record.generation,
            request_frame_digest: request.request_frame_digest,
            kind: request.kind,
            item_index: request.item_index,
            descriptor_digest: item.descriptor.digest,
            offset: request.offset,
            total_length: item.descriptor.length,
            bytes: item.bytes[offset..end].to_vec(),
            request_event_id: record.binding.request_event_id,
            run_id: record.binding.run_id,
            workflow_id: record.binding.workflow_id,
            workflow_digest: record.binding.workflow_digest,
            job_id: record.binding.job_id,
            attempt: record.binding.attempt,
        })
    }

    /// Recover every nonterminal binding before accepting new capacity.
    pub fn recover_open(&mut self, now: u64) -> Result<(), BindingError> {
        let records = self.journal.list()?;
        for record in records.into_iter().filter(|record| record.needs_recovery()) {
            match self.host.recover(record) {
                Ok(HostRecoveryReceipt::CapacityReturned(terminal)) => {
                    self.close_record(record, terminal, now)?;
                }
                Ok(HostRecoveryReceipt::Quarantine) | Err(_) => {
                    self.quarantine(record, now)?;
                }
            }
        }
        self.recovery_complete = true;
        Ok(())
    }

    /// Reconcile leases whose execd-owned deadline has elapsed.
    pub fn maintenance(&mut self, now: u64) -> Result<(), BindingError> {
        if !self.recovery_complete {
            return Err(BindingError::StateConflict);
        }
        let records = self.journal.list()?;
        for record in records
            .iter()
            .copied()
            .filter(|record| record.phase == BindingPhase::Running)
        {
            match self.host.poll_terminal(record.binding) {
                Ok(Some(terminal)) => {
                    self.close_record(record, terminal, now)?;
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = self.recover_after_failure(record, now);
                }
            }
        }
        let records = self.journal.list()?;
        for record in records
            .into_iter()
            .filter(|record| record.needs_recovery() && record.binding.deadline_at <= now)
        {
            let _ = self.stop_record(record, HostStopReason::Expired, now);
        }
        Ok(())
    }

    fn register_intent(
        &mut self,
        header: FrameHeader,
        request: RegisterJobIntentRequest,
        _now: u64,
    ) -> Result<ResponseCode, BindingError> {
        let admission = request.admission;
        let manifest = self
            .manifests
            .load(admission.lane_manifest_digest, admission.lane_epoch)?;
        let measured = self.host.identity()?;
        manifest.validate(admission, measured, self.time_reference)?;
        verify_admission_signature(manifest, admission)?;
        let intent = JobIntentV2::from_registration(request);
        intent.validate(admission, self.time_reference)?;

        let attempt_id = attempt_id_for_admission(admission);
        let admitted = match self.journal.load(attempt_id)? {
            Some(record) if record.binding.matches_request(admission) => true,
            Some(_) => return Err(BindingError::ReplayConflict),
            None => false,
        };

        match self.intents.register(header, request, intent)? {
            IntentRegistrationWrite::Written if admitted => Ok(ResponseCode::Existing),
            IntentRegistrationWrite::Written => Ok(ResponseCode::Ok),
            IntentRegistrationWrite::Existing => Ok(ResponseCode::Existing),
            IntentRegistrationWrite::Conflict => Err(BindingError::ReplayConflict),
        }
    }

    fn admit(&mut self, request: AdmitAttemptRequest, now: u64) -> BrokerResponse {
        let attempt_id = attempt_id_for_admission(request);
        match self.journal.load(attempt_id) {
            Ok(Some(record)) if record.binding.matches_request(request) => {
                return record_response(ResponseCode::Existing, record, now)
            }
            Ok(Some(_)) => return empty_response(ResponseCode::ReplayConflict, now),
            Err(_) => return empty_response(ResponseCode::StorageUnavailable, now),
            Ok(None) => {}
        }
        let manifest = match self
            .manifests
            .load(request.lane_manifest_digest, request.lane_epoch)
        {
            Ok(manifest) => manifest,
            Err(error) => return error_response(error, now),
        };
        let measured = match self.host.identity() {
            Ok(identity) => identity,
            Err(error) => return error_response(error, now),
        };
        if let Err(error) = manifest.validate(request, measured, self.time_reference) {
            return error_response(error, now);
        }
        if verify_admission_signature(manifest, request).is_err() {
            return empty_response(ResponseCode::PolicyDenied, now);
        }
        let registered = match self.intents.load(
            intent_registration_key_digest_for_admission(request),
            request.job_intent_digest,
        ) {
            Ok(registered) => registered,
            Err(error) => return error_response(error, now),
        };
        if registered.admission != request {
            return empty_response(ResponseCode::ReplayConflict, now);
        }
        let intent = registered.intent;
        if let Err(error) = intent.validate(request, self.time_reference) {
            return error_response(error, now);
        }
        let occupied = match self.journal.list() {
            Ok(records) => records
                .into_iter()
                .any(ExecutionBindingRecord::holds_capacity),
            Err(_) => return empty_response(ResponseCode::StorageUnavailable, now),
        };
        if occupied {
            return empty_response(ResponseCode::NoCapacity, now);
        }
        let binding = match ExecutionBindingV1::create(request, intent, now) {
            Ok(binding) => binding,
            Err(error) => return error_response(error, now),
        };
        let mut record = ExecutionBindingRecord::admitted(binding, now);
        match self.journal.insert(record) {
            Ok(JournalWrite::Written) => {}
            Ok(JournalWrite::Conflict) => return empty_response(ResponseCode::ReplayConflict, now),
            Err(_) => return empty_response(ResponseCode::StorageUnavailable, now),
        }
        let host_receipt_digest = match self.host.start(binding, intent) {
            Ok(digest) => digest,
            Err(_) => {
                let _ = self.recover_after_failure(record, now);
                return empty_response(ResponseCode::InternalFailure, now);
            }
        };
        let expected_generation = record.generation;
        record.host_receipt_digest = host_receipt_digest;
        if record.advance(BindingPhase::Running, now).is_err()
            || !matches!(
                self.journal.replace(expected_generation, record),
                Ok(JournalWrite::Written)
            )
        {
            let _ = self.host.recover(record);
            return empty_response(ResponseCode::StorageUnavailable, now);
        }
        record_response(ResponseCode::Ok, record, now)
    }

    fn get(&mut self, request: GetAttemptRequest, now: u64) -> BrokerResponse {
        match self.load_bound(request.attempt_id, request.execution_binding_digest) {
            Ok(record) => record_response(ResponseCode::Existing, record, now),
            Err(error) => error_response(error, now),
        }
    }

    fn cancel(&mut self, request: CancelAttemptRequest, now: u64) -> BrokerResponse {
        let record = match self.load_bound(request.attempt_id, request.execution_binding_digest) {
            Ok(record) => record,
            Err(error) => return error_response(error, now),
        };
        if request.actor_pubkey != record.binding.actor_pubkey || request.issued_at == 0 {
            return empty_response(ResponseCode::PolicyDenied, now);
        }
        if let Err(error) =
            validate_window(request.issued_at, request.expires_at, self.time_reference)
        {
            return error_response(error, now);
        }
        if request.expected_generation != record.generation {
            return record_response(ResponseCode::StateConflict, record, now);
        }
        if !record.needs_recovery() {
            return record_response(ResponseCode::Existing, record, now);
        }
        self.stop_record(record, HostStopReason::Cancelled, now)
    }

    fn complete(&mut self, request: CompleteAttemptRequest, now: u64) -> BrokerResponse {
        let record = match self.load_bound_lease(request.lease_id, request.execution_binding_digest)
        {
            Ok(record) => record,
            Err(error) => return error_response(error, now),
        };
        if request.signer_pubkey != record.binding.actor_pubkey
            || request.signed_request_digest != record.binding.signed_request_digest
            || request.run_id != record.binding.run_id
            || request.attempt != record.binding.attempt
            || request.lease_id != record.binding.lease_id
            || request.lease_generation != record.binding.lease_generation
            || request.evidence_set_digest == [0; 32]
            || request.terminal_at == 0
            || request.terminal_at > now
        {
            return empty_response(ResponseCode::PolicyDenied, now);
        }
        if !matches!(record.phase, BindingPhase::Running | BindingPhase::Draining) {
            return record_response(ResponseCode::Existing, record, now);
        }
        let mut draining = record;
        if draining.phase == BindingPhase::Running {
            let expected_generation = draining.generation;
            if draining.advance(BindingPhase::Draining, now).is_err()
                || !matches!(
                    self.journal.replace(expected_generation, draining),
                    Ok(JournalWrite::Written)
                )
            {
                return empty_response(ResponseCode::StorageUnavailable, now);
            }
        }
        let terminal = match self.host.finish(
            draining.binding,
            request.evidence_set_digest,
            HostStopReason::Completed,
        ) {
            Ok(terminal) => terminal,
            Err(_) => {
                let _ = self.recover_after_failure(draining, now);
                return empty_response(ResponseCode::InternalFailure, now);
            }
        };
        match self.close_record(draining, terminal, now) {
            Ok(record) => record_response(ResponseCode::Ok, record, now),
            Err(error) => error_response(error, now),
        }
    }

    fn stop_record(
        &mut self,
        mut record: ExecutionBindingRecord,
        reason: HostStopReason,
        now: u64,
    ) -> BrokerResponse {
        if record.phase != BindingPhase::Draining {
            let expected_generation = record.generation;
            if record.advance(BindingPhase::Draining, now).is_err()
                || !matches!(
                    self.journal.replace(expected_generation, record),
                    Ok(JournalWrite::Written)
                )
            {
                return empty_response(ResponseCode::StorageUnavailable, now);
            }
        }
        let terminal = match self.host.stop(record.binding, reason) {
            Ok(terminal) => terminal,
            Err(_) => {
                let _ = self.recover_after_failure(record, now);
                return empty_response(ResponseCode::InternalFailure, now);
            }
        };
        match self.close_record(record, terminal, now) {
            Ok(record) => record_response(ResponseCode::Ok, record, now),
            Err(error) => error_response(error, now),
        }
    }

    fn close_record(
        &mut self,
        mut record: ExecutionBindingRecord,
        terminal: HostTerminalReceipt,
        now: u64,
    ) -> Result<ExecutionBindingRecord, BindingError> {
        if !matches!(
            record.phase,
            BindingPhase::Draining | BindingPhase::Terminal
        ) {
            let expected_generation = record.generation;
            record.advance(BindingPhase::Draining, now)?;
            write_replacement(&mut self.journal, expected_generation, record)?;
        }
        if record.phase != BindingPhase::Terminal {
            let expected_generation = record.generation;
            record.conclusion = terminal.conclusion;
            record.evidence_set_digest = terminal.evidence_set_digest;
            record.teardown_digest = terminal.teardown_digest;
            record.advance(BindingPhase::Terminal, now)?;
            write_replacement(&mut self.journal, expected_generation, record)?;
        }
        let expected_generation = record.generation;
        record.advance(BindingPhase::CapacityReturned, now)?;
        write_replacement(&mut self.journal, expected_generation, record)?;
        Ok(record)
    }

    fn quarantine(
        &mut self,
        mut record: ExecutionBindingRecord,
        now: u64,
    ) -> Result<(), BindingError> {
        if record.phase == BindingPhase::Quarantined {
            return Ok(());
        }
        let expected_generation = record.generation;
        record.conclusion = Conclusion::InfrastructureFailure;
        record.advance(BindingPhase::Quarantined, now)?;
        write_replacement(&mut self.journal, expected_generation, record)
    }

    fn recover_after_failure(
        &mut self,
        record: ExecutionBindingRecord,
        now: u64,
    ) -> Result<(), BindingError> {
        match self.host.recover(record) {
            Ok(HostRecoveryReceipt::CapacityReturned(terminal)) => {
                self.close_record(record, terminal, now).map(|_| ())
            }
            Ok(HostRecoveryReceipt::Quarantine) | Err(_) => self.quarantine(record, now),
        }
    }

    fn load_bound(
        &mut self,
        attempt_id: [u8; 16],
        binding_digest: [u8; 32],
    ) -> Result<ExecutionBindingRecord, BindingError> {
        let record = self
            .journal
            .load(attempt_id)?
            .ok_or(BindingError::NotFound)?;
        if record.binding.execution_binding_digest != binding_digest
            || binding_digest == [0; 32]
            || record.binding.computed_digest() != binding_digest
        {
            return Err(BindingError::ReplayConflict);
        }
        Ok(record)
    }

    fn load_bound_lease(
        &mut self,
        lease_id: [u8; 16],
        binding_digest: [u8; 32],
    ) -> Result<ExecutionBindingRecord, BindingError> {
        let record = self
            .journal
            .list()?
            .into_iter()
            .find(|record| record.binding.lease_id == lease_id)
            .ok_or(BindingError::NotFound)?;
        if record.binding.execution_binding_digest != binding_digest
            || binding_digest == [0; 32]
            || record.binding.computed_digest() != binding_digest
        {
            return Err(BindingError::ReplayConflict);
        }
        Ok(record)
    }
}

impl<M, I, J, S> crate::control::ControlDispatch for ProductionBindingController<M, I, J, S>
where
    M: LaneManifestSource,
    I: JobIntentSource,
    J: ExecutionBindingJournal,
    S: PrivilegedHostSystem,
{
    fn dispatch(
        &mut self,
        header: buzz_ci_broker_protocol::FrameHeader,
        request: buzz_ci_broker_protocol::Request,
        now: u64,
    ) -> buzz_ci_broker_protocol::BrokerResponse {
        crate::Broker::new().handle(header, request, now)
    }

    fn dispatch_v2(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        ProductionBindingController::dispatch(self, header, request, now)
    }

    fn dispatch_v2_encoded(
        &mut self,
        header: FrameHeader,
        request: Request,
        now: u64,
    ) -> buzz_ci_broker_protocol::v2::EncodedFrame {
        match request {
            Request::RegisterJobIntent(value) => {
                let code = if header.operation != request.operation()
                    || intent_registration_request_frame_digest(header, &value)
                        != Some(value.request_frame_digest)
                {
                    ResponseCode::BadFrame
                } else if !self.recovery_complete {
                    ResponseCode::Reconciling
                } else {
                    self.register_intent(header, value, now)
                        .unwrap_or_else(error_code)
                };
                buzz_ci_broker_protocol::v2::encode_intent_registration_response(
                    header,
                    intent_registration_response(code, value),
                )
            }
            Request::DescribeAttemptEvidence(value) => {
                let response = if header.operation != request.operation() || !self.recovery_complete
                {
                    evidence_description_error(
                        if self.recovery_complete {
                            ResponseCode::BadFrame
                        } else {
                            ResponseCode::Reconciling
                        },
                        value,
                    )
                } else {
                    self.describe_evidence(header, value)
                        .unwrap_or_else(|error| {
                            evidence_description_error(error_code(error), value)
                        })
                };
                buzz_ci_broker_protocol::v2::encode_evidence_description_response(header, response)
            }
            Request::ReadAttemptEvidence(value) => {
                let response = if header.operation != request.operation() || !self.recovery_complete
                {
                    evidence_chunk_error(
                        if self.recovery_complete {
                            ResponseCode::BadFrame
                        } else {
                            ResponseCode::Reconciling
                        },
                        value,
                    )
                } else {
                    self.read_evidence(header, value)
                        .unwrap_or_else(|error| evidence_chunk_error(error_code(error), value))
                };
                buzz_ci_broker_protocol::v2::encode_evidence_chunk_response(header, &response)
            }
            _ => {
                let response = ProductionBindingController::dispatch(self, header, request, now);
                buzz_ci_broker_protocol::v2::encode_response(header, response)
            }
        }
    }

    fn maintenance(&mut self, now: u64) {
        let _ = ProductionBindingController::maintenance(self, now);
    }
}

fn write_replacement<J: ExecutionBindingJournal>(
    journal: &mut J,
    expected_generation: u64,
    record: ExecutionBindingRecord,
) -> Result<(), BindingError> {
    match journal.replace(expected_generation, record)? {
        JournalWrite::Written => Ok(()),
        JournalWrite::Conflict => Err(BindingError::StateConflict),
    }
}

fn descriptor_digest_material(bytes: &mut Vec<u8>, descriptor: EvidenceDescriptor) {
    bytes.push(descriptor.kind as u8);
    bytes.extend_from_slice(&descriptor.digest);
    bytes.extend_from_slice(&descriptor.length.to_be_bytes());
    bytes.extend_from_slice(&descriptor.artifact_name_digest);
    bytes.extend_from_slice(&descriptor.artifact_media_type_digest);
    bytes.extend_from_slice(&descriptor.teardown_lease_id);
    bytes.extend_from_slice(&descriptor.teardown_lease_generation.to_be_bytes());
    bytes.extend_from_slice(&descriptor.teardown_attestation_digest);
    put_text(bytes, descriptor.artifact_id);
    put_text(bytes, descriptor.artifact_name);
    put_text(bytes, descriptor.artifact_media_type);
}

fn evidence_description_error(
    code: ResponseCode,
    request: DescribeAttemptEvidenceRequest,
) -> EvidenceDescriptionResponse {
    EvidenceDescriptionResponse {
        code,
        execution_binding_digest: request.coordinates.execution_binding_digest,
        generation: request.coordinates.expected_generation,
        request_frame_digest: request.request_frame_digest,
        descriptor_set_digest: [0; 32],
        item_count: 0,
        items: [None; MAX_EVIDENCE_ITEMS],
        request_event_id: request.coordinates.request_event_id,
        run_id: request.coordinates.run_id,
        workflow_id: request.coordinates.workflow_id,
        workflow_digest: request.coordinates.workflow_digest,
        job_id: request.coordinates.job_id,
        attempt: request.coordinates.attempt,
    }
}

fn intent_registration_response(
    code: ResponseCode,
    request: RegisterJobIntentRequest,
) -> IntentRegistrationResponse {
    let admission = request.admission;
    IntentRegistrationResponse {
        code,
        retry_after_millis: 0,
        signed_request_digest: admission.signed_request_digest,
        job_intent_digest: admission.job_intent_digest,
        request_frame_digest: request.request_frame_digest,
        admission_message_digest: sha256(&admission_signature_message(&admission)),
        registration_key_digest: intent_registration_key_digest_for_admission(admission),
        lane_manifest_digest: admission.lane_manifest_digest,
        run_id: admission.run_id,
        lane_epoch: admission.lane_epoch,
        admission_key_generation: admission.admission_key_generation,
        issued_at: admission.issued_at,
        expires_at: admission.expires_at,
        attempt: admission.attempt,
    }
}

fn evidence_chunk_error(
    code: ResponseCode,
    request: ReadAttemptEvidenceRequest,
) -> EvidenceChunkResponse {
    EvidenceChunkResponse {
        code,
        execution_binding_digest: request.coordinates.execution_binding_digest,
        generation: request.coordinates.expected_generation,
        request_frame_digest: request.request_frame_digest,
        kind: request.kind,
        item_index: request.item_index,
        descriptor_digest: request.descriptor_digest,
        offset: request.offset,
        total_length: 0,
        bytes: Vec::new(),
        request_event_id: request.coordinates.request_event_id,
        run_id: request.coordinates.run_id,
        workflow_id: request.coordinates.workflow_id,
        workflow_digest: request.coordinates.workflow_digest,
        job_id: request.coordinates.job_id,
        attempt: request.coordinates.attempt,
    }
}

fn verify_admission_signature(
    manifest: LaneActivationManifestV1,
    request: AdmitAttemptRequest,
) -> Result<(), BindingError> {
    if manifest.admission_signature_algorithm != AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256
        || request.admission_signature_algorithm != manifest.admission_signature_algorithm
        || request.admission_key_generation != manifest.admission_key_generation
    {
        return Err(BindingError::SignatureRefused);
    }
    let key = XOnlyPublicKey::from_slice(&manifest.admission_verifying_key)
        .map_err(|_| BindingError::SignatureRefused)?;
    let signature = Signature::from_slice(&request.admission_signature)
        .map_err(|_| BindingError::SignatureRefused)?;
    let digest = sha256(&admission_signature_message(&request));
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(digest), &key)
        .map_err(|_| BindingError::SignatureRefused)
}

fn validate_host_receipts(
    binding: ExecutionBindingV1,
    receipts: &[HostStepReceipt],
) -> Result<(), BindingError> {
    if receipts.is_empty()
        || receipts.iter().any(|receipt| {
            receipt.execution_binding_digest != binding.execution_binding_digest
                || receipt.receipt_digest == [0; 32]
        })
    {
        return Err(BindingError::HostRefused);
    }
    Ok(())
}

fn validate_terminal(
    binding: ExecutionBindingV1,
    terminal: HostTerminalReceipt,
) -> Result<(), BindingError> {
    if terminal.execution_binding_digest != binding.execution_binding_digest
        || terminal.conclusion == Conclusion::None
        || terminal.evidence_set_digest == [0; 32]
        || terminal.teardown_digest == [0; 32]
    {
        return Err(BindingError::HostRefused);
    }
    Ok(())
}

fn record_response(
    code: ResponseCode,
    record: ExecutionBindingRecord,
    _now: u64,
) -> BrokerResponse {
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: record.binding.attempt_id,
        run_id: record.binding.run_id,
        accepted_request_digest: record.binding.signed_request_digest,
        job_intent_digest: record.binding.job_intent_digest,
        execution_binding_digest: record.binding.execution_binding_digest,
        tip_oid: Some(record.binding.tip_oid),
        broker_state: match record.phase {
            BindingPhase::Admitted | BindingPhase::Draining => BrokerState::Reconciling,
            BindingPhase::Running => BrokerState::Leased,
            BindingPhase::Terminal | BindingPhase::CapacityReturned => BrokerState::Terminal,
            BindingPhase::Quarantined => BrokerState::Quarantined,
        },
        conclusion: record.conclusion,
        terminal_reason: 0,
        generation: record.generation,
        accepted_at: record.binding.admitted_at,
        updated_at: record.updated_at,
        lease_generation: record.binding.lease_generation,
        evidence_set_digest: record.evidence_set_digest,
        teardown_digest: record.teardown_digest,
        attempt: record.binding.attempt,
    }
}

/// Construct the v2 zero-capacity response used by control transport fallback.
pub fn empty_response(code: ResponseCode, now: u64) -> BrokerResponse {
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: [0; 16],
        run_id: [0; 16],
        accepted_request_digest: [0; 32],
        job_intent_digest: [0; 32],
        execution_binding_digest: [0; 32],
        tip_oid: None,
        broker_state: BrokerState::Reconciling,
        conclusion: Conclusion::None,
        terminal_reason: 0,
        generation: 0,
        accepted_at: 0,
        updated_at: now,
        lease_generation: 0,
        evidence_set_digest: [0; 32],
        teardown_digest: [0; 32],
        attempt: 0,
    }
}

fn error_response(error: BindingError, now: u64) -> BrokerResponse {
    empty_response(error_code(error), now)
}

fn error_code(error: BindingError) -> ResponseCode {
    match error {
        BindingError::ManifestRefused
        | BindingError::IntentRefused
        | BindingError::SignatureRefused => ResponseCode::PolicyDenied,
        BindingError::IssuedAfterTimeReference => ResponseCode::IssuedAfterTimeReference,
        BindingError::ExpiredAtTimeReference => ResponseCode::ExpiredAtTimeReference,
        BindingError::StorageUnavailable => ResponseCode::StorageUnavailable,
        BindingError::NotFound => ResponseCode::NotFound,
        BindingError::ReplayConflict => ResponseCode::ReplayConflict,
        BindingError::StateConflict => ResponseCode::StateConflict,
        BindingError::HostRefused => ResponseCode::InternalFailure,
    }
}

fn derive_id(domain: &[u8], fields: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    fields.iter().for_each(|field| hasher.update(field));
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn attempt_id_for_admission(request: AdmitAttemptRequest) -> [u8; 16] {
    derive_id(
        b"buzz-ci-execd:attempt-id:v1\0",
        &[
            &request.lane_manifest_digest,
            &request.idempotency_digest,
            &request.run_id,
            &request.attempt.to_be_bytes(),
        ],
    )
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_text(bytes: &mut Vec<u8>, value: WireText64) {
    bytes.push(value.len);
    bytes.extend_from_slice(&value.bytes);
}

fn put_oid(bytes: &mut Vec<u8>, oid: GitOid) {
    match oid {
        GitOid::Sha1(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value);
        }
        GitOid::Sha256(value) => {
            bytes.push(2);
            bytes.extend_from_slice(&value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use nostr::secp256k1::{Keypair, SecretKey};

    use super::*;

    /// Package time reference the test controllers judge windows against; the
    /// fixture admission is issued at 10 and expires at 200, the lane opens at
    /// 1 and closes at 1000.
    const TIME_REFERENCE: u64 = 20;

    #[derive(Default)]
    struct HostState {
        calls: Vec<&'static str>,
        refuse_at: Option<&'static str>,
        recovery: Option<HostRecoveryReceipt>,
        evidence: Vec<HostEvidenceItem>,
    }

    struct FakeHost {
        state: Rc<RefCell<HostState>>,
        identity: HostIdentity,
    }

    impl FakeHost {
        fn receipt(
            &self,
            name: &'static str,
            binding: ExecutionBindingV1,
            byte: u8,
        ) -> Result<HostStepReceipt, BindingError> {
            let mut state = self.state.borrow_mut();
            state.calls.push(name);
            if state.refuse_at == Some(name) {
                return Err(BindingError::HostRefused);
            }
            Ok(HostStepReceipt {
                execution_binding_digest: binding.execution_binding_digest,
                receipt_digest: [byte; 32],
            })
        }
    }

    impl PrivilegedHostSystem for FakeHost {
        fn identity(&mut self) -> Result<HostIdentity, BindingError> {
            self.state.borrow_mut().calls.push("identity");
            Ok(self.identity)
        }

        fn executor_unit_handoff(
            &mut self,
            binding: ExecutionBindingV1,
            _intent: JobIntentV2,
        ) -> Result<HostStepReceipt, BindingError> {
            self.receipt("executor", binding, 1)
        }

        fn runtime_descriptor_provider(
            &mut self,
            binding: ExecutionBindingV1,
        ) -> Result<HostStepReceipt, BindingError> {
            self.receipt("runtime", binding, 2)
        }

        fn materialization_input_provider(
            &mut self,
            binding: ExecutionBindingV1,
            _intent: JobIntentV2,
        ) -> Result<HostStepReceipt, BindingError> {
            self.receipt("materialize", binding, 3)
        }

        fn proxy_input_and_lease_provider(
            &mut self,
            binding: ExecutionBindingV1,
        ) -> Result<HostStepReceipt, BindingError> {
            self.receipt("proxy", binding, 4)
        }

        fn terminal_evidence_collector(
            &mut self,
            binding: ExecutionBindingV1,
            claimed_evidence_digest: [u8; 32],
        ) -> Result<HostStepReceipt, BindingError> {
            let mut receipt = self.receipt("terminal", binding, 5)?;
            receipt.receipt_digest = claimed_evidence_digest;
            Ok(receipt)
        }

        fn teardown_provider(
            &mut self,
            binding: ExecutionBindingV1,
            _reason: HostStopReason,
        ) -> Result<HostTerminalReceipt, BindingError> {
            self.state.borrow_mut().calls.push("teardown");
            Ok(HostTerminalReceipt {
                execution_binding_digest: binding.execution_binding_digest,
                conclusion: Conclusion::Success,
                evidence_set_digest: [7; 32],
                teardown_digest: [8; 32],
            })
        }

        fn crash_recovery_coordinator(
            &mut self,
            binding: ExecutionBindingV1,
            _phase: BindingPhase,
        ) -> Result<HostRecoveryReceipt, BindingError> {
            self.state.borrow_mut().calls.push("recover");
            Ok(self
                .state
                .borrow()
                .recovery
                .unwrap_or(HostRecoveryReceipt::CapacityReturned(HostTerminalReceipt {
                    execution_binding_digest: binding.execution_binding_digest,
                    conclusion: Conclusion::InfrastructureFailure,
                    evidence_set_digest: [9; 32],
                    teardown_digest: [10; 32],
                })))
        }

        fn sealed_attempt_evidence(
            &mut self,
            _binding: ExecutionBindingV1,
        ) -> Result<Vec<HostEvidenceItem>, BindingError> {
            self.state.borrow_mut().calls.push("evidence_export");
            Ok(self.state.borrow().evidence.clone())
        }
    }

    fn signing_key() -> Keypair {
        let secret = SecretKey::from_slice(&[44; 32]).unwrap();
        Keypair::from_secret_key(SECP256K1, &secret)
    }

    fn manifest(key: &Keypair) -> LaneActivationManifestV1 {
        LaneActivationManifestV1 {
            schema_version: 1,
            lane_id: [1; 32],
            lane_epoch: 4,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_verifying_key: key.x_only_public_key().0.serialize(),
            admission_key_generation: 9,
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
            isolation_profile_digest: [5; 32],
            not_before: 1,
            expires_at: 1_000,
            max_wall_timeout_seconds: 100,
        }
    }

    fn intent_for(lane: LaneActivationManifestV1) -> JobIntentV2 {
        JobIntentV2 {
            schema_version: 2,
            signed_request_digest: [10; 32],
            actor_pubkey: [11; 32],
            audience_digest: [12; 32],
            idempotency_digest: [13; 32],
            source_pin_event_id: [14; 32],
            workflow_digest: [15; 32],
            isolation_profile_digest: [5; 32],
            lane_manifest_digest: lane.digest(),
            lane_epoch: lane.lane_epoch,
            admission_signature_algorithm: lane.admission_signature_algorithm,
            admission_key_generation: lane.admission_key_generation,
            run_id: [16; 16],
            tip_oid: GitOid::Sha256([17; 32]),
            base_oid: GitOid::Sha256([18; 32]),
            issued_at: 10,
            expires_at: 200,
            wall_timeout_seconds: 50,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            request_event_id: [10; 32],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
            artifact_count: 0,
            artifacts: [None],
        }
    }

    fn request(
        key: &Keypair,
        lane: LaneActivationManifestV1,
        job: JobIntentV2,
    ) -> AdmitAttemptRequest {
        let mut request = AdmitAttemptRequest {
            signed_request_digest: job.signed_request_digest,
            actor_pubkey: job.actor_pubkey,
            audience_digest: job.audience_digest,
            idempotency_digest: job.idempotency_digest,
            source_pin_event_id: job.source_pin_event_id,
            workflow_digest: job.workflow_digest,
            job_intent_digest: job.digest(),
            isolation_profile_digest: job.isolation_profile_digest,
            lane_manifest_digest: lane.digest(),
            admission_signature: [1; 64],
            run_id: job.run_id,
            tip_oid: job.tip_oid,
            base_oid: job.base_oid,
            issued_at: job.issued_at,
            expires_at: job.expires_at,
            lane_epoch: lane.lane_epoch,
            admission_key_generation: lane.admission_key_generation,
            wall_timeout_seconds: job.wall_timeout_seconds,
            attempt: job.attempt,
            parent_attempt: job.parent_attempt,
            trust_class: job.trust_class,
            admission_signature_algorithm: lane.admission_signature_algorithm,
        };
        let digest = sha256(&admission_signature_message(&request));
        request.admission_signature = SECP256K1
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), key)
            .serialize();
        request
    }

    fn request_for(key: &Keypair) -> AdmitAttemptRequest {
        let lane = manifest(key);
        request(key, lane, intent_for(lane))
    }

    fn registration(
        admission: AdmitAttemptRequest,
        intent: JobIntentV2,
        request_id: [u8; 16],
    ) -> (FrameHeader, RegisterJobIntentRequest) {
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::RegisterJobIntent,
            request_id,
        };
        let mut value = RegisterJobIntentRequest {
            admission,
            request_event_id: intent.request_event_id,
            workflow_id: intent.workflow_id,
            job_id: intent.job_id,
            artifact_count: intent.artifact_count,
            artifacts: intent.artifacts.map(|artifact| {
                artifact.map(
                    |artifact| buzz_ci_broker_protocol::v2::JobArtifactDeclaration {
                        artifact_id: artifact.artifact_id,
                        name: artifact.name,
                        media_type: artifact.media_type,
                        relative_name: artifact.relative_name,
                        max_bytes: artifact.max_bytes,
                    },
                )
            }),
            request_frame_digest: [1; 32],
        };
        value.request_frame_digest =
            intent_registration_request_frame_digest(header, &value).unwrap();
        (header, value)
    }

    #[test]
    fn sealed_evidence_export_is_chunked_replay_bound_and_attempt_exact() {
        use buzz_ci_broker_protocol::v2::{
            decode_evidence_chunk_response, decode_evidence_description_response,
            evidence_request_frame_digest, AttemptEvidenceCoordinates,
            DescribeAttemptEvidenceRequest, EvidenceDescriptor, EvidenceKind,
            ReadAttemptEvidenceRequest,
        };

        let key = signing_key();
        let lane = manifest(&key);
        let intent = intent_for(lane);
        let admission = request(&key, lane, intent);
        let binding = ExecutionBindingV1::create(admission, intent, 20).unwrap();
        let stdout = vec![b'x'; 5_000];
        let teardown = b"sealed teardown attestation".to_vec();
        let stdout_digest = sha256(&stdout);
        let teardown_digest = sha256(&teardown);
        let evidence = vec![
            HostEvidenceItem {
                descriptor: EvidenceDescriptor {
                    kind: EvidenceKind::Stdout,
                    digest: stdout_digest,
                    length: stdout.len() as u32,
                    artifact_name_digest: [0; 32],
                    artifact_media_type_digest: [0; 32],
                    artifact_id: WireText64::EMPTY,
                    artifact_name: WireText64::EMPTY,
                    artifact_media_type: WireText64::EMPTY,
                    teardown_lease_id: [0; 16],
                    teardown_lease_generation: 0,
                    teardown_attestation_digest: [0; 32],
                },
                bytes: stdout.clone(),
            },
            HostEvidenceItem {
                descriptor: EvidenceDescriptor {
                    kind: EvidenceKind::Teardown,
                    digest: teardown_digest,
                    length: teardown.len() as u32,
                    artifact_name_digest: [0; 32],
                    artifact_media_type_digest: [0; 32],
                    artifact_id: WireText64::EMPTY,
                    artifact_name: WireText64::EMPTY,
                    artifact_media_type: WireText64::EMPTY,
                    teardown_lease_id: binding.lease_id,
                    teardown_lease_generation: binding.lease_generation,
                    teardown_attestation_digest: teardown_digest,
                },
                bytes: teardown,
            },
        ];
        let state = Rc::new(RefCell::new(HostState {
            evidence,
            ..HostState::default()
        }));
        let host = FakeHost {
            state,
            identity: HostIdentity {
                broker_build_identity: lane.broker_build_identity,
                host_profile_digest: lane.host_profile_digest,
                suite_identity: lane.suite_identity,
            },
        };
        let mut intents = StaticJobIntents::default();
        intents.insert(request(&key, lane, intent), intent).unwrap();
        let mut journal = MemoryExecutionBindingJournal::default();
        let record = ExecutionBindingRecord {
            binding,
            phase: BindingPhase::CapacityReturned,
            generation: 4,
            updated_at: 30,
            conclusion: Conclusion::Success,
            host_receipt_digest: [21; 32],
            evidence_set_digest: stdout_digest,
            teardown_digest,
        };
        assert_eq!(journal.insert(record).unwrap(), JournalWrite::Written);
        let mut controller = ProductionBindingController::new(
            StaticLaneManifest::new(lane),
            intents,
            journal,
            host,
            TIME_REFERENCE,
        );
        controller.recovery_complete = true;
        let coordinates = AttemptEvidenceCoordinates {
            signed_request_digest: binding.signed_request_digest,
            run_id: binding.run_id,
            workflow_digest: intent.workflow_digest,
            job_intent_digest: binding.job_intent_digest,
            attempt: binding.attempt,
            attempt_id: binding.attempt_id,
            execution_binding_digest: binding.execution_binding_digest,
            expected_generation: record.generation,
            request_event_id: binding.request_event_id,
            workflow_id: binding.workflow_id,
            job_id: binding.job_id,
        };

        let describe_header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::DescribeAttemptEvidence,
            request_id: [31; 16],
        };
        let mut describe = DescribeAttemptEvidenceRequest {
            coordinates,
            idempotency_digest: binding.idempotency_digest,
            request_frame_digest: [1; 32],
        };
        describe.request_frame_digest = evidence_request_frame_digest(
            describe_header,
            &Request::DescribeAttemptEvidence(describe),
        )
        .unwrap();
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            describe_header,
            Request::DescribeAttemptEvidence(describe),
            31,
        );
        let described =
            decode_evidence_description_response(describe_header, encoded.as_bytes()).unwrap();
        assert_eq!(described.code, ResponseCode::Ok);
        assert_eq!(described.item_count, 2);
        assert_eq!(described.items[0].unwrap().digest, stdout_digest);
        assert_eq!(
            described.items[1].unwrap().teardown_lease_id,
            binding.lease_id
        );

        let read_header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::ReadAttemptEvidence,
            request_id: [32; 16],
        };
        let mut read = ReadAttemptEvidenceRequest {
            coordinates,
            idempotency_digest: binding.idempotency_digest,
            request_frame_digest: [1; 32],
            kind: EvidenceKind::Stdout,
            item_index: 0,
            descriptor_digest: stdout_digest,
            offset: 1_000,
            max_length: MAX_EVIDENCE_CHUNK_SIZE as u32,
        };
        read.request_frame_digest =
            evidence_request_frame_digest(read_header, &Request::ReadAttemptEvidence(read))
                .unwrap();
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            read_header,
            Request::ReadAttemptEvidence(read),
            32,
        );
        let chunk = decode_evidence_chunk_response(read_header, encoded.as_bytes()).unwrap();
        assert_eq!(chunk.code, ResponseCode::Ok);
        assert_eq!(chunk.bytes.len(), 4_000);
        assert_eq!(chunk.total_length, 5_000);

        let mut stale = describe;
        stale.coordinates.expected_generation -= 1;
        stale.request_frame_digest = evidence_request_frame_digest(
            describe_header,
            &Request::DescribeAttemptEvidence(stale),
        )
        .unwrap();
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            describe_header,
            Request::DescribeAttemptEvidence(stale),
            33,
        );
        assert_eq!(
            decode_evidence_description_response(describe_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::StateConflict
        );

        let mut mixed = describe;
        mixed.coordinates.job_id = WireText64::from_ascii("other-job").unwrap();
        mixed.request_frame_digest = evidence_request_frame_digest(
            describe_header,
            &Request::DescribeAttemptEvidence(mixed),
        )
        .unwrap();
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            describe_header,
            Request::DescribeAttemptEvidence(mixed),
            33,
        );
        assert_eq!(
            decode_evidence_description_response(describe_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::StateConflict
        );

        let mut hostile = describe;
        hostile.coordinates.run_id[0] ^= 1;
        hostile.request_frame_digest[0] ^= 1;
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            describe_header,
            Request::DescribeAttemptEvidence(hostile),
            34,
        );
        assert_eq!(
            decode_evidence_description_response(describe_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::ReplayConflict
        );

        controller
            .journal
            .records
            .get_mut(&binding.attempt_id)
            .unwrap()
            .phase = BindingPhase::Running;
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            describe_header,
            Request::DescribeAttemptEvidence(describe),
            35,
        );
        assert_eq!(
            decode_evidence_description_response(describe_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::StateConflict
        );
    }

    type Controller = ProductionBindingController<
        StaticLaneManifest,
        StaticJobIntents,
        MemoryExecutionBindingJournal,
        FakeHost,
    >;

    fn controller() -> (Controller, Keypair, Rc<RefCell<HostState>>) {
        controller_with_preseed(true)
    }

    fn controller_with_preseed(preseed: bool) -> (Controller, Keypair, Rc<RefCell<HostState>>) {
        let key = signing_key();
        let manifest = manifest(&key);
        let job = intent_for(manifest);
        let mut intents = StaticJobIntents::default();
        if preseed {
            intents.insert(request(&key, manifest, job), job).unwrap();
        }
        let state = Rc::new(RefCell::new(HostState::default()));
        let host = FakeHost {
            state: Rc::clone(&state),
            identity: HostIdentity {
                broker_build_identity: manifest.broker_build_identity,
                host_profile_digest: manifest.host_profile_digest,
                suite_identity: manifest.suite_identity,
            },
        };
        let mut controller = ProductionBindingController::new(
            StaticLaneManifest::new(manifest),
            intents,
            MemoryExecutionBindingJournal::default(),
            host,
            TIME_REFERENCE,
        );
        controller.recover_open(10).unwrap();
        (controller, key, state)
    }

    fn header(operation: buzz_ci_broker_protocol::Operation) -> FrameHeader {
        FrameHeader {
            operation,
            request_id: [99; 16],
        }
    }

    /// H8 clean host, diagnostic boots 3 and 4: execd compared the frozen
    /// fixture's window with its wall clock, so RegisterJobIntent was refused
    /// eight minutes after materialization (expired) and, with the reference
    /// stamped ahead of the clock, before it (issued in the future). Windows
    /// are judged against the package time reference alone; the wall clock only
    /// stamps the record, and the two failures answer their own codes.
    #[test]
    fn windows_are_judged_against_the_package_time_reference_not_the_clock() {
        let (mut admitted, key, state) = controller();
        let lane = manifest(&key);
        let job = intent_for(lane);
        let request = request(&key, lane, job);
        let admit = header(buzz_ci_broker_protocol::Operation::AdmitAttempt);
        // The wall clock sits far beyond expires_at 200; the reference (20) is
        // inside the window, so the admission proceeds and the deadline is
        // bounded by the window length, not by the absolute expiry.
        let response = admitted.dispatch(admit, Request::AdmitAttempt(request), 5_000);
        assert_eq!(response.code, ResponseCode::Ok);
        assert_eq!(response.broker_state, BrokerState::Leased);
        assert_eq!(
            state.borrow().calls,
            ["identity", "executor", "runtime", "materialize", "proxy"]
        );
        let (mut early_clock, key, _) = controller();
        let response = early_clock.dispatch(admit, Request::AdmitAttempt(request_for(&key)), 1);
        assert_eq!(response.code, ResponseCode::Ok);

        let (mut expired, key, state) = controller();
        expired.time_reference = 200;
        let response = expired.dispatch(admit, Request::AdmitAttempt(request_for(&key)), 20);
        assert_eq!(response.code, ResponseCode::ExpiredAtTimeReference);
        assert_eq!(state.borrow().calls, ["identity"]);

        let (mut future, key, state) = controller();
        future.time_reference = 9;
        let response = future.dispatch(admit, Request::AdmitAttempt(request_for(&key)), 20);
        assert_eq!(response.code, ResponseCode::IssuedAfterTimeReference);
        assert_eq!(state.borrow().calls, ["identity"]);

        let (mut lane_closed, key, _) = controller();
        lane_closed.time_reference = 1_000;
        let response = lane_closed.dispatch(admit, Request::AdmitAttempt(request_for(&key)), 20);
        assert_eq!(response.code, ResponseCode::ExpiredAtTimeReference);

        assert_eq!(validate_window(10, 200, 10), Ok(()));
        assert_eq!(validate_window(10, 200, 199), Ok(()));
        assert_eq!(
            validate_window(10, 200, 200),
            Err(BindingError::ExpiredAtTimeReference)
        );
        assert_eq!(
            validate_window(10, 200, 9),
            Err(BindingError::IssuedAfterTimeReference)
        );
        assert_eq!(
            error_code(BindingError::IssuedAfterTimeReference),
            ResponseCode::IssuedAfterTimeReference
        );
        assert_eq!(
            error_code(BindingError::ExpiredAtTimeReference),
            ResponseCode::ExpiredAtTimeReference
        );
    }

    #[test]
    fn admission_binds_manifest_intent_signature_and_all_start_seams() {
        let (mut controller, key, state) = controller();
        let lane = manifest(&key);
        let job = intent_for(lane);
        let request = request(&key, lane, job);
        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request),
            20,
        );
        assert_eq!(response.code, ResponseCode::Ok);
        assert_ne!(response.execution_binding_digest, [0; 32]);
        assert_eq!(response.job_intent_digest, job.digest());
        assert_eq!(response.broker_state, BrokerState::Leased);
        assert_eq!(
            state.borrow().calls,
            ["identity", "executor", "runtime", "materialize", "proxy"]
        );
    }

    #[test]
    fn authenticated_registration_is_create_once_replay_bound_and_required_for_admission() {
        use buzz_ci_broker_protocol::v2::decode_intent_registration_response;

        let (mut controller, key, state) = controller_with_preseed(false);
        let lane = manifest(&key);
        let intent = intent_for(lane);
        let admission = request(&key, lane, intent);

        let absent = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(admission),
            20,
        );
        assert_eq!(absent.code, ResponseCode::PolicyDenied);
        assert_eq!(state.borrow().calls, ["identity"]);

        let (register_header, register) = registration(admission, intent, [41; 16]);
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            register_header,
            Request::RegisterJobIntent(register),
            20,
        );
        let written =
            decode_intent_registration_response(register_header, encoded.as_bytes()).unwrap();
        assert_eq!(written.code, ResponseCode::Ok);
        assert_eq!(written.job_intent_digest, admission.job_intent_digest);
        assert_eq!(written.request_frame_digest, register.request_frame_digest);
        assert_eq!(
            written.admission_message_digest,
            sha256(&admission_signature_message(&admission))
        );
        assert_eq!(
            written.registration_key_digest,
            intent_registration_key_digest_for_admission(admission)
        );

        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            register_header,
            Request::RegisterJobIntent(register),
            20,
        );
        assert_eq!(
            decode_intent_registration_response(register_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::Existing
        );

        let (new_frame_header, new_frame) = registration(admission, intent, [44; 16]);
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            new_frame_header,
            Request::RegisterJobIntent(new_frame),
            20,
        );
        assert_eq!(
            decode_intent_registration_response(new_frame_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::ReplayConflict
        );

        let mut bad_frame = register;
        bad_frame.request_frame_digest[0] ^= 1;
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            register_header,
            Request::RegisterJobIntent(bad_frame),
            20,
        );
        assert_eq!(
            decode_intent_registration_response(register_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::BadFrame
        );

        let mut other_intent = intent;
        other_intent.job_id = WireText64::from_ascii("other-job").unwrap();
        let other_admission = request(&key, lane, other_intent);
        let (other_header, other_register) = registration(other_admission, other_intent, [42; 16]);
        let encoded = crate::control::ControlDispatch::dispatch_v2_encoded(
            &mut controller,
            other_header,
            Request::RegisterJobIntent(other_register),
            20,
        );
        assert_eq!(
            decode_intent_registration_response(other_header, encoded.as_bytes())
                .unwrap()
                .code,
            ResponseCode::ReplayConflict
        );

        let admitted = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(admission),
            20,
        );
        assert_eq!(admitted.code, ResponseCode::Ok);
        assert_eq!(admitted.job_intent_digest, intent.digest());
    }

    #[test]
    fn fresh_controller_stays_reconciling_until_startup_recovery_completes() {
        let key = signing_key();
        let manifest = manifest(&key);
        let job = intent_for(manifest);
        let mut intents = StaticJobIntents::default();
        intents.insert(request(&key, manifest, job), job).unwrap();
        let state = Rc::new(RefCell::new(HostState::default()));
        let host = FakeHost {
            state: Rc::clone(&state),
            identity: HostIdentity {
                broker_build_identity: manifest.broker_build_identity,
                host_profile_digest: manifest.host_profile_digest,
                suite_identity: manifest.suite_identity,
            },
        };
        let mut controller = ProductionBindingController::new(
            StaticLaneManifest::new(manifest),
            intents,
            MemoryExecutionBindingJournal::default(),
            host,
            TIME_REFERENCE,
        );

        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request(&key, manifest, job)),
            20,
        );

        assert_eq!(response.code, ResponseCode::Reconciling);
        assert!(state.borrow().calls.is_empty());
        assert!(controller.journal.list().unwrap().is_empty());
    }

    #[test]
    fn replay_is_idempotent_but_any_signed_coordinate_drift_is_refused() {
        let (mut controller, key, state) = controller();
        let request = request_for(&key);
        let first = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request),
            20,
        );
        let replay = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request),
            21,
        );
        assert_eq!(replay.code, ResponseCode::Existing);
        assert_eq!(
            replay.execution_binding_digest,
            first.execution_binding_digest
        );
        assert_eq!(state.borrow().calls.len(), 5);

        let mut drift = request;
        drift.workflow_digest[0] ^= 1;
        assert_eq!(
            controller
                .dispatch(
                    header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
                    Request::AdmitAttempt(drift),
                    22,
                )
                .code,
            ResponseCode::ReplayConflict
        );
    }

    #[test]
    fn host_failure_quarantines_and_never_reports_a_lease() {
        let (mut controller, key, state) = controller();
        {
            let mut state = state.borrow_mut();
            state.refuse_at = Some("materialize");
            state.recovery = Some(HostRecoveryReceipt::Quarantine);
        }
        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        assert_eq!(response.code, ResponseCode::InternalFailure);
        let record = controller.journal.list().unwrap().pop().unwrap();
        assert_eq!(record.phase, BindingPhase::Quarantined);
        assert_ne!(record.binding.execution_binding_digest, [0; 32]);
    }

    #[test]
    fn partial_start_failure_runs_recovery_before_capacity_can_return() {
        let (mut controller, key, state) = controller();
        state.borrow_mut().refuse_at = Some("proxy");
        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        assert_eq!(response.code, ResponseCode::InternalFailure);
        let record = controller.journal.list().unwrap().pop().unwrap();
        assert_eq!(record.phase, BindingPhase::CapacityReturned);
        assert_eq!(state.borrow().calls.last(), Some(&"recover"));
    }

    #[test]
    fn quarantined_binding_keeps_capacity_closed() {
        let (mut controller, key, state) = controller();
        {
            let mut host = state.borrow_mut();
            host.refuse_at = Some("materialize");
            host.recovery = Some(HostRecoveryReceipt::Quarantine);
        }
        let first = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        assert_eq!(first.code, ResponseCode::InternalFailure);

        state.borrow_mut().refuse_at = None;
        let lane = manifest(&key);
        let mut second_intent = intent_for(lane);
        second_intent.idempotency_digest = [71; 32];
        second_intent.run_id = [72; 16];
        controller
            .intents
            .insert(request(&key, manifest(&key), second_intent), second_intent)
            .unwrap();
        let second = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request(&key, manifest(&key), second_intent)),
            21,
        );
        assert_eq!(second.code, ResponseCode::NoCapacity);
        assert_eq!(
            state
                .borrow()
                .calls
                .iter()
                .filter(|call| **call == "executor")
                .count(),
            1
        );
    }

    #[test]
    fn completion_requires_the_exact_binding_and_closes_capacity_in_order() {
        let (mut controller, key, state) = controller();
        let admitted = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        let record = controller.journal.list().unwrap()[0];
        let complete = CompleteAttemptRequest {
            signer_pubkey: record.binding.actor_pubkey,
            signed_request_digest: record.binding.signed_request_digest,
            run_id: record.binding.run_id,
            attempt: record.binding.attempt,
            lease_id: record.binding.lease_id,
            lease_generation: record.binding.lease_generation,
            execution_binding_digest: admitted.execution_binding_digest,
            advisory_conclusion: Conclusion::Failure,
            evidence_set_digest: [7; 32],
            terminal_at: 25,
        };
        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::CompleteAttempt),
            Request::CompleteAttempt(complete),
            25,
        );
        assert_eq!(response.code, ResponseCode::Ok);
        assert_eq!(response.broker_state, BrokerState::Terminal);
        assert_eq!(response.conclusion, Conclusion::Success);
        assert_eq!(
            controller.journal.list().unwrap()[0].phase,
            BindingPhase::CapacityReturned
        );
        assert!(state.borrow().calls.ends_with(&["terminal", "teardown"]));
    }

    #[test]
    fn every_post_admission_operation_refuses_a_binding_digest_mismatch() {
        let (mut controller, key, state) = controller();
        controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        let record = controller.journal.list().unwrap()[0];
        let wrong_digest = [99; 32];

        let get = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::GetAttempt),
            Request::GetAttempt(GetAttemptRequest {
                attempt_id: record.binding.attempt_id,
                execution_binding_digest: wrong_digest,
            }),
            21,
        );
        let cancel = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::CancelAttempt),
            Request::CancelAttempt(CancelAttemptRequest {
                attempt_id: record.binding.attempt_id,
                execution_binding_digest: wrong_digest,
                actor_pubkey: record.binding.actor_pubkey,
                cancel_digest: [98; 32],
                issued_at: 21,
                expires_at: 40,
                expected_generation: record.generation,
                reason: buzz_ci_broker_protocol::CancelReason::UserRequest,
            }),
            21,
        );
        let complete = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::CompleteAttempt),
            Request::CompleteAttempt(CompleteAttemptRequest {
                signer_pubkey: record.binding.actor_pubkey,
                signed_request_digest: record.binding.signed_request_digest,
                run_id: record.binding.run_id,
                attempt: record.binding.attempt,
                lease_id: record.binding.lease_id,
                lease_generation: record.binding.lease_generation,
                execution_binding_digest: wrong_digest,
                advisory_conclusion: Conclusion::Success,
                evidence_set_digest: [7; 32],
                terminal_at: 21,
            }),
            21,
        );

        assert_eq!(get.code, ResponseCode::ReplayConflict);
        assert_eq!(cancel.code, ResponseCode::ReplayConflict);
        assert_eq!(complete.code, ResponseCode::ReplayConflict);
        assert_eq!(state.borrow().calls.len(), 5);
        assert_eq!(controller.journal.list().unwrap()[0], record);
    }

    #[test]
    fn restart_recovery_reuses_the_binding_and_never_reruns_start() {
        let (mut first_process, key, state) = controller();
        let admitted = first_process.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        let ProductionBindingController {
            manifests,
            intents,
            journal,
            host,
            recovery_complete: _,
            time_reference,
        } = first_process;
        let mut restarted = ProductionBindingController {
            manifests,
            intents,
            journal,
            host,
            recovery_complete: false,
            time_reference,
        };
        restarted.recover_open(30).unwrap();
        let record = restarted.journal.list().unwrap()[0];
        assert_eq!(record.phase, BindingPhase::CapacityReturned);
        assert_eq!(
            record.binding.execution_binding_digest,
            admitted.execution_binding_digest
        );
        assert_eq!(
            state
                .borrow()
                .calls
                .iter()
                .filter(|call| **call == "executor")
                .count(),
            1
        );
        assert_eq!(state.borrow().calls.last(), Some(&"recover"));
    }

    #[test]
    fn ambiguous_restart_recovery_quarantines_the_exact_binding() {
        let (mut first_process, key, state) = controller();
        let admitted = first_process.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        state.borrow_mut().recovery = Some(HostRecoveryReceipt::Quarantine);
        let ProductionBindingController {
            manifests,
            intents,
            journal,
            host,
            recovery_complete: _,
            time_reference,
        } = first_process;
        let mut restarted = ProductionBindingController {
            manifests,
            intents,
            journal,
            host,
            recovery_complete: false,
            time_reference,
        };

        restarted.recover_open(30).unwrap();

        let record = restarted.journal.list().unwrap()[0];
        assert_eq!(record.phase, BindingPhase::Quarantined);
        assert_eq!(
            record.binding.execution_binding_digest,
            admitted.execution_binding_digest
        );
        assert_eq!(record.conclusion, Conclusion::InfrastructureFailure);
    }

    #[test]
    fn lifecycle_refuses_skips_and_terminal_reentry_without_mutation() {
        let key = signing_key();
        let lane = manifest(&key);
        let intent = intent_for(lane);
        let request = request(&key, lane, intent);
        let binding = ExecutionBindingV1::create(request, intent, 20).unwrap();
        let mut record = ExecutionBindingRecord::admitted(binding, 20);
        let admitted = record;
        assert_eq!(
            record.advance(BindingPhase::Terminal, 21),
            Err(BindingError::StateConflict)
        );
        assert_eq!(record, admitted);

        record.advance(BindingPhase::Running, 21).unwrap();
        record.advance(BindingPhase::Terminal, 22).unwrap();
        record.advance(BindingPhase::CapacityReturned, 23).unwrap();
        let returned = record;
        assert_eq!(
            record.advance(BindingPhase::Running, 24),
            Err(BindingError::StateConflict)
        );
        assert_eq!(record, returned);
    }

    #[test]
    fn digest_identity_and_signature_mismatches_fail_before_host_mutation() {
        let (mut first_controller, key, state) = controller();
        let mut hostile_request = request_for(&key);
        hostile_request.job_intent_digest[0] ^= 1;
        hostile_request.admission_signature = SECP256K1
            .sign_schnorr_no_aux_rand(
                &Message::from_digest(sha256(&admission_signature_message(&hostile_request))),
                &key,
            )
            .serialize();
        let response = first_controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(hostile_request),
            20,
        );
        assert_eq!(response.code, ResponseCode::PolicyDenied);
        assert_eq!(state.borrow().calls, ["identity"]);

        let (mut second_controller, key, state) = controller();
        second_controller.host.system.identity.host_profile_digest[0] ^= 1;
        let response = second_controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(request_for(&key)),
            20,
        );
        assert_eq!(response.code, ResponseCode::PolicyDenied);
        assert_eq!(state.borrow().calls, ["identity"]);
    }

    #[test]
    fn admission_key_generation_mismatch_is_rejected_before_host_mutation() {
        let (mut controller, key, state) = controller();
        let mut hostile_request = request_for(&key);
        hostile_request.admission_key_generation += 1;
        hostile_request.admission_signature = SECP256K1
            .sign_schnorr_no_aux_rand(
                &Message::from_digest(sha256(&admission_signature_message(&hostile_request))),
                &key,
            )
            .serialize();

        let response = controller.dispatch(
            header(buzz_ci_broker_protocol::Operation::AdmitAttempt),
            Request::AdmitAttempt(hostile_request),
            20,
        );

        assert_eq!(response.code, ResponseCode::PolicyDenied);
        assert_eq!(state.borrow().calls, ["identity"]);
        assert!(controller.journal.list().unwrap().is_empty());
    }
}
