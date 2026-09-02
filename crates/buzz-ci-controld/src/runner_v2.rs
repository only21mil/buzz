//! Exact version-2 runner-control client.
//!
//! Controld sends only complete broker v2 frames to the authenticated runner
//! socket. The runner remains a transport proxy; no execd endpoint or local
//! evidence path is representable here.

use buzz_ci_broker_protocol::v2::{
    self, admission_signature_message, evidence_request_frame_digest,
    intent_registration_key_digest, intent_registration_request_frame_digest,
    AdmissionSignatureAlgorithm, AdmitAttemptRequest, AttemptEvidenceCoordinates,
    DescribeAttemptEvidenceRequest, EvidenceChunkResponse, EvidenceDescriptionResponse,
    FrameHeader, GetAttemptRequest, IntentRegistrationResponse, JobArtifactDeclaration,
    ReadAttemptEvidenceRequest, RegisterJobIntentRequest, Request, WireText64,
};
use buzz_ci_broker_protocol::{
    BrokerState, Conclusion, GitOid, ResponseCode, TrustClass, HEADER_SIZE,
};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use crate::production::AcceptedRequest;
use crate::runner_client::{UnixRunnerConnector, UnixRunnerConnectorError};

const REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:broker-request-id:v2\0";
const JOB_INTENT_SCHEMA_VERSION: u16 = 2;

/// Injectable exact-frame transport. Production uses the authenticated Unix
/// runner connector; tests may supply a network-free fake.
pub trait RunnerV2Transport {
    type Error;

    fn exchange_frame(
        &mut self,
        request: &[u8],
        response_length: usize,
        transport_attempts: u32,
    ) -> Result<Vec<u8>, Self::Error>;
}

impl RunnerV2Transport for UnixRunnerConnector {
    type Error = UnixRunnerConnectorError;

    fn exchange_frame(
        &mut self,
        request: &[u8],
        response_length: usize,
        transport_attempts: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        self.exchange_v2_frame(request, response_length, transport_attempts)
    }
}

/// Sanitized client failure with no frame or endpoint contents.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RunnerV2Error {
    #[error("runner v2 client configuration is invalid")]
    InvalidConfig,
    #[error("runner v2 request is invalid")]
    InvalidRequest,
    #[error("runner v2 transport failed")]
    Transport,
    #[error("runner v2 response is invalid")]
    InvalidResponse,
    #[error("runner v2 attempt did not become terminal before its deadline")]
    Deadline,
    #[error("runner v2 admission signing failed")]
    Signing,
}

/// Separate admission-signing seam. Production delegates to keyholder;
/// injected tests never need signer material.
pub trait AdmissionSigner {
    type Error;

    fn sign_admission(&mut self, request: &mut AdmitAttemptRequest) -> Result<(), Self::Error>;
}

impl AdmissionSigner for crate::keyholder::UnixKeyholderClient {
    type Error = crate::keyholder::KeyholderError;

    fn sign_admission(&mut self, request: &mut AdmitAttemptRequest) -> Result<(), Self::Error> {
        self.sign_admission_v2(request)
    }
}

/// Immutable activation bindings supplied only by the strict daemon config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticAdmissionBindings {
    pub audience_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub lane_manifest_digest: [u8; 32],
    pub lane_epoch: u64,
    pub admission_key_generation: u64,
    pub workflow_id: String,
    pub workflow_digest: [u8; 32],
    pub job_ids: Vec<String>,
    pub artifacts: Vec<StaticArtifactBinding>,
}

/// One exact artifact declaration included in the static JobIntentV2 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticArtifactBinding {
    pub artifact_id: String,
    pub name: String,
    pub media_type: String,
    pub relative_name: String,
    pub max_bytes: u32,
}

impl StaticAdmissionBindings {
    pub fn validate(&self) -> Result<(), RunnerV2Error> {
        let mut unique = std::collections::BTreeSet::new();
        if self.audience_digest == [0; 32]
            || self.isolation_profile_digest == [0; 32]
            || self.lane_manifest_digest == [0; 32]
            || self.workflow_digest == [0; 32]
            || self.lane_epoch == 0
            || self.admission_key_generation == 0
            || self.workflow_id.is_empty()
            || self.job_ids.len() != 1
            || self.artifacts.len() != 1
            || self
                .job_ids
                .iter()
                .any(|job| job.is_empty() || !unique.insert(job))
            || self.artifacts.iter().any(|artifact| {
                wire_artifact_text(&artifact.artifact_id).is_err()
                    || wire_artifact_text(&artifact.name).is_err()
                    || WireText64::from_ascii(&artifact.media_type).is_err()
                    || !artifact.media_type.contains('/')
                    || !artifact.media_type.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'.' | b'-')
                    })
                    || wire_artifact_text(&artifact.relative_name).is_err()
                    || artifact.max_bytes == 0
                    || artifact.max_bytes > 32 * 1024
            })
        {
            return Err(RunnerV2Error::InvalidConfig);
        }
        Ok(())
    }
}

/// Terminal execd binding used by evidence operations 7 and 8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalAttempt {
    pub admission: AdmitAttemptRequest,
    pub response: v2::BrokerResponse,
}

/// Validated leased-or-terminal binding returned immediately after admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAttempt {
    pub admission: AdmitAttemptRequest,
    pub response: v2::BrokerResponse,
}

impl BoundAttempt {
    /// The attempt's deadline as execd judges it: the admission time the
    /// broker recorded plus the lesser of the wall timeout and the frozen
    /// request window's length. The window itself is a package constant
    /// judged against the package time reference, never against the wall
    /// clock, so a retained package admits and completes on any host date.
    pub fn deadline_at(self) -> Result<u64, RunnerV2Error> {
        let window = self
            .admission
            .expires_at
            .checked_sub(self.admission.issued_at)
            .filter(|window| *window > 0)
            .ok_or(RunnerV2Error::InvalidRequest)?;
        self.response
            .accepted_at
            .checked_add(u64::from(self.admission.wall_timeout_seconds).min(window))
            .filter(|deadline| *deadline > self.response.accepted_at)
            .ok_or(RunnerV2Error::InvalidRequest)
    }
}

impl TerminalAttempt {
    pub fn evidence_coordinates(
        self,
        accepted: &AcceptedRequest,
        job_id: &str,
    ) -> Result<AttemptEvidenceCoordinates, RunnerV2Error> {
        if decode_array::<32>(&accepted.event_id)? != self.admission.signed_request_digest
            || decode_array::<32>(&accepted.envelope.workflow_digest)?
                != self.admission.workflow_digest
            || accepted.envelope.run_id != Uuid::from_bytes(self.admission.run_id).to_string()
            || accepted.envelope.attempt != self.admission.attempt
        {
            return Err(RunnerV2Error::InvalidRequest);
        }
        Ok(AttemptEvidenceCoordinates {
            signed_request_digest: self.admission.signed_request_digest,
            run_id: self.admission.run_id,
            workflow_digest: self.admission.workflow_digest,
            job_intent_digest: self.admission.job_intent_digest,
            attempt: self.admission.attempt,
            attempt_id: self.response.attempt_id,
            execution_binding_digest: self.response.execution_binding_digest,
            expected_generation: self.response.generation,
            request_event_id: decode_array(&accepted.event_id)?,
            workflow_id: WireText64::from_ascii(&accepted.envelope.workflow_id)
                .map_err(|_| RunnerV2Error::InvalidRequest)?,
            job_id: WireText64::from_ascii(job_id).map_err(|_| RunnerV2Error::InvalidRequest)?,
        })
    }
}

/// Exact runner v2 exchange client. Retry policy lives at the authenticated
/// connector and therefore always reuses the already encoded request bytes.
pub struct RunnerV2Client<T> {
    transport: T,
    transport_attempts: u32,
}

impl<T> RunnerV2Client<T>
where
    T: RunnerV2Transport,
{
    pub fn new(transport: T, transport_attempts: u32) -> Result<Self, RunnerV2Error> {
        if !(1..=8).contains(&transport_attempts) {
            return Err(RunnerV2Error::InvalidConfig);
        }
        Ok(Self {
            transport,
            transport_attempts,
        })
    }

    /// Exchange a normal v2 operation and decode only the fixed broker
    /// response shape.
    pub fn exchange(&mut self, request: Request) -> Result<v2::BrokerResponse, RunnerV2Error> {
        if matches!(
            request,
            Request::DescribeAttemptEvidence(_)
                | Request::ReadAttemptEvidence(_)
                | Request::RegisterJobIntent(_)
        ) {
            return Err(RunnerV2Error::InvalidRequest);
        }
        let header = deterministic_header(request);
        let frame = v2::encode_request(header.request_id, request);
        let response = self
            .transport
            .exchange_frame(
                frame.as_bytes(),
                HEADER_SIZE + v2::RESPONSE_BODY_SIZE,
                self.transport_attempts,
            )
            .map_err(|_| RunnerV2Error::Transport)?;
        v2::decode_response(header, &response).map_err(|_| RunnerV2Error::InvalidResponse)
    }

    /// Create-once register the exact JobIntentV2 preimage before admission.
    /// Transport retries reuse one immutable operation-9 frame.
    pub fn register_job_intent(
        &mut self,
        admission: AdmitAttemptRequest,
        accepted: &AcceptedRequest,
        bindings: &StaticAdmissionBindings,
    ) -> Result<IntentRegistrationResponse, RunnerV2Error> {
        let declared = bindings
            .artifacts
            .first()
            .ok_or(RunnerV2Error::InvalidRequest)?;
        if bindings.artifacts.len() != 1 || accepted.envelope.job_ids.len() != 1 {
            return Err(RunnerV2Error::InvalidRequest);
        }
        let mut request = RegisterJobIntentRequest {
            admission,
            request_event_id: decode_array(&accepted.event_id)?,
            workflow_id: WireText64::from_ascii(&bindings.workflow_id)
                .map_err(|_| RunnerV2Error::InvalidRequest)?,
            job_id: WireText64::from_ascii(&bindings.job_ids[0])
                .map_err(|_| RunnerV2Error::InvalidRequest)?,
            artifact_count: 1,
            artifacts: [Some(JobArtifactDeclaration {
                artifact_id: WireText64::from_ascii(&declared.artifact_id)
                    .map_err(|_| RunnerV2Error::InvalidRequest)?,
                name: WireText64::from_ascii(&declared.name)
                    .map_err(|_| RunnerV2Error::InvalidRequest)?,
                media_type: WireText64::from_ascii(&declared.media_type)
                    .map_err(|_| RunnerV2Error::InvalidRequest)?,
                relative_name: WireText64::from_ascii(&declared.relative_name)
                    .map_err(|_| RunnerV2Error::InvalidRequest)?,
                max_bytes: declared.max_bytes,
            })],
            request_frame_digest: [0; 32],
        };
        let header = deterministic_registration_header(request);
        request.request_frame_digest = intent_registration_request_frame_digest(header, &request)
            .ok_or(RunnerV2Error::InvalidRequest)?;
        let frame = v2::encode_request(header.request_id, Request::RegisterJobIntent(request));
        let response = self
            .transport
            .exchange_frame(
                frame.as_bytes(),
                HEADER_SIZE + v2::INTENT_REGISTRATION_RESPONSE_BODY_SIZE,
                self.transport_attempts,
            )
            .map_err(|_| RunnerV2Error::Transport)?;
        let response = v2::decode_intent_registration_response(header, &response)
            .map_err(|_| RunnerV2Error::InvalidResponse)?;
        let admission_message_digest: [u8; 32] =
            Sha256::digest(admission_signature_message(&admission)).into();
        if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
            || response.signed_request_digest != admission.signed_request_digest
            || response.job_intent_digest != admission.job_intent_digest
            || response.request_frame_digest != request.request_frame_digest
            || response.admission_message_digest != admission_message_digest
            || response.registration_key_digest != intent_registration_key_digest(&request)
            || response.lane_manifest_digest != admission.lane_manifest_digest
            || response.run_id != admission.run_id
            || response.lane_epoch != admission.lane_epoch
            || response.admission_key_generation != admission.admission_key_generation
            || response.issued_at != admission.issued_at
            || response.expires_at != admission.expires_at
            || response.attempt != admission.attempt
        {
            return Err(RunnerV2Error::InvalidResponse);
        }
        Ok(response)
    }

    /// Describe terminal evidence with a request digest that commits the
    /// deterministic request ID and every coordinate.
    pub fn describe(
        &mut self,
        mut request: DescribeAttemptEvidenceRequest,
    ) -> Result<EvidenceDescriptionResponse, RunnerV2Error> {
        request.request_frame_digest = [0; 32];
        let header = deterministic_header(Request::DescribeAttemptEvidence(request));
        request.request_frame_digest =
            evidence_request_frame_digest(header, &Request::DescribeAttemptEvidence(request))
                .ok_or(RunnerV2Error::InvalidRequest)?;
        let frame =
            v2::encode_request(header.request_id, Request::DescribeAttemptEvidence(request));
        let response = self
            .transport
            .exchange_frame(
                frame.as_bytes(),
                HEADER_SIZE + v2::EVIDENCE_DESCRIPTION_BODY_SIZE,
                self.transport_attempts,
            )
            .map_err(|_| RunnerV2Error::Transport)?;
        let response = v2::decode_evidence_description_response(header, &response)
            .map_err(|_| RunnerV2Error::InvalidResponse)?;
        if response.execution_binding_digest != request.coordinates.execution_binding_digest
            || response.generation != request.coordinates.expected_generation
            || response.request_frame_digest != request.request_frame_digest
            || response.request_event_id != request.coordinates.request_event_id
            || response.run_id != request.coordinates.run_id
            || response.workflow_id != request.coordinates.workflow_id
            || response.workflow_digest != request.coordinates.workflow_digest
            || response.job_id != request.coordinates.job_id
            || response.attempt != request.coordinates.attempt
        {
            return Err(RunnerV2Error::InvalidResponse);
        }
        Ok(response)
    }

    /// Read one bounded terminal evidence chunk. A response must echo the full
    /// descriptor selector and cannot exceed either requested bound.
    pub fn read(
        &mut self,
        mut request: ReadAttemptEvidenceRequest,
    ) -> Result<EvidenceChunkResponse, RunnerV2Error> {
        if request.max_length == 0 || request.max_length as usize > v2::MAX_EVIDENCE_CHUNK_SIZE {
            return Err(RunnerV2Error::InvalidRequest);
        }
        request.request_frame_digest = [0; 32];
        let header = deterministic_header(Request::ReadAttemptEvidence(request));
        request.request_frame_digest =
            evidence_request_frame_digest(header, &Request::ReadAttemptEvidence(request))
                .ok_or(RunnerV2Error::InvalidRequest)?;
        let frame = v2::encode_request(header.request_id, Request::ReadAttemptEvidence(request));
        let response = self
            .transport
            .exchange_frame(
                frame.as_bytes(),
                HEADER_SIZE + v2::EVIDENCE_CHUNK_BODY_SIZE,
                self.transport_attempts,
            )
            .map_err(|_| RunnerV2Error::Transport)?;
        let response = v2::decode_evidence_chunk_response(header, &response)
            .map_err(|_| RunnerV2Error::InvalidResponse)?;
        if response.execution_binding_digest != request.coordinates.execution_binding_digest
            || response.generation != request.coordinates.expected_generation
            || response.request_frame_digest != request.request_frame_digest
            || response.kind != request.kind
            || response.item_index != request.item_index
            || response.descriptor_digest != request.descriptor_digest
            || response.offset != request.offset
            || response.bytes.len() > request.max_length as usize
            || response.bytes.len() > v2::MAX_EVIDENCE_CHUNK_SIZE
            || response.offset > response.total_length
            || response.bytes.len() as u32 > response.total_length - response.offset
            || response.request_event_id != request.coordinates.request_event_id
            || response.run_id != request.coordinates.run_id
            || response.workflow_id != request.coordinates.workflow_id
            || response.workflow_digest != request.coordinates.workflow_digest
            || response.job_id != request.coordinates.job_id
            || response.attempt != request.coordinates.attempt
        {
            return Err(RunnerV2Error::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Admit one exact signed intent and reconcile the broker-owned binding to
    /// terminal state. Repeating this after restart sends the same admission
    /// and accepts only an exact Existing binding.
    pub fn admit_and_wait(
        &mut self,
        admission: AdmitAttemptRequest,
        poll_interval: Duration,
    ) -> Result<TerminalAttempt, RunnerV2Error> {
        let bound = self.admit(admission)?;
        self.wait_terminal(bound, poll_interval)
    }

    /// Admit once and return the exact durable binding without waiting for a
    /// terminal result. This is the only seam used by controld cancellation.
    pub fn admit(&mut self, admission: AdmitAttemptRequest) -> Result<BoundAttempt, RunnerV2Error> {
        let response = self.exchange(Request::AdmitAttempt(admission))?;
        validate_bound_response(admission, response)?;
        Ok(BoundAttempt {
            admission,
            response,
        })
    }

    /// Reconcile one already validated binding to a terminal state.
    pub fn wait_terminal(
        &mut self,
        bound: BoundAttempt,
        poll_interval: Duration,
    ) -> Result<TerminalAttempt, RunnerV2Error> {
        if poll_interval.is_zero() || poll_interval > Duration::from_secs(60) {
            return Err(RunnerV2Error::InvalidConfig);
        }
        let admission = bound.admission;
        let deadline_at = bound.deadline_at()?;
        let mut response = bound.response;
        loop {
            if response.broker_state == BrokerState::Terminal {
                return Ok(TerminalAttempt {
                    admission,
                    response,
                });
            }
            let now = live_bound_now()?;
            if now >= deadline_at {
                return Err(RunnerV2Error::Deadline);
            }
            let remaining = Duration::from_secs(deadline_at - now);
            thread::sleep(poll_interval.min(remaining));
            response = self.exchange(Request::GetAttempt(GetAttemptRequest {
                attempt_id: response.attempt_id,
                execution_binding_digest: response.execution_binding_digest,
            }))?;
            validate_bound_response(admission, response)?;
        }
    }

    /// Send one exact cancellation request. The service validates the returned
    /// terminal response against the durable admitted binding.
    pub fn cancel(
        &mut self,
        request: v2::CancelAttemptRequest,
    ) -> Result<v2::BrokerResponse, RunnerV2Error> {
        self.exchange(Request::CancelAttempt(request))
    }
}

/// Construct the exact JobIntentV2, bind it to one accepted request, and ask
/// only the configured keyholder manifest selector to sign the admission.
pub fn prepare_signed_admission(
    accepted: &AcceptedRequest,
    bindings: &StaticAdmissionBindings,
    signer: &mut impl AdmissionSigner,
) -> Result<AdmitAttemptRequest, RunnerV2Error> {
    bindings.validate()?;
    let request = &accepted.envelope;
    request
        .validate()
        .map_err(|_| RunnerV2Error::InvalidRequest)?;
    if request.workflow_id != bindings.workflow_id
        || decode_array::<32>(&request.workflow_digest)? != bindings.workflow_digest
        || request.job_ids != bindings.job_ids
    {
        return Err(RunnerV2Error::InvalidRequest);
    }
    let idempotency =
        Uuid::parse_str(&request.idempotency_key).map_err(|_| RunnerV2Error::InvalidRequest)?;
    let run_id = Uuid::parse_str(&request.run_id).map_err(|_| RunnerV2Error::InvalidRequest)?;
    let timeout =
        u32::try_from(request.timeout_seconds).map_err(|_| RunnerV2Error::InvalidRequest)?;
    let mut admission = AdmitAttemptRequest {
        signed_request_digest: decode_array(&accepted.event_id)?,
        actor_pubkey: decode_array(&request.actor)?,
        audience_digest: bindings.audience_digest,
        idempotency_digest: Sha256::digest(idempotency.as_bytes()).into(),
        source_pin_event_id: decode_array(&request.trigger_event_id)?,
        workflow_digest: bindings.workflow_digest,
        job_intent_digest: [0; 32],
        isolation_profile_digest: bindings.isolation_profile_digest,
        lane_manifest_digest: bindings.lane_manifest_digest,
        admission_signature: [0; 64],
        run_id: *run_id.as_bytes(),
        tip_oid: parse_oid(&request.tip_oid)?,
        base_oid: parse_oid(&request.base_oid)?,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        lane_epoch: bindings.lane_epoch,
        admission_key_generation: bindings.admission_key_generation,
        wall_timeout_seconds: timeout,
        attempt: request.attempt,
        parent_attempt: request.parent_attempt.unwrap_or(0),
        trust_class: TrustClass::AcceptedReviewed,
        admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
    };
    admission.job_intent_digest = job_intent_digest(admission, accepted, bindings)?;
    signer
        .sign_admission(&mut admission)
        .map_err(|_| RunnerV2Error::Signing)?;
    if admission.admission_signature == [0; 64]
        || admission.job_intent_digest != job_intent_digest(admission, accepted, bindings)?
    {
        return Err(RunnerV2Error::Signing);
    }
    Ok(admission)
}

fn validate_bound_response(
    admission: AdmitAttemptRequest,
    response: v2::BrokerResponse,
) -> Result<(), RunnerV2Error> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        || response.attempt_id == [0; 16]
        || response.run_id != admission.run_id
        || response.accepted_request_digest != admission.signed_request_digest
        || response.job_intent_digest != admission.job_intent_digest
        || response.execution_binding_digest == [0; 32]
        || response.tip_oid != Some(admission.tip_oid)
        || !matches!(
            response.broker_state,
            BrokerState::Leased | BrokerState::Terminal
        )
        || response.generation == 0
        || response.accepted_at == 0
        || response.updated_at < response.accepted_at
        || response.lease_generation == 0
        || response.attempt != admission.attempt
        || (response.broker_state == BrokerState::Terminal)
            != (response.conclusion != Conclusion::None)
        || (response.broker_state == BrokerState::Terminal
            && (response.evidence_set_digest == [0; 32] || response.teardown_digest == [0; 32]))
        || (response.broker_state != BrokerState::Terminal
            && (response.evidence_set_digest != [0; 32] || response.teardown_digest != [0; 32]))
    {
        return Err(RunnerV2Error::InvalidResponse);
    }
    Ok(())
}

fn job_intent_digest(
    request: AdmitAttemptRequest,
    accepted: &AcceptedRequest,
    bindings: &StaticAdmissionBindings,
) -> Result<[u8; 32], RunnerV2Error> {
    let mut bytes = Vec::with_capacity(360);
    bytes.extend_from_slice(v2::JOB_INTENT_DIGEST_DOMAIN);
    bytes.extend_from_slice(&JOB_INTENT_SCHEMA_VERSION.to_be_bytes());
    bytes.extend_from_slice(&request.signed_request_digest);
    bytes.extend_from_slice(&request.actor_pubkey);
    bytes.extend_from_slice(&request.audience_digest);
    bytes.extend_from_slice(&request.idempotency_digest);
    bytes.extend_from_slice(&request.source_pin_event_id);
    bytes.extend_from_slice(&request.workflow_digest);
    bytes.extend_from_slice(&request.isolation_profile_digest);
    bytes.extend_from_slice(&request.lane_manifest_digest);
    bytes.extend_from_slice(&request.lane_epoch.to_be_bytes());
    bytes.push(request.admission_signature_algorithm as u8);
    bytes.extend_from_slice(&request.admission_key_generation.to_be_bytes());
    bytes.extend_from_slice(&request.run_id);
    put_oid(&mut bytes, request.tip_oid);
    put_oid(&mut bytes, request.base_oid);
    bytes.extend_from_slice(&request.issued_at.to_be_bytes());
    bytes.extend_from_slice(&request.expires_at.to_be_bytes());
    bytes.extend_from_slice(&request.wall_timeout_seconds.to_be_bytes());
    bytes.extend_from_slice(&request.attempt.to_be_bytes());
    bytes.extend_from_slice(&request.parent_attempt.to_be_bytes());
    bytes.push(request.trust_class as u8);
    bytes.extend_from_slice(&decode_array::<32>(&accepted.event_id)?);
    put_text(
        &mut bytes,
        WireText64::from_ascii(&bindings.workflow_id).map_err(|_| RunnerV2Error::InvalidRequest)?,
    );
    put_text(
        &mut bytes,
        WireText64::from_ascii(&bindings.job_ids[0]).map_err(|_| RunnerV2Error::InvalidRequest)?,
    );
    bytes.push(bindings.artifacts.len() as u8);
    for artifact in &bindings.artifacts {
        bytes.push(1);
        put_text(&mut bytes, wire_artifact_text(&artifact.artifact_id)?);
        put_text(&mut bytes, wire_artifact_text(&artifact.name)?);
        put_text(
            &mut bytes,
            WireText64::from_ascii(&artifact.media_type)
                .map_err(|_| RunnerV2Error::InvalidRequest)?,
        );
        put_text(&mut bytes, wire_artifact_text(&artifact.relative_name)?);
        bytes.extend_from_slice(&artifact.max_bytes.to_be_bytes());
    }
    Ok(Sha256::digest(bytes).into())
}

fn put_text(bytes: &mut Vec<u8>, value: WireText64) {
    bytes.push(value.len);
    bytes.extend_from_slice(&value.bytes);
}

fn wire_artifact_text(value: &str) -> Result<WireText64, RunnerV2Error> {
    if matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RunnerV2Error::InvalidRequest);
    }
    WireText64::from_ascii(value).map_err(|_| RunnerV2Error::InvalidRequest)
}

fn put_oid(bytes: &mut Vec<u8>, value: GitOid) {
    match value {
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

fn parse_oid(value: &str) -> Result<GitOid, RunnerV2Error> {
    match value.len() {
        40 => Ok(GitOid::Sha1(decode_array(value)?)),
        64 => Ok(GitOid::Sha256(decode_array(value)?)),
        _ => Err(RunnerV2Error::InvalidRequest),
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], RunnerV2Error> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RunnerV2Error::InvalidRequest);
    }
    hex::decode(value)
        .map_err(|_| RunnerV2Error::InvalidRequest)?
        .try_into()
        .map_err(|_| RunnerV2Error::InvalidRequest)
}

/// The host clock, used only to bound a live operation: the attempt wait,
/// the acceptance command hold, and cancel eligibility all compare it with
/// [`BoundAttempt::deadline_at`], which execd anchored at admission on this
/// same host clock. It never judges a package-bound window; those are judged
/// by the runner and execd against `acceptance_time_reference`. See
/// deploy/native-ci/README.md, "Clock model". This is the only wall-clock
/// read in controld's attempt path (pinned by a test).
pub fn live_bound_now() -> Result<u64, RunnerV2Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RunnerV2Error::Deadline)
}

fn deterministic_header(request: Request) -> FrameHeader {
    let seed = v2::encode_request([1; 16], request);
    let digest = Sha256::new()
        .chain_update(REQUEST_ID_DOMAIN)
        .chain_update(seed.as_bytes())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    FrameHeader {
        operation: request.operation(),
        request_id,
    }
}

fn deterministic_registration_header(request: RegisterJobIntentRequest) -> FrameHeader {
    let mut canonical = request;
    canonical.request_frame_digest = [0; 32];
    let seed = v2::encode_request([0; 16], Request::RegisterJobIntent(canonical));
    let digest = Sha256::new()
        .chain_update(REQUEST_ID_DOMAIN)
        .chain_update(seed.as_bytes())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    FrameHeader {
        operation: buzz_ci_broker_protocol::Operation::RegisterJobIntent,
        request_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_ci_broker_protocol::v2::{
        AttemptEvidenceCoordinates, EvidenceDescriptor, EvidenceKind,
    };
    use buzz_ci_broker_protocol::{Operation, ResponseCode};
    use buzz_ci_execd::production_binding::{
        ArtifactDeclarationV1, JobIntentV2, JOB_INTENT_SCHEMA_V2,
    };
    use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};

    #[derive(Default)]
    struct FakeTransport {
        requests: Vec<Vec<u8>>,
    }

    impl RunnerV2Transport for FakeTransport {
        type Error = ();

        fn exchange_frame(
            &mut self,
            request: &[u8],
            response_length: usize,
            _transport_attempts: u32,
        ) -> Result<Vec<u8>, Self::Error> {
            self.requests.push(request.to_vec());
            let (header, decoded) = v2::decode_request(request).unwrap();
            match decoded {
                Request::RegisterJobIntent(value) => {
                    assert_eq!(
                        response_length,
                        HEADER_SIZE + v2::INTENT_REGISTRATION_RESPONSE_BODY_SIZE
                    );
                    let expected_header = deterministic_registration_header(value);
                    assert_eq!(header.request_id, expected_header.request_id);
                    assert_eq!(
                        value.request_frame_digest,
                        intent_registration_request_frame_digest(header, &value).unwrap()
                    );
                    Ok(v2::encode_intent_registration_response(
                        header,
                        IntentRegistrationResponse {
                            code: ResponseCode::Ok,
                            retry_after_millis: 0,
                            signed_request_digest: value.admission.signed_request_digest,
                            job_intent_digest: value.admission.job_intent_digest,
                            request_frame_digest: value.request_frame_digest,
                            admission_message_digest: Sha256::digest(admission_signature_message(
                                &value.admission,
                            ))
                            .into(),
                            registration_key_digest: intent_registration_key_digest(&value),
                            lane_manifest_digest: value.admission.lane_manifest_digest,
                            run_id: value.admission.run_id,
                            lane_epoch: value.admission.lane_epoch,
                            admission_key_generation: value.admission.admission_key_generation,
                            issued_at: value.admission.issued_at,
                            expires_at: value.admission.expires_at,
                            attempt: value.admission.attempt,
                        },
                    )
                    .as_bytes()
                    .to_vec())
                }
                Request::DescribeAttemptEvidence(value) => {
                    assert_eq!(
                        response_length,
                        HEADER_SIZE + v2::EVIDENCE_DESCRIPTION_BODY_SIZE
                    );
                    Ok(v2::encode_evidence_description_response(
                        header,
                        EvidenceDescriptionResponse {
                            code: ResponseCode::Ok,
                            execution_binding_digest: value.coordinates.execution_binding_digest,
                            generation: value.coordinates.expected_generation,
                            request_frame_digest: value.request_frame_digest,
                            descriptor_set_digest: [8; 32],
                            item_count: 1,
                            items: [
                                Some(EvidenceDescriptor {
                                    kind: EvidenceKind::Stdout,
                                    digest: [9; 32],
                                    length: 2,
                                    artifact_name_digest: [0; 32],
                                    artifact_media_type_digest: [0; 32],
                                    artifact_id: WireText64::EMPTY,
                                    artifact_name: WireText64::EMPTY,
                                    artifact_media_type: WireText64::EMPTY,
                                    teardown_lease_id: [0; 16],
                                    teardown_lease_generation: 0,
                                    teardown_attestation_digest: [0; 32],
                                }),
                                None,
                                None,
                                None,
                            ],
                            request_event_id: value.coordinates.request_event_id,
                            run_id: value.coordinates.run_id,
                            workflow_id: value.coordinates.workflow_id,
                            workflow_digest: value.coordinates.workflow_digest,
                            job_id: value.coordinates.job_id,
                            attempt: value.coordinates.attempt,
                        },
                    )
                    .as_bytes()
                    .to_vec())
                }
                Request::ReadAttemptEvidence(value) => {
                    assert_eq!(response_length, HEADER_SIZE + v2::EVIDENCE_CHUNK_BODY_SIZE);
                    Ok(v2::encode_evidence_chunk_response(
                        header,
                        &EvidenceChunkResponse {
                            code: ResponseCode::Ok,
                            execution_binding_digest: value.coordinates.execution_binding_digest,
                            generation: value.coordinates.expected_generation,
                            request_frame_digest: value.request_frame_digest,
                            kind: value.kind,
                            item_index: value.item_index,
                            descriptor_digest: value.descriptor_digest,
                            offset: value.offset,
                            total_length: 2,
                            bytes: b"ok".to_vec(),
                            request_event_id: value.coordinates.request_event_id,
                            run_id: value.coordinates.run_id,
                            workflow_id: value.coordinates.workflow_id,
                            workflow_digest: value.coordinates.workflow_digest,
                            job_id: value.coordinates.job_id,
                            attempt: value.coordinates.attempt,
                        },
                    )
                    .as_bytes()
                    .to_vec())
                }
                _ => unreachable!(),
            }
        }
    }

    fn coordinates() -> AttemptEvidenceCoordinates {
        AttemptEvidenceCoordinates {
            signed_request_digest: [1; 32],
            run_id: [2; 16],
            workflow_digest: [3; 32],
            job_intent_digest: [4; 32],
            attempt: 1,
            attempt_id: [5; 16],
            execution_binding_digest: [6; 32],
            expected_generation: 7,
            request_event_id: [1; 32],
            workflow_id: WireText64::from_ascii("ci").unwrap(),
            job_id: WireText64::from_ascii("test").unwrap(),
        }
    }

    fn accepted() -> AcceptedRequest {
        AcceptedRequest {
            channel_id: "123e4567-e89b-12d3-a456-426614174099".into(),
            watch_cursor: 1,
            event_id: "11".repeat(32),
            envelope: CiRequestEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_type: CiRequestType::Run,
                target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
                pr_root_event_id: "33".repeat(32),
                pr_update_event_id: None,
                source_clone_url: "https://relay.example/git/repo".into(),
                immutable_source_ref: "refs/nostr/source".into(),
                tip_oid: "44".repeat(20),
                source_branch: "feature".into(),
                base_ref: "refs/heads/main".into(),
                base_oid: "55".repeat(20),
                workflow_id: "native-ci".into(),
                workflow_digest: "66".repeat(32),
                job_ids: vec!["test".into()],
                run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
                attempt: 1,
                parent_attempt: None,
                parent_run_id: None,
                trigger_event_id: "33".repeat(32),
                actor: "88".repeat(32),
                timeout_seconds: 30,
                idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
                issued_at: 10,
                expires_at: 40,
            },
        }
    }

    fn bindings() -> StaticAdmissionBindings {
        StaticAdmissionBindings {
            audience_digest: [0x99; 32],
            isolation_profile_digest: [0xaa; 32],
            lane_manifest_digest: [0xbb; 32],
            lane_epoch: 7,
            admission_key_generation: 3,
            workflow_id: "native-ci".into(),
            workflow_digest: [0x66; 32],
            job_ids: vec!["test".into()],
            artifacts: vec![StaticArtifactBinding {
                artifact_id: "result".into(),
                name: "result.json".into(),
                media_type: "application/json".into(),
                relative_name: "result.json".into(),
                max_bytes: 32 * 1024,
            }],
        }
    }

    struct Signer;

    impl AdmissionSigner for Signer {
        type Error = ();

        fn sign_admission(&mut self, request: &mut AdmitAttemptRequest) -> Result<(), Self::Error> {
            request.admission_signature = [0x77; 64];
            Ok(())
        }
    }

    #[test]
    fn evidence_requests_bind_deterministic_ids_and_exact_echoes() {
        let mut client = RunnerV2Client::new(FakeTransport::default(), 2).unwrap();
        let description = client
            .describe(DescribeAttemptEvidenceRequest {
                coordinates: coordinates(),
                idempotency_digest: [7; 32],
                request_frame_digest: [0; 32],
            })
            .unwrap();
        assert_eq!(description.item_count, 1);
        let chunk = client
            .read(ReadAttemptEvidenceRequest {
                coordinates: coordinates(),
                idempotency_digest: [7; 32],
                request_frame_digest: [0; 32],
                kind: EvidenceKind::Stdout,
                item_index: 0,
                descriptor_digest: [9; 32],
                offset: 0,
                max_length: 2,
            })
            .unwrap();
        assert_eq!(chunk.bytes, b"ok");

        let transport = client.into_transport();
        assert_eq!(transport.requests.len(), 2);
        for frame in transport.requests {
            let (header, request) = v2::decode_request(&frame).unwrap();
            assert_ne!(header.request_id, [0; 16]);
            assert_eq!(
                evidence_request_frame_digest(header, &request),
                match request {
                    Request::DescribeAttemptEvidence(value) => Some(value.request_frame_digest),
                    Request::ReadAttemptEvidence(value) => Some(value.request_frame_digest),
                    _ => None,
                }
            );
        }
    }

    #[test]
    fn registration_uses_zeroed_frame_request_id_formula_and_exact_response_binding() {
        let request = accepted();
        let bindings = bindings();
        let admission = prepare_signed_admission(&request, &bindings, &mut Signer).unwrap();
        let mut client = RunnerV2Client::new(FakeTransport::default(), 2).unwrap();

        let response = client
            .register_job_intent(admission, &request, &bindings)
            .unwrap();

        assert_eq!(response.code, ResponseCode::Ok);
        assert_eq!(response.job_intent_digest, admission.job_intent_digest);
        assert_eq!(client.into_transport().requests.len(), 1);
    }

    #[test]
    fn normal_exchange_rejects_evidence_shapes() {
        let mut client = RunnerV2Client::new(FakeTransport::default(), 1).unwrap();
        assert_eq!(
            client.exchange(Request::DescribeAttemptEvidence(
                DescribeAttemptEvidenceRequest {
                    coordinates: coordinates(),
                    idempotency_digest: [7; 32],
                    request_frame_digest: [0; 32],
                }
            )),
            Err(RunnerV2Error::InvalidRequest)
        );
    }

    /// H10 clean host, boot 4: a package materialized eleven minutes earlier
    /// admitted (the runner and execd judge the frozen window against the
    /// package time reference) but controld's wait_terminal compared the
    /// window with its own clock and failed the attempt at once. The deadline
    /// is now the broker's admission time plus the lesser of the wall timeout
    /// and the window length, as execd judges it.
    fn admission_fixture() -> AdmitAttemptRequest {
        prepare_signed_admission(&accepted(), &bindings(), &mut Signer).unwrap()
    }

    #[test]
    fn attempt_deadline_follows_admission_time_and_window_length_not_the_wall_clock() {
        let mut admission = admission_fixture();
        // A package frozen in 2023: its window closed by wall clock long ago.
        admission.issued_at = 1_700_000_000;
        admission.expires_at = 1_700_000_300;
        admission.wall_timeout_seconds = 120;
        let now = live_bound_now().unwrap();
        let leased = |accepted_at: u64| BoundAttempt {
            admission,
            response: v2::BrokerResponse {
                code: ResponseCode::Ok,
                retry_after_millis: 0,
                attempt_id: [14; 16],
                run_id: admission.run_id,
                accepted_request_digest: admission.signed_request_digest,
                job_intent_digest: admission.job_intent_digest,
                execution_binding_digest: [15; 32],
                tip_oid: Some(admission.tip_oid),
                broker_state: BrokerState::Leased,
                conclusion: Conclusion::None,
                terminal_reason: 0,
                generation: 2,
                accepted_at,
                updated_at: accepted_at,
                lease_generation: 1,
                evidence_set_digest: [0; 32],
                teardown_digest: [0; 32],
                attempt: admission.attempt,
            },
        };
        assert_eq!(leased(now).deadline_at(), Ok(now + 120));
        let mut short = leased(now);
        short.admission.wall_timeout_seconds = 30;
        assert_eq!(short.deadline_at(), Ok(now + 30));
        let mut narrow = leased(now);
        narrow.admission.expires_at = narrow.admission.issued_at + 45;
        assert_eq!(narrow.deadline_at(), Ok(now + 45));
        let mut empty = leased(now);
        empty.admission.expires_at = empty.admission.issued_at;
        assert_eq!(empty.deadline_at(), Err(RunnerV2Error::InvalidRequest));

        struct TerminalTransport;
        impl RunnerV2Transport for TerminalTransport {
            type Error = ();

            fn exchange_frame(
                &mut self,
                request: &[u8],
                _response_length: usize,
                _transport_attempts: u32,
            ) -> Result<Vec<u8>, Self::Error> {
                let (header, decoded) = v2::decode_request(request).unwrap();
                let Request::GetAttempt(value) = decoded else {
                    unreachable!();
                };
                let admission = admission_fixture();
                Ok(v2::encode_response(
                    header,
                    v2::BrokerResponse {
                        code: ResponseCode::Existing,
                        retry_after_millis: 0,
                        attempt_id: value.attempt_id,
                        run_id: admission.run_id,
                        accepted_request_digest: admission.signed_request_digest,
                        job_intent_digest: admission.job_intent_digest,
                        execution_binding_digest: value.execution_binding_digest,
                        tip_oid: Some(admission.tip_oid),
                        broker_state: BrokerState::Terminal,
                        conclusion: Conclusion::Success,
                        terminal_reason: 0,
                        generation: 5,
                        accepted_at: 1_800_000_000,
                        updated_at: 1_800_000_011,
                        lease_generation: 1,
                        evidence_set_digest: [16; 32],
                        teardown_digest: [17; 32],
                        attempt: admission.attempt,
                    },
                )
                .as_bytes()
                .to_vec())
            }
        }
        // The frozen window closed by wall clock long ago; the deadline is live.
        assert!(now >= admission.expires_at);
        let mut client = RunnerV2Client::new(TerminalTransport, 1).unwrap();
        let terminal = client
            .wait_terminal(leased(now), Duration::from_millis(1))
            .expect("a live deadline reconciles the attempt");
        assert_eq!(terminal.response.conclusion, Conclusion::Success);
        // A deadline already behind the clock is refused before any poll.
        let mut client = RunnerV2Client::new(TerminalTransport, 1).unwrap();
        assert_eq!(
            client
                .wait_terminal(leased(now - 200), Duration::from_millis(1))
                .map(|_| ()),
            Err(RunnerV2Error::Deadline)
        );
    }

    #[test]
    fn operation_numbers_are_frozen() {
        assert_eq!(Operation::DescribeAttemptEvidence as u16, 7);
        assert_eq!(Operation::ReadAttemptEvidence as u16, 8);
    }

    #[test]
    fn admission_digest_matches_execd_static_job_intent_with_artifact() {
        let accepted = accepted();
        let bindings = bindings();
        let admission = prepare_signed_admission(&accepted, &bindings, &mut Signer).unwrap();
        let artifact = &bindings.artifacts[0];
        let intent = JobIntentV2 {
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
            request_event_id: admission.signed_request_digest,
            workflow_id: WireText64::from_ascii(&bindings.workflow_id).unwrap(),
            job_id: WireText64::from_ascii(&bindings.job_ids[0]).unwrap(),
            artifact_count: 1,
            artifacts: [Some(ArtifactDeclarationV1 {
                artifact_id: WireText64::from_ascii(&artifact.artifact_id).unwrap(),
                name: WireText64::from_ascii(&artifact.name).unwrap(),
                media_type: WireText64::from_ascii(&artifact.media_type).unwrap(),
                relative_name: WireText64::from_ascii(&artifact.relative_name).unwrap(),
                max_bytes: artifact.max_bytes,
            })],
        };
        assert_eq!(admission.job_intent_digest, intent.digest());
    }

    /// Sol focus read of head Q, findings 3 to 5: the attempt wait, the
    /// acceptance command hold, and cancel eligibility read the host clock.
    /// They bound live operations against a deadline anchored at admission
    /// on the same host; the package-bound windows are judged elsewhere
    /// against the time reference. This pins the rule so a reviewer can
    /// verify it by grep: `live_bound_now` is the only wall-clock read in
    /// controld's attempt path, and the two callers name it.
    #[test]
    fn live_bound_now_is_the_only_wall_clock_in_the_attempt_path() {
        let needle = concat!("SystemTime", "::now()");
        assert_eq!(include_str!("runner_v2.rs").matches(needle).count(), 1);
        for (name, source) in [
            ("production_v2.rs", include_str!("production_v2.rs")),
            ("service.rs", include_str!("service.rs")),
        ] {
            assert_eq!(source.matches(needle).count(), 0, "{name}");
            assert!(source.contains("live_bound_now()"), "{name}");
        }
    }
}
