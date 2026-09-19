//! Capacity-zero responses shared by runtime dispatch and the self-check.

use buzz_ci_broker_protocol::{v2, BrokerState, Conclusion, ResponseCode};
use sha2::{Digest, Sha256};
use v2::BrokerResponse;

/// Encode the operation-specific capacity-zero response without constructing a
/// legacy dispatcher.
pub fn encode_not_provisioned_v2(
    header: v2::FrameHeader,
    request: v2::Request,
    now: u64,
) -> v2::EncodedFrame {
    match request {
        v2::Request::DescribeAttemptEvidence(value) => v2::encode_evidence_description_response(
            header,
            v2::EvidenceDescriptionResponse {
                code: ResponseCode::NotProvisioned,
                execution_binding_digest: value.coordinates.execution_binding_digest,
                generation: value.coordinates.expected_generation,
                request_frame_digest: value.request_frame_digest,
                descriptor_set_digest: [0; 32],
                item_count: 0,
                items: [None; v2::MAX_EVIDENCE_ITEMS],
                request_event_id: value.coordinates.request_event_id,
                run_id: value.coordinates.run_id,
                workflow_id: value.coordinates.workflow_id,
                workflow_digest: value.coordinates.workflow_digest,
                job_id: value.coordinates.job_id,
                attempt: value.coordinates.attempt,
            },
        ),
        v2::Request::ReadAttemptEvidence(value) => v2::encode_evidence_chunk_response(
            header,
            &v2::EvidenceChunkResponse {
                code: ResponseCode::NotProvisioned,
                execution_binding_digest: value.coordinates.execution_binding_digest,
                generation: value.coordinates.expected_generation,
                request_frame_digest: value.request_frame_digest,
                kind: value.kind,
                item_index: value.item_index,
                descriptor_digest: value.descriptor_digest,
                offset: value.offset,
                total_length: 0,
                bytes: Vec::new(),
                request_event_id: value.coordinates.request_event_id,
                run_id: value.coordinates.run_id,
                workflow_id: value.coordinates.workflow_id,
                workflow_digest: value.coordinates.workflow_digest,
                job_id: value.coordinates.job_id,
                attempt: value.coordinates.attempt,
            },
        ),
        v2::Request::RegisterJobIntent(value) => {
            let admission = value.admission;
            v2::encode_intent_registration_response(
                header,
                v2::IntentRegistrationResponse {
                    code: ResponseCode::NotProvisioned,
                    retry_after_millis: 0,
                    signed_request_digest: admission.signed_request_digest,
                    job_intent_digest: admission.job_intent_digest,
                    request_frame_digest: value.request_frame_digest,
                    admission_message_digest: Sha256::digest(v2::admission_signature_message(
                        &admission,
                    ))
                    .into(),
                    registration_key_digest: v2::intent_registration_key_digest(&value),
                    lane_manifest_digest: admission.lane_manifest_digest,
                    run_id: admission.run_id,
                    lane_epoch: admission.lane_epoch,
                    admission_key_generation: admission.admission_key_generation,
                    issued_at: admission.issued_at,
                    expires_at: admission.expires_at,
                    attempt: admission.attempt,
                },
            )
        }
        _ => v2::encode_response(header, empty_response(ResponseCode::NotProvisioned, now)),
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
