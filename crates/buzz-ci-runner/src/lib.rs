//! Unprivileged runner boundary for Buzz CI.
//!
//! This crate validates owner-authorized public CI requests, reduces them to
//! the content-blind broker protocol, drives a separately supplied unprivileged
//! execution backend, and constructs teardown attestations only from terminal
//! broker receipts. It does not own privileged resources.
//!
//! The daemon's controld-facing transport is limited to the frozen socket,
//! framing, dispatch, and receipt fields in [`transport`]. Authentication,
//! execution dispatch, evidence validation, and reconciliation remain outside
//! the transport layer.

#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod handler;
pub mod host;
pub mod journal;
pub mod service;
pub mod transport;

use std::collections::HashSet;

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, BrokerResponse, BrokerState, Conclusion, GitOid, TrustClass,
};
use buzz_core::ci::{
    CiRequestEnvelope, CiTeardownAttestationEnvelope, CiTeardownLease, CI_MAX_SAFE_INTEGER,
    CI_PROTOCOL_CONTRACT_SHA256, CI_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const BINDING_PROTOCOL_CONTRACT_SHA256: &str = CI_PROTOCOL_CONTRACT_SHA256;
pub const BINDING_RELAY_API_CONTRACT_SHA256: &str =
    "9e4727a55599150de762d26ec04186ca6a002ee79a9cf6d8a8dcd072fa7960f3";

pub trait RequestAuthorizer {
    fn authorize(&self, request: &CiRequestEnvelope) -> bool;
}

pub struct AuthorizedRequest<'a> {
    request: &'a CiRequestEnvelope,
    signed_request_digest: [u8; 32],
    trust_class: TrustClass,
}

impl<'a> AuthorizedRequest<'a> {
    pub fn request(&self) -> &'a CiRequestEnvelope {
        self.request
    }

    pub fn check_expiry(self, now: u64) -> Result<UnexpiredAuthorizedRequest<'a>, ControlError> {
        if now >= self.request.expires_at {
            return Err(ControlError::ExpiredRequest);
        }
        Ok(UnexpiredAuthorizedRequest { authorized: self })
    }
}

pub struct UnexpiredAuthorizedRequest<'a> {
    authorized: AuthorizedRequest<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerManifestBinding {
    pub signed_request_digest: [u8; 32],
    pub audience_digest: [u8; 32],
    pub job_manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownLeaseReceipt {
    pub job_id: String,
    pub job_manifest_digest: [u8; 32],
    pub receipt: BrokerResponse,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    #[error("invalid public CI request")]
    InvalidRequest,
    #[error("request is not authorized by owner-configured policy")]
    Unauthorized,
    #[error("request does not carry accepted reviewed trust")]
    UnacceptedTrust,
    #[error("external fork requests are not accepted")]
    ExternalFork,
    #[error("request has expired")]
    ExpiredRequest,
    #[error("manifest binding does not match the authenticated request")]
    InvalidBinding,
    #[error("invalid hex field")]
    InvalidHex,
    #[error("invalid UUID field")]
    InvalidUuid,
    #[error("timeout does not fit the broker protocol")]
    InvalidTimeout,
    #[error("broker receipt does not prove an empty terminal lease")]
    TeardownNotProven,
    #[error("invalid teardown attestation")]
    InvalidAttestation,
    #[error("broker socket is unavailable")]
    BrokerUnavailable,
    #[error("broker transport failed")]
    TransportFailure,
    #[error("broker returned an invalid response")]
    InvalidBrokerResponse,
    #[error("broker rejected the request")]
    BrokerRejected,
    #[error("workflow execution backend is unavailable")]
    ExecutionBackendUnavailable,
    #[error("workflow execution failed")]
    ExecutionFailed,
    #[error("workflow execution did not produce valid bounded evidence")]
    InvalidExecutionEvidence,
}

pub fn authorize_request<'a>(
    authenticated: control::AuthenticatedCiRequest<'a>,
    workflow_policy: control::CiWorkflowPolicy,
    policy: &impl RequestAuthorizer,
) -> Result<AuthorizedRequest<'a>, ControlError> {
    let request = authenticated.envelope();
    request
        .validate()
        .map_err(|_| ControlError::InvalidRequest)?;
    let trust_class = workflow_policy.accepted_trust_class()?;
    if !policy.authorize(request) {
        return Err(ControlError::Unauthorized);
    }
    Ok(AuthorizedRequest {
        request,
        signed_request_digest: authenticated.signed_request_digest(),
        trust_class,
    })
}

pub fn normalize_admit_request(
    authorized: UnexpiredAuthorizedRequest<'_>,
    binding: BrokerManifestBinding,
) -> Result<AdmitAttemptRequest, ControlError> {
    let request = authorized.authorized.request;
    if authorized.authorized.signed_request_digest != binding.signed_request_digest {
        return Err(ControlError::InvalidBinding);
    }
    let trust_class = authorized.authorized.trust_class;
    let timeout =
        u32::try_from(request.timeout_seconds).map_err(|_| ControlError::InvalidTimeout)?;
    let run_id = Uuid::parse_str(&request.run_id).map_err(|_| ControlError::InvalidUuid)?;
    let idempotency =
        Uuid::parse_str(&request.idempotency_key).map_err(|_| ControlError::InvalidUuid)?;

    Ok(AdmitAttemptRequest {
        signed_request_digest: require_nonzero(binding.signed_request_digest)?,
        actor_pubkey: parse_hex_array(&request.actor)?,
        audience_digest: require_nonzero(binding.audience_digest)?,
        idempotency_digest: Sha256::digest(idempotency.as_bytes()).into(),
        source_pin_event_id: parse_hex_array(&request.trigger_event_id)?,
        workflow_digest: parse_hex_array(&request.workflow_digest)?,
        job_manifest_digest: require_nonzero(binding.job_manifest_digest)?,
        isolation_profile_digest: require_nonzero(binding.isolation_profile_digest)?,
        run_id: *run_id.as_bytes(),
        tip_oid: parse_oid(&request.tip_oid)?,
        base_oid: parse_oid(&request.base_oid)?,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        wall_timeout_seconds: timeout,
        attempt: request.attempt,
        parent_attempt: request.parent_attempt.unwrap_or(0),
        trust_class,
    })
}

pub fn build_teardown_attestation(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    relay_signer: &str,
    reducer_selected_job_attempts: &[(String, u32)],
    lease_receipts: Vec<TeardownLeaseReceipt>,
) -> Result<CiTeardownAttestationEnvelope, ControlError> {
    request
        .validate()
        .map_err(|_| ControlError::InvalidRequest)?;
    let run_id = Uuid::parse_str(&request.run_id).map_err(|_| ControlError::InvalidUuid)?;
    let request_id: [u8; 32] = parse_hex_array(request_event_id)?;
    let tip_oid = parse_oid(&request.tip_oid)?;
    if lease_receipts.is_empty() {
        return Err(ControlError::TeardownNotProven);
    }

    let reducer_selected: HashSet<(&str, u32)> = reducer_selected_job_attempts
        .iter()
        .map(|(job_id, attempt)| (job_id.as_str(), *attempt))
        .collect();
    let reducer_selected_job_ids: HashSet<&str> = reducer_selected_job_attempts
        .iter()
        .map(|(job_id, _)| job_id.as_str())
        .collect();
    if reducer_selected_job_attempts.is_empty()
        || reducer_selected.len() != reducer_selected_job_attempts.len()
        || reducer_selected_job_ids.len() != reducer_selected_job_attempts.len()
        || reducer_selected
            .iter()
            .any(|(job_id, attempt)| job_id.is_empty() || *attempt == 0)
    {
        return Err(ControlError::InvalidAttestation);
    }

    let mut leases = Vec::with_capacity(lease_receipts.len());
    let mut teardown_at = 0;
    for proof in lease_receipts {
        let receipt = proof.receipt;
        if !matches!(
            receipt.code,
            buzz_ci_broker_protocol::ResponseCode::Ok
                | buzz_ci_broker_protocol::ResponseCode::Existing
        ) || receipt.broker_state != BrokerState::Terminal
            || receipt.attempt_id == [0; 16]
            || receipt.teardown_digest == [0; 32]
            || matches!(receipt.conclusion, Conclusion::None)
            || receipt.generation == 0
            || receipt.accepted_at == 0
            || receipt.updated_at < receipt.accepted_at
            || receipt.updated_at > CI_MAX_SAFE_INTEGER
            || receipt.lease_generation == 0
            || receipt.run_id != *run_id.as_bytes()
            || receipt.accepted_request_digest != request_id
            || receipt.job_manifest_digest != require_nonzero(proof.job_manifest_digest)?
            || receipt.tip_oid != Some(tip_oid)
            || receipt.attempt == 0
        {
            return Err(ControlError::TeardownNotProven);
        }
        leases.push(CiTeardownLease {
            job_id: proof.job_id,
            attempt: receipt.attempt,
            lease_id: Uuid::from_bytes(receipt.attempt_id).to_string(),
        });
        teardown_at = teardown_at.max(receipt.updated_at);
    }
    leases.sort_by(|left, right| {
        (&left.job_id, left.attempt, &left.lease_id).cmp(&(
            &right.job_id,
            right.attempt,
            &right.lease_id,
        ))
    });
    let receipt_selected: HashSet<(&str, u32)> = leases
        .iter()
        .map(|lease| (lease.job_id.as_str(), lease.attempt))
        .collect();
    if receipt_selected.len() != leases.len()
        || receipt_selected.len() != reducer_selected.len()
        || receipt_selected != reducer_selected
    {
        return Err(ControlError::InvalidAttestation);
    }
    let attempt = reducer_selected_job_attempts
        .iter()
        .map(|(_, attempt)| *attempt)
        .max()
        .ok_or(ControlError::InvalidAttestation)?;
    let attestation = CiTeardownAttestationEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_string(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        base_oid: request.base_oid.clone(),
        workflow_digest: request.workflow_digest.clone(),
        attempt,
        leases,
        lease_empty: true,
        teardown_at,
        relay_signer: relay_signer.to_string(),
    };
    attestation
        .validate_context(request_event_id, request, reducer_selected_job_attempts)
        .map_err(|_| ControlError::InvalidAttestation)?;
    Ok(attestation)
}

fn require_nonzero(value: [u8; 32]) -> Result<[u8; 32], ControlError> {
    if value == [0; 32] {
        return Err(ControlError::InvalidHex);
    }
    Ok(value)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], ControlError> {
    let bytes = hex::decode(value).map_err(|_| ControlError::InvalidHex)?;
    let array: [u8; N] = bytes.try_into().map_err(|_| ControlError::InvalidHex)?;
    if array.iter().all(|byte| *byte == 0) {
        return Err(ControlError::InvalidHex);
    }
    Ok(array)
}

fn parse_oid(value: &str) -> Result<GitOid, ControlError> {
    match value.len() {
        40 => parse_hex_array(value).map(GitOid::Sha1),
        64 => parse_hex_array(value).map(GitOid::Sha256),
        _ => Err(ControlError::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_ci_broker_protocol::{Conclusion, ResponseCode};
    use buzz_core::ci::CiRequestType;

    struct Policy(bool);

    impl RequestAuthorizer for Policy {
        fn authorize(&self, _request: &CiRequestEnvelope) -> bool {
            self.0
        }
    }

    fn request() -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
            pr_root_event_id: "22".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_string(),
            immutable_source_ref: "refs/nostr/source".to_string(),
            tip_oid: "33".repeat(20),
            source_branch: "feature".to_string(),
            base_ref: "refs/heads/main".to_string(),
            base_oid: "44".repeat(20),
            workflow_id: "ci".to_string(),
            workflow_digest: "55".repeat(32),
            job_ids: vec!["test".to_string()],
            run_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "22".repeat(32),
            actor: "66".repeat(32),
            timeout_seconds: 300,
            idempotency_key: "123e4567-e89b-12d3-a456-426614174001".to_string(),
            issued_at: 10,
            expires_at: 20,
        }
    }

    #[test]
    fn authorization_is_mandatory_before_normalization() {
        assert!(matches!(
            authorize_request(
                control::AuthenticatedCiRequest::new(&request(), [1; 32]),
                control::CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), false),
                &Policy(false)
            ),
            Err(ControlError::Unauthorized)
        ));
    }

    #[test]
    fn authorized_request_reduces_to_content_blind_fields() {
        let request = request();
        let authorized = authorize_request(
            control::AuthenticatedCiRequest::new(&request, [1; 32]),
            control::CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), false),
            &Policy(true),
        )
        .expect("authorized request")
        .check_expiry(19)
        .expect("unexpired request");
        let normalized = normalize_admit_request(
            authorized,
            BrokerManifestBinding {
                signed_request_digest: [1; 32],
                audience_digest: [2; 32],
                job_manifest_digest: [3; 32],
                isolation_profile_digest: [4; 32],
            },
        )
        .expect("normalized request");
        assert_eq!(normalized.actor_pubkey, [0x66; 32]);
        assert_eq!(normalized.source_pin_event_id, [0x22; 32]);
        assert_eq!(normalized.workflow_digest, [0x55; 32]);
        assert_eq!(normalized.attempt, 1);
        assert_eq!(normalized.parent_attempt, 0);
    }

    fn terminal_receipt(lease_id: &str, attempt: u32, manifest: u8) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: *Uuid::parse_str(lease_id).expect("UUID").as_bytes(),
            run_id: *Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("UUID")
                .as_bytes(),
            accepted_request_digest: [0x77; 32],
            job_manifest_digest: [manifest; 32],
            tip_oid: Some(GitOid::Sha1([0x33; 20])),
            broker_state: BrokerState::Terminal,
            conclusion: Conclusion::Success,
            terminal_reason: 0,
            generation: 1,
            accepted_at: 10,
            updated_at: 20,
            lease_generation: 1,
            evidence_set_digest: [3; 32],
            teardown_digest: [4; 32],
            attempt,
        }
    }

    fn lease_receipt(job_id: &str, receipt: BrokerResponse) -> TeardownLeaseReceipt {
        TeardownLeaseReceipt {
            job_id: job_id.to_string(),
            job_manifest_digest: receipt.job_manifest_digest,
            receipt,
        }
    }

    fn build(
        request: &CiRequestEnvelope,
        selected_job_attempts: &[(String, u32)],
        receipts: Vec<TeardownLeaseReceipt>,
    ) -> Result<CiTeardownAttestationEnvelope, ControlError> {
        build_teardown_attestation(
            &"77".repeat(32),
            request,
            &"88".repeat(32),
            selected_job_attempts,
            receipts,
        )
    }

    #[test]
    fn contract_hashes_bind_to_reviewed_v1_4_anchor() {
        assert_eq!(
            BINDING_PROTOCOL_CONTRACT_SHA256,
            "8b9715d719b057d5d297074c3d019e40d1d2104eeafa2b6033f17b465e7d5a1c"
        );
        assert_eq!(
            BINDING_RELAY_API_CONTRACT_SHA256,
            "9e4727a55599150de762d26ec04186ca6a002ee79a9cf6d8a8dcd072fa7960f3"
        );
    }

    #[test]
    fn teardown_fact_matches_reducer_selected_rerun_graph() {
        let mut request = request();
        request.request_type = CiRequestType::Rerun;
        request.job_ids = vec!["lint".to_string()];
        request.attempt = 2;
        request.parent_attempt = Some(1);
        request.parent_run_id = Some(request.run_id.clone());
        let selected = vec![("lint".to_string(), 2), ("test".to_string(), 1)];
        let test = terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 1, 2);
        let mut lint = terminal_receipt("123e4567-e89b-12d3-a456-426614174011", 2, 5);
        lint.updated_at = 21;
        let attestation = build(
            &request,
            &selected,
            vec![lease_receipt("test", test), lease_receipt("lint", lint)],
        )
        .expect("valid teardown fact");
        assert!(attestation.lease_empty);
        assert_eq!(attestation.base_oid, request.base_oid);
        assert_eq!(attestation.workflow_digest, request.workflow_digest);
        assert_eq!(attestation.attempt, 2);
        assert_eq!(attestation.teardown_at, 21);
        assert_eq!(
            attestation.leases,
            vec![
                CiTeardownLease {
                    job_id: "lint".to_string(),
                    attempt: 2,
                    lease_id: "123e4567-e89b-12d3-a456-426614174011".to_string(),
                },
                CiTeardownLease {
                    job_id: "test".to_string(),
                    attempt: 1,
                    lease_id: "123e4567-e89b-12d3-a456-426614174010".to_string(),
                },
            ]
        );
    }

    #[test]
    fn teardown_fact_rejects_ambiguous_job_or_lease_identity() {
        let mut request = request();
        request.job_ids = vec!["lint".to_string(), "test".to_string()];
        let selected = vec![("test".to_string(), 1)];

        let first = terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 1, 2);
        let duplicate_job_attempt = terminal_receipt("123e4567-e89b-12d3-a456-426614174011", 1, 5);
        assert_eq!(
            build(
                &request,
                &selected,
                vec![
                    lease_receipt("test", first),
                    lease_receipt("test", duplicate_job_attempt),
                ],
            ),
            Err(ControlError::InvalidAttestation)
        );

        let duplicate_lease = terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 2, 5);
        assert_eq!(
            build(
                &request,
                &[("test".to_string(), 1), ("lint".to_string(), 2)],
                vec![
                    lease_receipt("test", first),
                    lease_receipt("lint", duplicate_lease),
                ],
            ),
            Err(ControlError::InvalidAttestation)
        );
    }

    #[test]
    fn teardown_fact_requires_terminal_nonempty_broker_proof() {
        let request = request();
        let selected = vec![("test".to_string(), 1)];
        let valid = || terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 1, 2);

        assert_eq!(
            build(&request, &selected, Vec::new()),
            Err(ControlError::TeardownNotProven)
        );

        let mut incomplete = valid();
        incomplete.teardown_digest = [0; 32];
        assert_eq!(
            build(&request, &selected, vec![lease_receipt("test", incomplete)]),
            Err(ControlError::TeardownNotProven)
        );

        let mut wrong_run = valid();
        wrong_run.run_id = [9; 16];
        assert_eq!(
            build(&request, &selected, vec![lease_receipt("test", wrong_run)]),
            Err(ControlError::TeardownNotProven)
        );

        let mut wrong_tip = valid();
        wrong_tip.tip_oid = Some(GitOid::Sha1([0x34; 20]));
        assert_eq!(
            build(&request, &selected, vec![lease_receipt("test", wrong_tip)]),
            Err(ControlError::TeardownNotProven)
        );

        let mut zero_attempt = valid();
        zero_attempt.attempt = 0;
        assert_eq!(
            build(
                &request,
                &selected,
                vec![lease_receipt("test", zero_attempt)]
            ),
            Err(ControlError::TeardownNotProven)
        );

        let mut wrong_request = valid();
        wrong_request.accepted_request_digest = [0x78; 32];
        assert_eq!(
            build(
                &request,
                &selected,
                vec![lease_receipt("test", wrong_request)]
            ),
            Err(ControlError::TeardownNotProven)
        );

        let mut missing_lease_generation = valid();
        missing_lease_generation.lease_generation = 0;
        assert_eq!(
            build(
                &request,
                &selected,
                vec![lease_receipt("test", missing_lease_generation)]
            ),
            Err(ControlError::TeardownNotProven)
        );

        let mut time_reversed = valid();
        time_reversed.updated_at = time_reversed.accepted_at - 1;
        assert_eq!(
            build(
                &request,
                &selected,
                vec![lease_receipt("test", time_reversed)]
            ),
            Err(ControlError::TeardownNotProven)
        );

        let receipt = valid();
        let mut wrong_manifest = lease_receipt("test", receipt);
        wrong_manifest.job_manifest_digest = [9; 32];
        assert_eq!(
            build(&request, &selected, vec![wrong_manifest]),
            Err(ControlError::TeardownNotProven)
        );
    }

    #[test]
    fn teardown_fact_rejects_receipts_that_do_not_exactly_match_reducer_graph() {
        let mut request = request();
        request.job_ids = vec!["lint".to_string(), "test".to_string()];
        let lint = || {
            lease_receipt(
                "lint",
                terminal_receipt("123e4567-e89b-12d3-a456-426614174011", 1, 5),
            )
        };
        let test = || {
            lease_receipt(
                "test",
                terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 1, 2),
            )
        };
        let selected = vec![("lint".to_string(), 1), ("test".to_string(), 1)];

        assert_eq!(
            build(&request, &selected, vec![test()]),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(&request, &[("test".to_string(), 1)], vec![lint(), test()]),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(
                &request,
                &[("lint".to_string(), 2), ("test".to_string(), 1)],
                vec![lint(), test()],
            ),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(
                &request,
                &[("lint".to_string(), 1), ("lint".to_string(), 1)],
                vec![lint()],
            ),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(
                &request,
                &[("lint".to_string(), 1), ("lint".to_string(), 2)],
                vec![
                    lint(),
                    lease_receipt(
                        "lint",
                        terminal_receipt("123e4567-e89b-12d3-a456-426614174012", 2, 6),
                    ),
                ],
            ),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(
                &request,
                &[("lint".to_string(), 0), ("test".to_string(), 1)],
                vec![lint(), test()],
            ),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(
                &request,
                &[(String::new(), 1)],
                vec![lease_receipt(
                    "",
                    terminal_receipt("123e4567-e89b-12d3-a456-426614174012", 1, 6),
                )],
            ),
            Err(ControlError::InvalidAttestation)
        );
        assert_eq!(
            build(&request, &[], vec![test()]),
            Err(ControlError::InvalidAttestation)
        );
    }

    #[test]
    fn teardown_fact_matches_reducer_selected_initial_run_graph() {
        let mut request = request();
        request.job_ids = vec!["lint".to_string(), "test".to_string()];
        let selected = vec![("lint".to_string(), 1), ("test".to_string(), 1)];
        let lint = terminal_receipt("123e4567-e89b-12d3-a456-426614174011", 1, 5);
        let test = terminal_receipt("123e4567-e89b-12d3-a456-426614174010", 1, 2);

        let attestation = build(
            &request,
            &selected,
            vec![lease_receipt("test", test), lease_receipt("lint", lint)],
        )
        .expect("valid initial-run teardown fact");

        assert_eq!(attestation.attempt, 1);
        assert_eq!(attestation.leases.len(), 2);
    }
}
