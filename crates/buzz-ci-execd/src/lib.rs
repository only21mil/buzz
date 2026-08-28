//! Keyless, networkless control logic for the privileged Buzz CI broker.
//!
//! Wave 1 deliberately exposes zero execution capacity until root-owned host
//! provisioning and the full security acceptance suite pass. This crate owns
//! no relay identity, repository credential, network client, workflow parser,
//! shell, or process execution path.

#![forbid(unsafe_code)]

pub mod activation;
#[cfg(target_os = "linux")]
pub mod activation_coordinator;
#[cfg(target_os = "linux")]
pub mod control;
#[cfg(target_os = "linux")]
pub mod dns_activation;
#[cfg(target_os = "linux")]
pub mod dns_exec;
#[cfg(target_os = "linux")]
pub mod dns_host;
pub mod dns_isolation;
#[cfg(target_os = "linux")]
pub mod durable_dispatch;
#[cfg(unix)]
pub mod evidence;
#[cfg(target_os = "linux")]
pub mod git_host_observer;
#[cfg(unix)]
pub mod harness;
#[cfg(target_os = "linux")]
pub mod host_composition;
#[cfg(unix)]
pub mod materializer_evidence;
#[cfg(target_os = "linux")]
pub mod materializer_handoff;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod normal_backend;
#[cfg(target_os = "linux")]
pub mod normal_engine;
#[cfg(target_os = "linux")]
pub mod normal_qualification;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod normal_qualification_host;
#[cfg(target_os = "linux")]
pub mod normal_source;
#[cfg(target_os = "linux")]
pub mod production_composition;
mod proxy_journal;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod proxy_lease;
#[cfg(target_os = "linux")]
pub mod qualification_cleanup;
#[cfg(target_os = "linux")]
pub mod qualification_exec;
pub mod qualification_host;
#[cfg(unix)]
pub mod runtime;

use buzz_ci_broker_protocol::{
    BrokerResponse, BrokerState, Conclusion, FrameHeader, Request, ResponseCode,
};

pub mod seccomp;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod seccomp_activation;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod seccomp_exec;
pub mod seccomp_host;

pub const FORBIDDEN_ENVIRONMENT_KEYS: &[&str] = &[
    "BUZZ_RELAY_PRIVATE_KEY",
    "BUZZ_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "REDIS_URL",
];

/// Return the first forbidden inherited environment key without reading or
/// exposing any value.
pub fn forbidden_environment_key<'a>(keys: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    keys.into_iter()
        .find(|key| FORBIDDEN_ENVIRONMENT_KEYS.contains(key))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Broker {
    generation: u64,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    /// Construct the Phase-1 broker in its mandatory zero-capacity state.
    pub const fn new() -> Self {
        Self { generation: 1 }
    }

    /// Handle one already-framed and decoded request.
    ///
    /// No operation can allocate a lease or execute work in this phase.
    pub fn handle(&self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        if header.operation != request.operation() {
            return self.response(ResponseCode::BadFrame, now);
        }
        match request {
            Request::Hello(_) => self.response(ResponseCode::NotProvisioned, now),
            Request::AdmitAttempt(admit) => BrokerResponse {
                code: ResponseCode::NotProvisioned,
                retry_after_millis: 0,
                attempt_id: [0; 16],
                run_id: admit.run_id,
                accepted_request_digest: admit.signed_request_digest,
                job_manifest_digest: admit.job_manifest_digest,
                tip_oid: Some(admit.tip_oid),
                broker_state: BrokerState::Reconciling,
                conclusion: Conclusion::None,
                terminal_reason: 0,
                generation: self.generation,
                accepted_at: 0,
                updated_at: now,
                lease_generation: 0,
                evidence_set_digest: [0; 32],
                teardown_digest: [0; 32],
                attempt: admit.attempt,
            },
            Request::AdmitQualification(_) => self.response(ResponseCode::NotProvisioned, now),
            Request::CancelAttempt(_) | Request::GetAttempt(_) | Request::CompleteAttempt(_) => {
                self.response(ResponseCode::NotFound, now)
            }
        }
    }

    fn response(&self, code: ResponseCode, now: u64) -> BrokerResponse {
        BrokerResponse {
            code,
            retry_after_millis: 0,
            attempt_id: [0; 16],
            run_id: [0; 16],
            accepted_request_digest: [0; 32],
            job_manifest_digest: [0; 32],
            tip_oid: None,
            broker_state: BrokerState::Reconciling,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: self.generation,
            accepted_at: 0,
            updated_at: now,
            lease_generation: 0,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 0,
        }
    }
}

/// Exercise the complete fixed-frame request/response path without touching
/// sockets, accounts, files, processes, or network state.
pub fn self_check() -> Result<(), &'static str> {
    use buzz_ci_broker_protocol::{
        decode_request, decode_response, encode_request, encode_response, HelloRequest,
    };

    let request = Request::Hello(HelloRequest {
        controller_instance: [1; 32],
        nonce: [2; 32],
    });
    let encoded = encode_request([3; 16], request);
    let (header, decoded) = decode_request(encoded.as_bytes()).map_err(|_| "request decode")?;
    let response = Broker::new().handle(header, decoded, 1);
    if response.code != ResponseCode::NotProvisioned {
        return Err("broker admitted work before provisioning");
    }
    let encoded_response = encode_response(header, response);
    let decoded_response =
        decode_response(header, encoded_response.as_bytes()).map_err(|_| "response decode")?;
    if decoded_response != response {
        return Err("response round-trip mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_ci_broker_protocol::{
        AdmitAttemptRequest, CancelAttemptRequest, CancelReason, GetAttemptRequest, GitOid,
        HelloRequest, Operation, TrustClass,
    };

    fn header(operation: Operation) -> FrameHeader {
        FrameHeader {
            operation,
            request_id: [1; 16],
        }
    }

    fn admit() -> AdmitAttemptRequest {
        AdmitAttemptRequest {
            signed_request_digest: [1; 32],
            actor_pubkey: [2; 32],
            audience_digest: [3; 32],
            idempotency_digest: [4; 32],
            source_pin_event_id: [5; 32],
            workflow_digest: [6; 32],
            job_manifest_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            run_id: [9; 16],
            tip_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            issued_at: 10,
            expires_at: 20,
            wall_timeout_seconds: 5,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    #[test]
    fn zero_capacity_never_admits_an_attempt() {
        let broker = Broker::new();
        let response = broker.handle(
            header(Operation::AdmitAttempt),
            Request::AdmitAttempt(admit()),
            12,
        );
        assert_eq!(response.code, ResponseCode::NotProvisioned);
        assert_eq!(response.broker_state, BrokerState::Reconciling);
        assert_eq!(response.conclusion, Conclusion::None);
        assert_eq!(response.attempt_id, [0; 16]);
        assert_eq!(response.lease_generation, 0);
        assert_eq!(response.evidence_set_digest, [0; 32]);
        assert_eq!(response.teardown_digest, [0; 32]);
        assert_eq!(response.attempt, 1);
    }

    #[test]
    fn every_operation_is_non_executing() {
        let broker = Broker::new();
        let cases = [
            (
                header(Operation::Hello),
                Request::Hello(HelloRequest {
                    controller_instance: [1; 32],
                    nonce: [2; 32],
                }),
                ResponseCode::NotProvisioned,
            ),
            (
                header(Operation::CancelAttempt),
                Request::CancelAttempt(CancelAttemptRequest {
                    attempt_id: [1; 16],
                    actor_pubkey: [2; 32],
                    cancel_digest: [3; 32],
                    issued_at: 10,
                    expires_at: 20,
                    expected_generation: 1,
                    reason: CancelReason::Shutdown,
                }),
                ResponseCode::NotFound,
            ),
            (
                header(Operation::GetAttempt),
                Request::GetAttempt(GetAttemptRequest {
                    attempt_id: [1; 16],
                }),
                ResponseCode::NotFound,
            ),
        ];
        for (header, request, code) in cases {
            let response = broker.handle(header, request, 10);
            assert_eq!(response.code, code);
            assert_eq!(response.attempt_id, [0; 16]);
        }
    }

    #[test]
    fn forbidden_environment_check_reads_names_only() {
        assert_eq!(
            forbidden_environment_key(["PATH", "BUZZ_PRIVATE_KEY", "LANG"]),
            Some("BUZZ_PRIVATE_KEY")
        );
        assert_eq!(forbidden_environment_key(["PATH", "LANG"]), None);
    }

    #[test]
    fn fixed_frame_self_check_passes() {
        assert_eq!(self_check(), Ok(()));
    }

    #[test]
    fn header_operation_mismatch_is_rejected() {
        let response =
            Broker::new().handle(header(Operation::Hello), Request::AdmitAttempt(admit()), 12);
        assert_eq!(response.code, ResponseCode::BadFrame);
    }
}
