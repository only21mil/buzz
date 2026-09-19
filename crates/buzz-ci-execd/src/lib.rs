//! Keyless, networkless control logic for the privileged Buzz CI broker.
//!
//! Wave 1 deliberately exposes zero execution capacity until root-owned host
//! provisioning and the full security acceptance suite pass. This crate owns
//! no relay identity, repository credential, network client, workflow parser,
//! shell, or process execution path.

#![forbid(unsafe_code)]

mod closed_response;

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
pub mod production_binding;
#[cfg(target_os = "linux")]
pub mod production_composition;
#[cfg(target_os = "linux")]
pub mod production_v2;
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

use buzz_ci_broker_protocol::ResponseCode;

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

/// Exercise the real capacity-zero response encoder through the v2 codec without touching
/// sockets, accounts, files, processes, or network state.
pub fn self_check() -> Result<(), &'static str> {
    use buzz_ci_broker_protocol::v2::{decode_request, decode_response, encode_request, Request};
    use buzz_ci_broker_protocol::HelloRequest;

    let request = Request::Hello(HelloRequest {
        controller_instance: [1; 32],
        nonce: [2; 32],
    });
    let encoded = encode_request([3; 16], request);
    let (header, decoded) = decode_request(encoded.as_bytes()).map_err(|_| "request decode")?;
    if decoded != request {
        return Err("request round-trip mismatch");
    }
    let encoded_response = closed_response::encode_not_provisioned_v2(header, decoded, 1);
    let decoded_response =
        decode_response(header, encoded_response.as_bytes()).map_err(|_| "response decode")?;
    if decoded_response != closed_response::empty_response(ResponseCode::NotProvisioned, 1) {
        return Err("response round-trip mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
