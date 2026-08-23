//! CI preflight route: `POST /ci/preflight`.
//!
//! NIP-98 authenticated handler that resolves a repository PR snapshot,
//! workflow bytes, and job selection.  The request and response shapes are
//! frozen in `docs/ci/BUZZ_CI_RELAY_API_CONTRACT.md` section 2.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

use crate::state::AppState;
use crate::tenant::bind_community;

/// Request body for `POST /ci/preflight`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRequest {
    /// Target repository coordinate: `30617:<owner-hex>:<repo-id>`.
    pub target_repo_a: String,
    /// Exact full source object ID (SHA-1 or SHA-256).
    pub requested_tip_oid: String,
    /// Optional workflow ID or digest selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_selector: Option<String>,
    /// Optional explicit static job selection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_job_ids: Option<Vec<String>>,
}

/// Job definition in the preflight response.
#[derive(Debug, Clone, Serialize)]
pub struct PreflightJob {
    /// Static job ID matching `^[A-Za-z0-9_]{1,64}$`.
    pub job_id: String,
    /// Human-readable workflow job name.
    pub name: String,
    /// Whether the job is required (non-skip).
    pub required: bool,
    /// Skip policy string.
    pub skip_policy: String,
    /// Dependency job IDs.
    pub needs: Vec<String>,
}

/// Policy bounds in the preflight response.
#[derive(Debug, Clone, Serialize)]
pub struct PreflightPolicy {
    /// Minimum timeout in seconds.
    pub min_timeout_seconds: u64,
    /// Maximum timeout in seconds.
    pub max_timeout_seconds: u64,
    /// Maximum expiry in seconds.
    pub max_expiry_seconds: u64,
    /// Acknowledgement timeout in seconds.
    pub acknowledgement_timeout_seconds: u64,
    /// Maximum retry attempts.
    pub max_attempts: u64,
}

/// Response body for `POST /ci/preflight`.
///
/// Mirrors the frozen contract in
/// `docs/ci/BUZZ_CI_RELAY_API_CONTRACT.md` section 2.
#[derive(Debug, Clone, Serialize)]
pub struct PreflightResponse {
    /// Target repository coordinate.
    pub target_repo_a: String,
    /// Root PR event ID.
    pub pr_root_event_id: String,
    /// Optional PR update event ID.
    pub pr_update_event_id: Option<String>,
    /// Effective trigger event ID.
    pub trigger_event_id: String,
    /// Safe credential-free clone URL.
    pub source_clone_url: String,
    /// Non-empty advertised immutable ref.
    pub immutable_source_ref: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Source branch name.
    pub source_branch: String,
    /// Base ref name.
    pub base_ref: String,
    /// Base object ID.
    pub base_oid: String,
    /// Workflow ID.
    pub workflow_id: String,
    /// Workflow path.
    pub workflow_path: String,
    /// SHA-256 of decoded canonical workflow bytes.
    pub workflow_digest: String,
    /// Base64-encoded canonical workflow bytes.
    pub canonical_workflow_base64: String,
    /// Static job definitions.
    pub jobs: Vec<PreflightJob>,
    /// Selected job IDs (non-empty subset of `jobs`).
    pub selected_job_ids: Vec<String>,
    /// Policy bounds.
    pub policy: PreflightPolicy,
}

/// Standard error envelope.
fn api_error(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// `POST /ci/preflight` — resolve a repository PR snapshot, workflow bytes,
/// and job selection for a CI run.
///
/// NIP-98 authenticated; the authenticated pubkey must be a current member of
/// the repository's bound channel.  The full preflight resolution (git
/// hydration, manifest lookup, job selection) requires the relay's git API
/// infrastructure; this handler returns a clear error when the repository or
/// workflow is not found until that resolution is wired.
pub async fn ci_preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: bind this request to its community from the request host.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = bind_community(&state.db, raw_host).await.map_err(|_| {
        api_error(
            StatusCode::NOT_FOUND,
            "relay: no community is configured for this host",
        )
    })?;

    // NIP-98 authentication — same pattern as submit_event in bridge.rs.
    let url = super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, "/ci/preflight");
    let (pubkey, _event_id_bytes) = super::bridge::verify_bridge_auth(
        &headers,
        "POST",
        &url,
        Some(&body),
        state.config.require_auth_token,
    )?;

    // Parse the request body.
    let request: PreflightRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid request body"))?;

    // Validate the target_repo_a coordinate format.
    let mut parts = request.target_repo_a.splitn(3, ':');
    if parts.next() != Some("30617") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid target_repo_a: must start with 30617",
        ));
    }
    let owner = parts.next().ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid target_repo_a: missing owner",
        )
    })?;
    let repo_id = parts.next().ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid target_repo_a: missing repo_id",
        )
    })?;
    if owner.len() != 64
        || !owner
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || repo_id.is_empty()
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid target_repo_a: malformed owner or repo_id",
        ));
    }

    // The full preflight resolution requires the relay's git API to hydrate
    // the repository, resolve the PR snapshot, and extract the workflow bytes.
    // Until that wiring is complete, return a clear not-implemented error so
    // the CLI can distinguish "not wired" from "not found".
    let _ = (pubkey, owner, repo_id, &tenant);
    tracing::info!(
        community = %tenant.community(),
        target_repo_a = %request.target_repo_a,
        requested_tip_oid = %request.requested_tip_oid,
        "CI preflight request received (resolution not yet wired)",
    );
    Err(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "CI preflight resolution is not yet implemented on this relay",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_request_parses_valid_json() {
        let json = serde_json::json!({
            "target_repo_a": "30617:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:repo",
            "requested_tip_oid": "abc123",
        });
        let req: PreflightRequest = serde_json::from_value(json).unwrap();
        assert!(req.workflow_selector.is_none());
        assert!(req.requested_job_ids.is_none());
    }

    #[test]
    fn preflight_request_parses_optional_fields() {
        let json = serde_json::json!({
            "target_repo_a": "30617:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:repo",
            "requested_tip_oid": "abc123",
            "workflow_selector": "wf-1",
            "requested_job_ids": ["job_a", "job_b"],
        });
        let req: PreflightRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.workflow_selector.as_deref(), Some("wf-1"));
        assert_eq!(
            req.requested_job_ids.as_deref(),
            Some(&["job_a".to_string(), "job_b".to_string()][..])
        );
    }

    #[test]
    fn preflight_request_rejects_unknown_fields() {
        let json = serde_json::json!({
            "target_repo_a": "30617:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:repo",
            "requested_tip_oid": "abc123",
            "extra_field": true,
        });
        let result: Result<PreflightRequest, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject extra fields"
        );
    }

    #[test]
    fn preflight_request_rejects_missing_target_repo_a() {
        let json = serde_json::json!({
            "requested_tip_oid": "abc123",
        });
        let result: Result<PreflightRequest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "missing target_repo_a must be rejected");
    }
}
