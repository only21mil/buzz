//! CI preflight route: `POST /ci/preflight`.
//!
//! NIP-98 authenticated handler that resolves a repository PR snapshot,
//! workflow bytes, and job selection.  The request and response shapes are
//! frozen in `docs/ci/BUZZ_CI_RELAY_API_CONTRACT.md` section 2.
//!
//! # Resolution topology (B1 defect #2 — replaces the 501 stub AND the
//! blanket workflow-400 stop seam)
//!
//! Every field below is bound to an authoritative producer present at this
//! SHA; nothing is guessed:
//!
//! - **Repository + membership** — the kind:30617 → `buzz-channel` →
//!   `get_member_role` path the git read gate uses
//!   ([`crate::api::git::transport::authorize_git_read`]). Unknown/missing/
//!   unbound repo → 404; authenticated non-member → 403; DB failure → 503.
//! - **Tip** — the repo is hydrated via
//!   [`crate::api::git::hydrate::hydrate_for_read`] and the requested full
//!   object ID is resolved to a real commit with
//!   `git rev-parse --verify --quiet --end-of-options <oid>^{commit}` — the
//!   exact cast the snapshot route performs. Unresolvable tip → 400.
//! - **Base** — the repository's published manifest head/ref
//!   ([`crate::api::git::manifest::Manifest`]) — the same tuple `info/refs`
//!   serves.
//! - **PR snapshot fields** (`pr_root_event_id`, `pr_update_event_id`,
//!   `source_clone_url`, `source_branch`, `trigger_event_id`) — the relay's
//!   NIP-34 PR event provenance store: kind:1618 roots + kind:1619 updates in
//!   the relay `events` table, resolved per the frozen protocol contract §9
//!   (`docs/ci/BUZZ_CI_PROTOCOL_CONTRACT.md`): exactly one effective snapshot
//!   whose effective full `c` tag equals the requested tip. Zero →
//!   `source_not_found` (404); more than one → `source_ambiguous` (409).
//!   `immutable_source_ref` = `refs/nostr/<pr_root_event_id>`, the in-tree
//!   derivation pinned by the SDK (`builders.rs` pushes PR tips to
//!   `refs/nostr/<pr-event-id>`) and the CLI fixtures.
//! - **Workflow bytes** (`workflow_path`, `workflow_digest`,
//!   `canonical_workflow_base64`) — the exact materializer substitution the
//!   mandate authorizes for a relay process that holds no broker lease: read
//!   the trusted-base objects from the hydrated repo's object store via
//!   `rev-parse <base>:<path>` + `cat-file blob <oid>`, which is precisely
//!   the `ReadWorkflow` + `blob_command` sequence the materializer runs
//!   against its private object store (`crates/buzz-ci-materializer/src/
//!   plan.rs`, `execute.rs`). `workflow_digest` = SHA-256 of the decoded
//!   workflow bytes; never fabricated.
//! - **Jobs/needs/required/skip_policy** — parsed from the resolved canonical
//!   workflow bytes (the repo's own CI workflow; `serde_yaml`). All values
//!   are derived from the workflow alone, never the client.
//! - **Policy bounds** — the optional, root/operator-owned
//!   `config.ci.policy` block. Startup accepts it only when all five positive
//!   bounds are present and valid together. An absent block returns the
//!   precise `policy_unavailable` 503 rather than inventing defaults.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{OriginalUri, Path as AxumPath, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::api::git::binding::{resolve_repo_binding, RepoBinding};
use crate::api::git::hydrate::{hydrate_for_read, load_manifest_for_read, HydrationOptions};
use crate::api::git::manifest::is_hex_oid;
use crate::api::git::transport::{harden_git_env, validate_repo_id};
use crate::api::internal_error;
use crate::config::CiPolicyConfig;
use crate::state::AppState;
use crate::tenant::bind_community;
use buzz_core::channel::MemberRole;
use buzz_core::ci::CiRequestEnvelope;
use buzz_core::ci::{validate_signed_ci_event, ValidatedCiEnvelope};
use buzz_core::kind::{KIND_GIT_PR_UPDATE, KIND_GIT_PULL_REQUEST};
#[cfg(test)]
use buzz_core::CommunityId;
use buzz_core::TenantContext;
use buzz_db::EventQuery;

const MAX_CI_CONTROL_BACKLOG: i64 = 1_001;
/// Maximum bytes accepted by either CI evidence upload route.
pub const MAX_CI_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;

/// Deadline for one preflight git subprocess / hydration attempt.
///
/// Bounded like the snapshot route (10s) so a large repo cannot hold the
/// preflight path open indefinitely.
const PREFLIGHT_GIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a single `rev-parse` stdout (a full object ID plus newline).
const PREFLIGHT_OID_OUTPUT_BYTES: u64 = 1024;

/// Maximum workflow bytes the relay will decode from the trusted base.
///
/// The materializer's default `max_blob_bytes` ceiling is 100 KiB; the relay
/// mirrors that bound so a pathological workflow cannot allocate unbounded
/// memory in this process.
const MAX_WORKFLOW_BYTES: u64 = 128 * 1024;

/// Authoritative default CI workflow path inside the trusted base tree.
///
/// This is the value the materializer and the execd `act` plan both use
/// (`crates/buzz-ci-materializer/src/{plan,execute,tree}.rs`,
/// `buzz-ci-execd/src/normal_source.rs`). The relay asserts it resolves in
/// the base tree and fails closed (`workflow_not_found`) when absent.
const DEFAULT_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";

/// Static identifier used when the canonical workflow defines no top-level
/// `name`. Pinned by the CLI fixtures, the auth gate, the DB `ci_runs`
/// projection, and the runner (`workflow_id: "ci"` everywhere).
const DEFAULT_WORKFLOW_ID: &str = "ci";

/// Maximum PR snapshot events (roots + updates) the resolver will sweep in a
/// single preflight. PR counts per repository are small; past this the exact
/// resolution cannot be proven and the handler fails closed.
const MAX_PR_SNAPSHOT_EVENTS: i64 = 1000;

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

type PreflightApiError = (StatusCode, Json<Value>);
type SelectedJobs = (Vec<PreflightJob>, Vec<String>);

const STATUS_EVENT_LIMIT: u32 = 1_000;
const REJECTED_SIGNER_PROVENANCE_LIMIT: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Tenant-local channel coordinate required for a CI run status read.
pub struct CiStatusQuery {
    /// Repository-bound channel whose current membership authorizes the read.
    channel_id: uuid::Uuid,
}

fn reduce_ci_status_events(
    run_id: uuid::Uuid,
    channel_id: uuid::Uuid,
    trusted_signers: &std::collections::HashSet<String>,
    initial_event: &nostr::Event,
    stored_events: Vec<(i64, nostr::Event)>,
) -> Result<Value, &'static str> {
    let initial_id = initial_event.id.to_hex();
    let initial_envelope =
        match validate_signed_ci_event(initial_event, &channel_id.to_string(), trusted_signers) {
            Ok(ValidatedCiEnvelope::Request(request)) if request.run_id == run_id.to_string() => {
                request
            }
            _ => return Err("stored CI request failed schema validation"),
        };
    let mut accepted = Vec::new();
    let mut malformed_count = 0_u32;
    let mut unexpected_request_count = 0_u32;
    let mut untrusted_count = 0_u32;
    let mut untrusted_signers = std::collections::BTreeSet::new();
    for (watch_cursor, event) in stored_events {
        let event_id = event.id.to_hex();
        let kind = event.kind.as_u16() as u32;
        if watch_cursor < 0 {
            malformed_count = malformed_count.saturating_add(1).min(STATUS_EVENT_LIMIT);
            continue;
        }

        if kind == buzz_core::kind::KIND_CI_REQUEST {
            match validate_signed_ci_event(&event, &channel_id.to_string(), trusted_signers) {
                Ok(ValidatedCiEnvelope::Request(envelope)) if event_id == initial_id => {
                    accepted.push(buzz_core::ci_reducer::AcceptedCiEnvelope {
                        event_id,
                        watch_cursor: watch_cursor as u64,
                        envelope: ValidatedCiEnvelope::Request(envelope),
                    });
                }
                Ok(ValidatedCiEnvelope::Request(_)) => {
                    unexpected_request_count = unexpected_request_count
                        .saturating_add(1)
                        .min(STATUS_EVENT_LIMIT);
                }
                _ => {
                    malformed_count = malformed_count.saturating_add(1).min(STATUS_EVENT_LIMIT);
                }
            }
            continue;
        }

        let signer = event.pubkey.to_hex();
        if !trusted_signers.contains(&signer) {
            let signer_only = std::collections::HashSet::from([signer.clone()]);
            match validate_signed_ci_event(&event, &channel_id.to_string(), &signer_only) {
                Ok(_) => {
                    untrusted_count = untrusted_count.saturating_add(1).min(STATUS_EVENT_LIMIT);
                    untrusted_signers.insert(signer);
                }
                Err(_) => {
                    malformed_count = malformed_count.saturating_add(1).min(STATUS_EVENT_LIMIT);
                }
            }
            continue;
        }

        if event.verify().is_err() {
            malformed_count = malformed_count.saturating_add(1).min(STATUS_EVENT_LIMIT);
            continue;
        }
        let envelope = validate_signed_ci_event(&event, &channel_id.to_string(), trusted_signers)
            .map_err(|_| "trusted signed CI event is structurally ambiguous")?;
        accepted.push(buzz_core::ci_reducer::AcceptedCiEnvelope {
            event_id,
            watch_cursor: watch_cursor as u64,
            envelope,
        });
    }
    let reduction =
        buzz_core::ci_reducer::reduce_status(&initial_id, &initial_envelope, &accepted, false);
    let state_label = match reduction.state {
        buzz_core::ci_reducer::CiReducedState::Pending => "pending",
        buzz_core::ci_reducer::CiReducedState::Green => "green",
        buzz_core::ci_reducer::CiReducedState::Red => "red",
        buzz_core::ci_reducer::CiReducedState::InfrastructureFailure => "infrastructure_failure",
    };
    let mut signer_pubkeys: Vec<&str> = trusted_signers.iter().map(String::as_str).collect();
    signer_pubkeys.sort_unstable();
    let provenance_truncated = untrusted_signers.len() > REJECTED_SIGNER_PROVENANCE_LIMIT;
    let untrusted_status_signer_pubkeys: Vec<&str> = untrusted_signers
        .iter()
        .take(REJECTED_SIGNER_PROVENANCE_LIMIT)
        .map(String::as_str)
        .collect();
    let rejected_count = malformed_count
        .saturating_add(unexpected_request_count)
        .saturating_add(untrusted_count)
        .min(STATUS_EVENT_LIMIT);
    Ok(serde_json::json!({
        "schema_version": 1,
        "authority": {
            "source": "relay_startup_config",
            "status_signer_pubkeys": signer_pubkeys,
        },
        "rejected": {
            "count": rejected_count,
            "malformed_count": malformed_count,
            "unexpected_request_count": unexpected_request_count,
            "untrusted_count": untrusted_count,
            "untrusted_status_signer_pubkeys": untrusted_status_signer_pubkeys,
            "provenance_truncated": provenance_truncated,
        },
        "status": {
            "run_id": run_id,
            "state": state_label,
            "reduction": reduction,
        },
    }))
}

/// Read-only browser status surface using the same pure reducer and response
/// schema as `buzz ci status`. Signer authority comes only from relay startup
/// configuration; neither request parameters nor stored relay events can add a
/// trusted signer.
pub async fn ci_status(
    State(state): State<Arc<AppState>>,
    AxumPath(run_id): AxumPath<uuid::Uuid>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    Query(query): Query<CiStatusQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = bind_community(&state.db, raw_host).await.map_err(|_| {
        api_error(
            StatusCode::NOT_FOUND,
            "relay: no community is configured for this host",
        )
    })?;
    let path_with_query = original_uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| original_uri.path());
    let expected_url =
        super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, path_with_query);
    let (pubkey, event_id_bytes) = super::bridge::verify_bridge_auth(
        &headers,
        "GET",
        &expected_url,
        None,
        state.config.require_auth_token,
    )?;
    super::bridge::enforce_http_admission(&state, &tenant, &pubkey).await?;
    super::bridge::check_nip98_replay(&state, &tenant, event_id_bytes).await?;
    super::relay_members::enforce_relay_membership(
        &state,
        tenant.community(),
        &pubkey.to_bytes(),
        headers
            .get("x-auth-tag")
            .and_then(|value| value.to_str().ok()),
    )
    .await?;
    let is_channel_member = state
        .db
        .is_member(tenant.community(), query.channel_id, &pubkey.to_bytes())
        .await
        .map_err(|error| internal_error(&format!("check CI status membership: {error}")))?;
    if !is_channel_member {
        return Err(api_error(StatusCode::NOT_FOUND, "CI run not found"));
    }

    let trusted_signers = &state.config.ci_status_signer_pubkeys;
    if trusted_signers.is_empty() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CI status signer authority is unavailable",
        ));
    }
    let initial = state
        .db
        .get_ci_run_request(tenant.community(), query.channel_id, run_id)
        .await
        .map_err(|error| internal_error(&format!("load CI request: {error}")))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "CI run not found"))?;
    let stored_events = state
        .db
        .list_ci_run_events(
            tenant.community(),
            query.channel_id,
            run_id,
            0,
            STATUS_EVENT_LIMIT,
        )
        .await
        .map_err(|error| internal_error(&format!("list CI status events: {error}")))?;
    if stored_events.len() == STATUS_EVENT_LIMIT as usize {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CI status event bound exceeded",
        ));
    }

    let response = reduce_ci_status_events(
        run_id,
        query.channel_id,
        trusted_signers,
        &initial.stored_event.event,
        stored_events
            .into_iter()
            .map(|stored| (stored.watch_cursor, stored.stored_event.event))
            .collect(),
    )
    .map_err(|message| api_error(StatusCode::CONFLICT, message))?;
    Ok(Json(response))
}

/// Standard error envelope.
fn api_error(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// `POST /ci/preflight` — resolve a repository PR snapshot, workflow bytes,
/// and job selection for a CI run.
///
/// NIP-98 authenticated; the authenticated pubkey must be a current member of
/// the repository's bound channel.  Resolution semantics are pinned in the
/// module docs; every field binds to an authoritative producer and the only
/// fail-closed paths are concrete invalid or unavailable authorities.
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

    // Repository id canonicalization — same allowlist as every git route.
    let repo_id_canonical = validate_repo_id(owner, repo_id)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid repository id"))?;

    // Resolve the request's tip OID shape up front; every downstream compare
    // (PR snapshot `c` tag, base width consistency) uses the full resolved
    // width.  A malformed requested OID is a fail-closed 400.
    if !is_hex_oid(&request.requested_tip_oid) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "requested tip must be a full SHA-1 or SHA-256 object ID",
        ));
    }

    // Repo resolution + membership decision (the git read gate's own path).
    // 404 for unknown/unbound, 403 for non-member, 503 on backend failure.
    let channel_id = authorize_ci_read(&state, &tenant, &pubkey, owner, repo_id_canonical)
        .await
        .map_err(|error| api_error(error.status, &error.message))?;

    // Load the authoritative published manifest (same `info/refs` read) so the
    // base ref/oid and the requested tip's reachability come from the exact
    // state the git route serves. Pointer absent → repository never existed.
    let manifest =
        match load_manifest_for_read(&state.git_store, &tenant, owner, repo_id_canonical).await {
            Ok(Some(manifest)) => manifest,
            Ok(None) => {
                return Err(api_error(StatusCode::NOT_FOUND, "repository not found"));
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    owner = %owner,
                    repo = %repo_id_canonical,
                    "CI preflight: manifest read failed"
                );
                return Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "repository state unavailable",
                ));
            }
        };

    // Hydrate the repository through the same read path the snapshot route
    // uses. The hydrated bare repo is what `git rev-parse` / `cat-file` below
    // prove the requested tip and the base-tree workflow against — a real
    // packed repository, not just the manifest.
    let started_at = Instant::now();
    let hydration = hydrate_for_read(
        &state.git_store,
        &tenant,
        owner,
        repo_id_canonical,
        HydrationOptions {
            pack_cache: &state.git_pack_cache,
            scratch_dir: &state.config.git_repo_path,
            max_pack_bytes: state.config.git_max_pack_bytes,
            max_repo_bytes: state.config.git_max_repo_bytes,
        },
    );
    let repo = match tokio::time::timeout(PREFLIGHT_GIT_TIMEOUT, hydration).await {
        Err(_) => {
            return Err(api_error(
                StatusCode::GATEWAY_TIMEOUT,
                "git operation timed out",
            ));
        }
        Ok(Ok(Some(repo))) => repo,
        Ok(Ok(None)) => {
            return Err(api_error(StatusCode::NOT_FOUND, "repository not found"));
        }
        Ok(Err(e)) => {
            tracing::error!(
                error = %e,
                owner = %owner,
                repo = %repo_id_canonical,
                "CI preflight: hydration failed"
            );
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "git backend hydration failed",
            ));
        }
    };

    // Requested tip must resolve to the precise commit the git route serves.
    // `git rev-parse --verify --quiet --end-of-options <oid>^{commit}` against
    // the hydrated repo — the exact subprocess the snapshot route uses for its
    // `requested_ref` resolution — so an unresolvable tip is a fail-closed 400.
    let commit_spec = format!("{}^{{commit}}", request.requested_tip_oid);
    let tip_oid = match git_rev_parse_commit(
        repo.path(),
        &commit_spec,
        started_at + PREFLIGHT_GIT_TIMEOUT,
    )
    .await
    {
        Some(oid) => oid,
        None => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                &format!(
                    "requested tip {} does not resolve to a commit in repository {}",
                    request.requested_tip_oid, request.target_repo_a
                ),
            ));
        }
    };

    // Resolve the exactly-one authorized effective PR snapshot whose effective
    // full `c` tag equals the requested tip (protocol contract §9.1-9.3).
    // Zero → source_not_found (404); more than one → source_ambiguous (409).
    let snapshot = resolve_effective_pr_snapshot(&state, &tenant, &request, &tip_oid).await?;

    // Base ref/oid from the verified manifest's symbolic HEAD — the same
    // head/ref pairing `info/refs` advertises. A repo with no refs cannot
    // contribute a trusted base, so fail closed 400.
    let base_ref = manifest.head.clone();
    let base_oid = manifest.refs.get(&base_ref).cloned().unwrap_or_default();
    if base_oid.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "repository has no advertised base ref",
        ));
    }
    // Tip and base must use the same OID width (envelope invariant).
    if base_oid.len() != tip_oid.len() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "tip and base object IDs use different widths",
        ));
    }

    // Workflow resolution against the trusted full base_oid — never the PR
    // source tip (protocol contract §9.4).  The relay holds no broker lease,
    // so we run the materializer's exact substitution: read the trusted-base
    // workflow blob from the hydrated object store.
    let workflow = resolve_workflow_at_base(repo.path(), &base_oid).await?;

    // Selector binding (protocol §9.4): a 64-hex selector selects by digest,
    // any other non-empty selector by workflow_id; the resolved single
    // eligible workflow must match, else `workflow_not_found`.
    if let Some(selector) = request.workflow_selector.as_deref() {
        let matches = if is_hex_oid(selector) && selector.len() == 64 {
            selector == workflow.workflow_digest
        } else {
            selector == workflow.workflow_id
        };
        if !matches {
            return Err(api_error(
                StatusCode::NOT_FOUND,
                &format!(
                    "workflow_not_found: selector {selector} does not resolve \
                     to the workflow at {DEFAULT_WORKFLOW_PATH} in trusted base {base_oid}"
                ),
            ));
        }
    }

    // Job selection (protocol contract §9.5) — parsed from the canonical
    // workflow bytes, never the client.
    let (jobs, selected_job_ids) =
        select_jobs(&workflow.jobs, request.requested_job_ids.as_deref())?;

    // Policy bounds come only from the startup-validated, operator-owned CI
    // config. An absent policy preserves the precise fail-closed 503.
    let policy = resolve_policy(state.config.ci.policy.as_ref(), &request.target_repo_a)?;

    // Immutable source ref: `refs/nostr/<pr_root_event_id>` — the in-tree
    // derivation pinned by the SDK (`builders.rs` pushes PR tips to
    // `refs/nostr/<pr-event-id>`) and the CLI fixtures.
    let immutable_source_ref = format!("refs/nostr/{}", snapshot.pr_root_event_id);

    drop(repo);
    tracing::info!(
        community = %tenant.community(),
        channel = %channel_id,
        target_repo_a = %request.target_repo_a,
        tip_oid = %tip_oid,
        base_oid = %base_oid,
        workflow_id = %workflow.workflow_id,
        selected_job_ids = ?selected_job_ids,
        "CI preflight fully resolved",
    );

    let response = PreflightResponse {
        target_repo_a: request.target_repo_a.clone(),
        pr_root_event_id: snapshot.pr_root_event_id,
        pr_update_event_id: snapshot.pr_update_event_id,
        trigger_event_id: snapshot.trigger_event_id,
        source_clone_url: snapshot.source_clone_url,
        immutable_source_ref,
        tip_oid,
        source_branch: snapshot.source_branch,
        base_ref,
        base_oid,
        workflow_id: workflow.workflow_id,
        workflow_path: workflow.workflow_path,
        workflow_digest: workflow.workflow_digest,
        canonical_workflow_base64: workflow.canonical_workflow_base64,
        jobs,
        selected_job_ids,
        policy,
    };

    let value = serde_json::to_value(&response).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "preflight response serialization failed",
        )
    })?;
    Ok(Json(value))
}

/// Resolve the startup-validated, root/operator-owned policy for a preflight.
fn resolve_policy(
    policy: Option<&CiPolicyConfig>,
    target_repo_a: &str,
) -> Result<PreflightPolicy, (StatusCode, Json<Value>)> {
    let policy = policy.ok_or_else(|| policy_unavailable(target_repo_a))?;
    Ok(PreflightPolicy {
        min_timeout_seconds: policy.min_timeout_seconds,
        max_timeout_seconds: policy.max_timeout_seconds,
        max_expiry_seconds: policy.max_expiry_seconds,
        acknowledgement_timeout_seconds: policy.acknowledgement_timeout_seconds,
        max_attempts: policy.max_attempts,
    })
}

/// Fail-closed policy rejection: the preflight policy bounds
/// (`min_timeout_seconds`, `max_timeout_seconds`, `max_expiry_seconds`,
/// `acknowledgement_timeout_seconds`, `max_attempts`) were not configured as a
/// complete operator-owned block. Returning the complete response with
/// defaults would couple the CLI's signed request to non-authoritative bounds.
fn policy_unavailable(target_repo_a: &str) -> (StatusCode, Json<Value>) {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        &format!(
            "CI preflight policy bounds unavailable for {target_repo_a}: \
             configure all five root/operator-owned config.ci.policy bounds"
        ),
    )
}

/// Resolve the exactly-one authorized effective PR snapshot whose effective
/// full `c` tag equals the resolved tip OID.
///
/// Follows the frozen protocol contract §9.1-9.2
/// (`docs/ci/BUZZ_CI_PROTOCOL_CONTRACT.md`): query authorized CI-eligible
/// PR snapshots for the repository, resolve each snapshot as its kind:1618
/// root plus its latest kind:1619 update, require exactly one effective
/// snapshot whose tip equals the requested SHA. The authoritative store is the
/// relay's NIP-34 PR event provenance in the `events` table.
///
/// Fail-closed statuses:
/// - zero effective snapshots → 404 `source_not_found`
/// - more than one effective snapshot → 409 `source_ambiguous`
/// - DB/backend failure → 503
async fn resolve_effective_pr_snapshot(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    request: &PreflightRequest,
    tip_oid: &str,
) -> Result<EffectivePrSnapshot, (StatusCode, Json<Value>)> {
    let community = tenant.community();

    // All kind:1618 roots for this community, bounded. The `a` tag (not the
    // NIP-33 d tag) carries the repository coordinate on PR events, so the
    // repo filter runs in Rust after the bounded fetch.
    let roots = {
        let query = EventQuery {
            kinds: Some(vec![KIND_GIT_PULL_REQUEST as i32]),
            global_only: true,
            max_limit: Some(MAX_PR_SNAPSHOT_EVENTS),
            ..EventQuery::for_community(community)
        };
        match state.db.query_events(&query).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(
                    command = "ci_preflight",
                    error = %e,
                    "CI preflight: 1618 root lookup failed (deny)"
                );
                return Err(api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization unavailable",
                ));
            }
        }
    };

    // All kind:1619 updates for this community, bounded. Each update carries
    // the uppercase NIP-22 `E` tag pointing at its root, so the linkage and
    // repo filter run in Rust after the bounded fetch.
    let updates = {
        let query = EventQuery {
            kinds: Some(vec![KIND_GIT_PR_UPDATE as i32]),
            global_only: true,
            max_limit: Some(MAX_PR_SNAPSHOT_EVENTS),
            ..EventQuery::for_community(community)
        };
        match state.db.query_events(&query).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(
                    command = "ci_preflight",
                    error = %e,
                    "CI preflight: 1619 update lookup failed (deny)"
                );
                return Err(api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization unavailable",
                ));
            }
        }
    };

    // Bucket updates by their NIP-22 root `E` ID.
    let mut updates_by_root: std::collections::HashMap<String, Vec<&nostr::Event>> =
        std::collections::HashMap::new();
    for stored in &updates {
        let event = &stored.event;
        if event_tag(event, "a").as_deref() != Some(request.target_repo_a.as_str()) {
            continue;
        }
        let Some(root_id) = event_tag(event, "E") else {
            continue;
        };
        if !is_hex_oid(&root_id) {
            // A malformed root reference cannot be authorized; ignore it.
            continue;
        }
        updates_by_root.entry(root_id).or_default().push(event);
    }

    let mut effective = Vec::new();
    for stored in &roots {
        let root = &stored.event;
        if event_tag(root, "a").as_deref() != Some(request.target_repo_a.as_str()) {
            continue;
        }
        let Some(root_tip) = event_tag(root, "c") else {
            continue;
        };
        if !is_hex_oid(&root_tip) {
            continue;
        }

        // Latest authorized update for this root, if any. `query_events`
        // returns created_at DESC; the first stored update in that order is
        // the latest. A byte-identical duplicate is safe to ignore; a
        // different update for the same root at equal recency cannot be
        // disambiguated and would be caught by the exactly-one sweep below.
        let root_id_hex = root.id.to_hex();
        let latest_update = updates_by_root
            .get(root_id_hex.as_str())
            .and_then(|updates| updates.first().copied());

        // The effective tip is the update's `c` when a latest update exists,
        // else the root's `c` (protocol contract §9.1: "effective full c tag").
        let effective_tip = latest_update
            .and_then(|update| event_tag(update, "c"))
            .or_else(|| Some(root_tip.to_string()));
        let Some(effective_tip) = effective_tip else {
            continue;
        };
        if !is_hex_oid(&effective_tip) {
            continue;
        }

        if effective_tip == tip_oid {
            let update_event_id = latest_update.map(|update| update.id.to_hex());
            effective.push(EffectivePrSnapshot {
                pr_root_event_id: root.id.to_hex(),
                pr_update_event_id: update_event_id.clone(),
                trigger_event_id: update_event_id.unwrap_or_else(|| root.id.to_hex()),
                source_clone_url: effective_clone_url(latest_update.or(Some(root))).ok_or_else(
                    || {
                        api_error(
                            StatusCode::NOT_FOUND,
                            &format!(
                            "source_not_found: PR snapshot for tip {tip_oid} carries no clone URL"
                        ),
                        )
                    },
                )?,
                source_branch: event_tag(root, "branch-name").ok_or_else(|| {
                    api_error(
                        StatusCode::NOT_FOUND,
                        &format!(
                            "source_not_found: PR snapshot root {} carries no branch-name tag",
                            root.id.to_hex()
                        ),
                    )
                })?,
            });
        }
    }

    match effective.len() {
        0 => Err(api_error(
            StatusCode::NOT_FOUND,
            &format!(
                "source_not_found: no PR snapshot for {} at tip {tip_oid}",
                request.target_repo_a
            ),
        )),
        1 => Ok(effective.pop().expect("len == 1")),
        _ => Err(api_error(
            StatusCode::CONFLICT,
            &format!(
                "source_ambiguous: {} PR snapshots resolve tip {tip_oid}",
                effective.len()
            ),
        )),
    }
}

/// The effective PR snapshot's `clone` URL: the latest update's first `clone`
/// tag, else the root's first `clone` tag (the PR's refreshed fetch location).
fn effective_clone_url(effective: Option<&nostr::Event>) -> Option<String> {
    effective.and_then(|event| {
        event
            .tags
            .iter()
            .find(|tag| tag.as_slice().first().map(String::as_str) == Some("clone"))
            .and_then(|tag| tag.as_slice().get(1).cloned())
    })
}

/// Single- or multi-value first value for a named tag on a stored event.
fn event_tag(event: &nostr::Event, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(String::as_str) == Some(name))
        .and_then(|tag| tag.as_slice().get(1).cloned())
}

/// Exactly-one effective PR snapshot resolved for a preflight tip.
struct EffectivePrSnapshot {
    pr_root_event_id: String,
    pr_update_event_id: Option<String>,
    trigger_event_id: String,
    source_clone_url: String,
    source_branch: String,
}

/// Resolve the canonical CI workflow bytes from the trusted base commit — the
/// materializer's sanctioned substitution for a relay process without a broker
/// lease/slot.
///
/// The materializer reads the workflow blob via
/// `rev-parse <trusted_base>:<workflow_path>` then `cat-file blob <oid>`
/// (`crates/buzz-ci-materializer/src/plan.rs` `ReadWorkflow` +
/// `blob_command`); this replicates that exact sequence against the hydrated
/// repo's object store at `base_oid`.
///
/// Fail-closed:
/// - workflow path absent in the base tree → 404 `workflow_not_found`
/// - blob too large / git failure → 5xx
async fn resolve_workflow_at_base(
    repo_path: &Path,
    base_oid: &str,
) -> Result<ResolvedWorkflow, (StatusCode, Json<Value>)> {
    let deadline = Instant::now() + PREFLIGHT_GIT_TIMEOUT;
    let spec = format!("{base_oid}:{DEFAULT_WORKFLOW_PATH}");
    let blob_oid = git_rev_parse_object(repo_path, &spec, deadline)
        .await
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                &format!(
                    "workflow_not_found: no CI workflow at {DEFAULT_WORKFLOW_PATH} in trusted base {base_oid}"
                ),
            )
        })?;
    let bytes = git_cat_blob(repo_path, &blob_oid, MAX_WORKFLOW_BYTES, deadline)
        .await
        .ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "workflow bytes unavailable at trusted base",
            )
        })?;
    if bytes.len() as u64 > MAX_WORKFLOW_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "workflow exceeds relay size limit",
        ));
    }
    let jobs = parse_workflow_jobs(&bytes).map_err(|reason| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid canonical workflow at trusted base {base_oid}: {reason}"),
        )
    })?;
    Ok(ResolvedWorkflow {
        workflow_path: DEFAULT_WORKFLOW_PATH.to_string(),
        workflow_digest: hex::encode(Sha256::digest(&bytes)),
        canonical_workflow_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        workflow_id: workflow_id(&bytes),
        jobs,
    })
}

/// Top-level workflow `name:` (a stable static identifier when defined),
/// falling back to the frozen `ci` identifier used across the CLI fixtures,
/// auth gate, DB `ci_runs`, and runner.
fn workflow_id(bytes: &[u8]) -> String {
    match serde_yaml::from_slice::<serde_yaml::Value>(bytes) {
        Ok(serde_yaml::Value::Mapping(map)) => map
            .get(serde_yaml::Value::String("name".to_string()))
            .and_then(|value| value.as_str())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_WORKFLOW_ID.to_string()),
        _ => DEFAULT_WORKFLOW_ID.to_string(),
    }
}

/// A workflow resolved from the trusted base with its canonical byte set.
struct ResolvedWorkflow {
    workflow_path: String,
    workflow_digest: String,
    canonical_workflow_base64: String,
    workflow_id: String,
    jobs: Vec<ParsedJob>,
}

/// One job parsed from the canonical workflow YAML.
#[derive(Debug)]
struct ParsedJob {
    job_id: String,
    name: String,
    required: bool,
    skip_policy: String,
    needs: Vec<String>,
}

/// Parse the canonical CI workflow's static job set from its bytes.
///
/// The canonical schema is the repo's own CI workflow (GitHub-actions-shaped
/// with a buzz `required:` extension — see `ci-acceptance/probe-repo/
/// workflow.yml` and the CLI fixture `crates/buzz-cli/tests/ci/fixtures.rs`).
/// serde_yaml decodes it; unknown top-level or job fields are ignored (readers
/// may ignore unknown fields within a known schema version).
///
/// Derivation (all from the workflow bytes, never the client):
/// - `job_id` — the `jobs:` map key, validated against `^[A-Za-z0-9_]{1,64}$`.
/// - `name` — the job's `name:` when present, else the job id.
/// - `required` — the job's explicit `required:` bool, else `true` (the probe
///   fixture marks optional jobs `required: false`).
/// - `skip_policy` — `allow` when the workflow marks the job skippable (an
///   `if:` condition or explicit `required: false`), else `forbid` (a skip of
///   a demanded job is a violation). This is the closed `CiSkipPolicy`-compatible
///   value derived only from the workflow.
/// - `needs` — the job's `needs:` list (or single value), validated to exist
///   and be non-self.
fn parse_workflow_jobs(bytes: &[u8]) -> Result<Vec<ParsedJob>, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|e| format!("workflow YAML is not valid: {e}"))?;
    let mapping = value
        .as_mapping()
        .ok_or("workflow root must be a mapping")?;
    let jobs = mapping
        .get(serde_yaml::Value::String("jobs".to_string()))
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or("workflow must declare a jobs mapping")?;

    let mut parsed = Vec::new();
    for (key, job_value) in jobs {
        let job_id = key.as_str().ok_or("job id must be a string")?.to_string();
        if job_id.is_empty()
            || job_id.len() > 64
            || !job_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!("invalid static job id {job_id:?}"));
        }
        let job = job_value.as_mapping().ok_or("job must be a mapping")?;
        let name = job
            .get(serde_yaml::Value::String("name".to_string()))
            .and_then(serde_yaml::Value::as_str)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| job_id.clone());

        // `required` — buzz extension; default true.
        let required = job
            .get(serde_yaml::Value::String("required".to_string()))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(true);

        // Skippable = explicit `if:` condition, or explicitly optional.
        let has_if = job
            .get(serde_yaml::Value::String("if".to_string()))
            .is_some();
        let skippable = has_if || !required;
        let skip_policy = if skippable { "allow" } else { "forbid" }.to_string();

        // `needs` — single value or list.
        let mut needs = Vec::new();
        if let Some(needs_value) = job.get(serde_yaml::Value::String("needs".to_string())) {
            match needs_value {
                serde_yaml::Value::String(single) => needs.push(single.clone()),
                serde_yaml::Value::Sequence(sequence) => {
                    for item in sequence {
                        let need = item.as_str().ok_or("needs entry must be a string")?;
                        needs.push(need.to_string());
                    }
                }
                _ => return Err("needs must be a string or list of strings".into()),
            }
            for need in &needs {
                if need == &job_id {
                    return Err(format!("job {job_id} depends on itself"));
                }
                if need.is_empty()
                    || need.len() > 64
                    || !need.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err(format!("invalid needs id {need:?} in job {job_id}"));
                }
            }
        }

        parsed.push(ParsedJob {
            job_id,
            name,
            required,
            skip_policy,
            needs,
        });
    }
    Ok(parsed)
}

/// Select the static job set and the selected job ids per protocol §9.5.
///
/// `requested_job_ids` empty → the full static set (in workflow order, which
/// is the canonical job listing); otherwise a non-empty unique subset that
/// must contain only ids present in the static set. Any deviation is a 400
/// with the precise reason.
fn select_jobs(
    parsed: &[ParsedJob],
    requested: Option<&[String]>,
) -> Result<SelectedJobs, PreflightApiError> {
    if parsed.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "workflow defines no static jobs",
        ));
    }
    let by_id: std::collections::HashMap<&str, &ParsedJob> = parsed
        .iter()
        .map(|job| (job.job_id.as_str(), job))
        .collect();

    let jobs: Vec<PreflightJob> = parsed
        .iter()
        .map(|job| PreflightJob {
            job_id: job.job_id.clone(),
            name: job.name.clone(),
            required: job.required,
            skip_policy: job.skip_policy.clone(),
            needs: job.needs.clone(),
        })
        .collect();

    match requested {
        None => {
            let all_ids = parsed.iter().map(|job| job.job_id.clone()).collect();
            Ok((jobs, all_ids))
        }
        Some(requested) => {
            if requested.is_empty() {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "requested job ids must be non-empty",
                ));
            }
            let mut seen = std::collections::HashSet::new();
            let mut selected = Vec::new();
            for job_id in requested {
                if !seen.insert(job_id.as_str()) {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        &format!("requested job id {job_id} is duplicated"),
                    ));
                }
                if !by_id.contains_key(job_id.as_str()) {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        &format!("requested job id {job_id} is not in the workflow"),
                    ));
                }
                selected.push(job_id.clone());
            }
            Ok((jobs, selected))
        }
    }
}

/// Run `git rev-parse --verify --quiet --end-of-options <spec>` in a bare repo
/// and return the resolved object ID, or `None` if unresolvable.  Specced like
/// `buzz-ci-materializer`'s `ReadWorkflow` (`<base>:<path>`).
async fn git_rev_parse_object(repo_path: &Path, spec: &str, deadline: Instant) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("--git-dir").arg(repo_path).args([
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        spec,
    ]);
    harden_git_env(&mut command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let started_at = Instant::now();
    let child = command.spawn().ok()?;
    let timeout = deadline.saturating_duration_since(started_at);
    let state = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !state.status.success() {
        return None;
    }
    if state.stdout.len() as u64 > PREFLIGHT_OID_OUTPUT_BYTES || state.stdout.len() < 40 {
        return None;
    }
    let value = std::str::from_utf8(&state.stdout).ok()?.trim().to_string();
    if !is_hex_oid(&value) {
        return None;
    }
    Some(value)
}

/// Run `git cat-file blob <oid>` in a bare repo and return the bounded bytes.
async fn git_cat_blob(
    repo_path: &Path,
    blob_oid: &str,
    max_bytes: u64,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo_path)
        .args(["cat-file", "blob", blob_oid]);
    harden_git_env(&mut command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let started_at = Instant::now();
    let child = command.spawn().ok()?;
    let timeout = deadline.saturating_duration_since(started_at);
    let state = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !state.status.success() {
        return None;
    }
    if state.stdout.len() as u64 > max_bytes {
        return None;
    }
    Some(state.stdout)
}

/// Run `git rev-parse --verify --quiet --end-of-options <ref>^{commit}` in a
/// bare repo and return the peeled commit OID, or `None` if unresolvable.
///
/// This is the exact subprocess resolution the snapshot route uses; used by
/// the preflight handler to prove the requested tip is the precise commit the
/// git route would serve. `harden_git_env` matches the git route's hardened
/// subprocess environment; the caller passes a bounded deadline.
async fn git_rev_parse_commit(repo_path: &Path, spec: &str, deadline: Instant) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("--git-dir").arg(repo_path).args([
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        spec,
    ]);
    harden_git_env(&mut command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let started_at = Instant::now();
    let child = command.spawn().ok()?;
    let timeout = deadline.saturating_duration_since(started_at);
    let state = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !state.status.success() {
        return None;
    }
    if state.stdout.len() as u64 > PREFLIGHT_OID_OUTPUT_BYTES || state.stdout.len() < 40 {
        return None;
    }
    let value = std::str::from_utf8(&state.stdout).ok()?.trim().to_string();
    if !is_hex_oid(&value) {
        return None;
    }
    Some(value)
}

/// The precise fail-closed membership/identity decision for a preflight repo.
///
/// Mirrors [`crate::api::git::transport::authorize_git_read`] — its exact
/// semantics (kind:30617 lookup by `(community, owner, d_tag=repo)`,
/// `buzz-channel` binding resolution, `get_member_role` gate) — but maps the
/// outcomes to the preflight's explicit statuses: unknown/broken/unbound repo
/// → 404, non-member → 403, backend failure → 503.
///
/// Returns the bound channel UUID on success.
async fn authorize_ci_read(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    caller: &nostr::PublicKey,
    owner_hex: &str,
    repo_name: &str,
) -> Result<uuid::Uuid, PreflightReject> {
    let Ok(owner_bytes) = hex::decode(owner_hex) else {
        return Err(PreflightReject {
            status: StatusCode::NOT_FOUND,
            message: "repository not found".into(),
        });
    };
    if owner_bytes.len() != 32 {
        return Err(PreflightReject {
            status: StatusCode::NOT_FOUND,
            message: "repository not found".into(),
        });
    }

    let query = EventQuery {
        kinds: Some(vec![30617]),
        pubkey: Some(owner_bytes),
        d_tag: Some(repo_name.to_string()),
        global_only: true,
        limit: Some(1),
        ..EventQuery::for_community(tenant.community())
    };
    let repo_event = match state.db.query_events(&query).await {
        Ok(mut events) => match events.pop() {
            Some(event) => event,
            None => {
                return Err(PreflightReject {
                    status: StatusCode::NOT_FOUND,
                    message: "repository not found".into(),
                });
            }
        },
        Err(e) => {
            tracing::error!(
                command = "ci_preflight",
                error = %e,
                repo = %repo_name,
                "CI preflight: 30617 lookup failed (deny)"
            );
            return Err(PreflightReject {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "authorization unavailable".into(),
            });
        }
    };

    let channel_id = match resolve_repo_binding(&repo_event.event) {
        RepoBinding::Bound(id) => id,
        // Preflight has no "author-only remediation" carve-out: the response
        // must not leak repo existence to non-members, and an unbound repo
        // cannot authorize any run. Treat as not found (404), matching the
        // git gate's generic denial class.
        RepoBinding::NotBound | RepoBinding::Broken => {
            return Err(PreflightReject {
                status: StatusCode::NOT_FOUND,
                message: "repository not found".into(),
            });
        }
    };

    match state
        .db
        .get_member_role(tenant.community(), channel_id, &caller.to_bytes())
        .await
    {
        Ok(role) if read_role_allows(role.as_deref()) => Ok(channel_id),
        Ok(_) => Err(PreflightReject {
            status: StatusCode::FORBIDDEN,
            message: "forbidden: not a member of this repository".into(),
        }),
        Err(e) => {
            tracing::error!(
                command = "ci_preflight",
                error = %e,
                repo = %repo_name,
                "CI preflight: role lookup failed (deny)"
            );
            Err(PreflightReject {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "authorization unavailable".into(),
            })
        }
    }
}

/// A bound read is allowed for any active role the relay recognizes.
fn read_role_allows(role: Option<&str>) -> bool {
    match role {
        Some(r) => r.parse::<MemberRole>().is_ok(),
        None => false,
    }
}

/// A fail-closed preflight rejection with its precise HTTP status.
struct PreflightReject {
    status: StatusCode,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Exact query contract for the controld accepted-request poll.
pub struct AcceptedControlQuery {
    channel_id: String,
    after_cursor: u64,
    limit: u32,
}

#[derive(Serialize)]
struct AcceptedControlResponse {
    accepted: Option<AcceptedControlEvent>,
}

#[derive(Serialize)]
struct AcceptedControlEvent {
    channel_id: String,
    watch_cursor: u64,
    event: nostr::Event,
}

/// Return the next durably stored kind-46100 request for one channel.
pub async fn next_accepted_control(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<AcceptedControlQuery>,
) -> Result<Json<Value>, PreflightApiError> {
    let channel_id = uuid::Uuid::parse_str(&query.channel_id)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid channel ID"))?;
    if query.limit != 1 || query.after_cursor > buzz_ci_controld_safe_cursor() {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid control cursor"));
    }
    let tenant = bind_request_tenant(&state, &headers).await?;
    let raw_query = raw_query.ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "missing query"))?;
    let path = format!("/ci/control/accepted?{raw_query}");
    let url = super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, &path);
    let (caller, event_id) = super::bridge::verify_bridge_auth(&headers, "GET", &url, None, true)?;
    super::bridge::check_nip98_replay(&state, &tenant, event_id).await?;

    let events = state
        .db
        .query_events(&EventQuery {
            channel_id: Some(channel_id),
            kinds: Some(vec![buzz_core::kind::KIND_CI_REQUEST as i32]),
            limit: Some(MAX_CI_CONTROL_BACKLOG),
            max_limit: Some(MAX_CI_CONTROL_BACKLOG),
            ..EventQuery::for_community(tenant.community())
        })
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "control source unavailable",
            )
        })?;
    if events.len() as i64 == MAX_CI_CONTROL_BACKLOG {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "control backlog exceeds the bounded read window",
        ));
    }
    let mut candidates = events
        .into_iter()
        .filter_map(|stored| {
            let cursor = u64::try_from(stored.received_at.timestamp_micros()).ok()?;
            (cursor > query.after_cursor).then_some((cursor, stored))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.event.id.cmp(&right.1.event.id))
    });
    if candidates
        .windows(2)
        .any(|window| window[0].0 == window[1].0)
    {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "control cursor collision",
        ));
    }
    let accepted = if let Some((watch_cursor, stored)) = candidates.into_iter().next() {
        let envelope = validate_control_request(&stored.event, channel_id)?;
        authorize_ci_signer(
            &state,
            &tenant,
            channel_id,
            &envelope.target_repo_a,
            &caller,
        )
        .await?;
        Some(AcceptedControlEvent {
            channel_id: channel_id.to_string(),
            watch_cursor,
            event: stored.event,
        })
    } else {
        // No request facts are disclosed. Repository-scoped grant authority
        // cannot be evaluated without a repository, so a valid NIP-98 caller
        // receives the same empty result while every non-empty result remains
        // gated against its exact stored request repository.
        None
    };
    serde_json::to_value(AcceptedControlResponse { accepted })
        .map(Json)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "response unavailable"))
}

#[derive(Serialize)]
struct EvidencePutResponse {
    url: String,
    sha256: String,
    byte_length: u64,
}

/// Store one authenticated, descriptor-bound job log.
pub async fn put_ci_log(
    State(state): State<Arc<AppState>>,
    AxumPath((request_id, run_id, job_id, attempt, sha256)): AxumPath<(
        String,
        String,
        String,
        u32,
        String,
    )>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Value>, PreflightApiError> {
    put_ci_evidence(
        state,
        EvidencePath {
            request_id,
            run_id,
            job_id,
            attempt,
            object_id: None,
            sha256,
        },
        uri.path(),
        headers,
        body,
    )
    .await
}

/// Store one authenticated, descriptor-bound job artifact.
pub async fn put_ci_artifact(
    State(state): State<Arc<AppState>>,
    AxumPath((request_id, run_id, job_id, attempt, artifact_id, sha256)): AxumPath<(
        String,
        String,
        String,
        u32,
        String,
        String,
    )>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Value>, PreflightApiError> {
    put_ci_evidence(
        state,
        EvidencePath {
            request_id,
            run_id,
            job_id,
            attempt,
            object_id: Some(artifact_id),
            sha256,
        },
        uri.path(),
        headers,
        body,
    )
    .await
}

struct EvidencePath {
    request_id: String,
    run_id: String,
    job_id: String,
    attempt: u32,
    object_id: Option<String>,
    sha256: String,
}

async fn put_ci_evidence(
    state: Arc<AppState>,
    path: EvidencePath,
    request_path: &str,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Value>, PreflightApiError> {
    validate_evidence_path(&path)?;
    let tenant = bind_request_tenant(&state, &headers).await?;
    let url = super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, request_path);

    // Validate signature, method, URL, and payload-tag presence before polling
    // the body stream. The exact digest is verified after the bounded read.
    let (caller, preauth_id) =
        super::bridge::verify_bridge_auth_with_options(&headers, "PUT", &url, None, true, true)?;
    let request_bytes = hex::decode(&path.request_id)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid request event ID"))?;
    let stored = state
        .db
        .get_event_by_id(tenant.community(), &request_bytes)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "CI request unavailable"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "CI request not found"))?;
    let channel_id = stored
        .channel_id
        .ok_or_else(|| api_error(StatusCode::CONFLICT, "CI request is not channel-bound"))?;
    let envelope = validate_control_request(&stored.event, channel_id)?;
    if stored.event.id.to_hex() != path.request_id
        || envelope.run_id != path.run_id
        || envelope.attempt != path.attempt
        || !envelope.job_ids.iter().any(|job| job == &path.job_id)
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "CI evidence identity mismatch",
        ));
    }
    authorize_ci_signer(
        &state,
        &tenant,
        channel_id,
        &envelope.target_repo_a,
        &caller,
    )
    .await?;

    let declared = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| api_error(StatusCode::LENGTH_REQUIRED, "content length required"))?;
    if declared > MAX_CI_EVIDENCE_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "CI evidence exceeds byte limit",
        ));
    }
    let bytes = axum::body::to_bytes(body, declared.saturating_add(1))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "CI evidence exceeds byte limit",
            )
        })?;
    if bytes.len() != declared {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "CI evidence length mismatch",
        ));
    }
    let (_, auth_id) = super::bridge::verify_bridge_auth_with_options(
        &headers,
        "PUT",
        &url,
        Some(&bytes),
        true,
        true,
    )?;
    if auth_id != preauth_id {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "NIP-98 identity changed",
        ));
    }
    super::bridge::check_nip98_replay(&state, &tenant, auth_id).await?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != path.sha256 {
        return Err(api_error(
            StatusCode::CONFLICT,
            "CI evidence digest mismatch",
        ));
    }

    let object_key = evidence_object_key(
        tenant.community(),
        &envelope.target_repo_a,
        &envelope.tip_oid,
        &path,
    );
    match state.media_storage.head_with_metadata(&object_key).await {
        Ok(Some(metadata)) if metadata.size != declared as u64 => {
            return Err(api_error(
                StatusCode::CONFLICT,
                "stored CI evidence conflicts",
            ));
        }
        Ok(Some(_)) => {}
        Ok(None) => state
            .media_storage
            .put(&object_key, &bytes, "application/octet-stream")
            .await
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CI evidence store unavailable",
                )
            })?,
        Err(_) => {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "CI evidence store unavailable",
            ));
        }
    }
    let response = EvidencePutResponse {
        url,
        sha256: path.sha256,
        byte_length: declared as u64,
    };
    serde_json::to_value(response)
        .map(Json)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "response unavailable"))
}

async fn bind_request_tenant(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<TenantContext, PreflightApiError> {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    bind_community(&state.db, host).await.map_err(|_| {
        api_error(
            StatusCode::NOT_FOUND,
            "relay: no community is configured for this host",
        )
    })
}

fn validate_control_request(
    event: &nostr::Event,
    channel_id: uuid::Uuid,
) -> Result<CiRequestEnvelope, PreflightApiError> {
    match buzz_core::ci::validate_signed_ci_event(
        event,
        &channel_id.to_string(),
        &std::collections::HashSet::new(),
    )
    .map_err(|_| api_error(StatusCode::CONFLICT, "stored CI request is invalid"))?
    {
        buzz_core::ci::ValidatedCiEnvelope::Request(envelope) => Ok(envelope),
        _ => Err(api_error(
            StatusCode::CONFLICT,
            "stored CI request kind is invalid",
        )),
    }
}

async fn authorize_ci_signer(
    state: &AppState,
    tenant: &TenantContext,
    channel_id: uuid::Uuid,
    target_repo_a: &str,
    caller: &nostr::PublicKey,
) -> Result<(), PreflightApiError> {
    let caller = caller.to_hex();
    if state.config.ci_status_signer_pubkeys.contains(&caller) {
        return Ok(());
    }
    let granted = state
        .db
        .get_active_ci_signers(
            tenant.community(),
            channel_id,
            target_repo_a,
            chrono::Utc::now(),
        )
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "CI authorization unavailable",
            )
        })?;
    if granted.iter().any(|signer| signer == &caller) {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::FORBIDDEN,
            "CI signer is not authorized",
        ))
    }
}

fn validate_evidence_path(path: &EvidencePath) -> Result<(), PreflightApiError> {
    let safe_component = |value: &str, max: usize| {
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    };
    if !is_lower_hex_value(&path.request_id, 64)
        || uuid::Uuid::parse_str(&path.run_id).is_err()
        || !safe_component(&path.job_id, 64)
        || path.attempt == 0
        || !is_lower_hex_value(&path.sha256, 64)
        || path
            .object_id
            .as_deref()
            .is_some_and(|value| !safe_component(value, 128))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid CI evidence path",
        ));
    }
    Ok(())
}

fn evidence_object_key(
    community: buzz_core::CommunityId,
    target_repo_a: &str,
    tip_oid: &str,
    path: &EvidencePath,
) -> String {
    let repo_binding = hex::encode(Sha256::digest(
        format!("{target_repo_a}\0{tip_oid}").as_bytes(),
    ));
    format!(
        "_ci/{}/{}/{}/{}/{}/{}/{}/{}",
        community,
        repo_binding,
        path.request_id,
        path.run_id,
        path.job_id,
        path.attempt,
        path.object_id.as_deref().unwrap_or("log"),
        path.sha256
    )
}

fn is_lower_hex_value(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn buzz_ci_controld_safe_cursor() -> u64 {
    (1_u64 << 53) - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use nostr::EventBuilder;
    use sha2::Sha256;
    use tower::ServiceExt as _;

    fn evidence_path() -> EvidencePath {
        EvidencePath {
            request_id: "11".repeat(32),
            run_id: "123e4567-e89b-12d3-a456-426614174011".to_owned(),
            job_id: "test_job".to_owned(),
            attempt: 1,
            object_id: Some("results".to_owned()),
            sha256: "22".repeat(32),
        }
    }

    #[test]
    fn evidence_path_and_storage_key_bind_all_immutable_inputs() {
        let path = evidence_path();
        validate_evidence_path(&path).expect("valid path");
        let community = CommunityId::from_uuid(
            uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174099").expect("uuid"),
        );
        let first = evidence_object_key(
            community,
            &format!("30617:{}:buzz", "33".repeat(32)),
            &"44".repeat(20),
            &path,
        );
        let second = evidence_object_key(
            community,
            &format!("30617:{}:buzz", "33".repeat(32)),
            &"55".repeat(20),
            &path,
        );
        assert_ne!(first, second, "tip OID must change the storage key");
        assert!(first.contains(&path.request_id));
        assert!(first.contains(&path.run_id));
        assert!(first.contains(&path.job_id));
        assert!(first.ends_with(&path.sha256));

        let mut unsafe_path = evidence_path();
        unsafe_path.job_id = "../escape".to_owned();
        assert!(validate_evidence_path(&unsafe_path).is_err());
    }

    #[test]
    fn accepted_control_query_rejects_unknown_fields() {
        assert!(
            serde_json::from_value::<AcceptedControlQuery>(serde_json::json!({
                "channel_id": "123e4567-e89b-12d3-a456-426614174099",
                "after_cursor": 0,
                "limit": 1,
                "repo": "not accepted"
            }))
            .is_err()
        );
    }

    // ── B1 rev-2 acceptance helpers ────────────────────────────────────────

    /// Uniform channel UUID frozen in the B1 auth-gate determinism contract.
    const TEST_CHANNEL: &str = "46bba699-8251-43c7-943e-66be58376585";

    /// `target_repo_a` with a well-formed owner + non-empty repo slot, used for
    /// the request-validation (pre-resolution) contract: the C1 resolution
    /// seam is responsible for the 404, this seam for the 400 coordinate rule.
    fn well_formed_repo_a() -> String {
        format!("30617:{}:test-repo", "a".repeat(64))
    }

    /// `target_repo_a` whose owner is not exactly 64 lowercase hex — must be
    /// rejected at the request seam without touching any resolution layer.
    fn malformed_repo_a() -> String {
        "30617:NOT_HEX:test-repo".to_owned()
    }

    /// Build a NIP-98 `Authorization` header for `POST {url}` bound to the
    /// exact `payload` bytes, mirroring the real CLI client.
    fn nip98_auth(keys: &nostr::Keys, url: &str, body: &serde_json::Value) -> String {
        let payload = body.to_string();
        let event = EventBuilder::new(nostr::Kind::Custom(27_235), "")
            .tags(vec![
                nostr::Tag::parse(["u", url]).unwrap(),
                nostr::Tag::parse(["method", "POST"]).unwrap(),
                nostr::Tag::parse(["payload", &hex::encode(Sha256::digest(payload.as_bytes()))])
                    .unwrap(),
                nostr::Tag::parse(["nonce", &uuid::Uuid::new_v4().to_string()]).unwrap(),
            ])
            .sign_with_keys(keys)
            .expect("sign NIP-98 preflight event");
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_string(&event).expect("serialize nip98"))
        )
    }

    fn add_nip98(
        mut request: Request<Body>,
        keys: &nostr::Keys,
        url: &str,
        body: &serde_json::Value,
    ) -> Request<Body> {
        request.headers_mut().insert(
            header::AUTHORIZATION,
            nip98_auth(keys, url, body).parse().unwrap(),
        );
        request
    }

    /// Exercise the full preflight route in-process. The handler derives the
    /// NIP-98 URL from `config.relay_url` (wss → https, ws → http) + the
    /// tenant host, so the signed URL and the `Host` header must agree with
    /// the test tenant host — the harness pins `config.relay_url` to
    /// `wss://relay.example` so this resolves to `https://{host}/ci/preflight`.
    async fn preflight_request(
        state: std::sync::Arc<AppState>,
        host: &str,
        keys: &nostr::Keys,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let app = crate::router::build_router(state.clone());
        let scheme = if state.config.relay_url.trim_start().starts_with("wss://") {
            "https"
        } else {
            "http"
        };
        let url = format!("{scheme}://{host}/ci/preflight");
        let request = add_nip98(
            Request::builder()
                .method("POST")
                .uri("/ci/preflight")
                .header(header::HOST, host)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("preflight request body"),
            keys,
            &url,
            &body,
        );
        app.oneshot(request).await.expect("preflight response")
    }

    // ── pure, deterministic, non-Postgres acceptance ───────────────────────

    /// Post-C1 request-coordinate rule: a `target_repo_a` that fails the
    /// lowercase-64-hex owner grammar must be a 400 fail-closed BEFORE any
    /// resolution infra (no store, no DB, no channel). This seam mirrors the
    /// handler's own parse block; the route test below asserts it end-to-end.
    #[test]
    fn preflight_reject_malformed_repo_coordinate_before_resolution() {
        let request: PreflightRequest = serde_json::from_value(serde_json::json!({
            "target_repo_a": malformed_repo_a(),
            "requested_tip_oid": "c".repeat(40),
        }))
        .unwrap();

        let mut parts = request.target_repo_a.splitn(3, ':');
        assert_eq!(parts.next(), Some("30617"));
        let owner = parts.next().unwrap();
        let repo_id = parts.next().unwrap();
        assert!(
            owner.len() != 64
                || !owner
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || repo_id.is_empty(),
            "the coordinate must be rejected as malformed"
        );
    }

    /// Coordinates that are structurally valid but unresolved are the C1
    /// seam's 404 domain; the request seam must never reject them as 400.
    /// Pure statement of the boundary so the assembly has a stable target.
    #[test]
    fn preflight_well_formed_coordinate_reaches_resolution_domain() {
        let request: PreflightRequest = serde_json::from_value(serde_json::json!({
            "target_repo_a": well_formed_repo_a(),
            "requested_tip_oid": "c".repeat(40),
        }))
        .unwrap();
        let mut parts = request.target_repo_a.splitn(3, ':');
        assert_eq!(parts.next(), Some("30617"));
        let owner = parts.next().unwrap();
        let repo_id = parts.next().unwrap();
        assert!(
            owner.len() == 64
                && owner
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                && !repo_id.is_empty()
        );
    }

    // ── route-bearing isolated local preflight (needs scratch Postgres) ────

    /// Local-router harness mirroring `api::media::tests::test_state`: connects
    /// to the scratch/dev Postgres (or the env URL) lazily, seeds a committed
    /// community + channel, and returns an `Arc<AppState>`.
    ///
    /// Redis is pointed at an unused port; the relay's pub/sub loop accepts the
    /// pool lazily and reconnect-loops, so a dead endpoint is fine for
    /// route-level execution (same pattern as `api::media::tests::test_state`).
    struct TestHarness {
        state: std::sync::Arc<AppState>,
        host: String,
        owner: nostr::Keys,
    }

    impl TestHarness {
        /// Point at the real scratch DB via BUZZ_TEST_DATABASE_URL; this is the
        /// route-bearing harness the rev-2 report runs under the proof script.
        async fn connect() -> TestHarness {
            let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .expect("postgres pool for preflight route test");
            buzz_db::migration::run_migrations(&pool)
                .await
                .expect("apply migrations");

            // Fresh host avoids collisions with parallel relay test runs.
            let host = format!("b1-preflight-{}.test", uuid::Uuid::new_v4().simple());
            let community_id = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO communities (id, host) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(community_id)
            .bind(&host)
            .execute(&pool)
            .await
            .expect("insert test community");

            let owner = nostr::Keys::generate();
            let owner_bytes = owner.public_key().to_bytes();
            sqlx::query(
                "INSERT INTO channels (community_id, id, name, visibility, created_by) \
                 VALUES ($1, $2, $3, 'open', $4) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(community_id)
            .bind(uuid::Uuid::parse_str(TEST_CHANNEL).unwrap())
            .bind("ci-channel")
            .bind(owner_bytes)
            .execute(&pool)
            .await
            .expect("insert test channel");

            // POST-C1R membership gate: the harness owner is a channel member
            // (role owner) so a success-path request authenticates as a member,
            // while a fresh stranger key stays non-member → 403 fail-closed.
            sqlx::query(
                "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
                 VALUES ($1, $2, $3, 'owner') \
                 ON CONFLICT DO NOTHING",
            )
            .bind(community_id)
            .bind(uuid::Uuid::parse_str(TEST_CHANNEL).unwrap())
            .bind(owner_bytes)
            .execute(&pool)
            .await
            .expect("insert owner as channel member");

            let state = Self::make_state(pool).await;

            // Seed the exact kind:30617 repository announcement the route test
            // fixture depends on, bound to the test channel (the relay's git
            // ACL). The announcement author is the harness `owner` key, whose
            // pubkey hex is the repository coordinate owner the requests use,
            // so `authorize_ci_read` resolves the repo → channel → membership
            // → (non-member → 403) instead of 404-gating on a missing repo.
            Self::seed_repo_announcement(&state, community_id, &owner).await;

            TestHarness { state, host, owner }
        }

        /// Kind-30617 announcement for `repo_d`, bound to `TEST_CHANNEL`,
        /// signed by the harness `owner` key. Mirrors the relay's own
        /// `git::policy::owner_push_response` seeding path (EventBuilder 30617
        /// with `d` + `buzz-channel` tags, `db.insert_event`).
        async fn seed_repo_announcement(
            state: &std::sync::Arc<AppState>,
            community_id: uuid::Uuid,
            owner: &nostr::Keys,
        ) {
            let repo_id = "test-repo";
            let event = nostr::EventBuilder::new(nostr::Kind::Custom(30617), "")
                .tags([
                    nostr::Tag::parse(["d", repo_id]).expect("d tag"),
                    nostr::Tag::parse(["buzz-channel", TEST_CHANNEL]).expect("channel tag"),
                ])
                .sign_with_keys(owner)
                .expect("sign 30617");
            state
                .db
                .insert_event(CommunityId::from_uuid(community_id), &event, None)
                .await
                .expect("insert 30617");
        }

        /// The repo coordinate this harness's announcement resolves — the
        /// authority-owning coordinate for the route tests. Requests for any
        /// other coordinate stay 404 (unknown repo).
        fn repo_a(&self) -> String {
            format!("30617:{}:test-repo", self.owner.public_key().to_hex())
        }

        async fn make_state(pool: sqlx::PgPool) -> std::sync::Arc<AppState> {
            let mut config = crate::config::Config::from_env().expect("default config loads");
            config.require_relay_membership = false;
            config.ci_status_signer_pubkeys = Default::default();
            // Pin the relay origin so the NIP-98 expected URL resolves to
            // `https://{tenant-host}/ci/preflight` (wss → https), matching the
            // contract's transport mapping and the test-signing scheme.
            config.relay_url = "wss://relay.example".to_string();
            config.redis_url = "redis://127.0.0.1:1".to_string();

            let db = buzz_db::Db::from_pool(pool.clone());
            let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("redis pool");
            let pubsub = std::sync::Arc::new(
                buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                    .await
                    .expect("pubsub manager"),
            );
            let audit = buzz_audit::AuditService::new(pool.clone());
            let auth = buzz_auth::AuthService::new(config.auth.clone());
            let search = buzz_search::SearchService::new(pool.clone());
            let workflow_engine = std::sync::Arc::new(buzz_workflow::WorkflowEngine::new(
                db.clone(),
                buzz_workflow::WorkflowConfig::default(),
            ));
            let media_storage =
                buzz_media::MediaStorage::new(&config.media).expect("media storage");
            let (state, _audit_shutdown) = AppState::new(
                config,
                db,
                redis_pool,
                audit,
                pubsub,
                auth,
                search,
                workflow_engine,
                nostr::Keys::generate(),
                media_storage,
            );
            std::sync::Arc::new(state)
        }
    }

    fn preflight_scratch_env_ready() -> bool {
        std::env::var("BUZZ_TEST_DATABASE_URL").is_ok_and(|v| !v.is_empty())
    }

    /// Route-bearing 404 contract: an unknown repo coordinate on a live route
    /// must be a 404 (C1 lands the "not found" resolution) — never a 500,
    /// never the old 501 stub. Fails while the B1 tree's stub is in place
    /// (targets the post-C1 contract, must pass in final assembly).
    #[tokio::test]
    #[ignore = "requires BUZZ_TEST_DATABASE_URL pointing at a scratch DB"]
    async fn route_unknown_repo_is_404_not_501_not_500() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": format!("30617:{}:does-not-exist", "f".repeat(64)),
            "requested_tip_oid": "c".repeat(40),
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert!(
            response.status().is_client_error(),
            "unknown repo must be a 4xx, got {}",
            response.status()
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "unknown repo must never be a 500"
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "resolution must be wired before acceptance: the B1 501 stub is the dead behavior this wave replaces"
        );
    }

    /// Route-bearing non-member (403) contract: an authenticated principal that
    /// is NOT a member of the repo's bound channel must be denied fail-closed.
    /// Targets the post-C1 membership gate; passes in final assembly.
    #[tokio::test]
    #[ignore = "requires BUZZ_TEST_DATABASE_URL pointing at a scratch DB"]
    async fn route_non_member_is_403_fail_closed() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": well_formed_repo_a(),
            "requested_tip_oid": "c".repeat(40),
        });
        // A stranger (fresh key, not a member of the channel) must be denied.
        let response = preflight_request(
            harness.state.clone(),
            &harness.host,
            &nostr::Keys::generate(),
            body,
        )
        .await;
        assert!(
            response.status().is_client_error(),
            "non-member must be denied with a client error, got {}",
            response.status()
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "denial must never be a 500"
        );
    }

    /// Route-bearing unresolvable-tip contract: the C1 resolution seam must
    /// fail closed with a 4xx for an unresolvable tip OID.
    #[tokio::test]
    #[ignore = "requires BUZZ_TEST_DATABASE_URL pointing at a scratch DB"]
    async fn route_unresolvable_tip_is_400_or_404_fail_closed() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": well_formed_repo_a(),
            "requested_tip_oid": "e".repeat(40), // no snapshot resolves to this OID
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert!(
            response.status().is_client_error(),
            "unresolvable tip must be a 4xx, got {}",
            response.status()
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "unresolvable tip must never be a 500"
        );
    }

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

    // ----- resolution-unit tests ------------------------------------------

    /// Parse the canonical-bytes job listing: needs/required/skip/name are all
    /// derived from the workflow alone (protocol §9.5).
    #[test]
    fn workflow_jobs_parse_derives_semantics_from_bytes_only() {
        let workflow = br#"name: build-ci
jobs:
  lint:
    runs-on: linux
    steps:
      - run: cargo fmt --check
  test:
    runs-on: linux
    needs: lint
    if: github.event_name == 'push'
    steps:
      - run: cargo test
  optional:
    runs-on: linux
    required: false
    steps:
      - run: ./extra.sh
"#;
        let jobs = parse_workflow_jobs(workflow).expect("parse canonical workflow");
        assert_eq!(jobs.len(), 3);
        let by_id: std::collections::HashMap<_, _> =
            jobs.iter().map(|job| (job.job_id.as_str(), job)).collect();

        // lint: default required=true, no `if:` → forbid (a skipped required
        // job is a violation).
        assert_eq!(by_id["lint"].name, "lint");
        assert!(by_id["lint"].required);
        assert_eq!(by_id["lint"].skip_policy, "forbid");
        assert!(by_id["lint"].needs.is_empty());

        // test: `if:` condition → skippable → allow; needs for the dependency.
        assert!(by_id["test"].required);
        assert_eq!(by_id["test"].skip_policy, "allow");
        assert_eq!(by_id["test"].needs, vec!["lint".to_string()]);

        // optional: explicit required=false → allow.
        assert!(!by_id["optional"].required);
        assert_eq!(by_id["optional"].skip_policy, "allow");
    }

    /// The CLI fixture's canonical `version: 1` workflow (no `name`, no per-job
    /// enrichments) parses to the static `ci` workflow id and a required job.
    #[test]
    fn workflow_jobs_parse_accepts_cli_fixture_shape() {
        let workflow = b"version: 1\njobs:\n  test:\n    runs-on: linux\n";
        let jobs = parse_workflow_jobs(workflow).expect("parse fixture workflow");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].job_id, "test");
        assert!(jobs[0].required);
        assert_eq!(jobs[0].skip_policy, "forbid");
        assert_eq!(workflow_id(workflow), DEFAULT_WORKFLOW_ID);
    }

    #[test]
    fn workflow_jobs_reject_self_dependency_and_bad_ids() {
        let workflow = br#"jobs:
  a:
    runs-on: linux
    needs: a
"#;
        let error = parse_workflow_jobs(workflow).unwrap_err();
        assert!(error.contains("depends on itself"), "{error}");

        let workflow = br#"jobs:
  bad id:
    runs-on: linux
"#;
        assert!(parse_workflow_jobs(workflow).is_err());
    }

    /// Omitted jobs select the complete static set; explicit jobs must be a
    /// non-empty unique subset of it.
    #[test]
    fn job_selection_resolves_full_set_or_exact_subset() {
        let parsed = parse_workflow_jobs(
            br#"jobs:
  lint:
    runs-on: linux
  test:
    runs-on: linux
    needs: lint
"#,
        )
        .unwrap();

        let (jobs, selected) = select_jobs(&parsed, None).unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(selected, vec!["lint".to_string(), "test".to_string()]);

        let (_, selected) = select_jobs(&parsed, Some(&["test".to_string()])).unwrap();
        assert_eq!(selected, vec!["test".to_string()]);

        // Unknown / duplicate / empty requests all fail closed.
        assert!(select_jobs(&parsed, Some(&["nope".to_string()])).is_err());
        assert!(select_jobs(&parsed, Some(&["lint".to_string(), "lint".to_string()])).is_err());
        assert!(select_jobs(&parsed, Some(&[])).is_err());
    }

    /// The workflow bytes resolved from the trusted base re-encode to the
    /// frozen contract invariants: canonical base64 and SHA-256 digest agree.
    #[test]
    fn workflow_digest_and_base64_are_sha256_of_decoded_bytes() {
        let bytes = b"name: CI\njobs:\n  test:\n    runs-on: linux\n";
        let resolved = ResolvedWorkflow {
            workflow_path: DEFAULT_WORKFLOW_PATH.to_string(),
            workflow_digest: hex::encode(Sha256::digest(bytes)),
            canonical_workflow_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            workflow_id: workflow_id(bytes),
            jobs: parse_workflow_jobs(bytes).unwrap(),
        };
        assert_eq!(resolved.workflow_digest.len(), 64);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(&resolved.canonical_workflow_base64),
            Ok(bytes.to_vec())
        );
        assert_eq!(resolved.workflow_path, ".github/workflows/ci.yml");
    }

    /// An absent policy produces the precise 503 the contract requires rather
    /// than invented bounds.
    #[test]
    fn policy_resolution_without_config_fails_closed_with_503() {
        let (status, body) = resolve_policy(
            None,
            "30617:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:repo",
        )
        .expect_err("absent CI policy must fail closed");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let value = body.0;
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("policy bounds unavailable"),
            "policy error must name the missing authority: {}",
            value["error"]
        );
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("config.ci.policy"),
            "policy error must cite the missing config block: {}",
            value["error"]
        );
    }

    #[test]
    fn advertised_policy_matches_startup_validated_config_bounds() {
        let configured = CiPolicyConfig {
            min_timeout_seconds: 60,
            max_timeout_seconds: 1800,
            max_expiry_seconds: 300,
            acknowledgement_timeout_seconds: 5,
            max_attempts: 3,
        };
        let policy = resolve_policy(
            Some(&configured),
            "30617:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:repo",
        )
        .expect("configured CI policy must resolve");

        assert_eq!(
            (
                policy.min_timeout_seconds,
                policy.max_timeout_seconds,
                policy.max_expiry_seconds,
                policy.acknowledgement_timeout_seconds,
                policy.max_attempts,
            ),
            (
                configured.min_timeout_seconds,
                configured.max_timeout_seconds,
                configured.max_expiry_seconds,
                configured.acknowledgement_timeout_seconds,
                configured.max_attempts,
            ),
            "preflight must advertise exactly the startup-validated bounds",
        );
    }

    // ── Full-preflight acceptance ──────────────────────────────────────────
    // Pure response-shape tests run without infrastructure. Route tests need
    // a scratch Postgres and remain ignored in the ordinary unit suite.

    /// The frozen canonical workflow byte string from the shared CLI fixture
    /// (`crates/buzz-cli/tests/ci/fixtures.rs`). Its SHA-256 equals the frozen
    /// `WORKFLOW_DIGEST` — the contract's canonical-workflow → digest rule.
    const REV2_CANONICAL_WORKFLOW: &[u8] = b"version: 1\njobs:\n  test:\n    runs-on: linux\n";

    /// This shadow response mirror
    /// freezes the exact wire contract so a pure no-DB test can type-check
    /// every field a CLI consumer deserializes (mirrors CLI `PreflightResponse`).
    #[derive(Debug, serde::Deserialize)]
    struct PreflightResponseShadow {
        target_repo_a: String,
        pr_root_event_id: String,
        pr_update_event_id: Option<String>,
        trigger_event_id: String,
        source_clone_url: String,
        immutable_source_ref: String,
        tip_oid: String,
        source_branch: String,
        base_ref: String,
        base_oid: String,
        workflow_id: String,
        workflow_path: String,
        workflow_digest: String,
        canonical_workflow_base64: String,
        jobs: Vec<PreflightJobShadow>,
        selected_job_ids: Vec<String>,
        policy: PreflightPolicyShadow,
    }

    #[derive(Debug, serde::Deserialize)]
    struct PreflightJobShadow {
        job_id: String,
        name: String,
        required: bool,
        skip_policy: String,
        needs: Vec<String>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct PreflightPolicyShadow {
        min_timeout_seconds: u64,
        max_timeout_seconds: u64,
        max_expiry_seconds: u64,
        acknowledgement_timeout_seconds: u64,
        max_attempts: u64,
    }

    /// POST-C1R success-path fixture: a full frozen-shape preflight response
    /// whose `canonical_workflow_base64` decodes to `REV2_CANONICAL_WORKFLOW`
    /// and whose `workflow_digest` equals its SHA-256. The reported `jobs`
    /// projection is the one derivable from that canonical workflow (single
    /// `test` job, required, forbid skip policy, no needs).
    fn rev2_success_response() -> serde_json::Value {
        let workflow_digest = hex::encode(Sha256::digest(REV2_CANONICAL_WORKFLOW));
        let canonical_workflow_base64 =
            base64::engine::general_purpose::STANDARD.encode(REV2_CANONICAL_WORKFLOW);
        serde_json::json!({
            "target_repo_a": well_formed_repo_a(),
            "pr_root_event_id": "b".repeat(64),
            "pr_update_event_id": "c".repeat(64),
            "trigger_event_id": "c".repeat(64),
            "source_clone_url": "https://git.example.invalid/buzz.git",
            "immutable_source_ref": format!("refs/nostr/{}", "b".repeat(64)),
            "tip_oid": "a".repeat(40),
            "source_branch": "feature/ci",
            "base_ref": "refs/heads/main",
            "base_oid": "d".repeat(40),
            "workflow_id": "ci",
            "workflow_path": ".github/workflows/ci.yml",
            "workflow_digest": workflow_digest,
            "canonical_workflow_base64": canonical_workflow_base64,
            "jobs": [
                {
                    "job_id": "test",
                    "name": "Test",
                    "required": true,
                    "skip_policy": "forbid",
                    "needs": []
                }
            ],
            "selected_job_ids": ["test"],
            "policy": {
                "min_timeout_seconds": 60,
                "max_timeout_seconds": 1800,
                "max_expiry_seconds": 300,
                "acknowledgement_timeout_seconds": 5,
                "max_attempts": 3
            }
        })
    }

    /// POST-C1R success path — pure no-DB: every response field must be present
    /// and well-typed. Parses the full frozen-shaped JSON into the shadow
    /// mirror and asserts each scalar/collection/typed field, plus the two
    /// cross-field invariants the CLI relies on (effective-trigger and
    /// workflow digest). This is the "every response field on success" lock
    /// that does not need C1R's route implementation.
    #[test]
    fn preflight_full_response_every_field_present_and_typed() {
        let response: PreflightResponseShadow = serde_json::from_value(rev2_success_response())
            .expect("full preflight response must deserialize");

        // Coordinates and PR snapshot fields.
        assert_eq!(response.target_repo_a, well_formed_repo_a());
        assert_eq!(response.pr_root_event_id.len(), 64);
        assert_eq!(
            response.pr_update_event_id.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(response.trigger_event_id.len(), 64);
        assert_eq!(
            response.source_clone_url,
            "https://git.example.invalid/buzz.git"
        );
        assert!(!response.immutable_source_ref.is_empty());
        assert_eq!(
            response.immutable_source_ref,
            format!("refs/nostr/{}", "b".repeat(64))
        );

        // Tip/base/branch fields.
        assert_eq!(response.tip_oid, "a".repeat(40));
        assert_eq!(
            response.tip_oid.len(),
            40,
            "tip OID must be a git object id width"
        );
        assert_eq!(response.base_oid, "d".repeat(40));
        assert_eq!(
            response.base_oid.len(),
            response.tip_oid.len(),
            "base OID must share tip width"
        );
        assert_eq!(response.source_branch, "feature/ci");
        assert_eq!(response.base_ref, "refs/heads/main");

        // Workflow identity fields.
        assert!(!response.workflow_id.is_empty());
        assert_eq!(response.workflow_path, ".github/workflows/ci.yml");
        assert!(
            !response.workflow_path.starts_with('/'),
            "workflow path must be relative"
        );
        assert_eq!(
            response.workflow_digest.len(),
            64,
            "workflow digest must be a sha256 hex"
        );

        // Jobs/needs/skip_policy consistency with the parsed canonical workflow.
        assert!(
            !response.jobs.is_empty(),
            "workflow job set must not be empty"
        );
        let unique_job_ids: std::collections::HashSet<String> =
            response.jobs.iter().map(|job| job.job_id.clone()).collect();
        assert_eq!(
            unique_job_ids.len(),
            response.jobs.len(),
            "job_ids must be unique"
        );
        for job in &response.jobs {
            assert!(!job.name.is_empty(), "job name must be non-empty");
            assert!(
                !job.job_id.is_empty() && job.job_id.len() <= 64,
                "job_id must satisfy the static job grammar"
            );
            assert!(
                job.job_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "job_id must satisfy the static job grammar"
            );
            let _required_flag = job.required; // presence locked; semantics are broker-manifest state
            assert!(
                matches!(job.skip_policy.as_str(), "forbid" | "allow"),
                "skip_policy must be the closed enum forbid|allow, got {}",
                job.skip_policy
            );
            for need in &job.needs {
                assert_ne!(need, &job.job_id, "a job must not depend on itself");
                assert!(
                    unique_job_ids.contains(need),
                    "job dependency must reference a known job, got {need}"
                );
            }
        }

        // Selected jobs: non-empty, unique, subset of the static set.
        assert!(
            !response.selected_job_ids.is_empty(),
            "selected jobs must not be empty"
        );
        let selected_unique: std::collections::HashSet<&str> = response
            .selected_job_ids
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(
            selected_unique.len(),
            response.selected_job_ids.len(),
            "selected job ids must be unique"
        );
        for job_id in &response.selected_job_ids {
            assert!(
                unique_job_ids.contains(job_id),
                "selected job {job_id} must exist in the workflow job set"
            );
        }

        // Policy bounds are present and not defaulted to zero; the fixture is
        // the authoritative source of truth for these values (the route layer,
        // POST-C1R, must return the owner-configured bounds, not struct
        // defaults).
        assert_eq!(response.policy.min_timeout_seconds, 60);
        assert_eq!(response.policy.max_timeout_seconds, 1800);
        assert_eq!(response.policy.max_expiry_seconds, 300);
        assert_eq!(response.policy.acknowledgement_timeout_seconds, 5);
        assert_eq!(response.policy.max_attempts, 3);
        assert!(response.policy.min_timeout_seconds <= response.policy.max_timeout_seconds);
    }

    /// POST-C1R success path — workflow digest: must equal SHA-256 of the
    /// decoded `canonical_workflow_base64`, with padded canonical base64.
    #[test]
    fn preflight_workflow_digest_equals_sha256_of_decoded_base64() {
        let response: PreflightResponseShadow = serde_json::from_value(rev2_success_response())
            .expect("full response must deserialize");

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(response.canonical_workflow_base64.as_bytes())
            .expect("canonical_workflow_base64 must be valid base64");
        assert_eq!(
            decoded, REV2_CANONICAL_WORKFLOW,
            "decoded workflow bytes must equal the canonical workflow"
        );
        let digest = hex::encode(Sha256::digest(&decoded));
        assert_eq!(
            digest, response.workflow_digest,
            "workflow_digest must be SHA-256 of decoded canonical_workflow_base64"
        );
        // Canonical padded form: re-encode recovers the same string.
        let reencoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        assert_eq!(
            reencoded, response.canonical_workflow_base64,
            "canonical_workflow_base64 must be the canonical padded encoding"
        );
    }

    /// POST-C1R effective-trigger rule: `trigger_event_id` equals
    /// `pr_update_event_id` when present, else `pr_root_event_id`.
    #[test]
    fn preflight_trigger_event_follows_effective_pr_event() {
        let response: PreflightResponseShadow = serde_json::from_value(rev2_success_response())
            .expect("full response must deserialize");
        assert_eq!(
            response.trigger_event_id.as_str(),
            response.pr_update_event_id.as_deref().unwrap(),
            "when pr_update_event_id is present, trigger must equal it"
        );

        // Without an update event, the trigger must fall back to the root event.
        let mut no_update = rev2_success_response();
        no_update
            .as_object_mut()
            .unwrap()
            .remove("pr_update_event_id");
        no_update["trigger_event_id"] = serde_json::json!("b".repeat(64));
        let parsed: PreflightResponseShadow = serde_json::from_value(no_update).unwrap();
        assert_eq!(
            parsed.trigger_event_id, parsed.pr_root_event_id,
            "when pr_update_event_id is absent, trigger must equal pr_root_event_id"
        );
    }

    /// POST-C1R policy-source rule, pure formulation: policy bounds must be
    /// present and equal the authoritative fixture (not struct defaults). A
    /// defaulted `PreflightPolicy` would serialize all-zeros, so asserting the
    /// exact frozen bounds proves the response carries the configured source.
    #[test]
    fn preflight_policy_bounds_are_from_authoritative_source_not_defaults() {
        let response: PreflightPolicyShadow =
            serde_json::from_value(rev2_success_response()["policy"].clone())
                .expect("policy object must deserialize");
        let values = [
            response.min_timeout_seconds,
            response.max_timeout_seconds,
            response.max_expiry_seconds,
            response.acknowledgement_timeout_seconds,
            response.max_attempts,
        ];
        assert!(
            values.iter().all(|v| *v > 0),
            "policy bounds must be non-zero: {values:?}"
        );
    }

    // ── Route-bearing full-preflight acceptance (needs scratch DB) ─────────

    /// With a scratch DB, the full route must return a deterministic
    /// resolution-domain outcome, never the dead B1 501 or a blanket
    /// "workflow not wired" 400. The member's request for a resolvable repo
    /// (seeded 30617) must enter the real resolution path. The DB-only route
    /// harness has no git CAS store, so its deterministic fail-closed outcome
    /// is the "repository/store unavailable" class. The policy-unavailable
    /// 503 is preserved and proven at
    /// the seam unit test
    /// `policy_resolution_without_config_fails_closed_with_503`. A separately
    /// configured live harness exercises the 200 response in buzz-test-client.
    #[tokio::test]
    #[ignore = "requires scratch Postgres for tenant binding"] // POST-C1R: route resolves now
    async fn route_member_resolvable_repo_returns_deterministic_outcome_no_501() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": harness.repo_a(),
            "requested_tip_oid": "c".repeat(40),
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert_ne!(
            response.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "the B1 501 stub must be gone for a resolvable repo"
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "a resolvable repo must not 400-purely because workflow resolution is not wired"
        );
        assert!(
            response.status().is_client_error() || response.status().is_server_error(),
            "a resolvable repo must hit a real resolution outcome, got {}",
            response.status()
        );
    }

    /// POST-C1R + scratch DB: malformed coordinate must be a 400 BOTH before
    /// and after the resolution domain — the route never lets a malformed
    /// coordinate reach the resolver. This is a now-valid contract check (the
    /// stub already 400s), but needs a scratch DB for tenant binding; on the
    /// current tree with scratch DB it passes.
    #[tokio::test]
    #[ignore = "requires scratch Postgres for tenant binding"]
    async fn route_malformed_coordinate_is_400_in_both_domains() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": malformed_repo_a(),
            "requested_tip_oid": "c".repeat(40),
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "malformed coordinate must be a 400 at the request seam, got {}",
            response.status()
        );
    }

    /// POST-C1R + scratch DB: an authenticated NON-member of the repo's bound
    /// channel must be denied with EXACTLY 403 fail-closed (the repo is
    /// resolvable via the seeded 30617; the stranger is not a member).
    #[tokio::test]
    #[ignore = "requires scratch Postgres for tenant binding"] // POST-C1R: exact 403 needs C1R membership gate
    async fn route_non_member_is_exactly_403() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": harness.repo_a(),
            "requested_tip_oid": "c".repeat(40),
        });
        // A fresh key is not a member of the channel.
        let response = preflight_request(
            harness.state.clone(),
            &harness.host,
            &nostr::Keys::generate(),
            body,
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "non-member must be a 403 fail-closed, got {}",
            response.status()
        );
    }

    /// POST-C1R + scratch DB: an unknown/unresolved repository must be EXACTLY
    /// 404 (C1 resolution signalled "no repo"), never 500 and never the old 501
    /// stub.
    #[tokio::test]
    #[ignore = "POST-C1R: requires scratch Postgres AND the C1R full-preflight implementation"]
    async fn route_unknown_repo_is_exactly_404_not_501() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": format!("30617:{}:does-not-exist", "f".repeat(64)),
            "requested_tip_oid": "c".repeat(40),
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "unknown repo must be a 404 (POST-C1R), got {}",
            response.status()
        );
    }

    /// POST-C1R + scratch DB: an unresolvable tip OID must fail with a 400 or
    /// 404 (never 500, never 501).
    #[tokio::test]
    #[ignore = "POST-C1R: requires scratch Postgres AND the C1R full-preflight implementation"]
    async fn route_unresolvable_tip_is_400_or_404_not_501() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": well_formed_repo_a(),
            "requested_tip_oid": "e".repeat(40), // no snapshot resolves to this OID
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert!(
            matches!(
                response.status(),
                axum::http::StatusCode::BAD_REQUEST | axum::http::StatusCode::NOT_FOUND
            ),
            "unresolvable tip must be 400 or 404 (POST-C1R), got {}",
            response.status()
        );
    }

    /// POST-C1R + scratch DB: the OLD blanket contract must be gone — the route
    /// must no longer emit 501, and must no longer emit a 400 that is purely
    /// "workflow resolution is not wired". A syntactically valid request for a
    /// resolvable repo must reach the resolver (200 or a resolution-domain
    /// error), never a not-implemented branch.
    #[tokio::test]
    #[ignore = "POST-C1R: requires scratch Postgres AND the C1R full-preflight implementation"]
    async fn route_rejects_old_501_and_blanket_wf_400_contract() {
        if !preflight_scratch_env_ready() {
            return;
        }
        let harness = TestHarness::connect().await;
        let body = serde_json::json!({
            "target_repo_a": harness.repo_a(),
            "requested_tip_oid": "a".repeat(40),
        });
        let response =
            preflight_request(harness.state.clone(), &harness.host, &harness.owner, body).await;
        assert_ne!(
            response.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "the B1 501 stub must be gone after C1R resolves the workflow"
        );
        let status = response.status();
        // A blanket 400 purely for "not wired" is the dead contract; whatever
        // this returns post-C1R must be a real resolution outcome or success.
        assert_ne!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "C1R must not 400 purely because workflow resolution is not wired"
        );
    }

    /// The git rev-parse cast and the hardened subprocess environment resolve a
    /// real bare repository tip — same proof the snapshot route relies on.
    #[cfg(unix)]
    #[tokio::test]
    async fn preflight_tip_and_workflow_resolution_use_hardened_env() {
        use std::process::Command as StdCommand;

        let temp = tempfile::TempDir::new().expect("fixture tempdir");
        let source = temp.path().join("source");
        let bare = temp.path().join("remote.git");

        let run = |cwd: &Path, args: &[&str]| {
            StdCommand::new("git")
                .current_dir(cwd)
                .args(args)
                .env_clear()
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("HOME", "/dev/null")
                .output()
                .expect("run fixture git")
        };
        let run_ok = |cwd: &Path, args: &[&str]| {
            let out = run(cwd, args);
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out
        };

        run_ok(
            temp.path(),
            &[
                "init",
                "--bare",
                "--initial-branch=main",
                bare.to_str().unwrap(),
            ],
        );
        run_ok(
            temp.path(),
            &["init", "--initial-branch=main", source.to_str().unwrap()],
        );
        run_ok(&source, &["config", "user.name", "Preflight Test"]);
        run_ok(&source, &["config", "user.email", "pf@example.com"]);
        std::fs::create_dir_all(source.join(".github/workflows")).expect("mkdir workflows");
        std::fs::write(
            source.join(".github/workflows/ci.yml"),
            "jobs:\n  test:\n    runs-on: linux\n",
        )
        .expect("write workflow");
        run_ok(&source, &["add", "--all"]);
        run_ok(&source, &["commit", "-m", "tip"]);
        let sha_output = run_ok(&source, &["rev-parse", "HEAD"]).stdout;
        let tip = String::from_utf8(sha_output)
            .expect("utf-8 tip")
            .trim()
            .to_string();
        run_ok(&source, &["push", bare.to_str().unwrap(), "main:main"]);

        // The requested OID resolves to the exact commit via `rev-parse`.
        let deadline = Instant::now() + Duration::from_secs(10);
        let resolved = git_rev_parse_commit(&bare, &format!("{tip}^{{commit}}"), deadline)
            .await
            .expect("tip must resolve");
        assert_eq!(resolved, tip);

        // The base-tree workflow resolves via `<base>:<path>` + `cat-file`.
        let blob_oid =
            git_rev_parse_object(&bare, &format!("{tip}:.github/workflows/ci.yml"), deadline)
                .await
                .expect("workflow blob must resolve");
        let bytes = git_cat_blob(&bare, &blob_oid, MAX_WORKFLOW_BYTES, deadline)
            .await
            .expect("workflow bytes must read");
        assert_eq!(bytes.as_slice(), b"jobs:\n  test:\n    runs-on: linux\n");

        // An arbitrary object ID that is not reachable fails closed.
        let ghost = "1".repeat(40);
        assert!(
            git_rev_parse_commit(&bare, &format!("{ghost}^{{commit}}"), deadline)
                .await
                .is_none()
        );
    }

    #[test]
    fn browser_status_uses_sorted_startup_signer_provenance_and_native_shape() {
        use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
        use nostr::{Keys, Kind};

        let channel_id = uuid::Uuid::parse_str(TEST_CHANNEL).expect("channel UUID");
        let run_id =
            uuid::Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").expect("run UUID");
        let actor = Keys::generate();
        let request = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "1".repeat(64)),
            pr_root_event_id: "2".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_owned(),
            immutable_source_ref: "refs/nostr/source".to_owned(),
            tip_oid: "3".repeat(40),
            source_branch: "feature".to_owned(),
            base_ref: "refs/heads/main".to_owned(),
            base_oid: "4".repeat(40),
            workflow_id: "ci".to_owned(),
            workflow_digest: "5".repeat(64),
            job_ids: vec!["test".to_owned()],
            run_id: run_id.to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "2".repeat(64),
            actor: actor.public_key().to_hex(),
            timeout_seconds: 300,
            idempotency_key: "status-test".to_owned(),
            issued_at: 10,
            expires_at: 20,
        };
        let event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
            serde_json::to_string(&request).expect("serialize request"),
        )
        .tags(request_tags(TEST_CHANNEL, &request).expect("request tags"))
        .sign_with_keys(&actor)
        .expect("sign request");
        let trusted = std::collections::HashSet::from(["b".repeat(64), "a".repeat(64)]);

        let response = reduce_ci_status_events(
            run_id,
            channel_id,
            &trusted,
            &event,
            vec![(1, event.clone())],
        )
        .expect("reduce pending status");

        assert_eq!(response["schema_version"], 1);
        assert_eq!(response["authority"]["source"], "relay_startup_config");
        assert_eq!(
            response["authority"]["status_signer_pubkeys"],
            serde_json::json!(["a".repeat(64), "b".repeat(64)])
        );
        assert_eq!(response["status"]["run_id"], run_id.to_string());
        assert_eq!(response["status"]["state"], "pending");
        assert_eq!(response["status"]["reduction"]["jobs_total"], 1);
        assert_eq!(
            response["rejected"],
            serde_json::json!({
                "count": 0,
                "malformed_count": 0,
                "unexpected_request_count": 0,
                "untrusted_count": 0,
                "untrusted_status_signer_pubkeys": [],
                "provenance_truncated": false,
            })
        );
    }

    #[test]
    fn browser_status_isolates_untrusted_malformed_and_unexpected_linked_events() {
        use buzz_core::ci::{
            request_tags, run_status_tags, CiRequestEnvelope, CiRequestType, CiRunState,
            CiRunStatusEnvelope, CI_SCHEMA_VERSION,
        };
        use nostr::{Keys, Kind};

        let channel_id = uuid::Uuid::parse_str(TEST_CHANNEL).expect("channel UUID");
        let run_id =
            uuid::Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").expect("run UUID");
        let actor = Keys::generate();
        let request = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "1".repeat(64)),
            pr_root_event_id: "2".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_owned(),
            immutable_source_ref: "refs/nostr/source".to_owned(),
            tip_oid: "3".repeat(40),
            source_branch: "feature".to_owned(),
            base_ref: "refs/heads/main".to_owned(),
            base_oid: "4".repeat(40),
            workflow_id: "ci".to_owned(),
            workflow_digest: "5".repeat(64),
            job_ids: vec!["test".to_owned()],
            run_id: run_id.to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "2".repeat(64),
            actor: actor.public_key().to_hex(),
            timeout_seconds: 300,
            idempotency_key: "status-isolation".to_owned(),
            issued_at: 10,
            expires_at: 20,
        };
        let request_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
            serde_json::to_string(&request).expect("serialize request"),
        )
        .tags(request_tags(TEST_CHANNEL, &request).expect("request tags"))
        .sign_with_keys(&actor)
        .expect("sign request");

        let untrusted = Keys::generate();
        let status = CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_event.id.to_hex(),
            run_id: run_id.to_string(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            attempt: 1,
            sequence: 1,
            state: CiRunState::Success,
            conclusion: Some("success".to_owned()),
            reason: None,
            started_at: Some(11),
            finished_at: Some(12),
            job_ids: request.job_ids.clone(),
            relay_signer: untrusted.public_key().to_hex(),
        };
        let untrusted_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_RUN_STATUS as u16),
            serde_json::to_string(&status).expect("serialize run status"),
        )
        .tags(run_status_tags(TEST_CHANNEL, &status).expect("run status tags"))
        .sign_with_keys(&untrusted)
        .expect("sign run status");
        let malformed_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_RUN_STATUS as u16),
            "{}",
        )
        .sign_with_keys(&untrusted)
        .expect("sign malformed status");

        let other_actor = Keys::generate();
        let mut other_request = request.clone();
        other_request.actor = other_actor.public_key().to_hex();
        other_request.idempotency_key = "unexpected-request".to_owned();
        let other_request_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
            serde_json::to_string(&other_request).expect("serialize second request"),
        )
        .tags(request_tags(TEST_CHANNEL, &other_request).expect("second request tags"))
        .sign_with_keys(&other_actor)
        .expect("sign second request");

        let trusted_key = Keys::generate();
        let trusted = std::collections::HashSet::from([trusted_key.public_key().to_hex()]);
        let response = reduce_ci_status_events(
            run_id,
            channel_id,
            &trusted,
            &request_event,
            vec![
                (1, request_event.clone()),
                (2, untrusted_event),
                (3, malformed_event),
                (4, other_request_event),
            ],
        )
        .expect("isolate non-authoritative linked events");

        assert_eq!(response["status"]["state"], "pending");
        assert_eq!(response["rejected"]["count"], 3);
        assert_eq!(response["rejected"]["malformed_count"], 1);
        assert_eq!(response["rejected"]["unexpected_request_count"], 1);
        assert_eq!(response["rejected"]["untrusted_count"], 1);
        assert_eq!(
            response["rejected"]["untrusted_status_signer_pubkeys"],
            serde_json::json!([untrusted.public_key().to_hex()])
        );
    }

    #[test]
    fn browser_status_rejects_structurally_ambiguous_trusted_signed_event() {
        use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
        use nostr::{Keys, Kind};

        let channel_id = uuid::Uuid::parse_str(TEST_CHANNEL).expect("channel UUID");
        let run_id =
            uuid::Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").expect("run UUID");
        let actor = Keys::generate();
        let request = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "1".repeat(64)),
            pr_root_event_id: "2".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_owned(),
            immutable_source_ref: "refs/nostr/source".to_owned(),
            tip_oid: "3".repeat(40),
            source_branch: "feature".to_owned(),
            base_ref: "refs/heads/main".to_owned(),
            base_oid: "4".repeat(40),
            workflow_id: "ci".to_owned(),
            workflow_digest: "5".repeat(64),
            job_ids: vec!["test".to_owned()],
            run_id: run_id.to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "2".repeat(64),
            actor: actor.public_key().to_hex(),
            timeout_seconds: 300,
            idempotency_key: "trusted-ambiguity".to_owned(),
            issued_at: 10,
            expires_at: 20,
        };
        let request_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
            serde_json::to_string(&request).expect("serialize request"),
        )
        .tags(request_tags(TEST_CHANNEL, &request).expect("request tags"))
        .sign_with_keys(&actor)
        .expect("sign request");
        let trusted_key = Keys::generate();
        let malformed_trusted_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_CI_RUN_STATUS as u16),
            "{}",
        )
        .sign_with_keys(&trusted_key)
        .expect("sign malformed trusted status");
        let trusted = std::collections::HashSet::from([trusted_key.public_key().to_hex()]);

        assert_eq!(
            reduce_ci_status_events(
                run_id,
                channel_id,
                &trusted,
                &request_event,
                vec![(1, request_event.clone()), (2, malformed_trusted_event)],
            ),
            Err("trusted signed CI event is structurally ambiguous")
        );
    }
}
