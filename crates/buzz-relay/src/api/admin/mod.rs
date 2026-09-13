//! Private deployment moderation API.
//!
//! Reads are available in both auth modes. Mutations and the staffing routes
//! require a NIP-98 principal (see [`auth`]); in `disabled` mode they always
//! `403`. The exact admin `Host` and same-origin checks stay active as an
//! ingress layer behind the credential check.

mod auth;
mod error;
pub mod roster;

use std::sync::Arc;

use auth::{
    admin_role_str, admin_source_str, authorize, require_mutation_principal, require_operator,
};
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use error::ApiError;
use roster::StoredAdminRole;
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

pub(crate) use auth::admin_api_origin;
pub(crate) fn is_admin_host(state: &crate::state::AppState, headers: &HeaderMap) -> bool {
    auth::is_admin_host(state, headers)
}

/// Build the deployment-admin routes.
pub fn router(state: Arc<crate::state::AppState>) -> Router {
    Router::new()
        .route("/reports", get(reports))
        .route("/reports/{id}", get(report_detail))
        .route("/feedback", get(feedback))
        .route("/feedback/{id}", get(feedback_detail))
        .route(
            "/feedback/{id}/attachments/{sha256}",
            get(feedback_attachment),
        )
        .route("/probe", get(probe))
        .route("/operators", get(list_operators))
        .route(
            "/operators/{pubkey}",
            get(get_operator).put(put_operator).delete(delete_operator),
        )
        .layer(middleware::from_fn(security_headers))
        .layer(RequestBodyLimitLayer::new(1024))
        .with_state(state)
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportQuery {
    community_id: Option<Uuid>,
    status: Option<String>,
    report_type: Option<String>,
    target_kind: Option<String>,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: Option<i64>,
}

fn limit(value: Option<i64>) -> Result<i64, ApiError> {
    match value.unwrap_or(50) {
        value @ 1..=200 => Ok(value),
        _ => Err(ApiError::bad_request(
            "invalid_limit",
            "limit must be between 1 and 200",
        )),
    }
}

fn validate(value: Option<&str>, allowed: &[&str], code: &'static str) -> Result<(), ApiError> {
    if value.is_some_and(|value| !allowed.contains(&value)) {
        Err(ApiError::bad_request(code, "filter is invalid"))
    } else {
        Ok(())
    }
}

/// Request target (path plus query string) the NIP-98 `u` tag signs.
/// `OriginalUri` preserves the pre-nesting target including the query string.
fn request_target(uri: &OriginalUri) -> String {
    uri.0
        .path_and_query()
        .map(|target| target.as_str().to_owned())
        .unwrap_or_else(|| uri.0.path().to_owned())
}

async fn reports(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Query(query): Query<ReportQuery>,
) -> Result<Json<Vec<buzz_db::admin_moderation::AdminReport>>, ApiError> {
    authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    validate(
        query.status.as_deref(),
        &["open", "resolved", "dismissed", "escalated"],
        "invalid_status",
    )?;
    validate(
        query.target_kind.as_deref(),
        &["event", "pubkey", "blob"],
        "invalid_target_kind",
    )?;
    let items = state
        .db
        .admin_list_reports(
            query.community_id,
            query.status.as_deref(),
            query.report_type.as_deref(),
            query.target_kind.as_deref(),
            query.after,
            query.before,
            None,
            limit(query.limit)?,
        )
        .await?;
    Ok(Json(items))
}

async fn report_detail(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path(id): Path<Uuid>,
) -> Result<Json<buzz_db::admin_moderation::AdminReportDetail>, ApiError> {
    authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    state
        .db
        .admin_get_report(id)
        .await?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FeedbackSummary {
    id: Uuid,
    community_id: Uuid,
    community_host: String,
    submitter_pubkey: String,
    category: Option<String>,
    body_summary: String,
    received_at: DateTime<Utc>,
}

async fn feedback(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
) -> Result<Json<Vec<FeedbackSummary>>, ApiError> {
    authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    let items = state
        .db
        .admin_list_feedback(100)
        .await?
        .into_iter()
        .map(|item| {
            let body_summary = summarize_body(&item.body, &item.tags);
            FeedbackSummary {
                id: item.id,
                community_id: item.community_id,
                community_host: item.community_host,
                submitter_pubkey: item.submitter_pubkey,
                category: item.category,
                body_summary,
                received_at: item.received_at,
            }
        })
        .collect();
    Ok(Json(items))
}

async fn feedback_detail(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path(id): Path<Uuid>,
) -> Result<Json<buzz_db::admin_moderation::AdminFeedback>, ApiError> {
    authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    state
        .db
        .admin_get_feedback(id)
        .await?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn feedback_attachment(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path((id, sha256)): Path<(Uuid, String)>,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    if !is_sha256(&sha256) {
        return Err(ApiError::not_found());
    }

    let feedback = state
        .db
        .admin_get_feedback(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if !feedback_references_hash(&feedback.tags, &feedback.community_host, &sha256) {
        return Err(ApiError::not_found());
    }

    // Resolve the tenant from server-owned feedback provenance, then assert the
    // resolved row still agrees with the feedback FK. Client input never names
    // a community, host, object key, extension, or upstream URL.
    let tenant = crate::tenant::bind_community(&state.db, &feedback.community_host)
        .await
        .map_err(|_| ApiError::not_found())?;
    if tenant.community().as_uuid() != &feedback.community_id {
        tracing::warn!(
            feedback_id = %feedback.id,
            feedback_community_id = %feedback.community_id,
            resolved_community_id = %tenant.community(),
            "admin feedback attachment tenant provenance mismatch"
        );
        return Err(ApiError::not_found());
    }

    let response = crate::api::media::serve_blob_for_tenant(&state, &tenant, &sha256, &headers)
        .await
        .map_err(|error| match error {
            buzz_media::MediaError::NotFound => ApiError::not_found(),
            _ => ApiError::internal(),
        })?;
    tracing::info!(
        feedback_id = %feedback.id,
        community_id = %feedback.community_id,
        attachment_sha256 = %sha256,
        "admin feedback attachment read"
    );
    Ok(response)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeResponse {
    auth: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
    can_act: bool,
    can_staff: bool,
}

/// Describe the caller's admin grant: auth mode, resolved role, and what the
/// role may do. Clients probe this to decide whether to render staffing UI.
///
/// In NIP-98 mode this route requires a credential like every other route;
/// unauthenticated callers get `401`, which is itself the mode discovery
/// signal (`200` means `disabled`). In disabled mode it reports the mode with
/// no role and no capabilities.
async fn probe(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
) -> Result<Json<ProbeResponse>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    Ok(Json(match principal {
        None => ProbeResponse {
            auth: "disabled",
            role: None,
            source: None,
            can_act: false,
            can_staff: false,
        },
        Some(principal) => {
            let can_staff = principal.role == auth::AdminRole::Operator;
            ProbeResponse {
                auth: "nip98",
                role: Some(admin_role_str(principal.role)),
                source: Some(admin_source_str(&principal.source)),
                can_act: true,
                can_staff,
            }
        }
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorEntry {
    pubkey: String,
    role: &'static str,
    source: &'static str,
}

fn operator_entry(pubkey_hex: String, role: &'static str, source: &'static str) -> OperatorEntry {
    OperatorEntry {
        pubkey: pubkey_hex,
        role,
        source,
    }
}

/// Operator-only roster listing: the union of config grants, the active owner
/// fallback, and roster-store rows. Moderators cannot view the roster.
async fn list_operators(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
) -> Result<Json<Vec<OperatorEntry>>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    require_operator(&require_mutation_principal(principal)?)?;

    let mut entries: Vec<OperatorEntry> = state
        .config
        .relay_operator_pubkeys
        .iter()
        .map(|pubkey| operator_entry(pubkey.clone(), "operator", "config"))
        .collect();
    if state.config.relay_operator_pubkeys.is_empty() {
        if let Some(owner) = state.config.relay_owner_pubkey.as_deref() {
            entries.push(operator_entry(
                owner.to_owned(),
                "operator",
                "owner_fallback",
            ));
        }
    }
    for row in state.admin_roster.list_entries().await? {
        entries.push(operator_entry(row.pubkey_hex, row.role.as_str(), "db"));
    }
    Ok(Json(entries))
}

/// Operator-only single roster read. Moderators get `403`; unknown pubkeys
/// get `404` regardless of layer.
async fn get_operator(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<OperatorEntry>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    require_operator(&require_mutation_principal(principal)?)?;

    let target_hex = canonical_pubkey_param(&pubkey_hex)?;
    if state
        .config
        .relay_operator_pubkeys
        .iter()
        .any(|entry| entry == &target_hex)
    {
        return Ok(Json(operator_entry(target_hex, "operator", "config")));
    }
    if state.config.relay_operator_pubkeys.is_empty()
        && state.config.relay_owner_pubkey.as_deref() == Some(target_hex.as_str())
    {
        return Ok(Json(operator_entry(
            target_hex,
            "operator",
            "owner_fallback",
        )));
    }
    let target_bytes = hex_to_bytes32(&target_hex)?;
    match state.admin_roster.role_for_pubkey(&target_bytes).await? {
        Some(role) => Ok(Json(operator_entry(target_hex, role.as_str(), "db"))),
        None => Err(ApiError::not_found()),
    }
}

#[derive(Deserialize)]
struct StaffingBody {
    role: String,
}

/// Grant or replace a roster-store grant. Operator-only. Config-backed and
/// owner-fallback pubkeys are immutable through the API (`409`).
async fn put_operator(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path(pubkey_hex): Path<String>,
    body: Bytes,
) -> Result<Json<OperatorEntry>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        Some(&body),
    )
    .await?;
    let principal = require_mutation_principal(principal)?;
    require_operator(&principal)?;

    let payload: StaffingBody = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("invalid_body", "body must be {\"role\": ...}"))?;
    let role = StoredAdminRole::parse(payload.role.trim()).ok_or_else(|| {
        ApiError::bad_request("invalid_role", "role must be operator or moderator")
    })?;

    let target_hex = canonical_pubkey_param(&pubkey_hex)?;
    reject_config_backed(&state, &target_hex)?;
    let target_bytes = hex_to_bytes32(&target_hex)?;
    state
        .admin_roster
        .grant(&target_bytes, role, &principal.pubkey)
        .await?;
    Ok(Json(operator_entry(target_hex, role.as_str(), "db")))
}

/// Revoke a roster-store grant. Operator-only. Config-backed and
/// owner-fallback pubkeys are immutable through the API (`409`); revoking a
/// missing grant is a `404` and writes nothing.
async fn delete_operator(
    State(state): State<Arc<crate::state::AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: OriginalUri,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        &request_target(&uri),
        method.as_str(),
        None,
    )
    .await?;
    let principal = require_mutation_principal(principal)?;
    require_operator(&principal)?;

    let target_hex = canonical_pubkey_param(&pubkey_hex)?;
    reject_config_backed(&state, &target_hex)?;
    let target_bytes = hex_to_bytes32(&target_hex)?;
    if !state
        .admin_roster
        .revoke(&target_bytes, &principal.pubkey)
        .await?
    {
        return Err(ApiError::not_found());
    }
    Ok(Json(
        serde_json::json!({"pubkey": target_hex, "removed": true}),
    ))
}

/// Config-backed pubkeys (allowlist members and the active owner fallback)
/// cannot change through the API; only a config deployment changes them.
fn reject_config_backed(state: &crate::state::AppState, target_hex: &str) -> Result<(), ApiError> {
    if state
        .config
        .relay_operator_pubkeys
        .iter()
        .any(|entry| entry == target_hex)
    {
        return Err(ApiError::conflict(
            "pubkey is granted by deployment config and cannot change through the API",
        ));
    }
    if state.config.relay_operator_pubkeys.is_empty()
        && state.config.relay_owner_pubkey.as_deref() == Some(target_hex)
    {
        return Err(ApiError::conflict(
            "the owner fallback grant is immutable through the API",
        ));
    }
    Ok(())
}

/// Canonicalize a `{pubkey}` path parameter to lowercase hex before every
/// comparison and store write, so an uppercase spelling cannot bypass the
/// config immutability guard or shadow a row for the same 32 bytes.
fn canonical_pubkey_param(value: &str) -> Result<String, ApiError> {
    let canonical = value.trim().to_lowercase();
    if canonical.len() == 64 && canonical.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(canonical)
    } else {
        Err(ApiError::bad_request(
            "invalid_pubkey",
            "pubkey must be 64-char hex",
        ))
    }
}

fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str).map_err(|_| ApiError::internal())?;
    bytes.try_into().map_err(|_| ApiError::internal())
}

fn feedback_references_hash(tags: &serde_json::Value, community_host: &str, sha256: &str) -> bool {
    tags.as_array()
        .into_iter()
        .flatten()
        .filter_map(|tag| tag.as_array())
        .filter(|tag| tag.first().and_then(|value| value.as_str()) == Some("imeta"))
        .any(|tag| {
            let fields = tag
                .iter()
                .skip(1)
                .filter_map(|value| value.as_str()?.split_once(' '))
                .collect::<std::collections::HashMap<_, _>>();
            fields.get("x") == Some(&sha256)
                && fields
                    .get("url")
                    .is_some_and(|url| attachment_url_matches(url, community_host, sha256))
        })
}

fn attachment_url_matches(url: &str, community_host: &str, sha256: &str) -> bool {
    let parsed = if url.starts_with('/') {
        url::Url::parse(&format!("https://{community_host}{url}"))
    } else {
        url::Url::parse(url)
    };
    let Ok(url) = parsed else {
        return false;
    };
    let authority = url.port().map_or_else(
        || url.host_str().unwrap_or_default().to_string(),
        |port| format!("{}:{port}", url.host_str().unwrap_or_default()),
    );
    let Some(media_name) = url.path().strip_prefix("/media/") else {
        return false;
    };
    let Some((url_hash, extension)) = media_name.split_once('.') else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && buzz_core::tenant::normalize_host(&authority)
            == buzz_core::tenant::normalize_host(community_host)
        && url_hash == sha256
        && crate::api::media::is_safe_ext(extension)
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

fn summarize_body(body: &str, tags: &serde_json::Value) -> String {
    const MAX_CHARS: usize = 240;
    let attachment_urls = tags
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tag| tag.as_array())
        .filter(|tag| tag.first().and_then(|value| value.as_str()) == Some("imeta"))
        .flat_map(|tag| tag.iter().skip(1))
        .filter_map(|value| value.as_str()?.strip_prefix("url "))
        .collect::<std::collections::HashSet<_>>();
    let body = body
        .lines()
        .filter(|line| {
            let line = line.trim();
            let url = line
                .strip_suffix(')')
                .and_then(|line| line.rsplit_once("]("))
                .and_then(|(label, url)| {
                    (label.starts_with('[') || label.starts_with("![")).then_some(url)
                });
            url.is_none_or(|url| !attachment_urls.contains(url))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut chars = body.trim().chars();
    let mut summary = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        summary.push('…');
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn test_state_with_auth(auth: crate::config::AdminAuth) -> Arc<crate::state::AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth_service = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth_service,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    async fn test_state() -> Arc<crate::state::AppState> {
        test_state_with_auth(crate::config::AdminAuth::Disabled).await
    }

    const HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[tokio::test]
    async fn report_detail_requires_admin_host_before_database_access() {
        let response = router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri(format!("/reports/{}", Uuid::nil()))
                    .header(header::HOST, "community.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn report_detail_rejects_unknown_report() {
        let response = router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri(format!("/reports/{}", Uuid::nil()))
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn feedback_attachment_requires_admin_host_before_database_access() {
        let response = router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri(format!("/feedback/{}/attachments/{HASH}", Uuid::nil()))
                    .header(header::HOST, "community.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn feedback_attachment_rejects_unknown_feedback() {
        let response = router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri(format!("/feedback/{}/attachments/{HASH}", Uuid::nil()))
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn feedback_attachment_rejects_write_methods() {
        let state = test_state().await;
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("/feedback/{}/attachments/{HASH}", Uuid::nil()))
                        .header(header::HOST, "admin.example")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn probe_reports_disabled_mode_without_credential() {
        let response = router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        let probe: serde_json::Value = serde_json::from_slice(&body).expect("probe json");
        assert_eq!(probe["auth"], "disabled");
        assert_eq!(probe["canAct"], false);
        assert_eq!(probe["canStaff"], false);
    }

    #[tokio::test]
    async fn disabled_mode_reads_pass_but_staffing_is_forbidden() {
        let state = test_state().await;
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn nip98_mode_rejects_unauthenticated_reads_with_challenge() {
        let response = router(test_state_with_auth(crate::config::AdminAuth::Nip98).await)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Nostr")
        );
    }

    #[test]
    fn report_filters_reject_unknown_values() {
        assert!(validate(Some("open"), &["open"], "invalid_status").is_ok());
        assert!(validate(Some("unknown"), &["open"], "invalid_status").is_err());
    }

    #[test]
    fn feedback_summary_is_unicode_safe_and_marks_truncation() {
        let body = "🐝".repeat(241);
        let summary = summarize_body(&body, &serde_json::Value::Null);
        assert_eq!(summary.chars().count(), 241);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn feedback_summary_omits_imeta_attachment_lines() {
        let url = "http://localhost:3000/media/abc.png";
        let tags = serde_json::json!([["imeta", format!("url {url}"), "m image/png"]]);
        assert_eq!(
            summarize_body(&format!("Useful context.\n![image]({url})"), &tags),
            "Useful context."
        );
    }

    fn attachment_tags(host: &str, x: &str, url_hash: &str) -> serde_json::Value {
        serde_json::json!([[
            "imeta",
            format!("url https://{host}/media/{url_hash}.png"),
            "m image/png",
            format!("x {x}"),
            "size 100"
        ]])
    }

    #[test]
    fn feedback_attachment_requires_matching_imeta_hash_and_source_host() {
        let tags = attachment_tags("community.example", HASH, HASH);
        assert!(feedback_references_hash(&tags, "community.example", HASH));

        let unreferenced = "f".repeat(64);
        assert!(!feedback_references_hash(
            &tags,
            "community.example",
            &unreferenced
        ));
        assert!(!feedback_references_hash(
            &tags,
            "other-community.example",
            HASH
        ));
    }

    #[test]
    fn feedback_attachment_rejects_cross_field_and_path_substitution() {
        let other_hash = "f".repeat(64);
        assert!(!feedback_references_hash(
            &attachment_tags("community.example", HASH, &other_hash),
            "community.example",
            HASH
        ));

        for url in [
            format!("https://community.example/media/{HASH}.png?token=leak"),
            format!("https://community.example/media/{HASH}.thumb.jpg"),
            format!("https://community.example/media/{HASH}.png/extra"),
            format!("https://evil.example/media/{HASH}.png"),
        ] {
            assert!(!attachment_url_matches(&url, "community.example", HASH));
        }
    }

    #[test]
    fn feedback_attachment_accepts_valid_relative_source_url() {
        assert!(attachment_url_matches(
            &format!("/media/{HASH}.png"),
            "community.example",
            HASH
        ));
    }

    #[test]
    fn feedback_attachment_hash_is_exact_lowercase_sha256() {
        assert!(is_sha256(HASH));
        assert!(!is_sha256(&HASH.to_uppercase()));
        assert!(!is_sha256(&HASH[..63]));
        assert!(!is_sha256(&format!("{HASH}.png")));
    }

    #[test]
    fn staffing_pubkey_param_rejects_malformed_values() {
        assert!(canonical_pubkey_param(&"ab".repeat(32)).is_ok());
        assert!(canonical_pubkey_param(&"AB".repeat(32)).is_ok());
        assert!(canonical_pubkey_param("xyz").is_err());
        assert!(canonical_pubkey_param(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn uppercase_spelling_canonicalizes_to_the_same_grant() {
        let lower = canonical_pubkey_param(&"ab".repeat(32)).expect("lower");
        let upper = canonical_pubkey_param(&"AB".repeat(32)).expect("upper");
        assert_eq!(lower, upper);
    }
}

#[cfg(test)]
mod nip98_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use base64::Engine as _;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use super::roster::{AdminRosterStore, RosterEntry, RosterError, StoredAdminRole};
    use super::router;

    struct FreshReplayGuard;

    impl buzz_auth::Nip98ReplayGuard for FreshReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }
    }

    struct FailingReplayGuard;

    impl buzz_auth::Nip98ReplayGuard for FailingReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Err(buzz_auth::AuthError::Internal("redis down".to_string())) })
        }
    }

    /// First claim succeeds, every later claim reports a replay.
    struct OnceReplayGuard {
        used: std::sync::atomic::AtomicBool,
    }

    impl buzz_auth::Nip98ReplayGuard for OnceReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            let replayed = self.used.swap(true, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok(!replayed) })
        }
    }

    /// Records every claim attempt; proves rejected requests never consume a
    /// replay slot.
    struct CountingGuard {
        calls: Arc<Mutex<u32>>,
    }

    impl buzz_auth::Nip98ReplayGuard for CountingGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            let mut calls = self.calls.lock().expect("mutex");
            *calls += 1;
            Box::pin(async { Ok(true) })
        }
    }

    #[derive(Debug, Default)]
    struct TestRoster {
        grants: Mutex<HashMap<[u8; 32], StoredAdminRole>>,
    }

    #[async_trait::async_trait]
    impl AdminRosterStore for TestRoster {
        async fn role_for_pubkey(
            &self,
            pubkey: &[u8; 32],
        ) -> Result<Option<StoredAdminRole>, RosterError> {
            Ok(self
                .grants
                .lock()
                .expect("roster mutex")
                .get(pubkey)
                .copied())
        }

        async fn list_entries(&self) -> Result<Vec<RosterEntry>, RosterError> {
            Ok(self
                .grants
                .lock()
                .expect("roster mutex")
                .iter()
                .map(|(pubkey, role)| RosterEntry {
                    pubkey_hex: hex::encode(pubkey),
                    role: *role,
                    added_by_hex: None,
                })
                .collect())
        }

        async fn grant(
            &self,
            pubkey: &[u8; 32],
            role: StoredAdminRole,
            _added_by: &[u8; 32],
        ) -> Result<Option<String>, RosterError> {
            Ok(self
                .grants
                .lock()
                .expect("roster mutex")
                .insert(*pubkey, role)
                .map(|prev| prev.as_str().to_owned()))
        }

        async fn revoke(&self, pubkey: &[u8; 32], _actor: &[u8; 32]) -> Result<bool, RosterError> {
            Ok(self
                .grants
                .lock()
                .expect("roster mutex")
                .remove(pubkey)
                .is_some())
        }
    }

    fn admin_url(target: &str) -> String {
        format!("https://admin.example/api/admin/v1{target}")
    }

    fn nip98_header(
        keys: &Keys,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        with_payload_tag: bool,
        created_at: Option<Timestamp>,
    ) -> String {
        let mut tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", method]).expect("method tag"),
        ];
        if let Some(body) = body {
            if with_payload_tag {
                let hash: [u8; 32] = Sha256::digest(body).into();
                tags.push(Tag::parse(["payload", hex::encode(hash).as_str()]).expect("payload"));
            }
        }
        let mut builder = EventBuilder::new(Kind::HttpAuth, "").tags(tags);
        if let Some(ts) = created_at {
            builder = builder.custom_created_at(ts);
        }
        let event = builder.sign_with_keys(keys).expect("sign NIP-98 event");
        let json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
        )
    }

    async fn nip98_test_state(
        operator_keys: &[Keys],
        owner_key: Option<&Keys>,
        roster: Arc<dyn AdminRosterStore>,
        replay: Arc<dyn buzz_auth::Nip98ReplayGuard>,
    ) -> Arc<crate::state::AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        config.relay_operator_pubkeys = operator_keys
            .iter()
            .map(|keys| keys.public_key().to_hex())
            .collect();
        config.relay_owner_pubkey = owner_key.map(|keys| keys.public_key().to_hex());
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth_service = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth_service,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.set_admin_roster(roster);
        state.set_nip98_replay(replay);
        Arc::new(state)
    }

    async fn default_nip98_state(operator_keys: &[Keys]) -> Arc<crate::state::AppState> {
        nip98_test_state(
            operator_keys,
            None,
            super::roster::no_db_roster(),
            Arc::new(FreshReplayGuard),
        )
        .await
    }

    fn authed_request(
        method: &str,
        target: &str,
        keys: &Keys,
        body: Option<Vec<u8>>,
        with_payload_tag: bool,
        host: &str,
    ) -> Request<Body> {
        let url = admin_url(target);
        let auth = nip98_header(keys, &url, method, body.as_deref(), with_payload_tag, None);
        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .header(header::HOST, host)
            .header(header::AUTHORIZATION, auth);
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(body.map_or_else(Body::empty, Body::from))
            .expect("request")
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn operator_probe_reports_full_grant() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let response = router(state)
            .oneshot(authed_request(
                "GET",
                "/probe",
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let probe = body_json(response).await;
        assert_eq!(probe["auth"], "nip98");
        assert_eq!(probe["role"], "operator");
        assert_eq!(probe["source"], "config");
        assert_eq!(probe["canAct"], true);
        assert_eq!(probe["canStaff"], true);
    }

    #[tokio::test]
    async fn owner_fallback_probe_reports_fallback_source() {
        let owner = Keys::generate();
        let state = nip98_test_state(
            &[],
            Some(&owner),
            super::roster::no_db_roster(),
            Arc::new(FreshReplayGuard),
        )
        .await;
        let response = router(state)
            .oneshot(authed_request(
                "GET",
                "/probe",
                &owner,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let probe = body_json(response).await;
        assert_eq!(probe["source"], "owner_fallback");
        assert_eq!(probe["canStaff"], true);
    }

    #[tokio::test]
    async fn moderator_probe_cannot_staff_and_staffing_forbids() {
        let moderator = Keys::generate();
        let roster: Arc<dyn AdminRosterStore> = Arc::new(TestRoster::default());
        roster
            .grant(
                &moderator.public_key().to_bytes(),
                StoredAdminRole::Moderator,
                &[9u8; 32],
            )
            .await
            .expect("seed moderator");
        let state = nip98_test_state(&[], None, roster, Arc::new(FreshReplayGuard)).await;

        let response = router(state.clone())
            .oneshot(authed_request(
                "GET",
                "/probe",
                &moderator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let probe = body_json(response).await;
        assert_eq!(probe["role"], "moderator");
        assert_eq!(probe["source"], "db");
        assert_eq!(probe["canAct"], true);
        assert_eq!(probe["canStaff"], false);

        for (method, target) in [("GET", "/operators"), ("DELETE", "/operators/ab")] {
            let response = router(state.clone())
                .oneshot(authed_request(
                    method,
                    target,
                    &moderator,
                    None,
                    true,
                    "admin.example",
                ))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {target}"
            );
        }
    }

    #[tokio::test]
    async fn unrostered_signer_is_forbidden_without_burning_replay() {
        let operator = Keys::generate();
        let stranger = Keys::generate();
        let calls = Arc::new(Mutex::new(0u32));
        let state = nip98_test_state(
            &[operator],
            None,
            super::roster::no_db_roster(),
            Arc::new(CountingGuard {
                calls: calls.clone(),
            }),
        )
        .await;

        let response = router(state)
            .oneshot(authed_request(
                "GET",
                "/probe",
                &stranger,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            *calls.lock().expect("mutex"),
            0,
            "no replay slot for strangers"
        );
    }

    #[tokio::test]
    async fn wrong_host_rejects_without_burning_replay() {
        let operator = Keys::generate();
        let state = nip98_test_state(
            std::slice::from_ref(&operator),
            None,
            super::roster::no_db_roster(),
            Arc::new(OnceReplayGuard {
                used: std::sync::atomic::AtomicBool::new(false),
            }),
        )
        .await;

        // Valid signature, wrong Host: 403, and the event id stays unclaimed.
        let url = admin_url("/probe");
        let auth = nip98_header(&operator, &url, "GET", None, true, None);
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "community.example")
                    .header(header::AUTHORIZATION, auth.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Same signature with the right Host: the replay slot is still free.
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn replayed_event_is_rejected() {
        let operator = Keys::generate();
        let state = nip98_test_state(
            std::slice::from_ref(&operator),
            None,
            super::roster::no_db_roster(),
            Arc::new(OnceReplayGuard {
                used: std::sync::atomic::AtomicBool::new(false),
            }),
        )
        .await;

        let url = admin_url("/probe");
        let auth = nip98_header(&operator, &url, "GET", None, true, None);
        for (attempt, expected) in [(1, StatusCode::OK), (2, StatusCode::UNAUTHORIZED)] {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri("/probe")
                        .header(header::HOST, "admin.example")
                        .header(header::AUTHORIZATION, auth.clone())
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), expected, "attempt {attempt}");
        }
    }

    #[tokio::test]
    async fn replay_backend_failure_fails_closed() {
        let operator = Keys::generate();
        let state = nip98_test_state(
            std::slice::from_ref(&operator),
            None,
            super::roster::no_db_roster(),
            Arc::new(FailingReplayGuard),
        )
        .await;
        let response = router(state)
            .oneshot(authed_request(
                "GET",
                "/probe",
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mutation_without_payload_tag_is_rejected() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let target = format!("/operators/{}", "cd".repeat(32));
        let body = br#"{"role":"moderator"}"#.to_vec();
        let response = router(state)
            .oneshot(authed_request(
                "PUT",
                &target,
                &operator,
                Some(body),
                false,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn method_substitution_is_rejected() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let target = format!("/operators/{}", "cd".repeat(32));
        let body = br#"{"role":"moderator"}"#.to_vec();
        // Sign the right URL and payload but the wrong method.
        let url = admin_url(&target);
        let hash: [u8; 32] = Sha256::digest(&body).into();
        let tags = vec![
            Tag::parse(["u", url.as_str()]).expect("u tag"),
            Tag::parse(["method", "GET"]).expect("method tag"),
            Tag::parse(["payload", hex::encode(hash).as_str()]).expect("payload"),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&operator)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        let auth = format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
        );
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(target)
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stale_event_is_rejected() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let url = admin_url("/probe");
        let old = Timestamp::from(Timestamp::now().as_secs().saturating_sub(3600));
        let auth = nip98_header(&operator, &url, "GET", None, true, Some(old));
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn duplicate_authorization_header_is_rejected() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let url = admin_url("/probe");
        let auth = nip98_header(&operator, &url, "GET", None, true, None);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, auth.clone())
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn browser_origin_mismatch_is_forbidden() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let url = admin_url("/probe");
        let auth = nip98_header(&operator, &url, "GET", None, true, None);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "admin.example")
                    .header(header::ORIGIN, "https://attacker.example")
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_config_backed_pubkey_conflicts_even_uppercase() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let listed = operator.public_key().to_hex().to_uppercase();
        let body = br#"{"role":"moderator"}"#.to_vec();
        let response = router(state)
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{listed}"),
                &operator,
                Some(body),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn put_owner_fallback_pubkey_conflicts() {
        let owner = Keys::generate();
        let state = nip98_test_state(
            &[],
            Some(&owner),
            super::roster::no_db_roster(),
            Arc::new(FreshReplayGuard),
        )
        .await;
        let body = br#"{"role":"moderator"}"#.to_vec();
        let response = router(state)
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{}", owner.public_key().to_hex()),
                &owner,
                Some(body),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn put_invalid_role_is_bad_request() {
        let operator = Keys::generate();
        let roster: Arc<dyn AdminRosterStore> = Arc::new(TestRoster::default());
        let state = nip98_test_state(
            std::slice::from_ref(&operator),
            None,
            roster,
            Arc::new(FreshReplayGuard),
        )
        .await;
        let body = br#"{"role":"superadmin"}"#.to_vec();
        let response = router(state)
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{}", "cd".repeat(32)),
                &operator,
                Some(body),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_without_roster_migration_is_unavailable() {
        let operator = Keys::generate();
        let state = default_nip98_state(std::slice::from_ref(&operator)).await;
        let body = br#"{"role":"moderator"}"#.to_vec();
        let response = router(state)
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{}", "cd".repeat(32)),
                &operator,
                Some(body),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let payload = body_json(response).await;
        assert_eq!(payload["error"]["code"], "roster_unavailable");
    }

    #[tokio::test]
    async fn staffing_round_trip_with_roster_store() {
        let operator = Keys::generate();
        let roster: Arc<dyn AdminRosterStore> = Arc::new(TestRoster::default());
        let state = nip98_test_state(
            std::slice::from_ref(&operator),
            None,
            roster,
            Arc::new(FreshReplayGuard),
        )
        .await;
        let newcomer = "cd".repeat(32);

        // Grant a moderator.
        let response = router(state.clone())
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{newcomer}"),
                &operator,
                Some(br#"{"role":"moderator"}"#.to_vec()),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let entry = body_json(response).await;
        assert_eq!(entry["pubkey"], newcomer);
        assert_eq!(entry["role"], "moderator");
        assert_eq!(entry["source"], "db");

        // Listing unions the config operator and the DB grant.
        let response = router(state.clone())
            .oneshot(authed_request(
                "GET",
                "/operators",
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        let sources: Vec<(&str, &str)> = list
            .as_array()
            .expect("array")
            .iter()
            .map(|row| {
                (
                    row["pubkey"].as_str().expect("pubkey"),
                    row["source"].as_str().expect("source"),
                )
            })
            .collect();
        assert!(sources.contains(&(operator.public_key().to_hex().as_str(), "config")));
        assert!(sources.contains(&(newcomer.as_str(), "db")));

        // Promote to operator, then revoke.
        let response = router(state.clone())
            .oneshot(authed_request(
                "PUT",
                &format!("/operators/{newcomer}"),
                &operator,
                Some(br#"{"role":"operator"}"#.to_vec()),
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["role"], "operator");

        let response = router(state.clone())
            .oneshot(authed_request(
                "DELETE",
                &format!("/operators/{newcomer}"),
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["removed"], true);

        // Revoking twice is a 404 and writes nothing.
        let response = router(state.clone())
            .oneshot(authed_request(
                "DELETE",
                &format!("/operators/{newcomer}"),
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = router(state)
            .oneshot(authed_request(
                "GET",
                &format!("/operators/{newcomer}"),
                &operator,
                None,
                true,
                "admin.example",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
