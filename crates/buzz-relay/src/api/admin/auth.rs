//! Authentication and principal resolution for the deployment-admin API.
//!
//! # NIP-98 mode (mutations available)
//!
//! Every request carries `Authorization: Nostr <base64 event>`. After
//! verifying the signature, timestamp, `u` tag, method tag, and (for
//! body-bearing requests) the `payload` sha256 tag, the authenticated pubkey
//! is resolved to an [`AdminPrincipal`] via [`resolve_admin_principal`].
//!
//! ## Principal resolution
//!
//! ```text
//! Operator/Config        if pubkey is in RELAY_OPERATOR_PUBKEYS
//! Operator/OwnerFallback if pubkey equals RELAY_OWNER_PUBKEY
//!                        AND configured RELAY_OPERATOR_PUBKEYS is empty
//!                        (evaluated from config, never runtime rows)
//! role from the roster store otherwise (DB-backed once P03 lands it)
//! None -> 403            no fall-through role, ever
//! ```
//!
//! Config outranks the roster store: a DB row for a config-backed operator
//! pubkey is never consulted, so it cannot demote a config grant.
//!
//! # Disabled mode (read-only)
//!
//! [`authorize`] succeeds for read requests but returns `None` for the
//! principal. Mutation and staffing routes call
//! [`require_mutation_principal`], which rejects `None` with `403`.
//!
//! # Ingress layer
//!
//! The exact admin `Host` check and the same-origin `Origin` check stay active
//! in every mode as defense-in-depth behind the credential check.

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use super::error::ApiError;
use super::roster::StoredAdminRole;
use crate::config::{AdminAuth, AdminConfig};
use crate::state::AppState;

/// Scope for the admin NIP-98 replay guard. Deployment-global, like the
/// operator-management scope in `api/operator.rs`.
const ADMIN_REPLAY_SCOPE: &str = "admin-moderation";

/// The API prefix the admin routes are mounted under in the relay router.
/// NIP-98 clients sign the full URL
/// (`https://admin.example/api/admin/v1/reports`); axum strips this prefix
/// before calling handlers, so callers re-add it when building the canonical
/// URL for event verification.
pub(crate) const ADMIN_API_PREFIX: &str = "/api/admin/v1";

/// The deployment-level role held by an authenticated principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    /// Deployment-wide operator. Reads, acts on reports, and staffs the roster.
    Operator,
    /// Day-to-day triage. Reads and acts on reports; never staffs the roster.
    Moderator,
}

/// How the principal's grant was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminSource {
    /// Pubkey is in `RELAY_OPERATOR_PUBKEYS` in the deployment config.
    Config,
    /// Pubkey equals `RELAY_OWNER_PUBKEY` while `RELAY_OPERATOR_PUBKEYS` is
    /// empty. Break-glass grant for self-hosters; immutable through the API.
    OwnerFallback,
    /// Pubkey holds a grant in the roster store.
    Db,
}

/// A resolved deployment-level principal, returned by [`authorize`] in NIP-98
/// mode.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    /// 32-byte pubkey (binary).
    pub pubkey: [u8; 32],
    /// Deployment role.
    pub role: AdminRole,
    /// How the grant was established.
    pub source: AdminSource,
}

/// Canonical wire string for an [`AdminRole`] (probe responses).
pub(crate) fn admin_role_str(role: AdminRole) -> &'static str {
    match role {
        AdminRole::Operator => "operator",
        AdminRole::Moderator => "moderator",
    }
}

/// Canonical wire string for an [`AdminSource`] (probe responses).
pub(crate) fn admin_source_str(source: &AdminSource) -> &'static str {
    match source {
        AdminSource::Config => "config",
        AdminSource::OwnerFallback => "owner_fallback",
        AdminSource::Db => "db",
    }
}

pub(crate) fn is_admin_host(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(config) = state.config.admin.as_ref() else {
        return false;
    };
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host == config.host)
}

/// Scheme for an admin authority: `http` for loopback hosts (`localhost`,
/// any `*.localhost` name, `[::1]`, `127.x`), else `https`.
///
/// Shared by [`canonical_url`] (NIP-98 `u`-tag verification) and
/// [`admin_api_origin`] (NIP-11 advertisement) so the origin the relay
/// advertises and the origin it verifies against never diverge.
fn scheme_for_host(host: &str) -> &'static str {
    // Strip any `:port` to get the bare host. A bracketed IPv6 authority
    // (`[::1]:3000`) carries its colons inside the brackets, so take the text
    // between them; bare unbracketed IPv6 literals are rejected at config
    // parse, so splitting on `:` only strips a port for every other form.
    let host_part = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let is_loopback = host_part == "localhost"
        || host_part.ends_with(".localhost")
        || host_part == "::1"
        || host_part.starts_with("127.");
    if is_loopback {
        "http"
    } else {
        "https"
    }
}

/// Canonical URL for a NIP-98 `u`-tag check.
fn canonical_url(host: &str, path: &str) -> String {
    format!("{}://{host}{path}", scheme_for_host(host))
}

/// Canonical admin API origin (`scheme://host[:port]`, no path) advertised in
/// the NIP-11 document so clients can discover the admin surface instead of
/// requiring manual URL entry. The scheme follows the same loopback rule as
/// [`canonical_url`].
pub(crate) fn admin_api_origin(host: &str) -> String {
    format!("{}://{host}", scheme_for_host(host))
}

/// Authenticate the request and return the resolved principal (NIP-98 mode).
///
/// `path_and_query` is the full request target including any query string
/// (e.g. `/reports?status=open`). NIP-98 clients sign the full URL; passing
/// only the path breaks every query-bearing request.
///
/// `raw_body` is the exact request body bytes. Body-bearing callers must
/// buffer the body, pass it here, then deserialize the same bytes. Pass
/// `None` only when the request carries no body.
///
/// Returns `Ok(Some(principal))` in NIP-98 mode, `Ok(None)` in disabled mode
/// (reads pass; mutations reject via [`require_mutation_principal`]).
pub async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    path_and_query: &str,
    method: &str,
    raw_body: Option<&[u8]>,
) -> Result<Option<AdminPrincipal>, ApiError> {
    let config = state
        .config
        .admin
        .as_ref()
        .ok_or_else(ApiError::not_found)?;

    // Credential check first: an unauthenticated caller learns nothing about
    // which Host or Origin the deployment expects.
    let (principal, nip98_event_id) = match &config.auth {
        AdminAuth::Disabled => (None, None),
        AdminAuth::Nip98 => {
            let full_path = format!("{ADMIN_API_PREFIX}{path_and_query}");
            let (pubkey_bytes, event_id) =
                authorize_nip98(config, headers, &full_path, method, raw_body).await?;
            // Resolve the roster grant BEFORE claiming the replay id: a
            // validly-signing but unrostered key must not consume replay slots
            // at request rate. Only an authorized request claims its event id.
            let principal = resolve_admin_principal(state, pubkey_bytes).await?;
            (Some(principal), Some(event_id))
        }
    };

    if !is_admin_host(state, headers) {
        return Err(ApiError::forbidden());
    }
    if headers.get(header::ORIGIN).is_some_and(|origin| {
        origin
            .to_str()
            .map_or(true, |origin| !origin_matches_host(origin, &config.host))
    }) {
        return Err(ApiError::forbidden());
    }

    // Claim the replay id only after Host and Origin pass, so a request
    // rejected by either check does not burn the event id. The caller can
    // retry with corrected headers without a fresh signature.
    if let Some(event_id) = nip98_event_id {
        claim_nip98_replay(state, &event_id).await?;
    }

    Ok(principal)
}

/// Resolve a 32-byte pubkey to an [`AdminPrincipal`] using config plus the
/// roster store.
///
/// Resolution order (config outranks the roster store):
/// 1. Operator/Config if pubkey is in `RELAY_OPERATOR_PUBKEYS`
/// 2. Operator/OwnerFallback if pubkey equals `RELAY_OWNER_PUBKEY` AND
///    configured `RELAY_OPERATOR_PUBKEYS` is empty
/// 3. Role from the roster store row
/// 4. No grant: `403`
pub async fn resolve_admin_principal(
    state: &AppState,
    pubkey: [u8; 32],
) -> Result<AdminPrincipal, ApiError> {
    if let Some(principal) = resolve_config_principal(
        &state.config.relay_operator_pubkeys,
        state.config.relay_owner_pubkey.as_deref(),
        pubkey,
    ) {
        return Ok(principal);
    }

    let stored = state
        .admin_roster
        .role_for_pubkey(&pubkey)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "admin roster lookup failed");
            ApiError::internal()
        })?;
    match stored {
        Some(StoredAdminRole::Operator) => Ok(AdminPrincipal {
            pubkey,
            role: AdminRole::Operator,
            source: AdminSource::Db,
        }),
        Some(StoredAdminRole::Moderator) => Ok(AdminPrincipal {
            pubkey,
            role: AdminRole::Moderator,
            source: AdminSource::Db,
        }),
        None => Err(ApiError::forbidden()),
    }
}

/// Pure config half of [`resolve_admin_principal`]: operator allowlist first,
/// owner fallback second, `None` when neither matches.
///
/// Split out so the role matrix is unit-testable without an `AppState`.
/// Both inputs are lowercase hex; config parsing normalizes them at startup.
pub fn resolve_config_principal(
    operator_pubkeys: &[String],
    owner_pubkey: Option<&str>,
    pubkey: [u8; 32],
) -> Option<AdminPrincipal> {
    let pubkey_hex = hex::encode(pubkey);
    if operator_pubkeys.iter().any(|entry| entry == &pubkey_hex) {
        return Some(AdminPrincipal {
            pubkey,
            role: AdminRole::Operator,
            source: AdminSource::Config,
        });
    }
    // Owner fallback is live only while no operator is configured. Read from
    // config, never from runtime roster rows: staffing an operator must
    // deactivate the break-glass grant on its own.
    if operator_pubkeys.is_empty() && owner_pubkey == Some(pubkey_hex.as_str()) {
        return Some(AdminPrincipal {
            pubkey,
            role: AdminRole::Operator,
            source: AdminSource::OwnerFallback,
        });
    }
    None
}

/// Require a resolved principal (NIP-98 mode) and return it. Mutation and
/// staffing routes are unavailable in disabled mode.
pub fn require_mutation_principal(
    principal: Option<AdminPrincipal>,
) -> Result<AdminPrincipal, ApiError> {
    principal
        .ok_or_else(|| ApiError::forbidden_with_message("mutations require BUZZ_ADMIN_AUTH=nip98"))
}

/// Require the operator role. Staffing routes call this after
/// [`require_mutation_principal`].
pub fn require_operator(principal: &AdminPrincipal) -> Result<(), ApiError> {
    if principal.role == AdminRole::Operator {
        Ok(())
    } else {
        Err(ApiError::forbidden_with_message(
            "staffing endpoints require the operator role",
        ))
    }
}

/// Require exactly one `Authorization: Nostr <base64 event>` header, verify
/// the NIP-98 event (method, url, and payload hash for body-bearing requests),
/// and return the authenticated pubkey bytes plus the event id.
///
/// This verifies only; it does NOT claim the replay id. The caller resolves
/// the principal first and claims the id only after authorization succeeds,
/// so an unrostered signer never consumes a replay slot.
///
/// Uniform `401` on any auth failure: no oracle for the failure mode.
async fn authorize_nip98(
    config: &AdminConfig,
    headers: &HeaderMap,
    path: &str,
    method: &str,
    raw_body: Option<&[u8]>,
) -> Result<([u8; 32], nostr::EventId), ApiError> {
    let unauth = ApiError::unauthorized;

    // Exactly one Authorization header.
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(unauth());
    };
    let credential = value
        .to_str()
        .ok()
        .and_then(nostr_credential)
        .ok_or_else(unauth)?;

    // Base64-decode to the signed event JSON.
    let event_json = {
        let bytes = BASE64.decode(credential).map_err(|_| unauth())?;
        String::from_utf8(bytes).map_err(|_| unauth())?
    };
    let event: nostr::Event = serde_json::from_str(&event_json).map_err(|_| unauth())?;
    let event_id = event.id;

    // A request carrying a body must commit to it with a `payload` tag.
    // Conditioned on the body being present, not on the method name: DELETE
    // carries no body in this API, so its callers pass `None`.
    if raw_body.is_some() {
        let has_payload = event
            .tags
            .iter()
            .any(|tag| tag.kind() == nostr::TagKind::Payload);
        if !has_payload {
            return Err(unauth());
        }
    }

    // The expected URL derives from config, never from the inbound Host.
    let url = canonical_url(&config.host, path);

    let pubkey =
        buzz_auth::verify_nip98_event(&event_json, &url, method, raw_body).map_err(|_| unauth())?;

    Ok((pubkey.to_bytes(), event_id))
}

/// Atomically claim a verified NIP-98 event id against the deployment-scoped
/// replay guard. Called only after verification and roster authorization, so
/// an unrostered signer never consumes a slot. Redis failure fails closed.
async fn claim_nip98_replay(state: &AppState, event_id: &nostr::EventId) -> Result<(), ApiError> {
    let unauth = ApiError::unauthorized;
    match state
        .nip98_replay
        .try_mark_in_scope(
            ADMIN_REPLAY_SCOPE,
            event_id,
            buzz_auth::DEFAULT_REPLAY_TTL_SECS,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(unauth()),
        Err(error) => {
            tracing::warn!(
                scope = ADMIN_REPLAY_SCOPE,
                error = %error,
                "admin NIP-98 replay guard failed; rejecting request fail-closed"
            );
            Err(unauth())
        }
    }
}

/// Extract the credential from an `Authorization: Nostr <base64>` value.
fn nostr_credential(value: &str) -> Option<&str> {
    let (scheme, credential) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Nostr")
        .then(|| credential.trim_start_matches(' '))
        .filter(|credential| !credential.is_empty())
}

fn origin_matches_host(origin: &str, host: &str) -> bool {
    // Compare against the exact canonical origin: `https` for non-loopback,
    // `http` for loopback. Accepting either scheme for production hosts would
    // admit plaintext origins.
    let expected = format!("{}://{host}", scheme_for_host(host));
    origin == expected
}

#[cfg(test)]
mod tests {
    use super::{
        admin_api_origin, canonical_url, nostr_credential, origin_matches_host,
        resolve_config_principal, AdminRole, AdminSource,
    };

    fn pubkey(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn config_operator_beats_everything() {
        let hex_key = hex::encode(pubkey(1));
        let principal =
            resolve_config_principal(&[hex_key], Some(&hex::encode(pubkey(2))), pubkey(1))
                .expect("config operator resolves");
        assert_eq!(principal.role, AdminRole::Operator);
        assert_eq!(principal.source, AdminSource::Config);
    }

    #[test]
    fn owner_fallback_needs_an_empty_operator_list() {
        let owner = hex::encode(pubkey(9));
        // Break-glass grant while no operator is configured.
        let principal = resolve_config_principal(&[], Some(&owner), pubkey(9)).expect("fallback");
        assert_eq!(principal.role, AdminRole::Operator);
        assert_eq!(principal.source, AdminSource::OwnerFallback);
        // Listing the same key as an operator keeps it an operator, but the
        // grant source becomes config: the allowlist outranks the fallback.
        let principal = resolve_config_principal(
            std::slice::from_ref(&owner),
            Some(&hex::encode(pubkey(9))),
            pubkey(9),
        )
        .expect("config grant");
        assert_eq!(principal.source, AdminSource::Config);
        // Staffing any operator deactivates the break-glass grant entirely:
        // the owner key alone no longer resolves once the list is non-empty.
        assert!(
            resolve_config_principal(&[hex::encode(pubkey(1))], Some(&owner), pubkey(9)).is_none(),
            "non-empty operator list deactivates the owner fallback"
        );
    }

    #[test]
    fn unlisted_pubkey_resolves_to_no_config_grant() {
        assert!(resolve_config_principal(
            &[hex::encode(pubkey(1))],
            Some(&hex::encode(pubkey(2))),
            pubkey(3)
        )
        .is_none());
        assert!(resolve_config_principal(&[], None, pubkey(3)).is_none());
    }

    #[test]
    fn browser_origin_must_match_admin_host() {
        assert!(origin_matches_host(
            "https://admin.example.com",
            "admin.example.com"
        ));
        assert!(origin_matches_host(
            "http://admin.localhost:3000",
            "admin.localhost:3000"
        ));
        assert!(!origin_matches_host(
            "https://attacker.example",
            "admin.example.com"
        ));
        assert!(!origin_matches_host("null", "admin.example.com"));
        assert!(!origin_matches_host(
            "http://admin.example.com",
            "admin.example.com"
        ));
        assert!(!origin_matches_host(
            "https://admin.localhost:3000",
            "admin.localhost:3000"
        ));
    }

    #[test]
    fn nostr_credential_is_case_insensitive_and_non_empty() {
        assert_eq!(nostr_credential("Nostr abc"), Some("abc"));
        assert_eq!(nostr_credential("nostr abc"), Some("abc"));
        assert_eq!(nostr_credential("NOSTR  abc"), Some("abc"));
        assert_eq!(nostr_credential("Nostr "), None);
        assert_eq!(nostr_credential("Bearer abc"), None);
        assert_eq!(nostr_credential("abc"), None);
    }

    #[test]
    fn canonical_url_uses_https_for_non_loopback_hosts() {
        assert_eq!(
            canonical_url("admin.example.com", "/api/admin/v1/reports"),
            "https://admin.example.com/api/admin/v1/reports"
        );
        assert_eq!(
            canonical_url("admin.example.com:8443", "/path"),
            "https://admin.example.com:8443/path"
        );
    }

    #[test]
    fn canonical_url_uses_http_for_loopback_hosts() {
        assert_eq!(
            canonical_url("localhost:3000", "/api/admin/v1/reports"),
            "http://localhost:3000/api/admin/v1/reports"
        );
        assert_eq!(
            canonical_url("127.0.0.1:3000", "/path"),
            "http://127.0.0.1:3000/path"
        );
        assert_eq!(
            canonical_url("admin.localhost:3000", "/api/admin/v1/reports"),
            "http://admin.localhost:3000/api/admin/v1/reports"
        );
    }

    #[test]
    fn admin_api_origin_matches_canonical_url_scheme() {
        for host in [
            "admin.example.com",
            "admin.example.com:8443",
            "localhost:3000",
            "127.0.0.1:3000",
            "[::1]:3000",
            "admin.localhost:3000",
        ] {
            let advertised = admin_api_origin(host);
            url::Url::parse(&advertised).unwrap_or_else(|error| {
                panic!("advertised origin {advertised:?} must parse: {error}")
            });
            let verified = canonical_url(host, "/api/admin/v1/reports");
            url::Url::parse(&verified)
                .unwrap_or_else(|error| panic!("canonical url {verified:?} must parse: {error}"));
            let advertised_scheme = advertised.split("://").next().expect("scheme");
            let verified_scheme = verified.split("://").next().expect("scheme");
            assert_eq!(
                advertised_scheme, verified_scheme,
                "advertised and verified schemes must match for host {host}"
            );
        }
    }
}
