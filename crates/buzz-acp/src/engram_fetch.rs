//! Fetch the agent's NIP-AE `core` engram at session creation and render it
//! into a prompt section.
//!
//! Scope per Tyler's spec:
//! - Fire one synchronous query for the core head when a *new* session is born.
//! - If a body is found, emit `[Agent Memory — core]\n<profile>`.
//! - If no body is found, seed the canonical lean core with the agent's own
//!   key and inject it immediately.
//! - If that first-run write fails, emit the legacy onboarding nudge instead.
//! - On any *error* (transport, parse), log and emit nothing. We must not
//!   mistake a relay outage for "no core" — that would invite the agent to
//!   overwrite real, just-unreachable memory with a fresh profile.
//! - Either way, session creation is never blocked.

use buzz_core::engram::{
    build_event, conversation_key, d_tag, select_head, validate_and_decrypt, Body,
};
use buzz_core::kind::KIND_AGENT_ENGRAM;
use nostr::{Event, Keys, PublicKey};

use crate::relay::RestClient;

/// Section header rendered into the prompt.
const SECTION_LABEL: &str = "Agent Memory — core";

/// Independent bounds for the read and first-run write. A stalled read emits
/// nothing; a stalled write falls back to [`ONBOARDING_NUDGE`].
const CORE_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Onboarding nudge for new agents with no core yet.
///
/// Wording is from Tyler's brief: "No core memory found. Use `buzz mem`
/// to create a core memory. Ask your user about yourself."
pub const ONBOARDING_NUDGE: &str = "No core memory found. \
    Use `buzz mem set core \"…\"` to create one (it will hold your identity, \
    rules, and goals across sessions). Ask your user about yourself.";

/// Canonical default for every newly provisioned Buzz agent's `core` engram.
///
/// This is the single source for the seeded text. Keep it lean: the core points
/// at Buzz records and the runtime's native instructions instead of copying
/// either into memory. [`render_lean_core`] owns placeholder substitution.
pub const LEAN_CORE_TEMPLATE: &str = "I am {identity}, a Buzz agent.\n\
Buzz coordinates: relay={relay_url} agent={agent_pubkey} owner={owner_pubkey}.\n\
Records: keep issues, PRs, review and status events, SHAs, CI, releases, deployments, migrations, incidents, and follow-ups synchronized with delivered state. Escalate approval-gated actions to Victor or Rachel (equal authority).\n\
Your runtime's native instruction file is authoritative.\n\
Memory habit: run `buzz mem ls` before relying on durable context, then read relevant records with `buzz mem get <slug>`.";

/// Render [`LEAN_CORE_TEMPLATE`] for one provisioned agent.
pub fn render_lean_core(
    identity: &str,
    relay_url: &str,
    agent_pubkey: &PublicKey,
    owner_pubkey: &PublicKey,
) -> String {
    LEAN_CORE_TEMPLATE
        .replace("{relay_url}", relay_url)
        .replace("{agent_pubkey}", &agent_pubkey.to_hex())
        .replace("{owner_pubkey}", &owner_pubkey.to_hex())
        .replace("{identity}", identity)
}

/// Build the rendered prompt section for the agent's core.
///
/// Returns:
/// - `Some(profile_section)` when a valid core exists,
/// - `Some(seeded_section)` when absence is confirmed and the seed succeeds,
/// - `Some(nudge_section)` when the confirmed-absent seed fails,
/// - `None` when the fetch failed (transport, parse, decrypt) — the caller
///   should inject no section in that case so the agent doesn't conclude
///   memory is empty.
pub async fn build_core_section(
    rest: &RestClient,
    agent_keys: &Keys,
    owner: &PublicKey,
    identity: &str,
    relay_url: &str,
) -> Option<String> {
    build_core_section_with(
        identity,
        relay_url,
        &agent_keys.public_key(),
        owner,
        || async move {
            tokio::time::timeout(CORE_IO_TIMEOUT, fetch_core_body(rest, agent_keys, owner))
                .await
                .map_err(|_| "core fetch timed out".to_string())?
        },
        |profile| async move {
            tokio::time::timeout(
                CORE_IO_TIMEOUT,
                seed_core(rest, agent_keys, owner, &profile),
            )
            .await
            .map_err(|_| "core seed write timed out".to_string())?
        },
    )
    .await
}

/// Coordinate the confirmed-absent seed while keeping the policy independently
/// testable from HTTP transport.
async fn build_core_section_with<Fetch, FetchFuture, Seed, SeedFuture>(
    identity: &str,
    relay_url: &str,
    agent_pubkey: &PublicKey,
    owner: &PublicKey,
    fetch: Fetch,
    seed: Seed,
) -> Option<String>
where
    Fetch: FnOnce() -> FetchFuture,
    FetchFuture: std::future::Future<Output = Result<Option<String>, String>>,
    Seed: FnOnce(String) -> SeedFuture,
    SeedFuture: std::future::Future<Output = Result<(), String>>,
{
    match fetch().await {
        Ok(Some(profile)) => Some(format!("[{SECTION_LABEL}]\n{profile}")),
        Ok(None) => {
            let profile = render_lean_core(identity, relay_url, agent_pubkey, owner);
            match seed(profile.clone()).await {
                Ok(()) => Some(format!("[{SECTION_LABEL}]\n{profile}")),
                Err(reason) => {
                    tracing::warn!(
                        target: "engram::core",
                        "first-run core seed failed: {reason} — injecting the onboarding nudge"
                    );
                    Some(format!("[{SECTION_LABEL}]\n{ONBOARDING_NUDGE}"))
                }
            }
        }
        Err(reason) => {
            tracing::warn!(
                target: "engram::core",
                "core fetch failed: {reason} — emitting no section to avoid \
                 confusing a relay outage with an absent core"
            );
            None
        }
    }
}

/// Agent-author the canonical core after a confirmed-absent read.
async fn seed_core(
    rest: &RestClient,
    agent_keys: &Keys,
    owner: &PublicKey,
    profile: &str,
) -> Result<(), String> {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let event = build_event(
        agent_keys,
        owner,
        &Body::Core {
            profile: profile.to_string(),
        },
        created_at,
    )
    .map_err(|e| format!("core event build failed: {e}"))?;
    let response = rest
        .submit_event(&event)
        .await
        .map_err(|e| format!("relay write failed: {e}"))?;
    let accepted = response
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let message = response
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing relay acceptance response");
    if !accepted || message.starts_with("duplicate:") {
        return Err(format!("relay did not accept the core seed: {message}"));
    }
    Ok(())
}

/// Query the relay for the core head and decode it. Returns:
/// - `Ok(Some(profile))` if a valid core body was found,
/// - `Ok(None)` only if the relay confirmed absence (empty result set),
/// - `Err(reason)` if the relay returned candidates we could not parse,
///   verify, or decrypt — those are NOT treated as absence (would let an
///   unreadable but real core be silently overwritten by the onboarding nudge),
/// - `Err` for transport / parse errors.
async fn fetch_core_body(
    rest: &RestClient,
    agent_keys: &Keys,
    owner: &PublicKey,
) -> Result<Option<String>, String> {
    let k_c = conversation_key(agent_keys.secret_key(), owner);
    let d = d_tag(&k_c, buzz_core::engram::CORE_SLUG);

    let filter = nostr::Filter::new()
        .kind(nostr::Kind::Custom(KIND_AGENT_ENGRAM as u16))
        .author(agent_keys.public_key())
        .custom_tags(nostr::SingleLetterTag::lowercase(nostr::Alphabet::D), [d])
        .custom_tags(
            nostr::SingleLetterTag::lowercase(nostr::Alphabet::P),
            [owner.to_hex()],
        )
        .limit(16);

    let value = rest
        .query(&[filter])
        .await
        .map_err(|e| format!("relay query failed: {e}"))?;
    let arr = value
        .as_array()
        .ok_or_else(|| "relay query returned non-array".to_string())?;
    decode_core_body(arr, agent_keys, owner)
}

/// Pure decoder: given the relay's JSON array, decide whether we have a
/// readable core, confirmed absence, or an ambiguous unreadable-state.
///
/// - Empty array → `Ok(None)` (confirmed absence; caller renders the nudge).
/// - At least one event decrypts → use the winning head's body.
///   * Body::Core → `Ok(Some(profile))`
///   * Body::Tombstone or unexpected shape → `Ok(None)` (treat as absent).
/// - Non-empty array but nothing decrypts → `Err` (fail closed; caller
///   emits no section, so the agent does not assume memory is empty and
///   try to overwrite a real-but-unreadable core).
fn decode_core_body(
    arr: &[serde_json::Value],
    agent_keys: &Keys,
    owner: &PublicKey,
) -> Result<Option<String>, String> {
    if arr.is_empty() {
        return Ok(None);
    }
    let mut valid_with_body: Vec<(Event, Body)> = Vec::with_capacity(arr.len());
    let mut candidates_seen = 0usize;
    let mut last_decrypt_err: Option<String> = None;
    for ev_json in arr {
        let event: Event = match serde_json::from_value(ev_json.clone()) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if event.verify().is_err() {
            continue;
        }
        candidates_seen += 1;
        match validate_and_decrypt(
            &event,
            &agent_keys.public_key(),
            owner,
            agent_keys.secret_key(),
            owner,
        ) {
            Ok(body) => valid_with_body.push((event, body)),
            Err(e) => {
                last_decrypt_err = Some(e.to_string());
                continue;
            }
        }
    }
    if valid_with_body.is_empty() {
        if candidates_seen > 0 {
            return Err(format!(
                "{candidates_seen} core candidate(s) returned but none decryptable                  (last error: {})",
                last_decrypt_err.as_deref().unwrap_or("unknown")
            ));
        }
        return Err(
            "relay returned core candidate(s) that could not be parsed or verified".to_string(),
        );
    }
    let events: Vec<Event> = valid_with_body.iter().map(|(e, _)| e.clone()).collect();
    // `select_head` returns `None` only on an empty iterator, which we
    // ruled out above.
    let Some(head) = select_head(events) else {
        return Ok(None);
    };
    let head_id = head.id;
    let body = valid_with_body
        .into_iter()
        .find(|(e, _)| e.id == head_id)
        .map(|(_, b)| b);
    match body {
        Some(Body::Core { profile }) => Ok(Some(profile)),
        // A tombstone or unexpectedly-shaped head means "no usable core."
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::engram::{build_event, Body};
    use serde_json::json;

    /// Empty array → confirmed absence → Ok(None), so the caller may seed the
    /// canonical core. This is the only path that maps to "no core."
    #[test]
    fn decode_empty_array_is_confirmed_absence() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let out = decode_core_body(&[], &agent, &owner.public_key()).unwrap();
        assert_eq!(out, None);
    }

    /// Happy path: a real, decryptable core event yields the profile.
    #[test]
    fn decode_valid_core_returns_profile() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let body = Body::Core {
            profile: "I am Sami.".to_string(),
        };
        let ev = build_event(&agent, &owner.public_key(), &body, 1_700_000_000).unwrap();
        let arr = vec![serde_json::to_value(&ev).unwrap()];
        let out = decode_core_body(&arr, &agent, &owner.public_key()).unwrap();
        assert_eq!(out.as_deref(), Some("I am Sami."));
    }

    /// Regression: when the relay returns a kind:30174 event addressed to
    /// this agent that we cannot decrypt (here: encrypted to a *different*
    /// owner's key, so the MAC fails for this agent↔owner pair), we MUST
    /// return Err and NOT Ok(None). Returning Ok(None) would cause the
    /// harness to emit the onboarding nudge, inviting the agent to overwrite
    /// a real-but-unreadable core.
    #[test]
    fn decode_undecryptable_candidate_is_err_not_absent() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let wrong_owner = Keys::generate();
        // Build an engram encrypted to wrong_owner (not owner). It will pass
        // sig verification but fail MAC/decrypt for the agent↔owner pair.
        let body = Body::Core {
            profile: "secret".to_string(),
        };
        let ev = build_event(&agent, &wrong_owner.public_key(), &body, 1_700_000_000).unwrap();
        let arr = vec![serde_json::to_value(&ev).unwrap()];
        let result = decode_core_body(&arr, &agent, &owner.public_key());
        assert!(result.is_err(), "expected Err, got: {result:?}");
        let msg = result.unwrap_err();
        assert!(msg.contains("decryptable"), "got: {msg}");
    }

    /// An unexpectedly-shaped head (here: a Memory body in what was supposed
    /// to be the core slot) is a legitimate, decryptable "no usable core" —
    /// Ok(None). Real `rm core` is refused at the CLI, so this is a defensive
    /// branch for malformed data on the wire.
    #[test]
    fn decode_non_core_body_is_absent() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let body = Body::Memory {
            slug: "mem/x".to_string(),
            value: None,
        };
        let ev = build_event(&agent, &owner.public_key(), &body, 1_700_000_000).unwrap();
        let arr = vec![serde_json::to_value(&ev).unwrap()];
        let out = decode_core_body(&arr, &agent, &owner.public_key()).unwrap();
        assert_eq!(out, None);
    }

    /// Non-empty array with only garbage entries (not even parseable as
    /// events) is also treated as a fetch error, not absence.
    #[test]
    fn decode_unparseable_candidates_is_err() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let arr = vec![json!({"not": "an event"}), json!("garbage")];
        let result = decode_core_body(&arr, &agent, &owner.public_key());
        assert!(result.is_err(), "expected Err, got: {result:?}");
    }

    #[derive(Default)]
    struct FakeCoreStore {
        core: std::sync::Mutex<Option<String>>,
        writes: std::sync::atomic::AtomicUsize,
        fail_writes: bool,
    }

    async fn build_with_fake_store(
        store: std::sync::Arc<FakeCoreStore>,
        agent: &Keys,
        owner: &PublicKey,
        identity: &str,
    ) -> Option<String> {
        use std::sync::atomic::Ordering;

        let fetch_store = store.clone();
        let seed_store = store;
        build_core_section_with(
            identity,
            "wss://buzz.example",
            &agent.public_key(),
            owner,
            move || async move { Ok(fetch_store.core.lock().unwrap().clone()) },
            move |profile| async move {
                seed_store.writes.fetch_add(1, Ordering::SeqCst);
                if seed_store.fail_writes {
                    Err("write disabled".to_string())
                } else {
                    *seed_store.core.lock().unwrap() = Some(profile);
                    Ok(())
                }
            },
        )
        .await
    }

    #[test]
    fn lean_core_template_renders_the_agent_identity_and_coordinates() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let rendered = render_lean_core(
            "Sami",
            "wss://buzz.example",
            &agent.public_key(),
            &owner.public_key(),
        );

        assert!(rendered.starts_with("I am Sami, a Buzz agent."));
        assert!(rendered.contains("relay=wss://buzz.example"));
        assert!(rendered.contains(&format!("agent={}", agent.public_key().to_hex())));
        assert!(rendered.contains(&format!("owner={}", owner.public_key().to_hex())));
        assert!(!rendered.contains("{identity}"));
    }

    #[tokio::test]
    async fn fresh_agent_bootstrap_seeds_once_and_second_session_does_not_overwrite() {
        use std::sync::atomic::Ordering;

        let agent = Keys::generate();
        let owner = Keys::generate();
        let store = std::sync::Arc::new(FakeCoreStore::default());

        let first = build_with_fake_store(store.clone(), &agent, &owner.public_key(), "Sami")
            .await
            .unwrap();
        let second = build_with_fake_store(
            store.clone(),
            &agent,
            &owner.public_key(),
            "Changed name must not replace core",
        )
        .await
        .unwrap();

        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
        assert_eq!(first, second);
        assert!(first.contains("I am Sami, a Buzz agent."));
    }

    #[tokio::test]
    async fn existing_core_is_injected_without_a_write() {
        use std::sync::atomic::Ordering;

        let agent = Keys::generate();
        let owner = Keys::generate();
        let store = std::sync::Arc::new(FakeCoreStore {
            core: std::sync::Mutex::new(Some("Existing owner-approved core.".to_string())),
            ..FakeCoreStore::default()
        });

        let section =
            build_with_fake_store(store.clone(), &agent, &owner.public_key(), "New draft name")
                .await
                .unwrap();

        assert_eq!(
            section,
            "[Agent Memory — core]\nExisting owner-approved core."
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.core.lock().unwrap().as_deref(),
            Some("Existing owner-approved core.")
        );
    }

    #[tokio::test]
    async fn seed_write_failure_degrades_to_the_existing_nudge() {
        use std::sync::atomic::Ordering;

        let agent = Keys::generate();
        let owner = Keys::generate();
        let store = std::sync::Arc::new(FakeCoreStore {
            fail_writes: true,
            ..FakeCoreStore::default()
        });

        let section = build_with_fake_store(store.clone(), &agent, &owner.public_key(), "Sami")
            .await
            .unwrap();

        assert_eq!(
            section,
            format!("[Agent Memory — core]\n{ONBOARDING_NUDGE}")
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
        assert!(store.core.lock().unwrap().is_none());
    }
}
