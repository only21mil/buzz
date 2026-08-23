//! Kind 10100 (agent directory record) publish and refresh.
//!
//! buzz-acp never published its own kind:10100 record, so an agent joined to a
//! new channel stayed hidden in the Desktop @ picker — the directory record
//! lacked the channel. This module reads the current record (if any), updates
//! `channel_ids`, and republishes through the HTTP bridge, preserving every
//! existing field and tag.
//!
//! The record is replaceable (NIP-01 kind 10000–19999), keyed by `(pubkey,
//! kind)`. The relay's `handle_agent_profile` side effect reads
//! `channel_add_policy` from the content JSON; the Desktop reads
//! `display_name`, `channel_ids`, and other optional fields. We preserve all
//! existing content fields and tags on republish and only overwrite
//! `channel_ids`.

use std::collections::HashSet;

use buzz_core::kind::KIND_AGENT_PROFILE;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::relay::{RelayError, RestClient};

/// The kind:10100 content JSON, built or updated from the current channel set.
///
/// If `existing_content` is `Some`, every field is preserved and `channel_ids`
/// is overwritten with `channel_ids`. If `None`, a fresh record is created with
/// `display_name` and `channel_ids`.
///
/// This is the pure, testable core — no I/O.
pub(crate) fn build_agent_profile_content(
    display_name: &str,
    channel_ids: &[Uuid],
    existing_content: Option<&str>,
) -> Result<String, serde_json::Error> {
    let mut object = match existing_content {
        Some(raw) => {
            let parsed: Value = serde_json::from_str(raw)?;
            parsed
                .as_object()
                .ok_or_else(|| serde::de::Error::custom("kind:10100 content is not a JSON object"))?
                .clone()
        }
        None => serde_json::Map::new(),
    };

    object.insert(
        "display_name".to_string(),
        Value::String(display_name.to_string()),
    );
    object.insert(
        "channel_ids".to_string(),
        json!(channel_ids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()),
    );

    serde_json::to_string(&Value::Object(object))
}

/// Extract tag vectors from an existing kind:10100 event JSON, filtering out
/// any stale `auth` tags (the CLI republish path does the same — a fresh auth
/// tag will be injected by `sign_event` if the caller has one).
fn retain_existing_tags(existing: &Value) -> Vec<Tag> {
    let empty = vec![];
    let raw_tags = existing
        .get("tags")
        .and_then(|t| t.as_array())
        .unwrap_or(&empty);

    raw_tags
        .iter()
        .filter_map(|raw_tag| {
            let values = raw_tag.as_array()?;
            let strs: Vec<String> = values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if strs.is_empty() {
                return None;
            }
            // Drop stale auth tags — the caller's sign path re-injects a
            // current attestation if configured.
            if strs[0] == "auth" {
                return None;
            }
            Tag::parse(strs).ok()
        })
        .collect()
}

/// Find the latest kind:10100 event from a query result array.
///
/// Events arrive newest-first from the relay; we still pick by `created_at`
/// (then `id` as a tiebreaker) to be robust against ordering changes.
pub(crate) fn latest_agent_profile_event(events: &[Value]) -> Option<&Value> {
    events.iter().max_by(|left, right| {
        left.get("created_at")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&right.get("created_at").and_then(Value::as_u64).unwrap_or(0))
            .then_with(|| {
                left.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("id").and_then(Value::as_str).unwrap_or(""))
            })
    })
}

/// Build a signed kind:10100 event from the given content and optional tags.
///
/// `created_at` is set to `max(existing_created_at + 1, now)` when an existing
/// event is present, so the relay's replaceable-event logic picks up the new
/// record. Without this, a same-second republish would be deduplicated.
pub(crate) fn sign_agent_profile_event(
    keys: &Keys,
    content: &str,
    mut tags: Vec<Tag>,
    existing: Option<&Value>,
) -> Result<nostr::Event, RelayError> {
    let created_at = match existing.and_then(|e| e.get("created_at").and_then(Value::as_u64)) {
        Some(prev) => Timestamp::from(prev.saturating_add(1).max(Timestamp::now().as_secs())),
        None => Timestamp::now(),
    };

    let builder = EventBuilder::new(Kind::Custom(KIND_AGENT_PROFILE as u16), content)
        .tags(tags.drain(..))
        .custom_created_at(created_at);

    builder
        .sign_with_keys(keys)
        .map_err(|e| RelayError::AuthFailed(e.to_string()))
}

/// Publish (or refresh) the agent's kind:10100 directory record.
///
/// Reads the current record (if any), merges `channel_ids` into the content
/// while preserving all other fields and tags, signs, and submits via the HTTP
/// bridge. Best-effort: errors are logged and returned but never crash the
/// harness.
pub(crate) async fn publish_agent_directory_record(
    rest: &RestClient,
    keys: &Keys,
    display_name: &str,
    channel_ids: &[Uuid],
) -> Result<(), RelayError> {
    let pubkey_hex = keys.public_key().to_hex();

    // Query for the existing kind:10100 record from this agent's pubkey.
    let filter = nostr::Filter::new()
        .kind(Kind::Custom(KIND_AGENT_PROFILE as u16))
        .authors(vec![keys.public_key()]);

    let events = rest.query(&[filter]).await?;
    let event_arr = events.as_array().ok_or_else(|| {
        RelayError::Http("expected JSON array from /query (agent profile)".into())
    })?;

    let existing = latest_agent_profile_event(event_arr);
    let existing_content = existing.and_then(|e| e.get("content").and_then(Value::as_str));

    let content = build_agent_profile_content(display_name, channel_ids, existing_content)
        .map_err(|e| RelayError::Http(format!("kind:10100 content build error: {e}")))?;

    let tags = retain_existing_tags(existing.unwrap_or(&Value::Null));

    let event = sign_agent_profile_event(keys, &content, tags, existing)?;

    tracing::info!(
        pubkey = %pubkey_hex,
        channels = channel_ids.len(),
        "publishing kind:10100 agent directory record"
    );

    rest.submit_event(&event).await?;
    Ok(())
}

/// Convenience: publish with a `HashSet` of channel IDs (the shape the event
/// loop tracks as `subscribed_channel_ids`).
pub(crate) async fn refresh_agent_directory_record(
    rest: &RestClient,
    keys: &Keys,
    display_name: &str,
    subscribed_channel_ids: &HashSet<Uuid>,
) {
    let channel_ids: Vec<Uuid> = {
        let mut v: Vec<Uuid> = subscribed_channel_ids.iter().copied().collect();
        v.sort_unstable();
        v
    };

    if let Err(e) = publish_agent_directory_record(rest, keys, display_name, &channel_ids).await {
        tracing::warn!("failed to publish kind:10100 agent directory record: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn make_keys() -> Keys {
        Keys::generate()
    }

    fn uuids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    /// Core test: the content builder merges `channel_ids` into an existing
    /// record while preserving other fields. This fails on the unfixed code
    /// because there is no builder function at all — calling
    /// `build_agent_profile_content` would be a compile error.
    #[test]
    fn build_content_preserves_existing_fields_and_overwrites_channel_ids() {
        let existing = r#"{"display_name":"old-name","channel_ids":["dead-beef"],"channel_add_policy":"owner_only","custom":{"keep":true}}"#;
        let channels = uuids(3);

        let content = build_agent_profile_content("new-name", &channels, Some(existing)).unwrap();

        let parsed: Value = serde_json::from_str(&content).unwrap();
        let obj = parsed.as_object().expect("content is a JSON object");

        // channel_ids overwritten with the new set.
        let ids: Vec<String> = obj["channel_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids.len(), 3);
        for ch in &channels {
            assert!(ids.contains(&ch.to_string()));
        }

        // display_name overwritten.
        assert_eq!(obj["display_name"].as_str().unwrap(), "new-name");

        // Existing fields preserved.
        assert_eq!(obj["channel_add_policy"].as_str().unwrap(), "owner_only");
        assert!(obj["custom"]["keep"].as_bool().unwrap());
    }

    /// Fresh record (no existing content) gets display_name + channel_ids only.
    #[test]
    fn build_content_from_scratch_has_display_name_and_channel_ids() {
        let channels = uuids(2);
        let content = build_agent_profile_content("agent-1", &channels, None).unwrap();

        let parsed: Value = serde_json::from_str(&content).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj["display_name"].as_str().unwrap(), "agent-1");
        assert_eq!(obj["channel_ids"].as_array().unwrap().len(), 2);
        // No stray fields.
        assert_eq!(obj.len(), 2);
    }

    /// Empty channel set produces an empty channel_ids array.
    #[test]
    fn build_content_with_zero_channels() {
        let content = build_agent_profile_content("solo", &[], None).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["channel_ids"].as_array().unwrap().is_empty());
    }

    /// The signed event is a valid kind:10100 with correct content and
    /// created_at > existing.
    #[test]
    fn sign_event_produces_valid_kind_10100_with_monotonic_timestamp() {
        let keys = make_keys();
        let channels = uuids(1);
        let content = build_agent_profile_content("test-agent", &channels, None).unwrap();

        // Existing event with created_at = 1000.
        let existing = json!({
            "created_at": 1000u64,
            "content": r#"{"display_name":"old"}"#,
            "tags": [],
            "id": "abc",
            "pubkey": keys.public_key().to_hex(),
        });

        let event = sign_agent_profile_event(&keys, &content, vec![], Some(&existing)).unwrap();

        assert_eq!(event.kind.as_u16(), KIND_AGENT_PROFILE as u16);
        assert!(event.created_at.as_secs() >= 1001);
        // Content round-trips as valid JSON.
        let parsed: Value = serde_json::from_str(&event.content).unwrap();
        assert_eq!(parsed["display_name"].as_str().unwrap(), "test-agent");
    }

    /// Without an existing event, created_at is ~now (no panic, no zero).
    #[test]
    fn sign_event_without_existing_uses_now() {
        let keys = make_keys();
        let content = build_agent_profile_content("fresh", &uuids(1), None).unwrap();
        let event = sign_agent_profile_event(&keys, &content, vec![], None).unwrap();
        assert!(event.created_at.as_secs() > 0);
    }

    /// `latest_agent_profile_event` picks the newest by created_at.
    #[test]
    fn latest_agent_profile_picks_newest() {
        let older = json!({"created_at": 100u64, "id": "aaa"});
        let newer = json!({"created_at": 200u64, "id": "bbb"});
        let events = vec![older, newer];
        let latest = latest_agent_profile_event(&events).unwrap();
        assert_eq!(latest["id"].as_str().unwrap(), "bbb");
    }

    /// `retain_existing_tags` drops stale `auth` tags but keeps everything else.
    #[test]
    fn retain_tags_drops_auth_keeps_rest() {
        let existing = json!({
            "tags": [
                ["auth", "deadbeef", "label", "sig"],
                ["custom", "value"],
                ["d", "some-id"],
            ]
        });
        let tags = retain_existing_tags(&existing);
        // auth dropped, custom + d kept.
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_slice()[0].as_str(), "custom");
        assert_eq!(tags[1].as_slice()[0].as_str(), "d");
    }

    /// Round-trip: build content from an existing event, sign, and verify the
    /// signed event's content parses back with the right channel_ids.
    #[test]
    fn full_build_and_sign_round_trip() {
        let keys = make_keys();
        let channels = uuids(4);
        let existing_content =
            r#"{"display_name":"v1","channel_ids":["x"],"channel_add_policy":"nobody"}"#;

        let content = build_agent_profile_content("v2", &channels, Some(existing_content)).unwrap();
        let event = sign_agent_profile_event(&keys, &content, vec![], None).unwrap();

        let parsed: Value = serde_json::from_str(&event.content).unwrap();
        assert_eq!(parsed["display_name"].as_str().unwrap(), "v2");
        assert_eq!(parsed["channel_add_policy"].as_str().unwrap(), "nobody");
        assert_eq!(parsed["channel_ids"].as_array().unwrap().len(), 4);
    }
}
