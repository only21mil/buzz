//! Kind 10100 (agent directory record) publish and refresh.
//!
//! buzz-acp never published its own kind:10100 record, so an agent joined to a
//! new channel stayed hidden in the Desktop @ picker — the directory record
//! lacked the channel. This module reads the current record (if any), derives
//! the active channel set from kind:39002 memberships minus DM and archived
//! channels, and republishes through the HTTP bridge, preserving every
//! existing field and tag.
//!
//! The record is replaceable (NIP-01 kind 10000–19999), keyed by `(pubkey,
//! kind)`. The relay's `handle_agent_profile` side effect reads
//! `channel_add_policy` from the content JSON; the Desktop reads
//! `display_name`, `channel_ids`, and other optional fields. We preserve all
//! existing content fields and tags on republish, overwrite `channel_ids` and
//! `channels` (names, in the same sorted order), and seed missing defaults on
//! a first-ever record (respond_to, respond_to_allowlist, channel_add_policy,
//! status) exactly like the fleet directory-sync timer.

use std::collections::HashSet;

use buzz_core::kind::KIND_AGENT_PROFILE;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::relay::{RelayError, RestClient};

/// One discovered channel from kind:39000 metadata, reduced to what the
/// directory record needs: id, display name, and whether it is a DM and/or
/// archived. DM and archived channels are excluded from the published record,
/// matching the timer's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChannelMeta {
    pub name: String,
    pub channel_type: String,
    pub archived: bool,
}

/// Reduce kind:39000 metadata events into a channel-id map, marking DM and
/// archived channels so the caller can exclude them.
///
/// Mirrors the fleet directory-sync timer's read: a channel is excluded from
/// the published record when its metadata is archived=true or its declared
/// type (or hidden flag) is dm. Archived channels are KEPT in the map with
/// `archived: true`, so "no metadata row" is distinguishable from
/// "metadata present but correctly excluded": a member channel absent from
/// this map is a genuinely missing read, the condition the refresh guard
/// fails closed on, never an archived channel.
pub(crate) fn channel_meta_from_events(
    meta_events: &Value,
) -> std::collections::HashMap<Uuid, ChannelMeta> {
    let mut map = std::collections::HashMap::new();
    if let Some(arr) = meta_events.as_array() {
        for ev in arr {
            let tags = match ev.get("tags").and_then(|t| t.as_array()) {
                Some(t) => t,
                None => continue,
            };
            let mut d_val = None;
            let mut name = None;
            let mut archived = false;
            let mut declared_type = None;
            let mut is_hidden = false;
            for tag in tags {
                if let Some(arr) = tag.as_array() {
                    match arr.first().and_then(|v| v.as_str()) {
                        Some("d") => d_val = arr.get(1).and_then(|v| v.as_str()),
                        Some("name") => name = arr.get(1).and_then(|v| v.as_str()),
                        Some("archived") => {
                            archived = arr.get(1).and_then(|v| v.as_str()) == Some("true")
                        }
                        Some("hidden") => is_hidden = true,
                        Some("t") => declared_type = arr.get(1).and_then(|v| v.as_str()),
                        _ => {}
                    }
                }
            }
            let Some(d) = d_val else { continue };
            let Ok(uuid) = d.parse::<Uuid>() else {
                continue;
            };
            let channel_type = if declared_type == Some("dm") || is_hidden {
                "dm".to_string()
            } else {
                declared_type.unwrap_or("stream").to_string()
            };
            map.insert(
                uuid,
                ChannelMeta {
                    name: name.unwrap_or("unknown").to_string(),
                    channel_type,
                    archived,
                },
            );
        }
    }
    map
}

/// The pure channel projection: given the member channel UUIDs and the
/// metadata map, return the sorted (id, name) pairs for channels that are
/// neither archived nor DM. Sort order is by channel id (UUID string), like
/// the timer, so the `channel_ids` and `channels` arrays line up.
pub(crate) fn project_member_channels(
    member_ids: &[Uuid],
    metas: &std::collections::HashMap<Uuid, ChannelMeta>,
) -> Vec<(Uuid, String)> {
    let mut out: Vec<(Uuid, String)> = member_ids
        .iter()
        .filter_map(|id| {
            let meta = metas.get(id)?;
            if meta.archived || meta.channel_type == "dm" {
                return None;
            }
            Some((*id, meta.name.clone()))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Member channel ids whose kind:39000 metadata is absent from the read map.
///
/// Archived and DM channels still carry metadata (with their `archived` and
/// `t` tags), so a channel landing here is a genuinely missing read, not an
/// intentional exclusion. The refresh guard fails closed on these.
pub(crate) fn member_channels_missing_metadata(
    member_ids: &[Uuid],
    metas: &std::collections::HashMap<Uuid, ChannelMeta>,
) -> Vec<Uuid> {
    let mut missing: Vec<Uuid> = member_ids
        .iter()
        .copied()
        .filter(|id| !metas.contains_key(id))
        .collect();
    missing.sort_unstable();
    missing
}

/// Default content for a first-ever record, seeded from the fixed Sats policy
/// table exactly like the directory-sync timer (respond_to allowlist with the
/// owner/allowlist set, channel_add_policy owner_only, status online).
fn fresh_record_defaults(allowlist: &[String]) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert("respond_to".into(), Value::String("allowlist".into()));
    map.insert(
        "respond_to_allowlist".into(),
        json!(allowlist.iter().collect::<Vec<_>>()),
    );
    map.insert(
        "channel_add_policy".into(),
        Value::String("owner_only".into()),
    );
    map.insert("status".into(), Value::String("online".into()));
    map
}

/// The kind:10100 content JSON, built or updated from the current channel set.
///
/// If `existing_content` is `Some`, every existing field is preserved,
/// `display_name` is overwritten, and `channel_ids` plus `channels` (names in
/// the same order) are written from the projection. If `None`, a fresh record
/// is created with `display_name`, `channel_ids`, `channels`, and the policy
/// defaults.
///
/// This is the pure, testable core — no I/O.
pub(crate) fn build_agent_profile_content(
    display_name: &str,
    channels: &[(Uuid, String)],
    existing_content: Option<&str>,
    allowlist: &[String],
) -> Result<String, serde_json::Error> {
    let channel_ids: Vec<String> = channels.iter().map(|(id, _)| id.to_string()).collect();
    let channel_names: Vec<String> = channels.iter().map(|(_, name)| name.clone()).collect();

    let mut object = match existing_content {
        Some(raw) => {
            let parsed: Value = serde_json::from_str(raw)?;
            parsed
                .as_object()
                .ok_or_else(|| serde::de::Error::custom("kind:10100 content is not a JSON object"))?
                .clone()
        }
        None => {
            let mut defaults = fresh_record_defaults(allowlist);
            defaults.insert(
                "display_name".to_string(),
                Value::String(display_name.to_string()),
            );
            defaults
        }
    };

    // On a merge (existing content present) preserve the curated display_name
    // from the existing record unless it is absent; on a fresh record use the
    // supplied name. A membership-only refresh must not clobber a display name
    // the owner set on the relay.
    if object.get("display_name").is_none() {
        object.insert(
            "display_name".to_string(),
            Value::String(display_name.to_string()),
        );
    }
    object.insert("channel_ids".to_string(), json!(channel_ids));
    object.insert("channels".to_string(), json!(channel_names));

    serde_json::to_string(&Value::Object(object))
}

/// Extract tag vectors from an existing kind:10100 event JSON.
///
/// Keeps every non-auth tag. Auth handling is left to `combine_auth_tag`:
/// the stored auth tag is preserved so a republish never strips the owner
/// attestation when no fresh one is available, and is replaced by a fresh one
/// when the caller has it. Exactly one auth tag is kept.
fn retain_existing_tags(existing: &Value) -> (Vec<Tag>, Option<Tag>) {
    let empty = vec![];
    let raw_tags = existing
        .get("tags")
        .and_then(|t| t.as_array())
        .unwrap_or(&empty);

    let mut tags = Vec::new();
    let mut stored_auth = None;
    for raw_tag in raw_tags {
        let Some(values) = raw_tag.as_array() else {
            continue;
        };
        let strs: Vec<String> = values
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if strs.is_empty() {
            continue;
        }
        if strs[0] == "auth" {
            // Keep the stored attestation; the combine step decides whether a
            // fresh one replaces it. A record with multiple auth tags fails
            // closed rather than silently choosing one.
            if stored_auth.is_some() {
                continue;
            }
            stored_auth = Tag::parse(&strs).ok();
            continue;
        }
        if let Ok(tag) = Tag::parse(&strs) {
            tags.push(tag);
        }
    }
    (tags, stored_auth)
}

/// Resolve the single auth tag to attach, exactly like the directory-sync
/// timer: a fresh auth (from the caller's BUZZ_AUTH_TAG) replaces the stored
/// one; otherwise the stored one is preserved byte-identical. The chosen tag
/// is appended last, so an event never carries two auth tags and never loses
/// the owner attestation that makes mentions wake seats.
fn combine_auth_tag(stored_auth: Option<Tag>, fresh_auth: Option<Tag>) -> Vec<Tag> {
    match fresh_auth {
        Some(tag) => vec![tag],
        None => stored_auth.into_iter().collect(),
    }
}

/// Find the latest kind:10100 event from a query result array.
///
/// Picks by `created_at`, then (for a created_at tie) by the LOWEST event id,
/// which is what NIP-01 replaceable-event semantics expect: among records with
/// the same timestamp, the earliest id is the stable one, not the greatest.
pub(crate) fn latest_agent_profile_event(events: &[Value]) -> Option<&Value> {
    events.iter().max_by(|left, right| {
        left.get("created_at")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&right.get("created_at").and_then(Value::as_u64).unwrap_or(0))
            .then_with(|| {
                // Equal created_at: lower id wins (ascending compare on the
                // reversed axis keeps max_by selecting the lower id).
                right
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(left.get("id").and_then(Value::as_str).unwrap_or(""))
            })
    })
}

/// Build a signed kind:10100 event from the given content and optional tags.
///
/// `created_at` is set to `max(existing_created_at + 1, now)` when an existing
/// event is present, so the relay's replaceable-event logic picks up the new
/// record. Without this, a same-second republish would be deduplicated.
///
/// `stored_auth` is the auth tag retained from the existing record;
/// `fresh_auth` is the current owner attestation from BUZZ_AUTH_TAG. When a
/// fresh one is present it replaces the stored one; otherwise the stored one
/// is preserved byte-identical. Exactly one auth tag is attached, appended
/// last, matching the directory-sync timer.
pub(crate) fn sign_agent_profile_event(
    keys: &Keys,
    content: &str,
    mut tags: Vec<Tag>,
    existing: Option<&Value>,
    stored_auth: Option<Tag>,
    fresh_auth: Option<Tag>,
) -> Result<nostr::Event, RelayError> {
    let created_at = match existing.and_then(|e| e.get("created_at").and_then(Value::as_u64)) {
        Some(prev) => Timestamp::from(prev.saturating_add(1).max(Timestamp::now().as_secs())),
        None => Timestamp::now(),
    };

    // Exactly one auth tag (fresh replaces stored; stored preserved when no
    // fresh is available), appended last so it never carries two attestations.
    tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("auth"));
    tags.extend(combine_auth_tag(stored_auth, fresh_auth));

    let builder = EventBuilder::new(Kind::Custom(KIND_AGENT_PROFILE as u16), content)
        .tags(tags.drain(..))
        .custom_created_at(created_at);

    builder
        .sign_with_keys(keys)
        .map_err(|e| RelayError::AuthFailed(e.to_string()))
}

/// Query kind:39002 memberships for this agent, then pull kind:39000 metadata
/// and reduce to the active (non-DM, non-archived) channel set sorted by id.
///
/// This is the read side of the timer contract: publish active memberships,
/// not configured subscriptions. DM channels are excluded on purpose (they are
/// per-user conversations, not directory entries) and archived channels are
/// excluded because they are unusable.
///
/// Returns the member channels whose metadata could not be read, so the
/// refresh can fail closed on a partial metadata read instead of silently
/// publishing a projection missing the agent from real channels.
pub(crate) async fn fetch_member_channels(
    rest: &RestClient,
    keys: &Keys,
) -> Result<Vec<(Uuid, String)>, RelayError> {
    let pubkey_hex = keys.public_key().to_hex();
    use nostr::{Alphabet, SingleLetterTag};

    // Step 1: kind:39002 group-members events where #p includes this agent.
    let p_tag = SingleLetterTag::lowercase(Alphabet::P);
    let member_filter = nostr::Filter::new()
        .kind(Kind::Custom(
            buzz_core::kind::KIND_NIP29_GROUP_MEMBERS as u16,
        ))
        .custom_tags(p_tag, [pubkey_hex.as_str()]);
    let member_events = rest.query(&[member_filter]).await?;
    let member_arr = member_events.as_array().ok_or_else(|| {
        RelayError::Http("expected JSON array from /query (group members)".into())
    })?;

    let mut member_ids: Vec<Uuid> = Vec::new();
    for ev in member_arr {
        if let Some(tags) = ev.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(arr) = tag.as_array() {
                    if arr.first().and_then(|v| v.as_str()) == Some("d") {
                        if let Some(d_val) = arr.get(1).and_then(|v| v.as_str()) {
                            if let Ok(uuid) = d_val.parse::<Uuid>() {
                                member_ids.push(uuid);
                            }
                        }
                    }
                }
            }
        }
    }
    member_ids.sort_unstable();
    member_ids.dedup();

    // Step 2: kind:39000 metadata for the discovered channels.
    if member_ids.is_empty() {
        return Ok(Vec::new());
    }
    let d_tag = SingleLetterTag::lowercase(Alphabet::D);
    let d_values: Vec<String> = member_ids.iter().map(|u| u.to_string()).collect();
    let meta_filter = nostr::Filter::new()
        .kind(Kind::Custom(
            buzz_core::kind::KIND_NIP29_GROUP_METADATA as u16,
        ))
        .custom_tags(d_tag, d_values);
    let meta_events = rest.query(&[meta_filter]).await?;
    let metas = channel_meta_from_events(&meta_events);

    let channels = project_member_channels(&member_ids, &metas);
    let missing = member_channels_missing_metadata(&member_ids, &metas);
    if !missing.is_empty() {
        tracing::warn!(
            missing = ?missing,
            members = member_ids.len(),
            "kind:10100 metadata read missing {} channel{}; failing closed",
            missing.len(),
            if missing.len() == 1 { "" } else { "s" }
        );
        return Err(RelayError::Http(format!(
            "incomplete kind:39000 metadata read; missing {} of {} member channels",
            missing.len(),
            member_ids.len()
        )));
    }

    Ok(channels)
}

/// Publish (or refresh) the agent's kind:10100 directory record.
///
/// Reads the current record (if any), merges the active member channel
/// projection into the content while preserving all other fields and tags,
/// signs, and submits via the HTTP bridge. Best-effort: errors are logged and
/// returned but never crash the harness.
pub(crate) async fn publish_agent_directory_record(
    rest: &RestClient,
    keys: &Keys,
    display_name: &str,
    channels: &[(Uuid, String)],
    allowlist: &[String],
    fresh_auth: Option<Tag>,
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

    let content = build_agent_profile_content(display_name, channels, existing_content, allowlist)
        .map_err(|e| RelayError::Http(format!("kind:10100 content build error: {e}")))?;

    let (tags, stored_auth) = retain_existing_tags(existing.unwrap_or(&Value::Null));

    let event = sign_agent_profile_event(keys, &content, tags, existing, stored_auth, fresh_auth)?;

    tracing::info!(
        pubkey = %pubkey_hex,
        channels = channels.len(),
        "publishing kind:10100 agent directory record"
    );

    // Fail closed on a relay duplicate. The relay's POST /events returns
    // {"event_id", "accepted", "message"}; a stale replaceable write (same
    // created_at or content already present, i.e. our read-merge-write lost a
    // race with the fleet timer) comes back as accepted:true with a message
    // starting "duplicate:". Rejections are HTTP 400 and become a RelayError
    // before any body is parsed, so the accepted:false branch is defensive
    // only. The response classification is a pure function so the wire shapes
    // are testable.
    //
    // This guard catches only the LOSING half of the race: a stale write that
    // submits and gets told duplicate. The winning half, a same-timestamp
    // write whose event id sorts lower than ours, is accepted by the relay
    // with no duplicate signal and would clobber concurrent fields (the
    // timer's). That residual is accepted here because the deployment plan
    // makes this code the sole writer: the timer is retired in the same
    // landing, so no concurrent writer exists in any window this guard runs
    // in, which is what makes it sound.
    let resp = rest.submit_event(&event).await?;
    if let Some(err) = classify_submit_response(&resp) {
        return Err(RelayError::Http(err));
    }

    Ok(())
}

/// Classify the relay's POST /events response into success or a non-deployable
/// outcome. Returns `Some(message)` when the write must NOT be reported as
/// done:
///
/// - `duplicate`: `accepted == true` with `message` starting `"duplicate:"`.
///   The relay judged the replaceable event not-new, so a concurrent writer
///   (the fleet timer) may have newer fields and our stale view must not
///   overwrite them.
/// - `rejected`: `accepted == false` (defensive; rejections are HTTP 400 and
///   surface as a `RelayError` before a body reaches us).
/// - `empty`: `submit_event` returns `Value::Null` on an empty 200 body. That
///   is not a duplicate signal and not a success signal either; treat it as
///   unknown and fail closed so a silent drop is never reported as done.
///
/// Anything else is treated as success.
fn classify_submit_response(resp: &Value) -> Option<String> {
    // Empty 200 body: submit_event returns Value::Null. Neither a duplicate
    // signal nor a success signal; fail closed so a silent drop is never
    // reported as done.
    if resp.is_null() {
        return Some(
            "kind:10100 submit returned an empty response; cannot confirm acceptance".to_string(),
        );
    }
    let obj = resp.as_object()?;
    let accepted = obj.get("accepted").and_then(Value::as_bool).unwrap_or(true);
    let message = obj.get("message").and_then(Value::as_str).unwrap_or("");

    if accepted && message.starts_with("duplicate:") {
        return Some(
            "kind:10100 submit reported duplicate; skipping (stale read or concurrent writer)"
                .to_string(),
        );
    }
    if !accepted {
        return Some(format!(
            "kind:10100 submit rejected: {}",
            if message.is_empty() {
                "unknown"
            } else {
                message
            }
        ));
    }
    None
}

/// Publish the record derived from the agent's active memberships. This is
/// what the startup and membership-change callers invoke: it re-reads
/// kind:39002 membership and kind:39000 metadata from the relay, so the record
/// reflects the canonical active set even after a batch of membership changes.
///
/// `fresh_auth` is the owner attestation parsed from BUZZ_AUTH_TAG; it is
/// attached (replacing any stored auth) when present, otherwise the stored
/// auth tag is preserved. A republish therefore never strips the attestation.
pub(crate) async fn refresh_agent_directory_record(
    rest: &RestClient,
    keys: &Keys,
    display_name: &str,
    allowlist: &[String],
    _subscribed_channel_ids: &HashSet<Uuid>,
    fresh_auth: Option<Tag>,
) {
    // `fetch_member_channels` fails closed on a partial kind:39000 metadata
    // read: any member channel whose metadata row is missing returns an error,
    // and we keep the previous record instead of publishing a projection that
    // silently drops the agent from real channels. Using the previous record
    // happens only on the assumption we still hold current owner auth; the
    // republish path would submit without auth if the stored record predates
    // any existing record on the relay, but publish fails closed on an empty
    // or duplicate response rather than reporting done.
    let channels = match fetch_member_channels(rest, keys).await {
        Ok(channels) => channels,
        Err(e) => {
            tracing::warn!("failed to read memberships for kind:10100 record: {e}");
            return;
        }
    };

    // A lagging membership query that returns zero channels would publish an
    // empty record and hide the agent everywhere. That is never correct while
    // the agent is online with subscriptions, so fail closed and keep the
    // previous record instead of silently publishing an empty projection.
    //
    // The reverse is a deliberate trade-off shared with the fleet directory
    // timer: after the final membership is removed the projection is
    // legitimately empty, so this guard also suppresses the empty publish that
    // a full removal would want, leaving a stale record containing the last
    // pre-removal channel until a future non-empty refresh replaces it. That
    // matches the retiring timer's own semantics (it errors on empty
    // membership too), and correctness here prefers a record that still lists
    // the agent somewhere over publishing a blank one that hides it everywhere.
    if channels.is_empty() {
        tracing::warn!(
            "kind:10100 refresh found zero active member channels; keeping the previous record"
        );
        return;
    }

    if let Err(e) =
        publish_agent_directory_record(rest, keys, display_name, &channels, allowlist, fresh_auth)
            .await
    {
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

    fn proj(ids: &[Uuid]) -> Vec<(Uuid, String)> {
        ids.iter().map(|&u| (u, format!("chan-{}", u))).collect()
    }

    /// Core test: the content builder merges channel_ids + channels into an
    /// existing record while preserving other fields. Fails on the unfixed
    /// code because the builder had no channel-names or allowlist support.
    #[test]
    fn build_content_preserves_existing_fields_and_overwrites_channel_ids() {
        let existing = r#"{"display_name":"old-name","channel_ids":["dead-beef"],"channel_add_policy":"owner_only","custom":{"keep":true}}"#;
        let pairs = vec![
            (Uuid::new_v4(), "one".to_string()),
            (Uuid::new_v4(), "two".to_string()),
            (Uuid::new_v4(), "three".to_string()),
        ];
        let allowlist = vec!["owner".to_string()];

        let content =
            build_agent_profile_content("new-name", &pairs, Some(existing), &allowlist).unwrap();

        let parsed: Value = serde_json::from_str(&content).unwrap();
        let obj = parsed.as_object().expect("content is a JSON object");

        let ids: Vec<String> = obj["channel_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let names: Vec<String> = obj["channels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids.len(), 3);
        assert_eq!(names, vec!["one", "two", "three"]);
        for (id, name) in &pairs {
            assert!(ids.contains(&id.to_string()));
            assert!(names.contains(name));
        }

        // Existing curated display_name is preserved on a membership-only
        // merge; the supplied name only seeds a fresh record.
        assert_eq!(obj["display_name"].as_str().unwrap(), "old-name");
        assert_eq!(obj["channel_add_policy"].as_str().unwrap(), "owner_only");
        assert!(obj["custom"]["keep"].as_bool().unwrap());
    }

    /// Fresh record (no existing content) gets display_name + channel_ids +
    /// channels + the policy defaults, not just two fields.
    #[test]
    fn build_content_from_scratch_has_display_name_and_channel_ids() {
        let pairs = proj(&uuids(2));
        let allowlist = vec!["owner".to_string(), "team".to_string()];
        let content = build_agent_profile_content("agent-1", &pairs, None, &allowlist).unwrap();

        let parsed: Value = serde_json::from_str(&content).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj["display_name"].as_str().unwrap(), "agent-1");
        assert_eq!(obj["channel_ids"].as_array().unwrap().len(), 2);
        assert_eq!(obj["channels"].as_array().unwrap().len(), 2);
        assert_eq!(obj["respond_to"].as_str().unwrap(), "allowlist");
        assert_eq!(obj["channel_add_policy"].as_str().unwrap(), "owner_only");
        let al = obj["respond_to_allowlist"].as_array().unwrap();
        assert_eq!(al.len(), 2);
    }

    /// Gate: from-scratch with ten keys/channels present, non-empty, names in
    /// order. The projection and builder must keep ids and names aligned even
    /// with ten memberships, and a fresh record is non-empty (not the two
    /// fields only, and not missing the names array).
    #[test]
    fn from_scratch_ten_channels_names_in_order() {
        let ids = uuids(10);
        let pairs: Vec<(Uuid, String)> = ids
            .iter()
            .enumerate()
            .map(|(i, &u)| (u, format!("channel-{:02}", i)))
            .collect();
        let allowlist = vec!["owner".to_string()];
        let content = build_agent_profile_content("ten", &pairs, None, &allowlist).unwrap();

        let parsed: Value = serde_json::from_str(&content).unwrap();
        let obj = parsed.as_object().unwrap();
        let ids_out: Vec<String> = obj["channel_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let names_out: Vec<String> = obj["channels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert_eq!(ids_out.len(), 10, "all ten channel ids present");
        assert_eq!(names_out.len(), 10, "all ten channel names present");
        assert!(!ids_out.is_empty() && !names_out.is_empty());
        for i in 0..10 {
            assert_eq!(ids_out[i], ids[i].to_string());
            assert_eq!(names_out[i], format!("channel-{:02}", i));
        }
    }

    /// Gate: DM-plus-archived exclusion. A member channel whose metadata is
    /// DM or archived must be dropped from the projection; the survivor stays.
    /// The map still carries the archived row; only the projection omits it.
    #[test]
    fn dm_and_archived_channels_are_excluded() {
        let live = Uuid::new_v4();
        let dm = Uuid::new_v4();
        let archived = Uuid::new_v4();
        let member_ids = vec![live, dm, archived];

        let metas: std::collections::HashMap<Uuid, ChannelMeta> = [
            (
                live,
                ChannelMeta {
                    name: "Live".into(),
                    channel_type: "stream".into(),
                    archived: false,
                },
            ),
            (
                dm,
                ChannelMeta {
                    name: "Direct".into(),
                    channel_type: "dm".into(),
                    archived: false,
                },
            ),
            (
                archived,
                ChannelMeta {
                    name: "Dead".into(),
                    channel_type: "stream".into(),
                    archived: true,
                },
            ),
        ]
        .into_iter()
        .collect();

        let projected = project_member_channels(&member_ids, &metas);
        assert_eq!(projected, vec![(live, "Live".to_string())]);
    }

    /// Gate: merge-existing with a membership change parsed-equal to the
    /// expected content. The builder must overwrite channel_ids + channels on
    /// a change and preserve the rest, and the result must equal the expected
    /// JSON exactly (id and name shown in sync).
    #[test]
    fn merge_existing_with_membership_change_parses_equal_to_expected() {
        let live = Uuid::new_v4();
        let existing =
            r#"{"display_name":"old","channel_ids":["dead"],"channel_add_policy":"nobody"}"#;
        let allowlist = vec!["owner".to_string()];
        let pairs = vec![(live, "general".to_string())];

        let content =
            build_agent_profile_content("New", &pairs, Some(existing), &allowlist).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        let expected: Value = serde_json::json!({
            // Existing curated display_name is preserved on merge.
            "display_name": "old",
            "channel_ids": [live.to_string()],
            "channels": ["general"],
            "channel_add_policy": "nobody",
        });
        assert_eq!(
            parsed, expected,
            "merged record must parse equal to expected"
        );
    }

    /// The signed event is a valid kind:10100 with correct content and
    /// created_at > existing.
    #[test]
    fn sign_event_produces_valid_kind_10100_with_monotonic_timestamp() {
        let keys = make_keys();
        let allowlist = vec!["owner".to_string()];
        let content =
            build_agent_profile_content("test-agent", &proj(&uuids(1)), None, &allowlist).unwrap();

        let existing = json!({
            "created_at": 1000u64,
            "content": r#"{"display_name":"old"}"#,
            "tags": [],
            "id": "abc",
            "pubkey": keys.public_key().to_hex(),
        });

        let event =
            sign_agent_profile_event(&keys, &content, vec![], Some(&existing), None, None).unwrap();

        assert_eq!(event.kind.as_u16(), KIND_AGENT_PROFILE as u16);
        assert!(event.created_at.as_secs() >= 1001);
        let parsed: Value = serde_json::from_str(&event.content).unwrap();
        assert_eq!(parsed["display_name"].as_str().unwrap(), "test-agent");
    }

    /// Without an existing event, created_at is ~now (no panic, no zero).
    #[test]
    fn sign_event_without_existing_uses_now() {
        let keys = make_keys();
        let allowlist = vec!["owner".to_string()];
        let content =
            build_agent_profile_content("fresh", &proj(&uuids(1)), None, &allowlist).unwrap();
        let event = sign_agent_profile_event(&keys, &content, vec![], None, None, None).unwrap();
        assert!(event.created_at.as_secs() > 0);
    }

    /// Discriminating auth test: an existing kind:10100 record carrying one
    /// auth tag republishes with that same tag byte-identical when no fresh
    /// auth is available. This fails on the old code, which dropped the stored
    /// auth and injected nothing, stripping the owner attestation.
    #[test]
    fn republish_preserves_stored_auth_when_no_fresh_auth() {
        let keys = make_keys();
        let existing_auth =
            Tag::parse(["auth", "4a34c131deadbeef", "created_at<4294967295", "sig"])
                .expect("valid auth tag");
        let existing = json!({
            "created_at": 1000u64,
            "content": r#"{"display_name":"old","channel_ids":["x"]}"#,
            "tags": [["auth", "4a34c131deadbeef", "created_at<4294967295", "sig"]],
            "id": "abc",
            "pubkey": keys.public_key().to_hex(),
        });

        let (tags, stored_auth) = retain_existing_tags(&existing);
        let event = sign_agent_profile_event(
            &keys,
            r#"{"display_name":"old","channel_ids":["y"]}"#,
            tags,
            Some(&existing),
            stored_auth,
            None,
        )
        .unwrap();

        let auth_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(String::as_str) == Some("auth"))
            .collect();
        assert_eq!(auth_tags.len(), 1, "exactly one auth tag preserved");
        assert_eq!(
            auth_tags[0].as_slice(),
            existing_auth.as_slice(),
            "stored auth tag preserved byte-identical"
        );
    }

    /// A fresh auth (from BUZZ_AUTH_TAG) replaces the stored auth, exactly one
    /// appended last — so the record never carries two attestations.
    #[test]
    fn fresh_auth_replaces_stored_auth_exactly_one() {
        let keys = make_keys();
        let existing = json!({
            "created_at": 1000u64,
            "content": r#"{"display_name":"old"}"#,
            "tags": [["auth", "deadbeef", "label", "oldsig"]],
            "id": "abc",
            "pubkey": keys.public_key().to_hex(),
        });
        let fresh = Tag::parse(["auth", "cafe", "label", "newsig"]).unwrap();

        let (tags, stored_auth) = retain_existing_tags(&existing);
        let event = sign_agent_profile_event(
            &keys,
            r#"{"display_name":"old"}"#,
            tags,
            Some(&existing),
            stored_auth,
            Some(fresh.clone()),
        )
        .unwrap();

        let auth_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(String::as_str) == Some("auth"))
            .collect();
        assert_eq!(auth_tags.len(), 1);
        assert_eq!(auth_tags[0].as_slice(), fresh.as_slice());
    }

    /// Regression for the GPT review finding: a membership-only merge must
    /// preserve the existing curated display_name, not replace it with the
    /// normalized executable name. Fails on revision 2, passes on this fix.
    #[test]
    fn merge_preserves_existing_curated_display_name() {
        let live = Uuid::new_v4();
        let existing = r#"{"display_name":"Curated Name","name":"Curated Name","channel_ids":["old"],"channel_add_policy":"nobody"}"#;
        let content = build_agent_profile_content(
            "buzz-sats-agent@foo.service",
            &[(live, "general".into())],
            Some(existing),
            &["owner".into()],
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["display_name"], "Curated Name");
        assert_eq!(parsed["name"], "Curated Name");
        assert_eq!(parsed["channel_ids"][0], live.to_string());
        assert_eq!(parsed["channels"][0], "general");
    }

    /// Regression: a merge onto an existing record that lacks display_name
    /// seeds it from the supplied name (the only case the supplied name may
    /// apply on a merge).
    #[test]
    fn merge_seeds_display_name_when_existing_lacks_it() {
        let live = Uuid::new_v4();
        let existing = r#"{"channel_ids":["old"],"channel_add_policy":"nobody"}"#;
        let content = build_agent_profile_content(
            "buzz-sats-agent@foo.service",
            &[(live, "general".into())],
            Some(existing),
            &["owner".into()],
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["display_name"], "buzz-sats-agent@foo.service");
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

    /// NIP-01 tie-break: for equal created_at, the LOWEST id wins (stable
    /// replaceable-event selection), not the greatest. Fails on revision 2.
    #[test]
    fn latest_agent_profile_uses_lowest_id_on_created_at_tie() {
        let events = vec![
            json!({"created_at": 100u64, "id": "ddd"}),
            json!({"created_at": 100u64, "id": "bbb"}),
            json!({"created_at": 100u64, "id": "aaa"}),
        ];
        let latest = latest_agent_profile_event(&events).unwrap();
        assert_eq!(latest["id"].as_str().unwrap(), "aaa");
    }

    /// The relay's real wire shapes for a POST /events submit: a stale
    /// duplicate is accepted:true with message "duplicate:..."; a new accepted
    /// write is accepted:true with a normal event_id/message; an empty 200
    /// body arrives as Value::Null. The classifier must fail closed on the
    /// duplicate and the empty body and pass the new accepted write.
    #[test]
    fn classify_submit_response_holds_live_wire_shapes() {
        // A new accepted replaceable write (the normal case).
        let accepted_new = json!({"event_id": "abc", "accepted": true, "message": "saved"});
        assert!(classify_submit_response(&accepted_new).is_none());

        // A stale duplicate: the exact failure the race guard must catch.
        let duplicate = json!({"event_id": "abc", "accepted": true, "message": "duplicate: such event already exists"});
        let err = classify_submit_response(&duplicate).expect("duplicate must fail closed");
        assert!(
            err.contains("duplicate"),
            "error should name the duplicate: {err}"
        );

        // Empty 200 body: submit_event returns Value::Null; must fail closed,
        // never reported as a silent success.
        let empty = Value::Null;
        let err = classify_submit_response(&empty).expect("empty body must fail closed");
        assert!(
            err.contains("empty"),
            "error should name the empty response: {err}"
        );

        // Defensive: an explicit accepted:false rejects even when no 400.
        let rejected = json!({"event_id": "abc", "accepted": false, "message": "denied"});
        let err = classify_submit_response(&rejected).expect("accepted:false must fail closed");
        assert!(
            err.contains("rejected"),
            "error should name the rejection: {err}"
        );
    }

    /// `retain_existing_tags` keeps non-auth tags and returns the single
    /// stored auth tag separately so the sign path can preserve or replace it.
    #[test]
    fn retain_tags_keeps_rest_and_returns_stored_auth() {
        let existing = json!({
            "tags": [
                ["auth", "deadbeef", "label", "sig"],
                ["custom", "value"],
                ["d", "some-id"],
            ]
        });
        let (tags, stored_auth) = retain_existing_tags(&existing);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_slice()[0].as_str(), "custom");
        assert_eq!(tags[1].as_slice()[0].as_str(), "d");
        let stored = stored_auth.expect("stored auth tag is retained");
        assert_eq!(stored.as_slice()[0].as_str(), "auth");
        assert_eq!(stored.as_slice()[1].as_str(), "deadbeef");
    }

    /// Channel-metadata reduction: DM and archived are flagged so the
    /// projection excludes them; a normal stream keeps its name. Archived
    /// channels stay in the map with archived=true so "metadata present but
    /// correctly excluded" stays distinguishable from a missing read.
    #[test]
    fn channel_meta_reduction_flags_dm_and_archived() {
        let live = Uuid::new_v4();
        let dm = Uuid::new_v4();
        let archived = Uuid::new_v4();
        let meta = json!([
            {"tags": [["d", live.to_string()], ["name", "general"], ["t", "stream"]]},
            {"tags": [["d", dm.to_string()], ["name", "Direct"], ["t", "dm"]]},
            {"tags": [["d", archived.to_string()], ["name", "Dead"], ["archived", "true"]]},
        ]);
        let map = channel_meta_from_events(&meta);
        assert_eq!(map.len(), 3);
        assert_eq!(map[&live].channel_type, "stream");
        assert_eq!(map[&dm].channel_type, "dm");
        let archived_meta = &map[&archived];
        assert!(
            archived_meta.archived,
            "archived channel must stay in the map"
        );
        assert_eq!(archived_meta.name, "Dead");
    }

    /// Gate for the GPT-review finding 2: a member channel whose kind:39000
    /// metadata is genuinely absent is reported as missing so the refresh can
    /// fail closed, while DM and archived memberships are NOT missing (their
    /// metadata exists with the type/archived tags). Fails on revision 4,
    /// where an archived membership was dropped from the metadata map and
    /// would have read as missing.
    #[test]
    fn member_channels_missing_metadata_distinguishes_absent_from_excluded() {
        let live = Uuid::new_v4();
        let dm = Uuid::new_v4();
        let archived = Uuid::new_v4();
        let phantom = Uuid::new_v4();
        let member_ids = vec![live, dm, archived, phantom];

        let metas: std::collections::HashMap<Uuid, ChannelMeta> = [
            (
                live,
                ChannelMeta {
                    name: "Live".into(),
                    channel_type: "stream".into(),
                    archived: false,
                },
            ),
            (
                dm,
                ChannelMeta {
                    name: "Direct".into(),
                    channel_type: "dm".into(),
                    archived: false,
                },
            ),
            (
                archived,
                ChannelMeta {
                    name: "Dead".into(),
                    channel_type: "stream".into(),
                    archived: true,
                },
            ),
        ]
        .into_iter()
        .collect();

        let missing = member_channels_missing_metadata(&member_ids, &metas);
        assert_eq!(
            missing,
            vec![phantom],
            "only the truly absent membership is missing; DM and archived are not"
        );
    }

    /// The fail-closed condition: any missing metadata row trips the guard,
    /// no matter how complete the rest of the projection is.
    #[test]
    fn member_channels_missing_metadata_fails_closed_on_any_absent_row() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let metas: std::collections::HashMap<Uuid, ChannelMeta> = [(
            a,
            ChannelMeta {
                name: "A".into(),
                channel_type: "stream".into(),
                archived: false,
            },
        )]
        .into_iter()
        .collect();

        let missing = member_channels_missing_metadata(&[a, b], &metas);
        assert_eq!(missing, vec![b], "the absent membership must be flagged");
    }
}
