//! Managed-agent kind:10100 directory record maintenance.
//!
//! Desktop builds its mention-autocomplete agent directory from kind:10100
//! events, so a record whose `channel_ids` projection is stale hides the agent
//! in every channel the record does not list. These helpers rebuild the
//! projection from the relay's canonical membership state after a channel
//! membership change, without dropping fields or tags authored by the agent.

use nostr::{EventBuilder, Kind, Tag};

use super::{query_relay_at_with_keys, relay_http_base_url, submit_signed_event_with_keys};
use crate::app_state::AppState;

/// Add a verified NIP-OA auth tag to an event builder.
///
/// `buzz-sdk` uses nostr 0.36 while the desktop crate uses nostr 0.37. Keep
/// the conversion in one place so every event signed by a managed agent uses
/// the same owner-attestation path as the kind:0 profile event.
pub(super) fn append_verified_auth_tag(
    builder: EventBuilder,
    agent_keys: &nostr::Keys,
    auth_tag_json: Option<&str>,
) -> Result<EventBuilder, String> {
    let Some(tag_json) = auth_tag_json else {
        return Ok(builder);
    };

    let agent_pubkey_hex = agent_keys.public_key().to_hex();
    let compat_pubkey = nostr::PublicKey::from_hex(&agent_pubkey_hex)
        .map_err(|e| format!("failed to convert agent pubkey for auth verification: {e}"))?;
    buzz_sdk_pkg::nip_oa::verify_auth_tag(tag_json, &compat_pubkey)
        .map_err(|e| format!("auth tag verification failed for profile event: {e}"))?;

    let compat_tag = buzz_sdk_pkg::nip_oa::parse_auth_tag(tag_json)
        .map_err(|e| format!("failed to parse verified auth tag: {e}"))?;
    let tag = nostr::Tag::parse(compat_tag.as_slice())
        .map_err(|e| format!("failed to convert auth tag to nostr 0.37: {e}"))?;
    Ok(builder.tags([tag]))
}

/// Merge the current channel membership projection into an agent's existing
/// kind:10100 record without dropping fields or tags authored by the agent.
fn merge_agent_profile_channel_ids(
    existing: Option<&nostr::Event>,
    display_name: &str,
    avatar_url: Option<&str>,
    channel_ids: &[String],
    auth_tag_json: Option<&str>,
    update_metadata: bool,
) -> Result<(String, Vec<Tag>), String> {
    let mut content = match existing {
        Some(event) => serde_json::from_str::<serde_json::Value>(&event.content)
            .map_err(|e| format!("agent kind:10100 content is not valid JSON: {e}"))?,
        None => serde_json::json!({}),
    };
    let object = content
        .as_object_mut()
        .ok_or_else(|| "agent kind:10100 content must be a JSON object".to_string())?;

    // A Desktop-owned save is authoritative for the display name. A
    // membership-only refresh changes channel_ids and leaves every other
    // existing field untouched.
    if update_metadata || existing.is_none() {
        object.insert(
            "display_name".to_string(),
            serde_json::Value::String(display_name.to_string()),
        );
        object.insert(
            "name".to_string(),
            serde_json::Value::String(display_name.to_string()),
        );
    }
    object.insert(
        "channel_ids".to_string(),
        serde_json::to_value(channel_ids)
            .map_err(|e| format!("channel_ids serialization failed: {e}"))?,
    );

    if (update_metadata || existing.is_none()) && avatar_url.is_some() {
        if let Some(avatar_url) = avatar_url {
            object.insert(
                "picture".to_string(),
                serde_json::Value::String(avatar_url.to_string()),
            );
        }
    }

    // The relay side effect requires this field. New Desktop-owned records get
    // the safe default; existing records retain their policy verbatim.
    object
        .entry("channel_add_policy".to_string())
        .or_insert_with(|| serde_json::Value::String("owner_only".to_string()));
    if existing.is_none() {
        object.insert(
            "agent_type".to_string(),
            serde_json::Value::String("agent".to_string()),
        );
        object.insert("channels".to_string(), serde_json::json!([]));
        object.insert("capabilities".to_string(), serde_json::json!([]));
        object.insert(
            "status".to_string(),
            serde_json::Value::String("offline".to_string()),
        );
    }

    let mut tags = existing
        .map(|event| event.tags.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    // The current auth tag is re-injected below. Keeping an old tag as well
    // would publish duplicate owner attestations after a key rotation.
    if auth_tag_json.is_some() {
        tags.retain(|tag| tag.as_slice().first().map(String::as_str) != Some("auth"));
    }

    Ok((content.to_string(), tags))
}

/// Republish a Desktop-owned managed agent's kind:10100 profile after a
/// channel membership change. Membership is re-read from the relay so the
/// record reflects the canonical current set even when several channels are
/// changed in quick succession.
pub async fn sync_managed_agent_profile_directory(
    state: &AppState,
    relay_url: &str,
    agent_keys: &nostr::Keys,
    display_name: &str,
    avatar_url: Option<&str>,
    auth_tag: Option<&str>,
    update_metadata: bool,
) -> Result<(), String> {
    use buzz_core_pkg::kind::KIND_AGENT_PROFILE;

    let api_base_url = relay_http_base_url(relay_url);
    let agent_pubkey = agent_keys.public_key().to_hex();
    // Read channel membership as the Desktop owner. This remains authorized
    // after the managed agent is removed from the channel being refreshed.
    let owner_keys = state.signing_keys()?;
    let member_events = query_relay_at_with_keys(
        state,
        &api_base_url,
        &[serde_json::json!({
            "kinds": [39002],
            "#p": [&agent_pubkey],
        })],
        &owner_keys,
        None,
    )
    .await?;

    let mut channel_ids: Vec<String> = member_events
        .iter()
        .filter_map(|event| {
            event.tags.iter().find_map(|tag| {
                let values = tag.as_slice();
                (values.len() >= 2 && values[0] == "d").then(|| values[1].clone())
            })
        })
        .collect();
    channel_ids.sort();
    channel_ids.dedup();

    let profile_events = query_relay_at_with_keys(
        state,
        &api_base_url,
        &[serde_json::json!({
            "authors": [&agent_pubkey],
            "kinds": [KIND_AGENT_PROFILE],
            "limit": 1,
        })],
        agent_keys,
        auth_tag,
    )
    .await?;
    let existing = profile_events.first();
    let (content, tags) = merge_agent_profile_channel_ids(
        existing,
        display_name,
        avatar_url,
        &channel_ids,
        auth_tag,
        update_metadata,
    )?;
    let created_at = existing
        .map(|event| event.created_at.as_secs().saturating_add(1))
        .unwrap_or_default()
        .max(nostr::Timestamp::now().as_secs());
    let builder = EventBuilder::new(Kind::Custom(KIND_AGENT_PROFILE as u16), &content)
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(created_at));
    let event = append_verified_auth_tag(builder, agent_keys, auth_tag)?
        .sign_with_keys(agent_keys)
        .map_err(|e| format!("failed to sign agent kind:10100 profile event: {e}"))?;

    submit_signed_event_with_keys(&event, state, agent_keys, auth_tag).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::merge_agent_profile_channel_ids;

    #[test]
    fn managed_agent_profile_refresh_preserves_fields_and_tags() {
        let agent_keys = nostr::Keys::generate();
        let existing = nostr::EventBuilder::new(
            nostr::Kind::Custom(buzz_core_pkg::kind::KIND_AGENT_PROFILE as u16),
            r#"{"display_name":"RelayName","name":"RelayName","channel_ids":["old"],"channel_add_policy":"nobody","custom":{"keep":true}}"#,
        )
        .tags([
            nostr::Tag::parse(["d", "profile"]).expect("valid tag"),
            nostr::Tag::parse(["custom", "preserve"]).expect("valid tag"),
        ])
        .sign_with_keys(&agent_keys)
        .expect("event should sign");

        let (content, tags) = merge_agent_profile_channel_ids(
            Some(&existing),
            "DesktopName",
            None,
            &["new-channel".to_string()],
            None,
            false,
        )
        .expect("profile merge should succeed");
        let content: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");

        assert_eq!(content["channel_ids"], serde_json::json!(["new-channel"]));
        assert_eq!(content["display_name"], "RelayName");
        assert_eq!(content["name"], "RelayName");
        assert_eq!(content["channel_add_policy"], "nobody");
        assert_eq!(content["custom"]["keep"], true);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_slice(), ["d", "profile"]);
        assert_eq!(tags[1].as_slice(), ["custom", "preserve"]);
    }
}
