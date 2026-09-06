use crate::{app_state::AppState, events, relay::query_relay};
use nostr::EventId;

/// Validate a cached NIP-10 root and parent before signing, without a relay read.
pub(super) fn provided_thread_ref(root: &str, parent: &str) -> Result<events::ThreadRef, String> {
    Ok(events::ThreadRef {
        root_event_id: EventId::from_hex(root)
            .map_err(|e| format!("invalid root event ID: {e}"))?,
        parent_event_id: EventId::from_hex(parent)
            .map_err(|e| format!("invalid parent event ID: {e}"))?,
    })
}

pub(super) async fn thread_ref(
    parent: &str,
    cached_root: Option<&str>,
    state: &AppState,
) -> Result<events::ThreadRef, String> {
    match cached_root {
        Some(root) => provided_thread_ref(root, parent),
        None => resolve_thread_ref(parent, state).await,
    }
}

/// Fetch a parent event and extract the thread root from its NIP-10 e-tags.
pub(super) async fn resolve_thread_ref(
    parent_event_id: &str,
    state: &AppState,
) -> Result<events::ThreadRef, String> {
    let parent_eid =
        EventId::from_hex(parent_event_id).map_err(|e| format!("invalid parent event ID: {e}"))?;

    let evs = query_relay(
        state,
        &[serde_json::json!({
            "ids": [parent_event_id],
            "kinds": [9, 40002, 45001, 45003, buzz_core_pkg::kind::KIND_HUDDLE_STARTED],
            "limit": 1
        })],
    )
    .await?;

    let parent = evs
        .first()
        .ok_or_else(|| "parent event not found".to_string())?;

    // Walk tags looking for NIP-10 root/reply markers.
    let (mut root, mut reply) = (None, None);
    for tag in parent.tags.iter() {
        let s = tag.as_slice();
        if s.len() >= 4 && s[0] == "e" {
            match s[3].as_str() {
                "root" => root = Some(s[1].clone()),
                "reply" => reply = Some(s[1].clone()),
                _ => {}
            }
        }
    }
    let root_hex = root.or(reply);

    let root_eid = match root_hex {
        Some(hex) if hex != parent_event_id => {
            EventId::from_hex(&hex).map_err(|e| format!("invalid root event ID: {e}"))?
        }
        _ => parent_eid,
    };

    Ok(events::ThreadRef {
        root_event_id: root_eid,
        parent_event_id: parent_eid,
    })
}
