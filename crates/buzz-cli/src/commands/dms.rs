use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;

use crate::client::{extract_d_tag, normalize_write_response, BuzzClient};
use crate::error::CliError;
use crate::validate::{parse_uuid, sdk_err, validate_hex64};

const MAX_DM_DISCOVERY_EVENTS: u32 = 10_000;

fn tag_values(event: &Value, name: &str) -> Vec<String> {
    event
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .filter(|tag| tag.first().and_then(Value::as_str) == Some(name))
        .filter_map(|tag| tag.get(1).and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn has_tag(event: &Value, name: &str) -> bool {
    event
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter()
                .filter_map(Value::as_array)
                .any(|tag| tag.first().and_then(Value::as_str) == Some(name))
        })
}

fn dm_projection(metadata: Vec<Value>, hidden: &HashSet<String>, limit: u32) -> Vec<Value> {
    let mut dms = metadata
        .into_iter()
        .filter(|event| {
            tag_values(event, "t").iter().any(|value| value == "dm") || has_tag(event, "hidden")
        })
        .filter_map(|event| {
            let dm_id = extract_d_tag(&event);
            if dm_id.is_empty() || hidden.contains(&dm_id) {
                return None;
            }
            Some(serde_json::json!({
                "dm_id": dm_id,
                "participants": tag_values(&event, "p"),
                "created_at": event.get("created_at").and_then(Value::as_u64).unwrap_or(0),
            }))
        })
        .collect::<Vec<_>>();
    dms.sort_by(|left, right| {
        right
            .get("created_at")
            .and_then(Value::as_u64)
            .cmp(&left.get("created_at").and_then(Value::as_u64))
            .then_with(|| {
                left.get("dm_id")
                    .and_then(Value::as_str)
                    .cmp(&right.get("dm_id").and_then(Value::as_str))
            })
    });
    dms.truncate(limit as usize);
    dms
}

async fn list_dms(client: &BuzzClient, limit: Option<u32>) -> Result<Vec<Value>, CliError> {
    let my_pk = client.keys().public_key().to_hex();
    let limit = limit.unwrap_or(50).min(200);
    let membership = client
        .query_all_bounded(
            serde_json::json!({"kinds": [39002], "#p": [&my_pk]}),
            MAX_DM_DISCOVERY_EVENTS,
        )
        .await?;
    let mut channel_ids = membership
        .iter()
        .map(extract_d_tag)
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    channel_ids.sort();
    channel_ids.dedup();

    let metadata = if channel_ids.is_empty() {
        Vec::new()
    } else {
        client
            .query_all_bounded(
                serde_json::json!({"kinds": [39000], "#d": channel_ids}),
                MAX_DM_DISCOVERY_EVENTS,
            )
            .await?
    };

    let visibility = client
        .query_paginated(
            serde_json::json!({
                "kinds": [buzz_core::kind::KIND_DM_VISIBILITY],
                "#p": [&my_pk]
            }),
            1,
        )
        .await?;
    let hidden = visibility
        .first()
        .map(|event| tag_values(event, "h").into_iter().collect())
        .unwrap_or_default();
    Ok(dm_projection(metadata, &hidden, limit))
}

/// List DM conversations from the current NIP-29 membership and metadata events.
pub async fn cmd_list_dms(client: &BuzzClient, limit: Option<u32>) -> Result<(), CliError> {
    let dms = list_dms(client, limit).await?;
    let output = serde_json::to_string(&dms)
        .map_err(|error| CliError::Other(format!("failed to serialize DM list: {error}")))?;
    println!("{output}");
    Ok(())
}

/// Open a DM with one or more users — sign and submit a kind:41010 event with a d-tag.
pub async fn cmd_open_dm(client: &BuzzClient, pubkeys: &[String]) -> Result<(), CliError> {
    if pubkeys.is_empty() || pubkeys.len() > 8 {
        return Err(CliError::Usage("--pubkey: must provide 1-8 pubkeys".into()));
    }
    for pk in pubkeys {
        validate_hex64(pk)?;
    }
    let dm_id = Uuid::new_v4().to_string();
    let refs: Vec<&str> = pubkeys.iter().map(String::as_str).collect();

    // build_dm_open doesn't accept a d-tag, so we build the event manually
    // using the SDK builder and add the d-tag ourselves.
    use nostr::{EventBuilder, Kind, Tag};
    let mut tags: Vec<Tag> = refs
        .iter()
        .map(|pk| Tag::parse(["p", *pk]).map_err(|e| CliError::Other(format!("tag error: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    tags.push(Tag::parse(["d", &dm_id]).map_err(|e| CliError::Other(format!("tag error: {e}")))?);
    let builder = EventBuilder::new(Kind::Custom(41010), "").tags(tags);
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    // Try to extract relay-assigned channel_id from response message.
    // Relay returns: {"event_id":"...","accepted":true,"message":"response:{\"channel_id\":\"...\",\"created\":true}"}
    let relay_dm_id = serde_json::from_str::<serde_json::Value>(&resp)
        .ok()
        .and_then(|v| v.get("message")?.as_str().map(|s| s.to_string()))
        .and_then(|msg| {
            let json_part = msg.strip_prefix("response:")?;
            serde_json::from_str::<serde_json::Value>(json_part).ok()
        })
        .and_then(|v| v.get("channel_id")?.as_str().map(|s| s.to_string()));
    let final_dm_id = relay_dm_id.unwrap_or(dm_id);

    let mut normalized: serde_json::Value =
        serde_json::from_str(&resp).unwrap_or(serde_json::json!({}));
    normalized["dm_id"] = serde_json::json!(final_dm_id);
    if normalized.get("accepted").is_none() {
        normalized["accepted"] = serde_json::json!(true);
    }
    println!("{normalized}");
    Ok(())
}

/// Hide a DM channel — sign and submit a kind:41012 event with h-tag.
pub async fn cmd_hide_dm(client: &BuzzClient, channel_id: &str) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;

    use nostr::{EventBuilder, Kind, Tag};
    let tags = vec![Tag::parse(["h", &channel_uuid.to_string()])
        .map_err(|e| CliError::Other(format!("tag error: {e}")))?];
    let builder =
        EventBuilder::new(Kind::Custom(buzz_sdk::kind::KIND_DM_HIDE as u16), "").tags(tags);
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Add a member to a DM group — sign and submit a kind:41011 event.
pub async fn cmd_add_dm_member(
    client: &BuzzClient,
    channel_id: &str,
    pubkey: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    validate_hex64(pubkey)?;

    let builder = buzz_sdk::build_dm_add_member(channel_uuid, pubkey).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

pub async fn dispatch(cmd: crate::DmsCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::DmsCmd;
    match cmd {
        DmsCmd::List { limit } => cmd_list_dms(client, limit).await,
        DmsCmd::Open { pubkeys } => cmd_open_dm(client, &pubkeys).await,
        DmsCmd::AddMember { channel, pubkey } => cmd_add_dm_member(client, &channel, &pubkey).await,
        DmsCmd::Hide { channel } => cmd_hide_dm(client, &channel).await,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, routing::post, Json, Router};
    use nostr::Keys;
    use serde_json::Value;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone, Default)]
    struct QueryState {
        filters: Arc<Mutex<Vec<Value>>>,
        membership: Vec<Value>,
        metadata: Vec<Value>,
        visibility: Vec<Value>,
    }

    async fn query_handler(
        State(state): State<QueryState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        state
            .filters
            .lock()
            .expect("query capture lock")
            .push(body.clone());
        let kinds = body
            .as_array()
            .and_then(|filters| filters.first())
            .and_then(|filter| filter.get("kinds"));
        let events = if kinds == Some(&serde_json::json!([39002])) {
            state.membership
        } else if kinds == Some(&serde_json::json!([39000])) {
            state.metadata
        } else if kinds == Some(&serde_json::json!([buzz_core::kind::KIND_DM_VISIBILITY])) {
            state.visibility
        } else {
            Vec::new()
        };
        Json(Value::Array(events))
    }

    async fn query_server(state: QueryState) -> (String, Arc<Mutex<Vec<Value>>>) {
        let filters = state.filters.clone();
        let app = Router::new()
            .route("/query", post(query_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), filters)
    }

    #[tokio::test]
    async fn list_discovers_dms_from_current_membership_events() {
        let (url, filters) = query_server(QueryState::default()).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();

        cmd_list_dms(&client, Some(50)).await.unwrap();

        let filters = filters.lock().unwrap();
        assert!(filters.iter().any(|body| {
            body.as_array().is_some_and(|entries| {
                entries.iter().any(|filter| {
                    filter.get("kinds") == Some(&serde_json::json!([39002]))
                        && filter.get("#p").is_some()
                })
            })
        }));
    }

    #[tokio::test]
    async fn list_returns_a_live_synthetic_dm() {
        let dm_id = Uuid::new_v4().to_string();
        let participant = "a".repeat(64);
        let state = QueryState {
            membership: vec![serde_json::json!({
                "id": "1".repeat(64),
                "created_at": 10,
                "tags": [["d", dm_id], ["p", participant]]
            })],
            metadata: vec![serde_json::json!({
                "id": "2".repeat(64),
                "created_at": 20,
                "tags": [["d", dm_id], ["hidden"], ["t", "dm"], ["p", participant]]
            })],
            ..QueryState::default()
        };
        let (url, _) = query_server(state).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();

        let dms = list_dms(&client, Some(50)).await.unwrap();

        assert_eq!(dms.len(), 1);
        assert_eq!(dms[0]["dm_id"], dm_id);
        assert_eq!(dms[0]["participants"], serde_json::json!([participant]));
    }

    #[test]
    fn projection_uses_dm_metadata_and_excludes_hidden_conversations() {
        let visible_id = Uuid::new_v4().to_string();
        let hidden_id = Uuid::new_v4().to_string();
        let participant = "a".repeat(64);
        let metadata = vec![
            serde_json::json!({
                "created_at": 20,
                "tags": [["d", visible_id], ["hidden"], ["t", "dm"], ["p", participant]]
            }),
            serde_json::json!({
                "created_at": 30,
                "tags": [["d", hidden_id], ["hidden"], ["t", "dm"]]
            }),
            serde_json::json!({
                "created_at": 40,
                "tags": [["d", Uuid::new_v4().to_string()], ["t", "stream"]]
            }),
        ];
        let hidden = HashSet::from([hidden_id]);

        let projected = dm_projection(metadata, &hidden, 50);

        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0]["dm_id"], visible_id);
        assert_eq!(
            projected[0]["participants"],
            serde_json::json!([participant])
        );
    }
}
