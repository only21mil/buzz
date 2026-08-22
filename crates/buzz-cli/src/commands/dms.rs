use uuid::Uuid;

use crate::client::{extract_d_tag, extract_tag_value, normalize_write_response, BuzzClient};
use crate::error::CliError;
use crate::validate::{parse_uuid, sdk_err, validate_hex64};

/// Collect the caller's DM channels via the two-step member-discovery path
/// (kind:39002 membership notifications → kind:39000 channel metadata), keeping
/// only DM channels (`t` tag == "dm"). Mirrors `cmd_list_channels` with
/// `member == Some(true)`.
///
/// `limit` caps the **final** DM list length (default 50, max 200); the
/// intermediate membership + metadata queries use a larger effective limit
/// (default 500) so all DM channels are discovered before the cap is applied.
pub async fn collect_dms(
    client: &BuzzClient,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, CliError> {
    let my_pk = client.keys().public_key().to_hex();
    let effective_limit = limit.unwrap_or(500);
    let cap = limit.unwrap_or(50).min(200) as usize;

    // Step 1: find channel ids where we're a member (kind:39002).
    let member_filter = serde_json::json!({
        "kinds": [39002],
        "#p": [my_pk],
    });
    let member_events = client
        .query_paginated(member_filter, effective_limit)
        .await?;
    let channel_ids: Vec<String> = member_events
        .iter()
        .map(extract_d_tag)
        .filter(|id| !id.is_empty())
        .collect();
    if channel_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: fetch kind:39000 metadata for those channels.
    let metadata_filter = serde_json::json!({
        "kinds": [39000],
        "#d": channel_ids,
    });
    let metadata_events = client
        .query_paginated(metadata_filter, effective_limit)
        .await?;

    // Step 3: keep only DM channels (t tag == "dm"), map to output shape, cap.
    let dms: Vec<serde_json::Value> = metadata_events
        .iter()
        .filter(|e| extract_tag_value(e, "t") == "dm")
        .map(|e| {
            let participants: Vec<String> = e
                .get("tags")
                .and_then(|t| t.as_array())
                .map(|tags| {
                    tags.iter()
                        .filter_map(|tag| {
                            let arr = tag.as_array()?;
                            if arr.first()?.as_str()? == "p" {
                                arr.get(1)?.as_str().map(|s| s.to_string())
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            serde_json::json!({
                "dm_id": extract_d_tag(e),
                "participants": participants,
                "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .take(cap)
        .collect();
    Ok(dms)
}

/// List DM conversations via the two-step member-discovery path
/// (kind:39002 → kind:39000, filtered to DM channels).
pub async fn cmd_list_dms(client: &BuzzClient, limit: Option<u32>) -> Result<(), CliError> {
    let dms = collect_dms(client, limit).await?;
    let output = serde_json::to_string(&dms).unwrap_or_default();
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
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use nostr::{EventBuilder, Keys, Kind};
    use tokio::net::TcpListener;

    use super::{collect_dms, BuzzClient};

    /// Canned responses for a mock `/query` server, selected by the `kinds`
    /// array in the incoming filter. The first matching kind wins.
    struct QueryResponses {
        /// (kind, response_body) pairs; the first pair whose kind appears in
        /// the request filter's `kinds` array is returned.
        responses: Vec<(u64, String)>,
    }

    impl QueryResponses {
        fn new() -> Self {
            Self {
                responses: Vec::new(),
            }
        }

        fn when(mut self, kind: u64, body: String) -> Self {
            self.responses.push((kind, body));
            self
        }

        fn select(&self, filter: &serde_json::Value) -> Option<&str> {
            let kinds = filter.get("kinds")?.as_array()?;
            for (kind, body) in &self.responses {
                let kind_matches = kinds.iter().any(|k| k.as_u64() == Some(*kind));
                if kind_matches {
                    return Some(body.as_str());
                }
            }
            None
        }
    }

    /// Spin up a one-shot axum server on a random port that handles `POST /query`.
    /// Each request's filter array is inspected; the first filter's `kinds`
    /// selects the canned response body. Returns the base URL.
    async fn query_server(responses: Arc<QueryResponses>) -> String {
        type S = Arc<QueryResponses>;
        let app = Router::new()
            .route(
                "/query",
                post(
                    |State(responses): State<S>, _headers: HeaderMap, body: Body| async move {
                        let bytes = axum::body::to_bytes(body, usize::MAX)
                            .await
                            .unwrap_or_default();
                        let filters: Vec<serde_json::Value> =
                            serde_json::from_slice(&bytes).unwrap_or_default();
                        let filter = filters.first().cloned().unwrap_or(serde_json::Value::Null);
                        let body_str = responses.select(&filter).unwrap_or("[]").to_string();
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Body::from(body_str))
                            .unwrap()
                    },
                ),
            )
            .with_state(responses);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn make_test_client(base_url: &str) -> BuzzClient {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("valid test key");
        BuzzClient::new(base_url.to_string(), keys, None, None)
            .expect("client construction should not fail")
    }

    /// Build a signed kind:39000 or kind:39002 event with the given tags so the
    /// pagination cursor (`advance_query_cursor`) can read `id`/`created_at`.
    fn signed_event(kind: u16, created_at: u64, tags: Vec<serde_json::Value>) -> serde_json::Value {
        use nostr::JsonUtil;
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let nostr_tags: Vec<nostr::Tag> = tags
            .iter()
            .map(|t| {
                let arr = t.as_array().unwrap();
                let strs: Vec<String> = arr
                    .iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect();
                nostr::Tag::parse(strs).unwrap()
            })
            .collect();
        let event = EventBuilder::new(Kind::Custom(kind), "")
            .tags(nostr_tags)
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(&keys)
            .unwrap();
        let json = event.as_json();
        serde_json::from_str(&json).unwrap()
    }

    /// `collect_dms` returns a DM channel when the caller's pubkey appears in
    /// kind:39002 membership notifications and the corresponding kind:39000
    /// metadata event has `t == "dm"`. Verifies the reproduction: the old
    /// kind:41001 path returned `[]`; the two-step path finds the channel.
    #[tokio::test]
    async fn collect_dms_finds_dm_channel_via_two_step_discovery() {
        let my_pk = "0000000000000000000000000000000000000000000000000000000000000001";
        let dm_channel_id = "11111111-1111-1111-1111-111111111111";
        let other_pk = "a".repeat(64);

        // kind:39002 membership notification: d=dm_channel_id, p=my_pk
        let member_event = signed_event(
            39002,
            100,
            vec![
                serde_json::json!(["d", dm_channel_id]),
                serde_json::json!(["p", my_pk, "member"]),
            ],
        );
        // kind:39000 metadata: d=dm_channel_id, t="dm", p=[my_pk, other_pk]
        let dm_metadata = signed_event(
            39000,
            200,
            vec![
                serde_json::json!(["d", dm_channel_id]),
                serde_json::json!(["t", "dm"]),
                serde_json::json!(["p", my_pk]),
                serde_json::json!(["p", other_pk]),
                serde_json::json!(["hidden"]),
            ],
        );

        let responses = Arc::new(
            QueryResponses::new()
                .when(39002, serde_json::json!([member_event]).to_string())
                .when(39000, serde_json::json!([dm_metadata]).to_string()),
        );
        let url = query_server(responses).await;
        let client = make_test_client(&url);

        let dms = collect_dms(&client, None)
            .await
            .expect("collect should succeed");
        assert_eq!(dms.len(), 1, "should find exactly one DM channel");
        assert_eq!(
            dms[0]["dm_id"].as_str(),
            Some(dm_channel_id),
            "dm_id should be the channel id"
        );
        let participants = dms[0]["participants"]
            .as_array()
            .expect("participants is an array");
        assert_eq!(participants.len(), 2, "both participants present");
        assert!(
            participants.iter().any(|p| p.as_str() == Some(my_pk)),
            "my_pk should be in participants"
        );
        assert!(
            participants.iter().any(|p| p.as_str() == Some(&other_pk)),
            "other_pk should be in participants"
        );
    }

    /// A non-DM channel (`t == "stream"`) appearing in kind:39002 membership
    /// and kind:39000 metadata is NOT returned by `collect_dms`.
    #[tokio::test]
    async fn collect_dms_excludes_non_dm_channels() {
        let my_pk = "0000000000000000000000000000000000000000000000000000000000000001";
        let dm_channel_id = "11111111-1111-1111-1111-111111111111";
        let stream_channel_id = "22222222-2222-2222-2222-222222222222";

        // Both channels appear in kind:39002 membership notifications.
        let member_events = serde_json::json!([
            signed_event(
                39002,
                100,
                vec![
                    serde_json::json!(["d", dm_channel_id]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
            signed_event(
                39002,
                101,
                vec![
                    serde_json::json!(["d", stream_channel_id]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
        ])
        .to_string();

        // kind:39000 metadata: one DM, one stream.
        let metadata_events = serde_json::json!([
            signed_event(
                39000,
                200,
                vec![
                    serde_json::json!(["d", dm_channel_id]),
                    serde_json::json!(["t", "dm"]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
            signed_event(
                39000,
                201,
                vec![
                    serde_json::json!(["d", stream_channel_id]),
                    serde_json::json!(["t", "stream"]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
        ])
        .to_string();

        let responses = Arc::new(
            QueryResponses::new()
                .when(39002, member_events)
                .when(39000, metadata_events),
        );
        let url = query_server(responses).await;
        let client = make_test_client(&url);

        let dms = collect_dms(&client, None)
            .await
            .expect("collect should succeed");
        assert_eq!(
            dms.len(),
            1,
            "only the DM channel should be returned, not the stream"
        );
        assert_eq!(
            dms[0]["dm_id"].as_str(),
            Some(dm_channel_id),
            "the returned channel should be the DM, not the stream"
        );
    }

    /// When there are no kind:39002 membership notifications for the caller,
    /// `collect_dms` returns an empty list (no relay round-trip for metadata).
    #[tokio::test]
    async fn collect_dms_empty_when_no_membership() {
        let responses = Arc::new(
            QueryResponses::new()
                .when(39002, "[]".to_string())
                .when(39000, "[]".to_string()),
        );
        let url = query_server(responses).await;
        let client = make_test_client(&url);

        let dms = collect_dms(&client, None)
            .await
            .expect("collect should succeed");
        assert!(
            dms.is_empty(),
            "no membership notifications => empty DM list"
        );
    }

    /// The `limit` cap is applied to the final DM list, not the intermediate
    /// membership query: a limit of 1 returns at most one DM even when two
    /// DM channels exist.
    #[tokio::test]
    async fn collect_dms_cap_applies_to_final_list() {
        let my_pk = "0000000000000000000000000000000000000000000000000000000000000001";
        let dm1 = "11111111-1111-1111-1111-111111111111";
        let dm2 = "22222222-2222-2222-2222-222222222222";

        let member_events = serde_json::json!([
            signed_event(
                39002,
                100,
                vec![
                    serde_json::json!(["d", dm1]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
            signed_event(
                39002,
                101,
                vec![
                    serde_json::json!(["d", dm2]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
        ])
        .to_string();

        let metadata_events = serde_json::json!([
            signed_event(
                39000,
                200,
                vec![
                    serde_json::json!(["d", dm1]),
                    serde_json::json!(["t", "dm"]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
            signed_event(
                39000,
                201,
                vec![
                    serde_json::json!(["d", dm2]),
                    serde_json::json!(["t", "dm"]),
                    serde_json::json!(["p", my_pk]),
                ]
            ),
        ])
        .to_string();

        let responses = Arc::new(
            QueryResponses::new()
                .when(39002, member_events)
                .when(39000, metadata_events),
        );
        let url = query_server(responses).await;
        let client = make_test_client(&url);

        let dms = collect_dms(&client, Some(1))
            .await
            .expect("collect should succeed");
        assert_eq!(dms.len(), 1, "limit=1 should cap the final list to 1 DM");
    }
}
