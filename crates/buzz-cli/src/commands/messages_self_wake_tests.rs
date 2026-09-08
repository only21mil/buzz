use super::*;
use axum::{extract::State, routing::post, Json, Router};
use nostr::{Event, Keys};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Relay {
    members: Arc<Mutex<Vec<String>>>,
    received: Arc<Mutex<Vec<Event>>>,
}

async fn query(State(state): State<Relay>, Json(filter): Json<Value>) -> Json<Value> {
    assert_eq!(filter[0]["kinds"], json!([39002]));
    let tags: Vec<_> = state
        .members
        .lock()
        .unwrap()
        .iter()
        .map(|key| json!(["p", key]))
        .collect();
    Json(json!([{"tags": tags}]))
}

async fn submit(State(state): State<Relay>, Json(event): Json<Event>) -> Json<Value> {
    event.verify().unwrap();
    let id = event.id.to_hex();
    state.received.lock().unwrap().push(event);
    Json(json!({"accepted": true, "id": id}))
}

fn params(channel: Uuid, wake_self: bool, kind: Option<u16>) -> SendMessageParams {
    SendMessageParams {
        channel_id: channel.to_string(),
        content: "tool completed".into(),
        kind,
        reply_to: None,
        broadcast: false,
        files: vec![],
        mentions: vec![],
        wake_self,
    }
}

#[tokio::test]
async fn self_wake_send_signs_explicit_target_and_preserves_membership_preflight() {
    let keys = Keys::generate();
    let signer = keys.public_key().to_hex();
    let state = Relay {
        members: Arc::new(Mutex::new(vec![signer.clone()])),
        received: Arc::new(Mutex::new(vec![])),
    };
    let app = Router::new()
        .route("/query", post(query))
        .route("/events", post(submit))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = BuzzClient::new(
        format!("http://{}", listener.local_addr().unwrap()),
        keys,
        None,
        None,
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let channel = Uuid::new_v4();
    let mut explicit = params(channel, true, None);
    explicit.mentions.push(signer.clone()); // already-mentioned self must not duplicate
    cmd_send_message(&client, explicit).await.unwrap();
    cmd_send_message(&client, params(channel, false, None))
        .await
        .unwrap();
    {
        let received = state.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].pubkey.to_hex(), signer);
        assert_eq!(received[0].kind.as_u16(), 9);
        assert_eq!(event_mention_pubkeys(&received[0]), vec![signer]);
        assert!(received[0]
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["h", channel.to_string().as_str()]));
        assert_eq!(
            received[0]
                .tags
                .iter()
                .filter(|tag| tag.as_slice() == ["wake", "self"])
                .count(),
            1
        );
        assert!(!received[1]
            .tags
            .iter()
            .any(|tag| tag.as_slice()[0] == "wake"));
        assert!(event_mention_pubkeys(&received[1]).is_empty());
    }
    assert!(
        cmd_send_message(&client, params(channel, true, Some(45001)))
            .await
            .unwrap_err()
            .to_string()
            .contains("--wake-self requires kind 9")
    );
    state.members.lock().unwrap().clear();
    assert!(cmd_send_message(&client, params(channel, true, Some(9)))
        .await
        .unwrap_err()
        .to_string()
        .contains("not channel members"));
    assert_eq!(
        state.received.lock().unwrap().len(),
        2,
        "invalid kind and missing membership must not publish"
    );
    server.abort();
}

#[test]
fn self_wake_cli_flag_is_explicit_and_defaults_off() {
    use clap::Parser;
    let channel = Uuid::new_v4().to_string();
    for enabled in [false, true] {
        let mut args = vec![
            "buzz",
            "--relay",
            "http://127.0.0.1:1",
            "--private-key",
            "synthetic",
            "--auth-tag",
            "[]",
            "messages",
            "send",
            "--channel",
            &channel,
            "--content",
            "done",
        ];
        if enabled {
            args.push("--wake-self");
        }
        let parsed = crate::Cli::try_parse_from(args).unwrap();
        let crate::Cmd::Messages(crate::MessagesCmd::Send { wake_self, .. }) = parsed.command
        else {
            panic!("wrong command");
        };
        assert_eq!(wake_self, enabled);
    }
}
