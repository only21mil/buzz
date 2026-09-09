//! Full Wry command path, with only the relay replaced by a loopback HTTP peer.
//! Run explicitly under Xvfb without system-keyring; no webviews or agent processes.
use super::*;
use axum::{extract::State, routing::post, Json, Router};
use std::sync::{atomic::AtomicUsize, Arc, Mutex};

#[derive(Default)]
struct RelayFixture {
    page: Vec<Event>,
    members: Vec<Event>,
    sent: Vec<Event>,
    switch_on_claim: Option<AppHandle>,
    fail_publication: bool,
}

async fn query(
    State(state): State<Arc<Mutex<RelayFixture>>>,
    Json(filters): Json<Value>,
) -> Json<Vec<Event>> {
    let state = state.lock().unwrap();
    Json(if filters[0]["kinds"][0] == 39002 {
        state.members.clone()
    } else {
        state.page.clone()
    })
}

async fn submit(
    State(state): State<Arc<Mutex<RelayFixture>>>,
    Json(event): Json<Event>,
) -> Json<Value> {
    event.verify().unwrap();
    let mut fixture = state.lock().unwrap();
    fixture.sent.push(event.clone());
    if event.kind.as_u16() == 14202 {
        if let Some(app) = fixture.switch_on_claim.take() {
            let state = app.state::<AppState>();
            let original = state.signing_keys().unwrap();
            state
                .replace_publication_keys(nostr::Keys::generate(), None)
                .unwrap();
            state.replace_publication_keys(original, None).unwrap();
        }
    }
    let stale = event.kind.as_u16() == 9000
        && event.created_at.as_secs() + 900 < nostr::Timestamp::now().as_secs();
    let refused = stale
        || (fixture.fail_publication
            && event.kind.as_u16() != 14202
            && event.kind.as_u16() != 9000);
    Json(
        json!({"event_id":event.id.to_hex(),"accepted":!refused,"message":if refused { "fixture publication refused" } else { "stored: agent-draft-v1" }}),
    )
}

fn request(
    owner: &nostr::Keys,
    agent: &nostr::Keys,
    channel: uuid::Uuid,
    malformed: bool,
) -> Event {
    let id = uuid::Uuid::new_v4();
    let body = if malformed {
        json!({"version":1})
    } else {
        json!({"version":1,"channelId":channel,"payload":{"type":"agent_management_request","requestId":id,"action":"create","request":{"channelId":channel,"displayName":"Fixture","systemPrompt":"Synthetic"}}})
    };
    let ciphertext =
        buzz_core_pkg::observer::encrypt_observer_payload(agent, &owner.public_key(), &body)
            .unwrap();
    buzz_sdk_pkg::build_agent_draft(
        &owner.public_key().to_hex(),
        &agent.public_key().to_hex(),
        &id.to_string(),
        &channel.to_string(),
        &ciphertext,
    )
    .unwrap()
    .sign_with_keys(agent)
    .unwrap()
}

fn members(
    owner: &nostr::Keys,
    agent: &nostr::Keys,
    channel: uuid::Uuid,
    instance: Option<&str>,
) -> Event {
    let mut tags = vec![
        nostr::Tag::parse(["d", &channel.to_string()]).unwrap(),
        nostr::Tag::public_key(owner.public_key()),
        nostr::Tag::public_key(agent.public_key()),
    ];
    if let Some(instance) = instance {
        tags.push(nostr::Tag::parse(["p", instance]).unwrap());
    }
    nostr::EventBuilder::new(nostr::Kind::Custom(39002), "")
        .tags(tags)
        .allow_self_tagging()
        .sign_with_keys(owner)
        .unwrap()
}

fn prepare(app: &AppHandle, s: &RetentionScope, event: &Event, action: &str) -> DraftOperation {
    agent_draft_prepare(
        s.owner_keys.public_key().to_hex(),
        s.relay_url.clone(),
        event.id.to_hex(),
        action.into(),
        json!({"displayName":"Fixture","systemPrompt":"Synthetic","avatarUrl":null}),
        None,
        // Exercise the real create command's validation failure, before key mint
        // or spawn, and then prove its durable uncertain marker stops any replay.
        matches!(action, "create" | "start").then(|| json!({"name":""})),
        None,
        app.clone(),
    )
    .unwrap()
}

async fn run() {
    let _serial = crate::relay_admission::TEST_SERIAL.lock().await;
    crate::relay_admission::reset_rate_limit_gate();
    let fixture = Arc::new(Mutex::new(RelayFixture::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/query", post(query))
        .route("/events", post(submit))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let state = crate::app_state::build_ephemeral_test_app_state();
    state
        .apply_publication_workspace(relay.clone(), None)
        .unwrap();
    let owner = state.signing_keys().unwrap();
    let agent = nostr::Keys::generate();
    let channel = uuid::Uuid::new_v4();
    let probe = crate::managed_agents::poll_read_probe::PollReadProbe {
        directory: tempfile::tempdir().unwrap(),
        global: AtomicUsize::new(0),
        teams: AtomicUsize::new(0),
    };
    let app = tauri::Builder::default()
        .any_thread()
        .manage(state)
        .manage(probe)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let handle = app.handle();
    let s = scope(handle, &owner.public_key().to_hex(), &relay).unwrap();
    let record = serde_json::from_value(json!({"pubkey":agent.public_key().to_hex(),"name":"Fixture sender","relay_url":relay,"acp_command":"buzz-acp","agent_command":"fixture-never-spawned","agent_args":[],"mcp_command":"","turn_timeout_seconds":320,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","auth_tag":buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").unwrap()})).unwrap();
    managed_agents::save_managed_agents(handle, &[record]).unwrap();
    fixture.lock().unwrap().members = vec![members(&owner, &agent, channel, None)];

    // Native backfill must retain both unavailable and valid requests, then the
    // real prepare/apply commands must reject unavailable content without decode.
    let malformed = request(&owner, &agent, channel, true);
    let valid = request(&owner, &agent, channel, false);
    let unreadable_route = request(&owner, &agent, channel, false);
    let unreadable = nostr::EventBuilder::new(
        unreadable_route.kind,
        buzz_core_pkg::observer::encrypt_observer_payload(
            &agent,
            &nostr::Keys::generate().public_key(),
            &json!({"version":1}),
        )
        .unwrap(),
    )
    .tags(unreadable_route.tags.clone())
    .allow_self_tagging()
    .sign_with_keys(&agent)
    .unwrap();
    fixture.lock().unwrap().page = vec![malformed.clone(), unreadable.clone(), valid.clone()];
    let page = agent_draft_backfill(
        owner.public_key().to_hex(),
        relay.clone(),
        None,
        None,
        Some(100),
        handle.clone(),
    )
    .await
    .unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(
        agent_draft_queue(owner.public_key().to_hex(), relay.clone(), handle.clone())
            .unwrap()
            .events
            .len(),
        3
    );
    assert!(request_body(&s, &unreadable).is_err());
    let unreadable_op = prepare(handle, &s, &unreadable, "reject");
    assert_eq!(
        agent_draft_apply(
            owner.public_key().to_hex(),
            relay.clone(),
            unreadable_op.request_event_id,
            handle.clone()
        )
        .await
        .unwrap()
        .state,
        "rejected"
    );
    assert!(stored_request(&s, &malformed.id.to_hex()).is_ok());
    assert!(agent_draft_prepare(
        owner.public_key().to_hex(),
        relay.clone(),
        malformed.id.to_hex(),
        "save".into(),
        json!({}),
        None,
        None,
        None,
        handle.clone()
    )
    .err()
    .unwrap()
    .contains("binding"));
    let rejected = prepare(handle, &s, &malformed, "reject");
    let result = agent_draft_apply(
        owner.public_key().to_hex(),
        relay.clone(),
        rejected.request_event_id,
        handle.clone(),
    )
    .await
    .unwrap();
    assert_eq!(result.state, "rejected");

    for action in ["save", "create", "start"] {
        let event = request(&owner, &agent, channel, false);
        agent_draft_receive(
            owner.public_key().to_hex(),
            relay.clone(),
            event.clone(),
            handle.clone(),
        )
        .unwrap();
        let prepared = prepare(handle, &s, &event, action);
        let result = agent_draft_apply(
            owner.public_key().to_hex(),
            relay.clone(),
            event.id.to_hex(),
            handle.clone(),
        )
        .await
        .unwrap();
        let personas = managed_agents::load_personas(handle).unwrap();
        assert_eq!(
            personas
                .iter()
                .filter(|p| p.id == prepared.target_id)
                .count(),
            1,
            "{action} must persist exactly one persona"
        );
        assert_eq!(
            result.state,
            if action == "save" {
                "applied"
            } else {
                "uncertain"
            }
        );
        let sent = fixture.lock().unwrap().sent.len();
        let repeated = agent_draft_apply(
            owner.public_key().to_hex(),
            relay.clone(),
            event.id.to_hex(),
            handle.clone(),
        )
        .await
        .unwrap();
        assert_eq!(repeated.state, result.state);
        assert_eq!(
            fixture.lock().unwrap().sent.len(),
            sent,
            "terminal/uncertain apply must not send or repeat side effects"
        );
    }

    // A -> B -> A while the claim is in flight must revoke the captured epoch,
    // even though the owner text once again matches before the local write.
    let event = request(&owner, &agent, channel, false);
    store_event(&s, &event).unwrap();
    let prepared = prepare(handle, &s, &event, "save");
    fixture.lock().unwrap().switch_on_claim = Some(handle.clone());
    let result = agent_draft_apply(
        owner.public_key().to_hex(),
        relay.clone(),
        event.id.to_hex(),
        handle.clone(),
    )
    .await;
    assert!(result.err().unwrap().contains("changed"));
    assert!(!managed_agents::load_personas(handle)
        .unwrap()
        .iter()
        .any(|p| p.id == prepared.target_id));

    // Seed only the crash boundary after an already successful Start; no fixture
    // creates a key or process. Confirm must renew expired attachment bytes or
    // reconcile an accepted attachment, then skip it on later outcome retries.
    for already_attached in [false, true] {
        let event = request(&owner, &agent, channel, false);
        store_event(&s, &event).unwrap();
        let mut op = prepare(handle, &s, &event, "start");
        let mut personas = managed_agents::load_personas(handle).unwrap();
        personas.push(op.persona.clone().unwrap());
        managed_agents::save_personas(handle, &personas).unwrap();
        op.state = "saved".into();
        let instance = nostr::Keys::generate().public_key().to_hex();
        op.instance = Some(json!({"pubkey":instance,"status":"running"}));
        op.channel_event = Some(
            crate::events::build_add_member(channel, &instance, None)
                .unwrap()
                .custom_created_at(nostr::Timestamp::from_secs(
                    nostr::Timestamp::now().as_secs() - 1800,
                ))
                .sign_with_keys(&owner)
                .unwrap(),
        );
        let expired = op.channel_event.clone().unwrap();
        op.publication = Some(
            managed_agents::persona_events::build_persona_event(op.persona.as_ref().unwrap())
                .unwrap()
                .sign_with_keys(&owner)
                .unwrap(),
        );
        put_operation(&s, &op).unwrap();
        fixture.lock().unwrap().members = vec![members(
            &owner,
            &agent,
            channel,
            already_attached.then_some(instance.as_str()),
        )];
        fixture.lock().unwrap().fail_publication = true;
        let before = fixture
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter(|e| e.kind.as_u16() == 9000)
            .count();
        let pending = agent_draft_confirm(
            owner.public_key().to_hex(),
            relay.clone(),
            event.id.to_hex(),
            handle.clone(),
        )
        .await
        .unwrap();
        assert_eq!(pending.state, "saved");
        assert!(pending.channel_attached);
        let after = fixture
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter(|e| e.kind.as_u16() == 9000)
            .count();
        assert_eq!(after - before, usize::from(!already_attached));
        if !already_attached {
            let refreshed = pending.channel_event.unwrap();
            assert_ne!(refreshed.id, expired.id);
            assert_eq!(refreshed.tags, expired.tags);
            assert_eq!(refreshed.content, expired.content);
            assert_eq!(refreshed.pubkey, expired.pubkey);
        }
        fixture.lock().unwrap().fail_publication = false;
        // Membership is now absent; the accepted journal must still prevent re-add.
        fixture.lock().unwrap().members = vec![members(&owner, &agent, channel, None)];
        let completed = agent_draft_confirm(
            owner.public_key().to_hex(),
            relay.clone(),
            event.id.to_hex(),
            handle.clone(),
        )
        .await
        .unwrap();
        assert_eq!(completed.state, "applied");
        assert_eq!(
            fixture
                .lock()
                .unwrap()
                .sent
                .iter()
                .filter(|e| e.kind.as_u16() == 9000)
                .count(),
            after
        );
        assert_eq!(
            managed_agents::load_managed_agents(handle).unwrap().len(),
            1
        );
    }
    server.abort();
}

#[test]
#[ignore = "requires disposable Xvfb; invoke explicitly without system-keyring"]
fn native_apply_and_recovery_complete_without_deadlock() {
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run());
        done.send(()).unwrap();
    });
    result
        .recv_timeout(std::time::Duration::from_secs(45))
        .expect("native command path deadlocked or exceeded its bounded timeout");
}
