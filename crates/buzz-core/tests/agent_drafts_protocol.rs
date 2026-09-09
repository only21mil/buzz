//! Signed protocol tests use synthetic keys and real NIP-44 ciphertext.
use buzz_core::{
    agent_drafts::{validate_decision, validate_request, DecisionState},
    filter::{filters_match, reader_authorized_for_event},
    kind::{KIND_AGENT_DRAFT, KIND_AGENT_DRAFT_DECISION, P_GATED_KINDS, RESULT_GATED_KINDS},
    StoredEvent,
};
use nostr::{nips::nip44, Event, EventBuilder, Filter, Keys, Kind, SecretKey, Tag, Timestamp};
use serde_json::json;
use uuid::Uuid;

fn keys(byte: u8) -> Keys {
    Keys::new(SecretKey::from_slice(&[byte; 32]).unwrap())
}
fn request_tags(owner: &Keys, agent: &Keys) -> Vec<Vec<String>> {
    vec![
        vec!["p".into(), owner.public_key().to_hex()],
        vec!["agent".into(), agent.public_key().to_hex()],
        vec!["r".into(), Uuid::from_u128(1).to_string()],
        vec!["h".into(), Uuid::from_u128(2).to_string()],
        vec!["v".into(), "1".into()],
    ]
}
fn ciphertext(sender: &Keys, owner: &Keys) -> String {
    nip44::encrypt(sender.secret_key(), &owner.public_key(), json!({
        "version":1,"request_id":Uuid::from_u128(1),"channel_id":Uuid::from_u128(2),
        "type":"agent_management_request","action":"create_persona", "system_prompt":"PRIVATE_DRAFT_SENTINEL"
    }).to_string(), nip44::Version::V2).unwrap()
}
fn sign(keys: &Keys, kind: u32, tags: Vec<Vec<String>>, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .allow_self_tagging()
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(1_788_800_000))
        .sign_with_keys(keys)
        .unwrap()
}
fn request() -> (Keys, Keys, Event) {
    let owner = keys(1);
    let agent = keys(2);
    let event = sign(
        &agent,
        KIND_AGENT_DRAFT,
        request_tags(&owner, &agent),
        &ciphertext(&agent, &owner),
    );
    (owner, agent, event)
}
fn decision_tags(owner: &Keys, request: &Event) -> Vec<Vec<String>> {
    vec![
        vec!["p".into(), owner.public_key().to_hex()],
        vec!["e".into(), request.id.to_hex()],
        vec!["previous".into(), request.id.to_hex()],
        vec!["generation".into(), "1".into()],
        vec!["state".into(), "applying".into()],
        vec!["v".into(), "1".into()],
    ]
}

#[test]
fn real_signed_ciphertext_binds_owner_agent_uuid_channel_and_hides_payload() {
    let (owner, agent, event) = request();
    event.verify().unwrap();
    let route = validate_request(&event).unwrap();
    assert_eq!(route.owner, owner.public_key());
    assert_eq!(route.agent, agent.public_key());
    assert_eq!(route.request_id, Uuid::from_u128(1));
    assert_eq!(route.channel, Uuid::from_u128(2));
    let plaintext =
        nip44::decrypt(owner.secret_key(), &agent.public_key(), &event.content).unwrap();
    assert!(plaintext.contains("PRIVATE_DRAFT_SENTINEL"));
    assert!(!serde_json::to_string(&event)
        .unwrap()
        .contains("PRIVATE_DRAFT_SENTINEL"));
    assert!(nip44::decrypt(keys(3).secret_key(), &agent.public_key(), &event.content).is_err());
}

#[test]
fn request_rejects_ambiguous_routes_bad_uuids_versions_and_plaintext_tags() {
    let (owner, agent, event) = request();
    for tag_name in ["p", "agent", "r", "h", "v"] {
        let mut tags = request_tags(&owner, &agent);
        let tag = tags.iter().find(|t| t[0] == tag_name).unwrap().clone();
        tags.push(tag);
        assert!(
            validate_request(&sign(&agent, KIND_AGENT_DRAFT, tags, &event.content)).is_err(),
            "duplicate {tag_name}"
        );
        let mut tags = request_tags(&owner, &agent);
        tags.iter_mut()
            .find(|t| t[0] == tag_name)
            .unwrap()
            .push("extra".into());
        assert!(
            validate_request(&sign(&agent, KIND_AGENT_DRAFT, tags, &event.content)).is_err(),
            "extended {tag_name}"
        );
    }
    for (name, value) in [("r", "not-a-uuid"), ("h", "not-a-channel"), ("v", "2")] {
        let mut tags = request_tags(&owner, &agent);
        tags.iter_mut().find(|t| t[0] == name).unwrap()[1] = value.into();
        assert!(
            validate_request(&sign(&agent, KIND_AGENT_DRAFT, tags, &event.content)).is_err(),
            "{name}"
        );
    }
    for name in [
        "expiration",
        "not_before",
        "d",
        "title",
        "system_prompt",
        "count",
    ] {
        let mut tags = request_tags(&owner, &agent);
        tags.push(vec![name.into(), "PRIVATE_DRAFT_SENTINEL".into()]);
        assert!(
            validate_request(&sign(&agent, KIND_AGENT_DRAFT, tags, &event.content)).is_err(),
            "plaintext/unsupported {name}"
        );
    }
    for content in [
        "plain text".to_string(),
        "!".repeat(200),
        "x".repeat(100_001),
    ] {
        assert!(validate_request(&sign(
            &agent,
            KIND_AGENT_DRAFT,
            request_tags(&owner, &agent),
            &content
        ))
        .is_err());
    }
}

#[test]
fn forged_signature_changed_ciphertext_and_wrong_request_signer_fail() {
    let (owner, agent, mut event) = request();
    let valid = event.clone();
    event.content = ciphertext(&agent, &owner);
    assert!(event.verify().is_err());
    assert!(
        validate_request(&event).is_err(),
        "changed ciphertext with old signed id"
    );
    event = valid;
    event.sig = sign(
        &keys(3),
        KIND_AGENT_DRAFT,
        request_tags(&owner, &agent),
        &event.content,
    )
    .sig;
    assert!(validate_request(&event).is_err(), "forged signature");
    for signer in [&owner, &keys(3)] {
        assert!(validate_request(&sign(
            signer,
            KIND_AGENT_DRAFT,
            request_tags(&owner, &agent),
            &event.content
        ))
        .is_err());
    }
}

#[test]
fn owner_decision_rejects_forgery_wrong_owner_ambiguous_tags_and_bad_state() {
    let (owner, agent, request) = request();
    let content = ciphertext(&owner, &owner);
    let tags = decision_tags(&owner, &request);
    let event = sign(&owner, KIND_AGENT_DRAFT_DECISION, tags.clone(), &content);
    assert_eq!(
        validate_decision(&event).unwrap().state,
        DecisionState::Applying
    );
    assert!(validate_decision(&sign(
        &agent,
        KIND_AGENT_DRAFT_DECISION,
        tags.clone(),
        &content
    ))
    .is_err());
    let mut forged = event.clone();
    forged.content = ciphertext(&owner, &owner);
    assert!(validate_decision(&forged).is_err());
    for name in ["p", "e", "previous", "generation", "state", "v"] {
        let mut invalid = tags.clone();
        invalid.push(tags.iter().find(|t| t[0] == name).unwrap().clone());
        assert!(
            validate_decision(&sign(&owner, KIND_AGENT_DRAFT_DECISION, invalid, &content)).is_err(),
            "duplicate {name}"
        );
    }
    for (name, value) in [
        ("generation", "0"),
        ("generation", "3"),
        ("generation", "-1"),
        ("state", "pending"),
        ("e", "bad"),
        ("previous", "bad"),
        ("v", "2"),
    ] {
        let mut invalid = tags.clone();
        invalid.iter_mut().find(|t| t[0] == name).unwrap()[1] = value.into();
        assert!(
            validate_decision(&sign(&owner, KIND_AGENT_DRAFT_DECISION, invalid, &content)).is_err(),
            "{name}={value}"
        );
    }
    for state in ["rejected", "applied"] {
        let mut terminal = tags.clone();
        terminal.iter_mut().find(|t| t[0] == "state").unwrap()[1] = state.into();
        assert!(
            validate_decision(&sign(&owner, KIND_AGENT_DRAFT_DECISION, terminal, &content)).is_ok()
        );
    }
}

#[test]
fn ids_only_match_does_not_grant_private_request_or_outcome_read_authority() {
    let (owner, agent, request) = request();
    let decision = sign(
        &owner,
        KIND_AGENT_DRAFT_DECISION,
        decision_tags(&owner, &request),
        &ciphertext(&owner, &owner),
    );
    for event in [request, decision] {
        assert!(P_GATED_KINDS.contains(&u32::from(event.kind.as_u16())));
        assert!(RESULT_GATED_KINDS.contains(&u32::from(event.kind.as_u16())));
        let filter = Filter::new().id(event.id);
        let stored = StoredEvent::with_received_at(event.clone(), chrono::Utc::now(), None, true);
        assert!(filters_match(&[filter], &stored));
        assert!(reader_authorized_for_event(
            &event,
            &owner.public_key().to_hex()
        ));
        for reader in [
            agent.public_key().to_hex(),
            keys(3).public_key().to_hex(),
            String::new(),
        ] {
            assert!(!reader_authorized_for_event(&event, &reader));
        }
    }
}
