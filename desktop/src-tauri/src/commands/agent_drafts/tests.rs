use super::*;
use std::cell::RefCell;

fn fixture() -> (tempfile::TempDir, RetentionScope, Event, DraftOperation) {
    let dir = tempfile::tempdir().unwrap();
    let owner = nostr::Keys::generate();
    let agent = nostr::Keys::generate();
    let channel = uuid::Uuid::new_v4().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let body = json!({"version":1,"channelId":channel,"payload":{"type":"agent_management_request","requestId":request_id,"action":"create","request":{"channelId":channel,"displayName":"Synthetic draft","systemPrompt":"Private synthetic prompt"}}});
    let ciphertext =
        buzz_core_pkg::observer::encrypt_observer_payload(&agent, &owner.public_key(), &body)
            .unwrap();
    let request = buzz_sdk_pkg::build_agent_draft(
        &owner.public_key().to_hex(),
        &agent.public_key().to_hex(),
        &request_id,
        &channel,
        &ciphertext,
    )
    .unwrap()
    .sign_with_keys(&agent)
    .unwrap();
    let scope = RetentionScope {
        db_path: dir.path().join("retention.sqlite"),
        relay_url: "wss://synthetic.invalid".into(),
        owner_keys: owner,
    };
    let input = json!({"displayName":"Synthetic draft","systemPrompt":"Private synthetic prompt","avatarUrl":null});
    let target = uuid::Uuid::new_v4().to_string();
    let claim = decision(
        &scope,
        &request.id.to_hex(),
        &request.id.to_hex(),
        1,
        "applying",
        &input,
    )
    .unwrap();
    let op = DraftOperation {
        request_event_id: request.id.to_hex(),
        target_id: target.clone(),
        action: "save".into(),
        state: "prepared".into(),
        claim_event: claim,
        outcome_event: None,
        persona: Some(edited_persona(&input, &target, None).unwrap()),
        error: None,
        instance: None,
        input,
        expected_content: None,
        instance_input: None,
        publication: None,
        channel_event: None,
        channel_attached: false,
        publish_shared: false,
    };
    (dir, scope, request, op)
}
#[test]
fn queue_and_operation_restart_keep_ciphertext_and_scoped_keys() {
    let (_dir, s, request, op) = fixture();
    store_event(&s, &request).unwrap();
    put_operation(&s, &op).unwrap();
    let raw: String = db(&s)
        .unwrap()
        .query_row("SELECT ciphertext FROM draft_operations", [], |r| r.get(0))
        .unwrap();
    assert!(!raw.contains("Private synthetic prompt"));
    let reopened = read_operation(&s, &op.request_event_id).unwrap().unwrap();
    assert_eq!(reopened.target_id, op.target_id);
    assert_eq!(reopened.claim_event, op.claim_event);
    let other = RetentionScope {
        db_path: s.db_path.clone(),
        relay_url: s.relay_url.clone(),
        owner_keys: nostr::Keys::generate(),
    };
    assert!(read_operation(&other, &op.request_event_id).is_err());
    assert!(store_event(&other, &request).is_err());
}
#[test]
fn crash_after_persona_save_recovers_exact_target_without_second_save() {
    let (_dir, s, _request, mut op) = fixture();
    put_operation(&s, &op).unwrap();
    let disk = RefCell::new(Vec::<AgentDefinition>::new());
    let writes = RefCell::new(0);
    let mut personas = Vec::new();
    persist_prepared_persona(
        &mut op,
        &mut personas,
        |o| put_operation(&s, o),
        |p| {
            *disk.borrow_mut() = p.to_vec();
            *writes.borrow_mut() += 1;
            Ok(())
        },
    )
    .unwrap();
    // Simulate process death before the caller journals state=saved/outcome.
    let mut recovered = read_operation(&s, &op.request_event_id).unwrap().unwrap();
    assert_eq!(recovered.state, "claimed");
    let mut personas = disk.borrow().clone();
    persist_prepared_persona(
        &mut recovered,
        &mut personas,
        |o| put_operation(&s, o),
        |_| {
            *writes.borrow_mut() += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(*writes.borrow(), 1);
    assert_eq!(personas.len(), 1);
    assert_eq!(personas[0].id, recovered.target_id);
    assert_eq!(recovered.state, "saved");
}
#[test]
fn journal_failure_precedes_first_persona_mutation_and_conflict_never_overwrites() {
    let (_dir, _s, _request, mut op) = fixture();
    let writes = RefCell::new(0);
    assert!(persist_prepared_persona(
        &mut op,
        &mut Vec::new(),
        |_| Err("disk full".into()),
        |_| {
            *writes.borrow_mut() += 1;
            Ok(())
        }
    )
    .is_err());
    assert_eq!(*writes.borrow(), 0);
    let mut conflict = op.persona.clone().unwrap();
    conflict.system_prompt = "Different content".into();
    assert!(persist_prepared_persona(
        &mut op,
        &mut vec![conflict],
        |_| Ok(()),
        |_| {
            *writes.borrow_mut() += 1;
            Ok(())
        }
    )
    .is_err());
    assert_eq!(*writes.borrow(), 0);
}
#[test]
fn terminal_outcome_before_request_remains_nonactionable_after_restart() {
    let (_dir, s, request, op) = fixture();
    let rejection = decision(
        &s,
        &request.id.to_hex(),
        &request.id.to_hex(),
        1,
        "rejected",
        &json!({"version":1}),
    )
    .unwrap();
    store_event(&s, &rejection).unwrap();
    store_event(&s, &request).unwrap();
    assert!(terminal_or_claimed(&s, &op.request_event_id).unwrap());
    assert!(read_operation(&s, &op.request_event_id).unwrap().is_none());
}
#[test]
fn saved_definition_edit_blocks_recovery_even_with_same_timestamp() {
    let (_dir, _s, _request, mut op) = fixture();
    op.state = "saved".into();
    let mut modified = op.persona.clone().unwrap();
    modified.system_prompt = "newer approved content".into();
    assert!(persist_prepared_persona(
        &mut op,
        &mut vec![modified],
        |_| Ok(()),
        |_| panic!("must not overwrite")
    )
    .is_err());
}

#[cfg(all(target_os = "linux", not(feature = "system-keyring")))]
mod native_commands;
