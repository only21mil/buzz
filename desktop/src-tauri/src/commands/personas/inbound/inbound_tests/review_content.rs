use super::*;

#[test]
fn equal_second_retained_owner_replacement_invalidates_review_content() {
    use crate::commands::personas::review_revision::validate_review_revision;
    use crate::managed_agents::{
        persona_events::persona_from_event,
        retention::{commit_inbound_with_store, open_retention_db, InboundOutcome, RetainedEvent},
        PersonaReviewContent,
    };
    use nostr::JsonUtil;

    let keys = nostr::Keys::generate();
    let mut first = local_in_app();
    first.source_team = None;
    let mut second = first.clone();
    second.system_prompt = "Different owner content in the same second".into();
    let mut events = [
        persona_event_at(&first, &keys, 1000),
        persona_event_at(&second, &keys, 1000),
    ];
    events.sort_by_key(|event| std::cmp::Reverse(event.id));
    assert_ne!(events[0].id, events[1].id);
    let dir = tempfile::tempdir().unwrap();
    let conn = open_retention_db(&dir.path().join("retention.sqlite")).unwrap();
    let mut personas = Vec::new();
    let mut reviewed = None;
    for event in events {
        event.verify().unwrap();
        assert_eq!(event.pubkey, keys.public_key());
        let retained = RetainedEvent {
            kind: buzz_core_pkg::kind::KIND_PERSONA,
            pubkey: event.pubkey.to_hex(),
            d_tag: UUID.into(),
            content: event.content.clone(),
            created_at: event.created_at.as_secs() as i64,
            raw_event: event.as_json(),
            pending_sync: false,
        };
        assert_eq!(
            commit_inbound_with_store(&conn, &retained, || {
                apply_inbound_persona(&mut personas, persona_from_event(&event)?);
                Ok(())
            })
            .unwrap(),
            InboundOutcome::Applied
        );
        if reviewed.is_none() {
            reviewed = Some(personas[0].clone());
        }
    }
    let reviewed = reviewed.unwrap();
    let current = &personas[0];
    assert_eq!(reviewed.updated_at, current.updated_at);
    assert_eq!(reviewed.shared, current.shared);
    assert_ne!(reviewed.system_prompt, current.system_prompt);
    let expected = PersonaReviewContent::from(&reviewed);
    let winning_prompt = current.system_prompt.clone();
    // This is the same pre-mutation guard called under update_persona_with's store lock.
    let save = validate_review_revision(
        Some(&reviewed.updated_at),
        Some(&expected),
        Some(reviewed.shared),
        &personas[0],
    );
    if save.is_ok() {
        personas[0].system_prompt = reviewed.system_prompt;
    }
    assert!(save.is_err());
    assert_eq!(personas[0].system_prompt, winning_prompt);
    let current = &personas[0];
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&PersonaReviewContent::from(current)),
        Some(current.shared),
        current
    )
    .is_ok());
}
