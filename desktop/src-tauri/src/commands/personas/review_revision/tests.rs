use super::*;

fn persona() -> AgentDefinition {
    serde_json::from_value(serde_json::json!({
        "id": "persona-1", "display_name": "Reviewed", "avatar_url": null,
        "system_prompt": "Original prompt", "created_at": "2026-09-07T00:00:00Z",
        "updated_at": "2026-09-07T00:00:00Z"
    }))
    .unwrap()
}

#[test]
fn unchanged_content_survives_ipc_serialization_defaults_and_map_order() {
    let mut current = persona();
    current.env_vars = [("Z".into(), "last".into()), ("A".into(), "first".into())].into();
    // Same camelCase payload emitted by Desktop; omitted options deserialize to None.
    let expected: PersonaReviewContent = serde_json::from_str(
        r#"{
        "systemPrompt":"Original prompt", "id":"persona-1", "displayName":"Reviewed",
        "envVars":{"Z":"last","A":"first"}, "namePool":[], "parallelism":null
    }"#,
    )
    .unwrap();
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &current
    )
    .is_ok());
}

#[test]
fn changed_content_timestamp_target_and_team_reject_before_mutation() {
    let current = persona();
    let expected = PersonaReviewContent::from(&current);
    let mut changed = current.clone();
    changed.system_prompt = "Same-second replacement".into();
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &changed
    )
    .is_err());
    assert_eq!(changed.system_prompt, "Same-second replacement");
    changed = current.clone();
    changed.updated_at = "2026-09-07T00:00:01Z".into();
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &changed
    )
    .is_err());
    changed = current.clone();
    changed.id = "different-persona".into();
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &changed
    )
    .is_err());
    changed = current.clone();
    changed.source_team = Some("team".into());
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &changed
    )
    .is_err());
    assert!(validate_review_revision(None, Some(&expected), None, &changed).is_err());
}

#[test]
fn sharing_still_compares_independently_of_content_and_time() {
    let mut current = persona();
    let expected = PersonaReviewContent::from(&current);
    current.shared = true;
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(false),
        &current
    )
    .is_err());
    assert!(validate_review_revision(
        Some(&current.updated_at),
        Some(&expected),
        Some(true),
        &current
    )
    .is_ok());
}

#[test]
fn ordinary_edits_omit_review_preconditions() {
    let current = persona();
    assert!(validate_review_revision(None, None, None, &current).is_ok());
    // A timestamp alone cannot identify an owner-reviewed revision.
    assert!(validate_review_revision(Some(&current.updated_at), None, None, &current).is_err());
    assert!(validate_review_revision(Some(""), None, None, &current).is_err());
}
