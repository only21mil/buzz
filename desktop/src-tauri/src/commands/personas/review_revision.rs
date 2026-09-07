/// Called after loading the current persona under the store lock and before
/// changing it. Ordinary edits omit the revision and keep their existing path.
pub(super) fn validate_review_revision(
    expected: Option<&str>,
    current: &str,
    is_team_persona: bool,
    expected_shared: Option<bool>,
    current_shared: bool,
) -> Result<(), String> {
    if let Some(expected) = expected {
        if expected.is_empty() || expected != current || is_team_persona {
            return Err("This agent changed since the draft opened. Close this review and request a new draft.".into());
        }
    }
    if expected_shared.is_some_and(|shared| shared != current_shared) {
        return Err("This agent sharing changed since the draft opened. Close this review and request a new draft.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_review_revision;

    #[test]
    fn review_accepts_only_the_unchanged_personal_revision() {
        assert!(
            validate_review_revision(Some("revision-1"), "revision-1", false, None, false).is_ok()
        );
        assert!(
            validate_review_revision(Some("revision-1"), "revision-2", false, None, false).is_err()
        );
        assert!(
            validate_review_revision(Some("revision-1"), "revision-1", true, None, false).is_err()
        );
        assert!(validate_review_revision(Some(""), "", false, None, false).is_err());
    }

    #[test]
    fn changed_sharing_rejects_even_when_timestamp_did_not_change() {
        assert!(validate_review_revision(
            Some("revision-1"),
            "revision-1",
            false,
            Some(false),
            true
        )
        .is_err());
        assert!(validate_review_revision(
            Some("revision-1"),
            "revision-1",
            false,
            Some(true),
            true
        )
        .is_ok());
    }

    #[test]
    fn ordinary_edit_without_review_revision_keeps_existing_behavior() {
        assert!(validate_review_revision(None, "revision-2", false, None, false).is_ok());
    }

    #[test]
    fn concurrent_review_cannot_overwrite_a_save_that_won_the_store_lock() {
        let mut revision = "revision-1";
        validate_review_revision(Some("revision-1"), revision, false, None, false).unwrap();
        revision = "revision-2";
        assert!(
            validate_review_revision(Some("revision-1"), revision, false, None, false).is_err()
        );
        assert_eq!(revision, "revision-2");
    }
}
