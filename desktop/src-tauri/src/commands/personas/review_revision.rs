use crate::managed_agents::{AgentDefinition, PersonaReviewContent};

/// Called after loading the current persona under the store lock and before
/// changing it. Ordinary edits omit review preconditions and keep their existing path.
pub(in crate::commands) fn validate_review_revision(
    expected_updated_at: Option<&str>,
    expected_content: Option<&PersonaReviewContent>,
    expected_shared: Option<bool>,
    current: &AgentDefinition,
) -> Result<(), String> {
    if (expected_updated_at.is_some() || expected_content.is_some())
        && (current.source_team.is_some()
            || (expected_updated_at.is_some() && expected_content.is_none())
            || expected_updated_at
                .is_some_and(|expected| expected.is_empty() || expected != current.updated_at)
            || expected_content
                .is_some_and(|expected| *expected != PersonaReviewContent::from(current)))
    {
        return Err(
            "This agent changed since the draft opened. Close this review and request a new draft."
                .into(),
        );
    }
    if expected_shared.is_some_and(|shared| shared != current.shared) {
        return Err("This agent sharing changed since the draft opened. Close this review and request a new draft.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
