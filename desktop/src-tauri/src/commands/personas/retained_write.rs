//! Save/retention boundaries for create and snapshot import. A failed enqueue
//! must report the local state already written, without implying rollback.

pub(super) enum LocalWrite<'a> {
    CreatedPersona(&'a str),
    ImportedPersona(&'a str),
    ImportedAgent {
        persona_id: &'a str,
        pubkey: &'a str,
    },
}

pub(super) fn save_and_retain(
    write: LocalWrite<'_>,
    save: impl FnOnce() -> Result<(), String>,
    retain: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    save()?;
    retain().map_err(|error| match write {
        LocalWrite::CreatedPersona(id) => format!(
            "Persona {id} was saved locally, but could not be queued for sync: {error}. \
             Edit and save the existing persona after resolving the error; creating it again will make a duplicate."
        ),
        LocalWrite::ImportedPersona(id) => format!(
            "Import stopped after saving persona {id} locally: it could not be queued for sync: {error}. \
             No agent was saved and no memory was restored. The saved persona remains; importing again will create another persona."
        ),
        LocalWrite::ImportedAgent { persona_id, pubkey } => format!(
            "Import stopped after saving persona {persona_id} and agent {pubkey} locally: the agent could not be queued for sync: {error}. \
             The persona is already queued for sync. Profile sync and memory restore were not attempted; importing again will create another agent."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn save_failure_never_attempts_retention_or_claims_a_local_save() {
        let error = save_and_retain(
            LocalWrite::CreatedPersona("persona-id"),
            || Err("disk full".into()),
            || panic!("retention must not run after a failed save"),
        )
        .unwrap_err();
        assert_eq!(error, "disk full");
    }

    #[test]
    fn successful_save_precedes_retention() {
        let saved = Cell::new(false);
        save_and_retain(
            LocalWrite::CreatedPersona("persona-id"),
            || {
                saved.set(true);
                Ok(())
            },
            || {
                assert!(saved.get());
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn retention_failures_report_each_partial_state_and_preserve_local_save() {
        for failure in [
            "identity is in recovery mode",
            "retention database unavailable",
        ] {
            for (write, expected_state) in [
                (
                    LocalWrite::CreatedPersona("created-id"),
                    "Persona created-id was saved locally",
                ),
                (
                    LocalWrite::ImportedPersona("imported-id"),
                    "No agent was saved and no memory was restored",
                ),
                (
                    LocalWrite::ImportedAgent {
                        persona_id: "imported-id",
                        pubkey: "agent-pubkey",
                    },
                    "Profile sync and memory restore were not attempted",
                ),
            ] {
                let saved = Cell::new(false);
                let result = save_and_retain(
                    write,
                    || {
                        saved.set(true);
                        Ok(())
                    },
                    || {
                        assert!(saved.get());
                        Err(failure.into())
                    },
                );
                let error = result.expect_err("a local save alone must not report success");
                assert!(
                    saved.get(),
                    "the failed enqueue does not roll back the save"
                );
                assert!(error.contains(failure), "{error}");
                assert!(error.contains(expected_state), "{error}");
                assert!(error.contains("again will"), "{error}");
            }
        }
    }
}
