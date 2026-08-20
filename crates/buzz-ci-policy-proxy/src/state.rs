use std::collections::{BTreeMap, BTreeSet};

use crate::ProxyError;

/// Attempt lifecycle enforced by the proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptPhase {
    /// No immutable manifest is installed. Nothing forwards.
    Locked,
    /// Controlled creates/starts/execs are admitted.
    Running,
    /// A broker seal is draining already-admitted mutations.
    Sealing,
    /// Executor-facing endpoint is read-only and archive reads are broker-only.
    TerminalReadOnly,
}

/// Attempt-owned container and exec IDs.
#[derive(Clone, Debug, Default)]
pub struct ObjectLedger {
    containers: BTreeMap<String, String>,
    started: BTreeSet<String>,
    execs: BTreeMap<String, String>,
}

impl ObjectLedger {
    /// Record an upstream container ID only after a policy-approved create.
    pub fn record_container(
        &mut self,
        id: String,
        create_fingerprint: String,
    ) -> Result<(), ProxyError> {
        if id.is_empty() || self.containers.contains_key(&id) {
            return Err(ProxyError::StateRefused(
                "empty or reused container ID".into(),
            ));
        }
        self.containers.insert(id, create_fingerprint);
        Ok(())
    }

    /// Return the approved create fingerprint for an owned container.
    pub fn container_fingerprint(&self, id: &str) -> Result<&str, ProxyError> {
        self.containers.get(id).map(String::as_str).ok_or_else(|| {
            ProxyError::StateRefused("container does not belong to this attempt".into())
        })
    }

    /// Mark an owned, pre-start-verified container as started.
    pub fn mark_started(&mut self, id: &str) -> Result<(), ProxyError> {
        self.container_fingerprint(id)?;
        self.started.insert(id.into());
        Ok(())
    }

    /// Verify that a container is owned and has a committed successful start.
    pub fn require_started(&self, id: &str) -> Result<(), ProxyError> {
        self.container_fingerprint(id)?;
        if self.started.contains(id) {
            Ok(())
        } else {
            Err(ProxyError::StateRefused(
                "container has not successfully started".into(),
            ))
        }
    }

    /// Mark an owned container stopped after a successful wait/readback.
    pub fn mark_stopped(&mut self, id: &str) -> Result<(), ProxyError> {
        self.container_fingerprint(id)?;
        self.started.remove(id);
        Ok(())
    }

    /// Return whether no owned container is currently recorded as started.
    pub fn all_stopped(&self) -> bool {
        self.started.is_empty()
    }

    /// Return the owned container identifiers in deterministic order.
    pub fn container_ids(&self) -> impl Iterator<Item = &str> {
        self.containers.keys().map(String::as_str)
    }

    /// Return whether an owned container has a committed successful start.
    pub fn is_started(&self, id: &str) -> Result<bool, ProxyError> {
        self.container_fingerprint(id)?;
        Ok(self.started.contains(id))
    }

    /// Record an exec ID bound to an already-started owned container.
    pub fn record_exec(&mut self, id: String, container_id: &str) -> Result<(), ProxyError> {
        self.require_started(container_id)?;
        if id.is_empty() || self.execs.contains_key(&id) {
            return Err(ProxyError::StateRefused("empty or reused exec ID".into()));
        }
        self.execs.insert(id, container_id.into());
        Ok(())
    }

    /// Verify that an exec belongs to this attempt.
    pub fn require_exec(&self, id: &str) -> Result<(), ProxyError> {
        if self.execs.contains_key(id) {
            Ok(())
        } else {
            Err(ProxyError::StateRefused(
                "exec does not belong to this attempt".into(),
            ))
        }
    }

    /// Remove a container from the attempt ledger during bounded cleanup.
    pub fn remove_container(&mut self, id: &str) -> Result<(), ProxyError> {
        self.container_fingerprint(id)?;
        self.containers.remove(id);
        self.started.remove(id);
        self.execs.retain(|_, container| container != id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_ids_do_not_overwrite_existing_ownership() {
        let mut ledger = ObjectLedger::default();
        ledger
            .record_container("container".into(), "first".into())
            .unwrap();
        assert!(ledger
            .record_container("container".into(), "replacement".into())
            .is_err());
        assert_eq!(ledger.container_fingerprint("container").unwrap(), "first");

        ledger.mark_started("container").unwrap();
        ledger.record_exec("exec".into(), "container").unwrap();
        assert!(ledger.record_exec("exec".into(), "container").is_err());
        assert!(ledger.require_exec("exec").is_ok());
    }
}
