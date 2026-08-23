//! Crash-safe, in-memory representation of the policy-proxy lifecycle journal.
//!
//! The journal is deliberately a pure schema and replay validator. Persistence
//! belongs to the lease owner. This module only checks the bytes it is given
//! and derives the safest state that those bytes prove.

use std::collections::{BTreeMap, BTreeSet};

use buzz_ci_policy_proxy::LifecyclePhase;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::evidence::{CiEventBinding, Digest32};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod store;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) use store::{ProxyJournalStore, ProxyJournalStoreError};

pub(crate) const JOURNAL_SCHEMA_VERSION: u16 = 1;
const MAX_ENTRIES: usize = 256;
// Reserve enough room for the seven-record clean path plus bounded fresh
// inventories after recovery-process crashes. Lifecycle admission stops before
// consuming this budget.
const RECONCILE_RESERVE: usize = 32;
const MAX_LIFECYCLE_ENTRIES: usize = MAX_ENTRIES - RECONCILE_RESERVE;
// A forwarded mutation can need intent, terminal result, and a final Poisoned
// fact when the executor disappears after the runtime result was persisted.
const LIFECYCLE_INTENT_RECORDS: usize = 3;
const MAX_RECONCILE_OBJECTS: usize = 32;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 4096;

/// The one mutation whose completion has not yet been durably recorded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum ProxyMutationIntent {
    Create,
    Start,
    ExecCreate,
    Stop,
    Delete,
    DeleteObject,
}

/// Serializable copy of the proxy's externally visible lifecycle phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum RecordedLifecyclePhase {
    AwaitCreate,
    Creating,
    Created,
    Starting,
    Started,
    Deleting,
    Removed,
}

impl TryFrom<LifecyclePhase> for RecordedLifecyclePhase {
    type Error = ProxyJournalError;

    fn try_from(value: LifecyclePhase) -> Result<Self, Self::Error> {
        match value {
            LifecyclePhase::AwaitCreate => Ok(Self::AwaitCreate),
            LifecyclePhase::Creating => Ok(Self::Creating),
            LifecyclePhase::Created => Ok(Self::Created),
            LifecyclePhase::Starting => Ok(Self::Starting),
            LifecyclePhase::Started => Ok(Self::Started),
            LifecyclePhase::Deleting => Ok(Self::Deleting),
            LifecyclePhase::Removed => Ok(Self::Removed),
            _ => Err(ProxyJournalError::UnsupportedLifecyclePhase),
        }
    }
}

/// The immutable create request authority retained by the journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalCreateAuthority {
    pub(crate) fingerprint: String,
    pub(crate) target: String,
    pub(crate) body_sha256: Digest32,
}

/// One exact lease-labelled runtime object observed during reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconcileObject {
    pub(crate) id: String,
    pub(crate) running: bool,
}

impl CanonicalCreateAuthority {
    pub(crate) fn new(
        fingerprint: String,
        target: String,
        body_sha256: Digest32,
    ) -> Result<Self, ProxyJournalError> {
        let authority = Self {
            fingerprint,
            target,
            body_sha256,
        };
        validate_authority(&authority)?;
        Ok(authority)
    }
}

/// One tagged lifecycle fact. The first create authority and every returned
/// runtime ID are repeated where needed so replay can compare exact values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "kind",
    content = "payload"
)]
pub(crate) enum ProxyJournalFact {
    CreateIntent {
        authority: CanonicalCreateAuthority,
    },
    CreateRejected {
        authority: CanonicalCreateAuthority,
    },
    Created {
        authority: CanonicalCreateAuthority,
        container_id: String,
    },
    StartIntent {
        container_id: String,
    },
    StartRejected {
        container_id: String,
    },
    Started {
        container_id: String,
    },
    Poisoned {
        phase: RecordedLifecyclePhase,
        container_id: Option<String>,
    },
    ExecCreateIntent {
        container_id: String,
    },
    ExecCreateRejected {
        container_id: String,
    },
    ExecCreated {
        container_id: String,
        exec_id: String,
    },
    DeleteIntent {
        container_id: String,
    },
    DeleteRejected {
        container_id: String,
    },
    Removed {
        container_id: String,
    },
    ReconcileInventory {
        objects: Vec<ReconcileObject>,
    },
    StopIntent {
        container_id: String,
    },
    Stopped {
        container_id: String,
    },
    DeleteObjectIntent {
        object_id: String,
    },
    DeletedObject {
        object_id: String,
    },
    ReconcileVerifiedEmpty,
}

impl ProxyJournalFact {
    pub(crate) fn create_intent(authority: CanonicalCreateAuthority) -> Self {
        Self::CreateIntent { authority }
    }

    pub(crate) fn create_rejected(authority: CanonicalCreateAuthority) -> Self {
        Self::CreateRejected { authority }
    }

    pub(crate) fn created(authority: CanonicalCreateAuthority, container_id: String) -> Self {
        Self::Created {
            authority,
            container_id,
        }
    }

    pub(crate) fn start_intent(container_id: String) -> Self {
        Self::StartIntent { container_id }
    }

    pub(crate) fn start_rejected(container_id: String) -> Self {
        Self::StartRejected { container_id }
    }

    pub(crate) fn started(container_id: String) -> Self {
        Self::Started { container_id }
    }

    pub(crate) fn poisoned(
        phase: LifecyclePhase,
        container_id: Option<String>,
    ) -> Result<Self, ProxyJournalError> {
        Ok(Self::Poisoned {
            phase: phase.try_into()?,
            container_id,
        })
    }

    pub(crate) fn exec_create_intent(container_id: String) -> Self {
        Self::ExecCreateIntent { container_id }
    }

    pub(crate) fn exec_create_rejected(container_id: String) -> Self {
        Self::ExecCreateRejected { container_id }
    }

    pub(crate) fn exec_created(container_id: String, exec_id: String) -> Self {
        Self::ExecCreated {
            container_id,
            exec_id,
        }
    }

    pub(crate) fn delete_intent(container_id: String) -> Self {
        Self::DeleteIntent { container_id }
    }

    pub(crate) fn delete_rejected(container_id: String) -> Self {
        Self::DeleteRejected { container_id }
    }

    pub(crate) fn removed(container_id: String) -> Self {
        Self::Removed { container_id }
    }

    pub(crate) fn reconcile_inventory(objects: Vec<ReconcileObject>) -> Self {
        Self::ReconcileInventory { objects }
    }

    pub(crate) fn stop_intent(container_id: String) -> Self {
        Self::StopIntent { container_id }
    }

    pub(crate) fn stopped(container_id: String) -> Self {
        Self::Stopped { container_id }
    }

    pub(crate) fn delete_object_intent(object_id: String) -> Self {
        Self::DeleteObjectIntent { object_id }
    }

    pub(crate) fn deleted_object(object_id: String) -> Self {
        Self::DeletedObject { object_id }
    }

    pub(crate) fn reconcile_verified_empty() -> Self {
        Self::ReconcileVerifiedEmpty
    }
}

/// One ordered journal record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyJournalEntry {
    pub(crate) sequence: u64,
    pub(crate) timestamp_unix_ns: u64,
    pub(crate) fact: ProxyJournalFact,
}

impl ProxyJournalEntry {
    pub(crate) fn new(
        sequence: u64,
        timestamp_unix_ns: u64,
        fact: ProxyJournalFact,
    ) -> Result<Self, ProxyJournalError> {
        if sequence == 0 {
            return Err(ProxyJournalError::InvalidSequence);
        }
        if timestamp_unix_ns == 0 {
            return Err(ProxyJournalError::InvalidTimestamp);
        }
        Ok(Self {
            sequence,
            timestamp_unix_ns,
            fact,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StrictEventBinding {
    request_event_id_46105: [u8; 32],
    teardown_event_id_46106: [u8; 32],
}

impl From<StrictEventBinding> for CiEventBinding {
    fn from(value: StrictEventBinding) -> Self {
        Self {
            request_event_id_46105: value.request_event_id_46105,
            teardown_event_id_46106: value.teardown_event_id_46106,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyJournalWire {
    schema_version: u16,
    lease_id: String,
    event_binding: StrictEventBinding,
    upstream_capability_sha256: Digest32,
    entries: Vec<ProxyJournalEntry>,
}

/// One lease's complete ordered journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyJournal {
    pub(crate) schema_version: u16,
    pub(crate) lease_id: String,
    pub(crate) event_binding: CiEventBinding,
    pub(crate) upstream_capability_sha256: Digest32,
    pub(crate) entries: Vec<ProxyJournalEntry>,
}

impl<'de> Deserialize<'de> for ProxyJournal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProxyJournalWire::deserialize(deserializer)?;
        Ok(Self {
            schema_version: wire.schema_version,
            lease_id: wire.lease_id,
            event_binding: wire.event_binding.into(),
            upstream_capability_sha256: wire.upstream_capability_sha256,
            entries: wire.entries,
        })
    }
}

impl ProxyJournal {
    pub(crate) fn new(
        lease_id: String,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
    ) -> Result<Self, ProxyJournalError> {
        let journal = Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            lease_id,
            event_binding,
            upstream_capability_sha256,
            entries: Vec::new(),
        };
        journal.validate_header()?;
        Ok(journal)
    }

    #[cfg(test)]
    pub(crate) fn from_entries(
        lease_id: String,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
        entries: Vec<ProxyJournalEntry>,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            lease_id,
            event_binding,
            upstream_capability_sha256,
            entries,
        }
    }

    pub(crate) fn append(
        &mut self,
        timestamp_unix_ns: u64,
        fact: ProxyJournalFact,
    ) -> Result<(), ProxyJournalError> {
        let prior_replay = self.replay()?;
        if timestamp_unix_ns == 0 {
            return Err(ProxyJournalError::InvalidTimestamp);
        }
        if let (
            Some(ProxyJournalEntry {
                fact: ProxyJournalFact::ReconcileInventory { objects: previous },
                ..
            }),
            ProxyJournalFact::ReconcileInventory { objects },
        ) = (self.entries.last(), &fact)
        {
            validate_reconcile_objects(objects)?;
            let previous = previous
                .iter()
                .map(|object| (object.id.as_str(), object.running))
                .collect::<BTreeMap<_, _>>();
            let current = objects
                .iter()
                .map(|object| (object.id.as_str(), object.running))
                .collect::<BTreeMap<_, _>>();
            if previous == current {
                return Ok(());
            }
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(ProxyJournalError::TooManyEntries);
        }
        let lifecycle_entries = self.lifecycle_entry_count();
        if is_mutation_intent(&fact) {
            let fits = if is_reconcile_fact(&fact) {
                self.entries.len() + 2 <= MAX_ENTRIES
            } else {
                lifecycle_entries + LIFECYCLE_INTENT_RECORDS <= MAX_LIFECYCLE_ENTRIES
            };
            if !fits {
                return Err(ProxyJournalError::TooManyEntries);
            }
        } else if lifecycle_entries >= MAX_LIFECYCLE_ENTRIES && !is_reconcile_fact(&fact) {
            return Err(ProxyJournalError::TooManyEntries);
        }
        let sequence = self.entries.len() as u64 + 1;
        let entry = ProxyJournalEntry::new(sequence, timestamp_unix_ns, fact)?;
        self.entries.push(entry);
        match self.replay() {
            Ok(replay)
                if self.entries.len()
                    + required_reconcile_capacity(&replay, &prior_replay, &self.entries)
                    <= MAX_ENTRIES => {}
            Ok(_) => {
                self.entries.pop();
                return Err(ProxyJournalError::TooManyEntries);
            }
            Err(error) => {
                self.entries.pop();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn replay(&self) -> Result<ProxyJournalReplay, ProxyJournalError> {
        self.validate_header()?;
        if self.entries.len() > MAX_ENTRIES {
            return Err(ProxyJournalError::TooManyEntries);
        }
        if self.lifecycle_entry_count() > MAX_LIFECYCLE_ENTRIES {
            return Err(ProxyJournalError::TooManyEntries);
        }

        let mut replay = ProxyJournalReplay::default();
        for (expected_sequence, entry) in (1_u64..).zip(self.entries.iter()) {
            if entry.sequence != expected_sequence {
                return Err(ProxyJournalError::InvalidSequence);
            }
            if entry.timestamp_unix_ns == 0 {
                return Err(ProxyJournalError::InvalidTimestamp);
            }
            apply_fact(&mut replay, &entry.fact)?;
        }
        Ok(replay)
    }

    fn lifecycle_entry_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| !is_reconcile_fact(&entry.fact))
            .count()
    }

    pub(crate) fn replay_for(
        &self,
        lease_id: &str,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
    ) -> Result<ProxyJournalReplay, ProxyJournalError> {
        if self.lease_id != lease_id
            || self.event_binding != event_binding
            || self.upstream_capability_sha256 != upstream_capability_sha256
        {
            return Err(ProxyJournalError::BindingMismatch);
        }
        self.replay()
    }

    fn validate_header(&self) -> Result<(), ProxyJournalError> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(ProxyJournalError::WrongSchemaVersion);
        }
        if !safe_lease_id(&self.lease_id) {
            return Err(ProxyJournalError::InvalidLeaseId);
        }
        validate_event_binding(self.event_binding)?;
        if self.upstream_capability_sha256.0 == [0; 32] {
            return Err(ProxyJournalError::InvalidCapabilityDigest);
        }
        Ok(())
    }
}

fn required_reconcile_capacity(
    replay: &ProxyJournalReplay,
    prior_replay: &ProxyJournalReplay,
    entries: &[ProxyJournalEntry],
) -> usize {
    if replay.is_clean_terminal() {
        return 0;
    }
    if !replay.reconcile.inventory_seen {
        // Initial inventory, then one running object's stop/delete path. Each
        // mutation keeps room for one post-crash inventory before its result.
        return 10;
    }

    let last_is_inventory = entries
        .last()
        .is_some_and(|entry| matches!(entry.fact, ProxyJournalFact::ReconcileInventory { .. }));
    match replay.unresolved_intent {
        Some(ProxyMutationIntent::Stop) => 7 + usize::from(!last_is_inventory),
        Some(ProxyMutationIntent::DeleteObject) => 3 + usize::from(!last_is_inventory),
        Some(_) => 10,
        None => match replay.reconcile.current_objects.values().next() {
            Some(true) => 9 + usize::from(!last_is_inventory),
            Some(false) => 5 + usize::from(!last_is_inventory),
            None => {
                let inventory_needs_confirmation = last_is_inventory
                    && (!prior_replay.reconcile.inventory_seen
                        || prior_replay.unresolved_intent.is_some());
                1 + usize::from(!last_is_inventory || inventory_needs_confirmation)
            }
        },
    }
}

fn is_reconcile_fact(fact: &ProxyJournalFact) -> bool {
    matches!(
        fact,
        ProxyJournalFact::ReconcileInventory { .. }
            | ProxyJournalFact::StopIntent { .. }
            | ProxyJournalFact::Stopped { .. }
            | ProxyJournalFact::DeleteObjectIntent { .. }
            | ProxyJournalFact::DeletedObject { .. }
            | ProxyJournalFact::ReconcileVerifiedEmpty
    )
}

fn is_mutation_intent(fact: &ProxyJournalFact) -> bool {
    matches!(
        fact,
        ProxyJournalFact::CreateIntent { .. }
            | ProxyJournalFact::StartIntent { .. }
            | ProxyJournalFact::ExecCreateIntent { .. }
            | ProxyJournalFact::DeleteIntent { .. }
            | ProxyJournalFact::StopIntent { .. }
            | ProxyJournalFact::DeleteObjectIntent { .. }
    )
}

/// The currently proven state after replaying a journal prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProxyJournalReplay {
    pub(crate) phase: LifecyclePhase,
    pub(crate) unresolved_intent: Option<ProxyMutationIntent>,
    pub(crate) poisoned: bool,
    pub(crate) canonical_create_authority: Option<CanonicalCreateAuthority>,
    pub(crate) known_container_id: Option<String>,
    pub(crate) known_exec_ids: BTreeSet<String>,
    pub(crate) stopped: bool,
    delete_return_phase: Option<LifecyclePhase>,
    pub(crate) reconcile: ReconcileProgress,
}

impl ProxyJournalReplay {
    pub(crate) fn is_clean_terminal(&self) -> bool {
        self.reconcile.verified_empty
    }
}

impl Default for ProxyJournalReplay {
    fn default() -> Self {
        Self {
            phase: LifecyclePhase::AwaitCreate,
            unresolved_intent: None,
            poisoned: false,
            canonical_create_authority: None,
            known_container_id: None,
            known_exec_ids: BTreeSet::new(),
            stopped: false,
            delete_return_phase: None,
            reconcile: ReconcileProgress::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReconcileProgress {
    pub(crate) current_objects: BTreeMap<String, bool>,
    pub(crate) known_objects: BTreeSet<String>,
    pub(crate) deleted_objects: BTreeSet<String>,
    pub(crate) stopped_objects: BTreeSet<String>,
    pub(crate) inventory_seen: bool,
    pub(crate) verified_empty: bool,
    pub(crate) trigger_intent: Option<ProxyMutationIntent>,
    pub(crate) pending_object_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProxyJournalError {
    #[error("journal schema version is not 1")]
    WrongSchemaVersion,
    #[error("journal lease id is not a safe identifier")]
    InvalidLeaseId,
    #[error("journal event binding is invalid")]
    InvalidEventBinding,
    #[error("journal upstream capability digest is invalid")]
    InvalidCapabilityDigest,
    #[error("journal does not match the expected lease, event, or upstream capability binding")]
    BindingMismatch,
    #[error("journal has too many entries")]
    TooManyEntries,
    #[error("journal sequence is not contiguous from 1")]
    InvalidSequence,
    #[error("journal timestamp is zero")]
    InvalidTimestamp,
    #[error("canonical create authority is invalid")]
    InvalidAuthority,
    #[error("runtime identifier is invalid")]
    InvalidIdentifier,
    #[error("reconcile inventory is invalid")]
    InvalidReconcileInventory,
    #[error("journal fact is not legal in the current lifecycle")]
    IllegalTransition,
    #[error("policy proxy lifecycle phase is unsupported by journal schema version 1")]
    UnsupportedLifecyclePhase,
    #[error("canonical create authority changed")]
    AuthorityMismatch,
    #[error("container identifier changed")]
    ContainerIdMismatch,
    #[error("exec identifier is duplicated")]
    DuplicateExecId,
    #[error("reconcile object is duplicated or reappeared")]
    DuplicateReconcileObject,
    #[error("reconcile inventory changed without a matching durable mutation intent")]
    ReconcileInventoryDrift,
}

fn apply_fact(
    replay: &mut ProxyJournalReplay,
    fact: &ProxyJournalFact,
) -> Result<(), ProxyJournalError> {
    if replay.reconcile.verified_empty {
        return Err(ProxyJournalError::IllegalTransition);
    }

    let reconcile_fact = matches!(
        fact,
        ProxyJournalFact::ReconcileInventory { .. }
            | ProxyJournalFact::StopIntent { .. }
            | ProxyJournalFact::Stopped { .. }
            | ProxyJournalFact::DeleteObjectIntent { .. }
            | ProxyJournalFact::DeletedObject { .. }
            | ProxyJournalFact::ReconcileVerifiedEmpty
    );
    if replay.reconcile.inventory_seen && !reconcile_fact {
        return Err(ProxyJournalError::IllegalTransition);
    }
    if replay.poisoned && !replay.reconcile.inventory_seen && !reconcile_fact {
        return Err(ProxyJournalError::IllegalTransition);
    }

    match fact {
        ProxyJournalFact::CreateIntent { authority } => {
            validate_authority(authority)?;
            if replay.phase != LifecyclePhase::AwaitCreate || replay.unresolved_intent.is_some() {
                return Err(ProxyJournalError::IllegalTransition);
            }
            match replay.canonical_create_authority.as_ref() {
                Some(expected) if expected != authority => {
                    return Err(ProxyJournalError::AuthorityMismatch);
                }
                None => replay.canonical_create_authority = Some(authority.clone()),
                Some(_) => {}
            }
            replay.unresolved_intent = Some(ProxyMutationIntent::Create);
            replay.phase = LifecyclePhase::Creating;
        }
        ProxyJournalFact::CreateRejected { authority } => {
            validate_authority(authority)?;
            require_authority(replay, authority)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Create) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::AwaitCreate;
        }
        ProxyJournalFact::Created {
            authority,
            container_id,
        } => {
            validate_authority(authority)?;
            validate_identifier(container_id)?;
            require_authority(replay, authority)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Create)
                || replay.known_container_id.is_some()
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.known_container_id = Some(container_id.clone());
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::Created;
        }
        ProxyJournalFact::StartIntent { container_id } => {
            require_container(replay, container_id)?;
            if replay.phase != LifecyclePhase::Created || replay.unresolved_intent.is_some() {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = Some(ProxyMutationIntent::Start);
            replay.phase = LifecyclePhase::Starting;
        }
        ProxyJournalFact::StartRejected { container_id } => {
            require_container(replay, container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Start) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::Created;
        }
        ProxyJournalFact::Started { container_id } => {
            require_container(replay, container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Start) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.stopped = false;
            replay.phase = LifecyclePhase::Started;
        }
        ProxyJournalFact::Poisoned {
            phase,
            container_id,
        } => {
            apply_poisoned(replay, *phase, container_id.as_deref())?;
            replay.poisoned = true;
        }
        ProxyJournalFact::ExecCreateIntent { container_id } => {
            require_container(replay, container_id)?;
            if replay.phase != LifecyclePhase::Started || replay.unresolved_intent.is_some() {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = Some(ProxyMutationIntent::ExecCreate);
        }
        ProxyJournalFact::ExecCreateRejected { container_id } => {
            require_container(replay, container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::ExecCreate) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
        }
        ProxyJournalFact::ExecCreated {
            container_id,
            exec_id,
        } => {
            require_container(replay, container_id)?;
            validate_identifier(exec_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::ExecCreate) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            if !replay.known_exec_ids.insert(exec_id.clone()) {
                return Err(ProxyJournalError::DuplicateExecId);
            }
            replay.unresolved_intent = None;
        }
        ProxyJournalFact::DeleteIntent { container_id } => {
            require_container(replay, container_id)?;
            if !matches!(
                replay.phase,
                LifecyclePhase::Created | LifecyclePhase::Started
            ) || replay.unresolved_intent.is_some()
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.delete_return_phase = Some(replay.phase);
            replay.unresolved_intent = Some(ProxyMutationIntent::Delete);
            replay.phase = LifecyclePhase::Deleting;
        }
        ProxyJournalFact::DeleteRejected { container_id } => {
            require_container(replay, container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Delete) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.phase = replay
                .delete_return_phase
                .take()
                .ok_or(ProxyJournalError::IllegalTransition)?;
        }
        ProxyJournalFact::Removed { container_id } => {
            require_container(replay, container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Delete) {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.delete_return_phase = None;
            replay.phase = LifecyclePhase::Removed;
        }
        ProxyJournalFact::ReconcileInventory { objects } => {
            validate_reconcile_objects(objects)?;
            if !replay.reconcile.inventory_seen {
                validate_first_reconcile_inventory(replay, objects)?;
            }
            let inventory_seen = replay.reconcile.inventory_seen;
            let previous_objects = replay.reconcile.current_objects.clone();
            let pending_intent = replay.unresolved_intent;
            let pending_object_id = replay.reconcile.pending_object_id.clone();
            if !replay.reconcile.inventory_seen {
                if replay.reconcile.trigger_intent.is_none() {
                    replay.reconcile.trigger_intent = replay.unresolved_intent;
                }
                replay.unresolved_intent = None;
                replay.delete_return_phase = None;
            }

            if replay.unresolved_intent == Some(ProxyMutationIntent::DeleteObject) {
                let pending = replay
                    .reconcile
                    .pending_object_id
                    .as_ref()
                    .ok_or(ProxyJournalError::IllegalTransition)?;
                if !objects.iter().any(|object| object.id == *pending) {
                    replay.reconcile.deleted_objects.insert(pending.clone());
                    replay.reconcile.pending_object_id = None;
                    replay.unresolved_intent = None;
                }
            } else if replay.unresolved_intent == Some(ProxyMutationIntent::Stop) {
                let pending = replay
                    .reconcile
                    .pending_object_id
                    .as_ref()
                    .ok_or(ProxyJournalError::IllegalTransition)?;
                match objects.iter().find(|object| object.id == *pending) {
                    None => {
                        replay.reconcile.deleted_objects.insert(pending.clone());
                        replay.reconcile.pending_object_id = None;
                        replay.unresolved_intent = None;
                        replay.stopped = true;
                    }
                    Some(object) if !object.running => {
                        replay.reconcile.stopped_objects.insert(pending.clone());
                        replay.reconcile.pending_object_id = None;
                        replay.unresolved_intent = None;
                        replay.stopped = true;
                    }
                    Some(_) => {}
                }
            } else if replay.unresolved_intent.is_some() {
                return Err(ProxyJournalError::IllegalTransition);
            }
            let observed = objects
                .iter()
                .map(|object| (object.id.clone(), object.running))
                .collect::<BTreeMap<_, _>>();
            if inventory_seen {
                if observed
                    .keys()
                    .any(|object| !replay.reconcile.known_objects.contains(object))
                    || observed.iter().any(|(object, running)| {
                        previous_objects.get(object) == Some(&false) && *running
                    })
                {
                    return Err(ProxyJournalError::ReconcileInventoryDrift);
                }
                let allowed_absence = matches!(
                    pending_intent,
                    Some(ProxyMutationIntent::Stop | ProxyMutationIntent::DeleteObject)
                );
                if previous_objects.keys().any(|object| {
                    !(observed.contains_key(object)
                        || allowed_absence && pending_object_id.as_ref() == Some(object))
                }) {
                    return Err(ProxyJournalError::ReconcileInventoryDrift);
                }
            }
            if observed
                .keys()
                .any(|object| replay.reconcile.deleted_objects.contains(object))
            {
                return Err(ProxyJournalError::DuplicateReconcileObject);
            }
            replay
                .reconcile
                .known_objects
                .extend(observed.keys().cloned());
            if replay.reconcile.known_objects.len() > MAX_RECONCILE_OBJECTS {
                return Err(ProxyJournalError::InvalidReconcileInventory);
            }
            replay.reconcile.current_objects = observed;
            replay.reconcile.inventory_seen = true;
            replay.phase = LifecyclePhase::Removed;
        }
        ProxyJournalFact::StopIntent { container_id } => {
            validate_identifier(container_id)?;
            if !replay.reconcile.inventory_seen
                || replay.reconcile.current_objects.get(container_id) != Some(&true)
                || replay.unresolved_intent.is_some()
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = Some(ProxyMutationIntent::Stop);
            replay.reconcile.pending_object_id = Some(container_id.clone());
        }
        ProxyJournalFact::Stopped { container_id } => {
            validate_identifier(container_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::Stop)
                || replay.reconcile.pending_object_id.as_deref() != Some(container_id)
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = None;
            replay.reconcile.pending_object_id = None;
            replay.stopped = true;
            replay
                .reconcile
                .current_objects
                .insert(container_id.clone(), false);
            replay
                .reconcile
                .stopped_objects
                .insert(container_id.clone());
        }
        ProxyJournalFact::DeleteObjectIntent { object_id } => {
            validate_identifier(object_id)?;
            if !replay.reconcile.inventory_seen
                || replay.unresolved_intent.is_some()
                || !replay.reconcile.current_objects.contains_key(object_id)
                || replay.reconcile.current_objects.get(object_id) == Some(&true)
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.unresolved_intent = Some(ProxyMutationIntent::DeleteObject);
            replay.reconcile.pending_object_id = Some(object_id.clone());
        }
        ProxyJournalFact::DeletedObject { object_id } => {
            validate_identifier(object_id)?;
            if replay.unresolved_intent != Some(ProxyMutationIntent::DeleteObject)
                || replay.reconcile.pending_object_id.as_deref() != Some(object_id)
                || replay.reconcile.current_objects.remove(object_id).is_none()
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.reconcile.deleted_objects.insert(object_id.clone());
            replay.unresolved_intent = None;
            replay.reconcile.pending_object_id = None;
        }
        ProxyJournalFact::ReconcileVerifiedEmpty => {
            if replay.unresolved_intent.is_some()
                || !replay.reconcile.current_objects.is_empty()
                || !replay.reconcile.inventory_seen
            {
                return Err(ProxyJournalError::IllegalTransition);
            }
            replay.reconcile.verified_empty = true;
        }
    }

    Ok(())
}

fn apply_poisoned(
    replay: &mut ProxyJournalReplay,
    observed_phase: RecordedLifecyclePhase,
    observed_container_id: Option<&str>,
) -> Result<(), ProxyJournalError> {
    let durable_phase = RecordedLifecyclePhase::try_from(replay.phase)?;
    if observed_phase == durable_phase {
        if observed_container_id != replay.known_container_id.as_deref() {
            return Err(ProxyJournalError::ContainerIdMismatch);
        }
        return Ok(());
    }

    let preserve_trigger = |replay: &mut ProxyJournalReplay, intent| {
        if replay.reconcile.trigger_intent.is_none() {
            replay.reconcile.trigger_intent = Some(intent);
        }
    };

    match (durable_phase, observed_phase) {
        (RecordedLifecyclePhase::AwaitCreate, RecordedLifecyclePhase::Creating) => {
            if observed_container_id.is_some() {
                return Err(ProxyJournalError::ContainerIdMismatch);
            }
            preserve_trigger(replay, ProxyMutationIntent::Create);
            replay.unresolved_intent = Some(ProxyMutationIntent::Create);
            replay.phase = LifecyclePhase::Creating;
        }
        (RecordedLifecyclePhase::Creating, RecordedLifecyclePhase::Created) => {
            let container_id = observed_container_id.ok_or(ProxyJournalError::InvalidIdentifier)?;
            validate_identifier(container_id)?;
            if replay.known_container_id.is_some() {
                return Err(ProxyJournalError::ContainerIdMismatch);
            }
            preserve_trigger(replay, ProxyMutationIntent::Create);
            replay.known_container_id = Some(container_id.to_owned());
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::Created;
        }
        (RecordedLifecyclePhase::Created, RecordedLifecyclePhase::Starting) => {
            require_container(replay, observed_container_id.unwrap_or_default())?;
            preserve_trigger(replay, ProxyMutationIntent::Start);
            replay.unresolved_intent = Some(ProxyMutationIntent::Start);
            replay.phase = LifecyclePhase::Starting;
        }
        (RecordedLifecyclePhase::Starting, RecordedLifecyclePhase::Started) => {
            require_container(replay, observed_container_id.unwrap_or_default())?;
            preserve_trigger(replay, ProxyMutationIntent::Start);
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::Started;
        }
        (
            RecordedLifecyclePhase::Created | RecordedLifecyclePhase::Started,
            RecordedLifecyclePhase::Deleting,
        ) => {
            require_container(replay, observed_container_id.unwrap_or_default())?;
            preserve_trigger(replay, ProxyMutationIntent::Delete);
            replay.delete_return_phase = Some(replay.phase);
            replay.unresolved_intent = Some(ProxyMutationIntent::Delete);
            replay.phase = LifecyclePhase::Deleting;
        }
        (RecordedLifecyclePhase::Deleting, RecordedLifecyclePhase::Removed) => {
            require_container(replay, observed_container_id.unwrap_or_default())?;
            preserve_trigger(replay, ProxyMutationIntent::Delete);
            replay.delete_return_phase = None;
            replay.unresolved_intent = None;
            replay.phase = LifecyclePhase::Removed;
        }
        _ => return Err(ProxyJournalError::IllegalTransition),
    }
    Ok(())
}

fn require_authority(
    replay: &ProxyJournalReplay,
    authority: &CanonicalCreateAuthority,
) -> Result<(), ProxyJournalError> {
    match replay.canonical_create_authority.as_ref() {
        Some(expected) if expected == authority => Ok(()),
        Some(_) => Err(ProxyJournalError::AuthorityMismatch),
        None => Err(ProxyJournalError::IllegalTransition),
    }
}

fn require_container(
    replay: &ProxyJournalReplay,
    container_id: &str,
) -> Result<(), ProxyJournalError> {
    validate_identifier(container_id)?;
    match replay.known_container_id.as_deref() {
        Some(expected) if expected == container_id => Ok(()),
        Some(_) => Err(ProxyJournalError::ContainerIdMismatch),
        None => Err(ProxyJournalError::IllegalTransition),
    }
}

fn validate_authority(authority: &CanonicalCreateAuthority) -> Result<(), ProxyJournalError> {
    if authority.fingerprint.len() != 64
        || !authority
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !canonical_create_target(&authority.target)
        || authority.body_sha256.0 == [0; 32]
    {
        return Err(ProxyJournalError::InvalidAuthority);
    }
    Ok(())
}

fn validate_event_binding(binding: CiEventBinding) -> Result<(), ProxyJournalError> {
    if binding.request_event_id_46105 == [0; 32]
        || binding.teardown_event_id_46106 == [0; 32]
        || binding.request_event_id_46105 == binding.teardown_event_id_46106
    {
        return Err(ProxyJournalError::InvalidEventBinding);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProxyJournalError> {
    if !safe_identifier(value) {
        return Err(ProxyJournalError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_reconcile_objects(objects: &[ReconcileObject]) -> Result<(), ProxyJournalError> {
    if objects.len() > MAX_RECONCILE_OBJECTS {
        return Err(ProxyJournalError::InvalidReconcileInventory);
    }
    let mut seen = BTreeSet::new();
    for object in objects {
        validate_identifier(&object.id)?;
        if !seen.insert(&object.id) {
            return Err(ProxyJournalError::DuplicateReconcileObject);
        }
    }
    Ok(())
}

fn validate_first_reconcile_inventory(
    replay: &ProxyJournalReplay,
    objects: &[ReconcileObject],
) -> Result<(), ProxyJournalError> {
    let valid = match replay.phase {
        LifecyclePhase::AwaitCreate | LifecyclePhase::Removed => objects.is_empty(),
        LifecyclePhase::Creating => match replay.known_container_id.as_deref() {
            Some(known) => {
                objects.len() <= 1 && objects.first().is_none_or(|item| item.id == known)
            }
            None => objects.len() <= 1,
        },
        LifecyclePhase::Created
        | LifecyclePhase::Starting
        | LifecyclePhase::Started
        | LifecyclePhase::Deleting => replay.known_container_id.as_deref().is_some_and(|known| {
            objects.len() <= 1 && objects.first().is_none_or(|item| item.id == known)
        }),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ProxyJournalError::InvalidReconcileInventory)
    }
}

fn safe_lease_id(value: &str) -> bool {
    safe_identifier(value) && value != "." && value != ".."
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_create_target(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_TARGET_BYTES
        || value
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || byte > 0x7e || matches!(byte, b'"' | b'\\'))
        || value.contains('#')
    {
        return false;
    }
    value.starts_with('/') && !value.starts_with("//")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn binding() -> CiEventBinding {
        CiEventBinding {
            request_event_id_46105: [1; 32],
            teardown_event_id_46106: [2; 32],
        }
    }

    fn capability_digest() -> Digest32 {
        Digest32([3; 32])
    }

    fn authority(seed: u8) -> CanonicalCreateAuthority {
        CanonicalCreateAuthority {
            fingerprint: format!("{seed:02x}{:0>62}", ""),
            target: "/containers/create?name=buzz-ci-test".to_owned(),
            body_sha256: Digest32([seed; 32]),
        }
    }

    fn object(id: &str, running: bool) -> ReconcileObject {
        ReconcileObject {
            id: id.to_owned(),
            running,
        }
    }

    fn journal() -> ProxyJournal {
        ProxyJournal::new("lease-01".to_owned(), binding(), capability_digest())
            .expect("valid journal")
    }

    fn append(journal: &mut ProxyJournal, fact: ProxyJournalFact) {
        let timestamp = journal.entries.len() as u64 + 1;
        journal.append(timestamp, fact).expect("valid fact");
    }

    fn create_started(journal: &mut ProxyJournal) {
        let authority = authority(1);
        append(journal, ProxyJournalFact::create_intent(authority.clone()));
        append(
            journal,
            ProxyJournalFact::created(authority, "container-1".to_owned()),
        );
        append(
            journal,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(journal, ProxyJournalFact::started("container-1".to_owned()));
    }

    fn remove_container(journal: &mut ProxyJournal) {
        append(
            journal,
            ProxyJournalFact::delete_intent("container-1".to_owned()),
        );
        append(journal, ProxyJournalFact::removed("container-1".to_owned()));
    }

    #[test]
    fn full_lifecycle_replays_to_reconcile_empty() {
        let mut journal = journal();
        let create_authority = authority(1);
        append(
            &mut journal,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut journal,
            ProxyJournalFact::created(create_authority, "container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::started("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::exec_create_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::exec_created("container-1".to_owned(), "exec-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
        );
        append(
            &mut journal,
            ProxyJournalFact::stop_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::stopped("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::deleted_object("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(Vec::new()),
        );
        append(&mut journal, ProxyJournalFact::reconcile_verified_empty());

        let replay = journal.replay().expect("happy lifecycle");
        assert_eq!(replay.phase, LifecyclePhase::Removed);
        assert_eq!(replay.known_container_id.as_deref(), Some("container-1"));
        assert_eq!(
            replay.known_exec_ids.iter().cloned().collect::<Vec<_>>(),
            ["exec-1"]
        );
        assert!(replay.reconcile.verified_empty);
        assert!(replay.is_clean_terminal());
    }

    #[test]
    fn max_admitted_lifecycle_leaves_reconcile_capacity() {
        let mut journal = journal();
        let create_authority = authority(1);
        for _ in 0..((MAX_LIFECYCLE_ENTRIES - 6) / 2) {
            append(
                &mut journal,
                ProxyJournalFact::create_intent(create_authority.clone()),
            );
            append(
                &mut journal,
                ProxyJournalFact::create_rejected(create_authority.clone()),
            );
        }
        append(
            &mut journal,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut journal,
            ProxyJournalFact::created(create_authority.clone(), "container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::started("container-1".to_owned()),
        );
        assert_eq!(journal.lifecycle_entry_count(), MAX_LIFECYCLE_ENTRIES - 2);

        let mut capped = journal.clone();
        assert_eq!(
            capped.append(
                capped.entries.len() as u64 + 1,
                ProxyJournalFact::exec_create_intent("container-1".to_owned()),
            ),
            Err(ProxyJournalError::TooManyEntries)
        );

        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
        );
        append(
            &mut journal,
            ProxyJournalFact::stop_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
        );
        append(
            &mut journal,
            ProxyJournalFact::stopped("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
        );
        append(
            &mut journal,
            ProxyJournalFact::deleted_object("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(Vec::new()),
        );
        append(&mut journal, ProxyJournalFact::reconcile_verified_empty());

        assert_eq!(journal.entries.len(), MAX_LIFECYCLE_ENTRIES - 2 + 9);
        let replay = journal.replay().expect("full cleanup fits");
        assert!(replay.is_clean_terminal());
        assert!(replay.stopped);
    }

    #[test]
    fn duplicate_restart_inventory_does_not_consume_terminal_recovery_capacity() {
        let mut journal = journal();
        let create_authority = authority(1);
        for _ in 0..((MAX_LIFECYCLE_ENTRIES - 6) / 2) {
            append(
                &mut journal,
                ProxyJournalFact::create_intent(create_authority.clone()),
            );
            append(
                &mut journal,
                ProxyJournalFact::create_rejected(create_authority.clone()),
            );
        }
        for fact in [
            ProxyJournalFact::create_intent(create_authority.clone()),
            ProxyJournalFact::created(create_authority, "container-1".to_owned()),
            ProxyJournalFact::start_intent("container-1".to_owned()),
            ProxyJournalFact::started("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
            ProxyJournalFact::stop_intent("container-1".to_owned()),
        ] {
            append(&mut journal, fact);
        }
        while journal.entries.len() < MAX_ENTRIES - 7 {
            let sequence = journal.entries.len() as u64 + 1;
            journal.entries.push(
                ProxyJournalEntry::new(
                    sequence,
                    sequence,
                    ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
                )
                .unwrap(),
            );
        }
        journal.replay().unwrap();
        let boundary = journal.entries.len();
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
        );
        assert_eq!(journal.entries.len(), boundary);

        for fact in [
            ProxyJournalFact::stopped("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
            ProxyJournalFact::deleted_object("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(Vec::new()),
            ProxyJournalFact::reconcile_verified_empty(),
        ] {
            append(&mut journal, fact);
        }
        assert_eq!(journal.entries.len(), MAX_ENTRIES);
        assert!(journal.replay().unwrap().is_clean_terminal());
    }

    #[test]
    fn rejected_mutations_clear_their_intents() {
        let create_authority = authority(1);
        let mut create = journal();
        append(
            &mut create,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut create,
            ProxyJournalFact::create_rejected(create_authority.clone()),
        );
        assert_eq!(create.replay().unwrap().phase, LifecyclePhase::AwaitCreate);

        let mut start = journal();
        append(
            &mut start,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut start,
            ProxyJournalFact::created(create_authority.clone(), "container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::start_rejected("container-1".to_owned()),
        );
        assert_eq!(start.replay().unwrap().phase, LifecyclePhase::Created);

        append(
            &mut start,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::started("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::exec_create_intent("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::exec_create_rejected("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::delete_intent("container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::delete_rejected("container-1".to_owned()),
        );
        let replay = start.replay().unwrap();
        assert_eq!(replay.phase, LifecyclePhase::Started);
        assert!(replay.unresolved_intent.is_none());
    }

    #[test]
    fn an_observed_empty_inventory_can_close_reconciliation() {
        let mut journal = journal();
        create_started(&mut journal);
        remove_container(&mut journal);
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(Vec::new()),
        );
        append(&mut journal, ProxyJournalFact::reconcile_verified_empty());
        let replay = journal.replay().unwrap();
        assert!(replay.reconcile.inventory_seen);
        assert!(replay.is_clean_terminal());
    }

    #[test]
    fn unresolved_mutation_prefixes_are_recovery_authority() {
        let authority = authority(1);
        let prefixes = [
            (
                ProxyMutationIntent::Create,
                vec![ProxyJournalFact::create_intent(authority.clone())],
            ),
            (
                ProxyMutationIntent::Start,
                vec![
                    ProxyJournalFact::create_intent(authority.clone()),
                    ProxyJournalFact::created(authority.clone(), "container-1".to_owned()),
                    ProxyJournalFact::start_intent("container-1".to_owned()),
                ],
            ),
            (
                ProxyMutationIntent::ExecCreate,
                vec![
                    ProxyJournalFact::create_intent(authority.clone()),
                    ProxyJournalFact::created(authority.clone(), "container-1".to_owned()),
                    ProxyJournalFact::start_intent("container-1".to_owned()),
                    ProxyJournalFact::started("container-1".to_owned()),
                    ProxyJournalFact::exec_create_intent("container-1".to_owned()),
                ],
            ),
            (
                ProxyMutationIntent::Delete,
                vec![
                    ProxyJournalFact::create_intent(authority.clone()),
                    ProxyJournalFact::created(authority.clone(), "container-1".to_owned()),
                    ProxyJournalFact::start_intent("container-1".to_owned()),
                    ProxyJournalFact::started("container-1".to_owned()),
                    ProxyJournalFact::delete_intent("container-1".to_owned()),
                ],
            ),
        ];
        for (expected, facts) in prefixes {
            let mut journal = journal();
            for fact in facts {
                append(&mut journal, fact);
            }
            let replay = journal.replay().expect("unresolved prefix");
            assert_eq!(replay.unresolved_intent, Some(expected));
            assert!(!replay.poisoned);
        }

        let mut reconcile = journal();
        create_started(&mut reconcile);
        append(
            &mut reconcile,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
        );
        append(
            &mut reconcile,
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
        );
        let replay = reconcile.replay().expect("delete-object prefix");
        assert_eq!(
            replay.unresolved_intent,
            Some(ProxyMutationIntent::DeleteObject)
        );

        let mut stop = journal();
        create_started(&mut stop);
        append(
            &mut stop,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
        );
        append(
            &mut stop,
            ProxyJournalFact::stop_intent("container-1".to_owned()),
        );
        assert_eq!(
            stop.replay().expect("stop prefix").unresolved_intent,
            Some(ProxyMutationIntent::Stop)
        );
    }

    #[test]
    fn skipped_terminal_persistence_prefixes_replay_conservatively() {
        let authority = authority(1);

        let mut create = journal();
        append(
            &mut create,
            ProxyJournalFact::create_intent(authority.clone()),
        );
        let replay = create.replay().expect("create intent prefix");
        assert_eq!(replay.phase, LifecyclePhase::Creating);

        let mut start = journal();
        append(
            &mut start,
            ProxyJournalFact::create_intent(authority.clone()),
        );
        append(
            &mut start,
            ProxyJournalFact::created(authority, "container-1".to_owned()),
        );
        append(
            &mut start,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        let replay = start.replay().expect("start intent prefix");
        assert_eq!(replay.phase, LifecyclePhase::Starting);

        let mut remove = journal();
        create_started(&mut remove);
        append(
            &mut remove,
            ProxyJournalFact::delete_intent("container-1".to_owned()),
        );
        let replay = remove.replay().expect("delete intent prefix");
        assert_eq!(replay.phase, LifecyclePhase::Deleting);
    }

    #[test]
    fn poisoned_overrides_even_without_a_terminal_fact() {
        let mut journal = journal();
        append(&mut journal, ProxyJournalFact::create_intent(authority(1)));
        append(
            &mut journal,
            ProxyJournalFact::poisoned(LifecyclePhase::Creating, None).unwrap(),
        );
        let replay = journal.replay().expect("poisoned prefix");
        assert!(replay.poisoned);
        assert_eq!(replay.unresolved_intent, Some(ProxyMutationIntent::Create));
        assert_eq!(replay.phase, LifecyclePhase::Creating);
        assert!(!replay.is_clean_terminal());
    }

    #[test]
    fn poisoned_and_unresolved_prefixes_can_reconcile_to_empty() {
        let cases = [
            (LifecyclePhase::Creating, None),
            (LifecyclePhase::Starting, Some("container-1".to_owned())),
        ];

        for (phase, container_id) in cases {
            let mut journal = journal();
            let create_authority = authority(1);
            append(
                &mut journal,
                ProxyJournalFact::create_intent(create_authority.clone()),
            );
            if phase == LifecyclePhase::Starting {
                append(
                    &mut journal,
                    ProxyJournalFact::created(create_authority, "container-1".to_owned()),
                );
                append(
                    &mut journal,
                    ProxyJournalFact::start_intent("container-1".to_owned()),
                );
            }
            append(
                &mut journal,
                ProxyJournalFact::poisoned(phase, container_id).unwrap(),
            );
            append(
                &mut journal,
                ProxyJournalFact::reconcile_inventory(Vec::new()),
            );
            append(&mut journal, ProxyJournalFact::reconcile_verified_empty());

            let replay = journal.replay().expect("reconciled unsafe prefix");
            assert!(replay.poisoned);
            assert!(replay.reconcile.trigger_intent.is_some());
            assert!(replay.is_clean_terminal());
        }
    }

    #[test]
    fn poison_accepts_only_exact_adjacent_policy_progress() {
        let mut missing_create_intent = journal();
        append(
            &mut missing_create_intent,
            ProxyJournalFact::poisoned(LifecyclePhase::Creating, None).unwrap(),
        );
        let replay = missing_create_intent.replay().unwrap();
        assert_eq!(replay.phase, LifecyclePhase::Creating);
        assert_eq!(
            replay.reconcile.trigger_intent,
            Some(ProxyMutationIntent::Create)
        );

        let create_authority = authority(1);
        let mut missing_created = journal();
        append(
            &mut missing_created,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut missing_created,
            ProxyJournalFact::poisoned(LifecyclePhase::Created, Some("container-1".to_owned()))
                .unwrap(),
        );
        let replay = missing_created.replay().unwrap();
        assert_eq!(replay.phase, LifecyclePhase::Created);
        assert_eq!(replay.known_container_id.as_deref(), Some("container-1"));
        assert_eq!(
            replay.reconcile.trigger_intent,
            Some(ProxyMutationIntent::Create)
        );

        let mut missing_started = journal();
        append(
            &mut missing_started,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut missing_started,
            ProxyJournalFact::created(create_authority, "container-1".to_owned()),
        );
        append(
            &mut missing_started,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        append(
            &mut missing_started,
            ProxyJournalFact::poisoned(LifecyclePhase::Started, Some("container-1".to_owned()))
                .unwrap(),
        );
        assert_eq!(
            missing_started.replay().unwrap().reconcile.trigger_intent,
            Some(ProxyMutationIntent::Start)
        );

        let mut wrong_id = missing_started.clone();
        wrong_id.entries.pop();
        assert!(wrong_id
            .append(
                wrong_id.entries.len() as u64 + 1,
                ProxyJournalFact::poisoned(
                    LifecyclePhase::Started,
                    Some("container-short".to_owned()),
                )
                .unwrap(),
            )
            .is_err());
    }

    #[test]
    fn fresh_inventory_resolves_an_already_absent_delete() {
        let mut journal = journal();
        create_started(&mut journal);
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
        );
        append(
            &mut journal,
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
        );
        append(
            &mut journal,
            ProxyJournalFact::reconcile_inventory(Vec::new()),
        );
        append(&mut journal, ProxyJournalFact::reconcile_verified_empty());

        let replay = journal.replay().expect("delete readback after restart");
        assert!(replay.reconcile.deleted_objects.contains("container-1"));
        assert!(replay.is_clean_terminal());
    }

    #[test]
    fn fresh_inventory_resolves_a_crashed_stop_by_live_state() {
        for replacement in [Vec::new(), vec![object("container-1", false)]] {
            let mut journal = journal();
            create_started(&mut journal);
            append(
                &mut journal,
                ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
            );
            append(
                &mut journal,
                ProxyJournalFact::stop_intent("container-1".to_owned()),
            );
            append(
                &mut journal,
                ProxyJournalFact::reconcile_inventory(replacement),
            );
            let replay = journal.replay().expect("fresh stop readback");
            assert!(replay.unresolved_intent.is_none());
            assert!(replay.reconcile.pending_object_id.is_none());
            assert!(replay.stopped);
        }
    }

    #[test]
    fn later_inventory_rejects_unexplained_identity_or_state_drift() {
        let mut base = journal();
        create_started(&mut base);
        append(
            &mut base,
            ProxyJournalFact::reconcile_inventory(vec![object("container-1", false)]),
        );

        let mut added = base.clone();
        assert!(matches!(
            added.append(
                added.entries.len() as u64 + 1,
                ProxyJournalFact::reconcile_inventory(vec![
                    object("container-1", false),
                    object("container-2", false),
                ]),
            ),
            Err(ProxyJournalError::ReconcileInventoryDrift)
        ));

        let mut restarted = base.clone();
        assert!(matches!(
            restarted.append(
                restarted.entries.len() as u64 + 1,
                ProxyJournalFact::reconcile_inventory(vec![object("container-1", true)]),
            ),
            Err(ProxyJournalError::ReconcileInventoryDrift)
        ));

        let mut disappeared = base;
        assert!(matches!(
            disappeared.append(
                disappeared.entries.len() as u64 + 1,
                ProxyJournalFact::reconcile_inventory(Vec::new()),
            ),
            Err(ProxyJournalError::ReconcileInventoryDrift)
        ));
    }

    #[test]
    fn first_inventory_is_bound_to_the_pre_recovery_lifecycle() {
        fn inventory_result(
            mut journal: ProxyJournal,
            objects: Vec<ReconcileObject>,
        ) -> Result<ProxyJournalReplay, ProxyJournalError> {
            journal.append(
                journal.entries.len() as u64 + 1,
                ProxyJournalFact::reconcile_inventory(objects),
            )?;
            journal.replay()
        }

        assert!(inventory_result(journal(), Vec::new()).is_ok());
        assert_eq!(
            inventory_result(journal(), vec![object("unexpected", false)]),
            Err(ProxyJournalError::InvalidReconcileInventory)
        );

        let mut creating = journal();
        append(&mut creating, ProxyJournalFact::create_intent(authority(1)));
        assert!(inventory_result(creating.clone(), Vec::new()).is_ok());
        assert!(inventory_result(
            creating.clone(),
            vec![object("one-exact-label-match", true)]
        )
        .is_ok());
        assert_eq!(
            inventory_result(
                creating,
                vec![object("first", false), object("second", false)]
            ),
            Err(ProxyJournalError::InvalidReconcileInventory)
        );

        let mut created = journal();
        let create_authority = authority(1);
        append(
            &mut created,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut created,
            ProxyJournalFact::created(create_authority, "container-1".to_owned()),
        );
        let mut starting = created.clone();
        append(
            &mut starting,
            ProxyJournalFact::start_intent("container-1".to_owned()),
        );
        let mut started = journal();
        create_started(&mut started);
        let mut deleting = started.clone();
        append(
            &mut deleting,
            ProxyJournalFact::delete_intent("container-1".to_owned()),
        );

        for state in [created, starting, started, deleting] {
            assert!(inventory_result(state.clone(), Vec::new()).is_ok());
            assert!(inventory_result(state.clone(), vec![object("container-1", true)]).is_ok());
            assert_eq!(
                inventory_result(state.clone(), vec![object("different", false)]),
                Err(ProxyJournalError::InvalidReconcileInventory)
            );
            assert_eq!(
                inventory_result(
                    state,
                    vec![object("container-1", false), object("extra", false)]
                ),
                Err(ProxyJournalError::InvalidReconcileInventory)
            );
        }

        let mut removed = journal();
        create_started(&mut removed);
        remove_container(&mut removed);
        assert!(inventory_result(removed.clone(), Vec::new()).is_ok());
        assert_eq!(
            inventory_result(removed, vec![object("container-1", false)]),
            Err(ProxyJournalError::InvalidReconcileInventory)
        );
    }

    #[test]
    fn delete_rejection_restores_created_or_started_phase() {
        for started in [false, true] {
            let mut journal = journal();
            let create_authority = authority(1);
            append(
                &mut journal,
                ProxyJournalFact::create_intent(create_authority.clone()),
            );
            append(
                &mut journal,
                ProxyJournalFact::created(create_authority, "container-1".to_owned()),
            );
            if started {
                append(
                    &mut journal,
                    ProxyJournalFact::start_intent("container-1".to_owned()),
                );
                append(
                    &mut journal,
                    ProxyJournalFact::started("container-1".to_owned()),
                );
            }
            append(
                &mut journal,
                ProxyJournalFact::delete_intent("container-1".to_owned()),
            );
            append(
                &mut journal,
                ProxyJournalFact::delete_rejected("container-1".to_owned()),
            );
            assert_eq!(
                journal.replay().unwrap().phase,
                if started {
                    LifecyclePhase::Started
                } else {
                    LifecyclePhase::Created
                }
            );
        }
    }

    #[test]
    fn rejects_header_sequence_and_transition_errors() {
        let mut wrong_version = journal();
        wrong_version.schema_version = 2;
        assert_eq!(
            wrong_version.replay().unwrap_err(),
            ProxyJournalError::WrongSchemaVersion
        );

        let mut wrong_binding = journal();
        wrong_binding.event_binding.request_event_id_46105 = [0; 32];
        assert_eq!(
            wrong_binding.replay().unwrap_err(),
            ProxyJournalError::InvalidEventBinding
        );

        let authority = authority(1);
        let entries = vec![
            ProxyJournalEntry::new(1, 1, ProxyJournalFact::create_intent(authority.clone()))
                .unwrap(),
            ProxyJournalEntry::new(
                3,
                2,
                ProxyJournalFact::created(authority, "container-1".to_owned()),
            )
            .unwrap(),
        ];
        assert_eq!(
            ProxyJournal::from_entries(
                "lease-01".to_owned(),
                binding(),
                capability_digest(),
                entries,
            )
            .replay()
            .unwrap_err(),
            ProxyJournalError::InvalidSequence
        );

        let mut illegal = journal();
        assert!(illegal
            .append(1, ProxyJournalFact::started("container-1".to_owned()))
            .is_err());
    }

    #[test]
    fn rejects_changed_authority_and_ids() {
        let mut changed_authority = journal();
        append(
            &mut changed_authority,
            ProxyJournalFact::create_intent(authority(1)),
        );
        assert!(changed_authority
            .append(
                2,
                ProxyJournalFact::created(authority(2), "container-1".to_owned()),
            )
            .is_err());

        let mut changed_container = journal();
        let create_authority = authority(1);
        append(
            &mut changed_container,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        append(
            &mut changed_container,
            ProxyJournalFact::created(create_authority, "container-1".to_owned()),
        );
        assert!(changed_container
            .append(3, ProxyJournalFact::start_intent("container".to_owned()))
            .is_err());

        let mut short_id = journal();
        let create_authority = authority(1);
        append(
            &mut short_id,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        assert!(short_id
            .append(
                2,
                ProxyJournalFact::created(create_authority, String::new()),
            )
            .is_err());
    }

    #[test]
    fn serde_rejects_unknown_fields_and_round_trips() {
        let mut journal = journal();
        append(&mut journal, ProxyJournalFact::create_intent(authority(1)));
        let value = serde_json::to_value(&journal).expect("serialize journal");
        let decoded: ProxyJournal = serde_json::from_value(value.clone()).expect("round trip");
        assert_eq!(decoded, journal);

        let mut unknown = value;
        unknown["extra"] = json!(true);
        assert!(serde_json::from_value::<ProxyJournal>(unknown).is_err());

        let mut nested = serde_json::to_value(&journal).expect("serialize journal");
        nested["event_binding"]["extra"] = json!(true);
        assert!(serde_json::from_value::<ProxyJournal>(nested).is_err());

        let mut fact = serde_json::to_value(ProxyJournalFact::create_intent(authority(1)))
            .expect("serialize fact");
        fact["payload"]["extra"] = json!(true);
        assert!(serde_json::from_value::<ProxyJournalFact>(fact).is_err());

        let mut entry = serde_json::to_value(
            ProxyJournalEntry::new(
                1,
                1,
                ProxyJournalFact::poisoned(LifecyclePhase::AwaitCreate, None).unwrap(),
            )
            .unwrap(),
        )
        .expect("serialize entry");
        entry["extra"] = json!(true);
        assert!(serde_json::from_value::<ProxyJournalEntry>(entry).is_err());

        let _: Value = serde_json::to_value(ProxyMutationIntent::Create).unwrap();
    }

    #[test]
    fn enforces_all_count_and_string_bounds() {
        let mut too_many = journal();
        for _ in 0..=MAX_ENTRIES {
            too_many.entries.push(ProxyJournalEntry {
                sequence: too_many.entries.len() as u64 + 1,
                timestamp_unix_ns: 1,
                fact: ProxyJournalFact::poisoned(LifecyclePhase::AwaitCreate, None).unwrap(),
            });
        }
        assert_eq!(
            too_many.replay().unwrap_err(),
            ProxyJournalError::TooManyEntries
        );

        assert!(CanonicalCreateAuthority::new(
            "a".repeat(63),
            "/containers/create".to_owned(),
            Digest32([1; 32]),
        )
        .is_err());
        assert!(CanonicalCreateAuthority::new(
            "g".repeat(64),
            "/containers/create".to_owned(),
            Digest32([1; 32]),
        )
        .is_err());
        assert!(CanonicalCreateAuthority::new(
            "a".repeat(64),
            "relative".to_owned(),
            Digest32([1; 32]),
        )
        .is_err());
        for target in [
            "/containers/create?name=\"quoted\"",
            "/containers/create?name=back\\slash",
        ] {
            assert!(CanonicalCreateAuthority::new(
                "a".repeat(64),
                target.to_owned(),
                Digest32([1; 32]),
            )
            .is_err());
        }
        assert!(CanonicalCreateAuthority::new(
            "a".repeat(64),
            format!("/{}", "x".repeat(MAX_TARGET_BYTES)),
            Digest32([1; 32]),
        )
        .is_err());

        let mut inventory = journal();
        create_started(&mut inventory);
        remove_container(&mut inventory);
        assert!(inventory
            .append(
                9,
                ProxyJournalFact::reconcile_inventory(
                    (0..=MAX_RECONCILE_OBJECTS)
                        .map(|index| object(&format!("object-{index}"), false))
                        .collect(),
                ),
            )
            .is_err());
        assert!(inventory
            .append(
                9,
                ProxyJournalFact::reconcile_inventory(vec![
                    object("same", false),
                    object("same", true),
                ]),
            )
            .is_err());

        let mut long_id = journal();
        let create_authority = authority(1);
        append(
            &mut long_id,
            ProxyJournalFact::create_intent(create_authority.clone()),
        );
        assert!(long_id
            .append(
                2,
                ProxyJournalFact::created(create_authority, "x".repeat(MAX_IDENTIFIER_BYTES + 1)),
            )
            .is_err());
    }

    #[test]
    fn replay_for_rejects_wrong_binding() {
        let journal = journal();
        assert_eq!(
            journal
                .replay_for("other", binding(), capability_digest())
                .unwrap_err(),
            ProxyJournalError::BindingMismatch
        );
        assert_eq!(
            journal
                .replay_for(
                    "lease-01",
                    CiEventBinding {
                        request_event_id_46105: [3; 32],
                        teardown_event_id_46106: [2; 32],
                    },
                    capability_digest(),
                )
                .unwrap_err(),
            ProxyJournalError::BindingMismatch
        );
        assert_eq!(
            journal
                .replay_for("lease-01", binding(), Digest32([4; 32]))
                .unwrap_err(),
            ProxyJournalError::BindingMismatch
        );
    }
}
