//! Crash-safe file-backed control state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::production::{ControlStore, RunFinalization, SignedCiEvent, StoredPublication};
use crate::{RunIdentity, RunRecord, StoreWrite, MAX_SAFE_INTEGER};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: u32 = 1;
const MAX_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
const LOCK_NAME: &str = ".control-store.lock";
const SNAPSHOT_NAME: &str = "control-store-v1.json";
const NEXT_NAME: &str = ".control-store-v1.json.next";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StoreError {
    #[error("control store path is invalid")]
    InvalidPath,
    #[error("control store metadata is insecure")]
    InsecureMetadata,
    #[error("control store is unavailable")]
    Unavailable,
    #[error("control store snapshot is invalid")]
    InvalidSnapshot,
    #[error("control store snapshot exceeds the byte limit")]
    Oversized,
    #[error("control store compare-and-swap conflict")]
    Conflict,
}

/// Durable JSON snapshot protected by a process-shared advisory lock.
#[derive(Clone, Debug)]
pub struct DurableControlStore {
    root: PathBuf,
    expected_owner_uid: u32,
}

impl DurableControlStore {
    pub fn open(root: impl Into<PathBuf>, expected_owner_uid: u32) -> Result<Self, StoreError> {
        let root = root.into();
        validate_absolute_path(&root)?;
        let metadata = fs::symlink_metadata(&root).map_err(|_| StoreError::Unavailable)?;
        validate_directory(&metadata, expected_owner_uid)?;
        if fs::canonicalize(&root).map_err(|_| StoreError::Unavailable)? != root {
            return Err(StoreError::InsecureMetadata);
        }
        let store = Self {
            root,
            expected_owner_uid,
        };
        store.with_locked(|snapshot| snapshot.validate())?;
        Ok(store)
    }

    fn with_locked<T>(
        &self,
        operation: impl FnOnce(&mut Snapshot) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let lock_path = self.root.join(LOCK_NAME);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .map_err(|_| StoreError::Unavailable)?;
        validate_file(
            &fs::symlink_metadata(&lock_path).map_err(|_| StoreError::Unavailable)?,
            self.expected_owner_uid,
        )?;
        let _lock =
            Flock::lock(lock_file, FlockArg::LockExclusive).map_err(|_| StoreError::Unavailable)?;
        let path = self.root.join(SNAPSHOT_NAME);
        let mut snapshot = if path.exists() {
            self.read_snapshot(&path)?
        } else {
            let snapshot = Snapshot::default();
            self.persist(&snapshot)?;
            snapshot
        };
        operation(&mut snapshot)
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut Snapshot) -> Result<(T, bool), StoreError>,
    ) -> Result<T, StoreError> {
        self.with_locked(|snapshot| {
            let (value, changed) = operation(snapshot)?;
            if changed {
                self.persist(snapshot)?;
            }
            Ok(value)
        })
    }

    fn read_snapshot(&self, path: &Path) -> Result<Snapshot, StoreError> {
        let before = fs::symlink_metadata(path).map_err(|_| StoreError::Unavailable)?;
        validate_file(&before, self.expected_owner_uid)?;
        if before.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Oversized);
        }
        if fs::canonicalize(path).map_err(|_| StoreError::Unavailable)? != path {
            return Err(StoreError::InsecureMetadata);
        }
        let file = File::open(path).map_err(|_| StoreError::Unavailable)?;
        let opened = file.metadata().map_err(|_| StoreError::Unavailable)?;
        validate_file(&opened, self.expected_owner_uid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(StoreError::InsecureMetadata);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_SNAPSHOT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Unavailable)?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Oversized);
        }
        let snapshot: Snapshot =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidSnapshot)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn persist(&self, snapshot: &Snapshot) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(snapshot).map_err(|_| StoreError::InvalidSnapshot)?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Oversized);
        }
        let next = self.root.join(NEXT_NAME);
        match fs::remove_file(&next) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Unavailable),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&next)
            .map_err(|_| StoreError::Unavailable)?;
        file.write_all(&bytes)
            .map_err(|_| StoreError::Unavailable)?;
        file.sync_all().map_err(|_| StoreError::Unavailable)?;
        drop(file);
        fs::rename(&next, self.root.join(SNAPSHOT_NAME)).map_err(|_| StoreError::Unavailable)?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Unavailable)
    }
}

impl ControlStore for DurableControlStore {
    type Error = StoreError;

    fn cursor(&self, channel_id: &str) -> Result<u64, Self::Error> {
        validate_key(channel_id)?;
        self.with_locked(|snapshot| Ok(snapshot.cursors.get(channel_id).copied().unwrap_or(0)))
    }

    fn advance_cursor(
        &mut self,
        channel_id: &str,
        expected: u64,
        next: u64,
    ) -> Result<bool, Self::Error> {
        validate_key(channel_id)?;
        if next <= expected || next > MAX_SAFE_INTEGER {
            return Err(StoreError::Conflict);
        }
        self.mutate(|snapshot| {
            let actual = snapshot.cursors.get(channel_id).copied().unwrap_or(0);
            if actual != expected {
                return Ok((false, false));
            }
            snapshot.cursors.insert(channel_id.to_owned(), next);
            Ok((true, true))
        })
    }

    fn load_run(&self, identity: &RunIdentity) -> Result<Option<(u64, RunRecord)>, Self::Error> {
        let key = identity_key(identity)?;
        self.with_locked(|snapshot| {
            Ok(snapshot
                .runs
                .get(&key)
                .map(|stored| (stored.revision, stored.record.clone())))
        })
    }

    fn compare_and_swap_run(
        &mut self,
        identity: &RunIdentity,
        expected_revision: Option<u64>,
        next: &RunRecord,
    ) -> Result<StoreWrite, Self::Error> {
        if next.identity() != identity {
            return Err(StoreError::Conflict);
        }
        let key = identity_key(identity)?;
        self.mutate(|snapshot| {
            let actual = snapshot.runs.get(&key).map(|stored| stored.revision);
            if actual != expected_revision {
                return Ok((
                    StoreWrite::Conflict {
                        actual_revision: actual,
                    },
                    false,
                ));
            }
            let revision = actual
                .unwrap_or(0)
                .checked_add(1)
                .filter(|revision| *revision <= MAX_SAFE_INTEGER)
                .ok_or(StoreError::Conflict)?;
            snapshot.runs.insert(
                key,
                StoredRun {
                    revision,
                    record: next.clone(),
                },
            );
            Ok((StoreWrite::Written { revision }, true))
        })
    }

    fn load_finalization(
        &self,
        run_id: &str,
    ) -> Result<Option<(u64, RunFinalization)>, Self::Error> {
        validate_key(run_id)?;
        self.with_locked(|snapshot| {
            Ok(snapshot
                .finalizations
                .get(run_id)
                .map(|stored| (stored.revision, stored.finalization.clone())))
        })
    }

    fn compare_and_swap_finalization(
        &mut self,
        run_id: &str,
        expected_revision: Option<u64>,
        next: &RunFinalization,
    ) -> Result<StoreWrite, Self::Error> {
        validate_key(run_id)?;
        next.validate().map_err(|_| StoreError::Conflict)?;
        self.mutate(|snapshot| {
            let actual = snapshot
                .finalizations
                .get(run_id)
                .map(|stored| stored.revision);
            if actual != expected_revision {
                return Ok((
                    StoreWrite::Conflict {
                        actual_revision: actual,
                    },
                    false,
                ));
            }
            let revision = actual
                .unwrap_or(0)
                .checked_add(1)
                .filter(|revision| *revision <= MAX_SAFE_INTEGER)
                .ok_or(StoreError::Conflict)?;
            snapshot.finalizations.insert(
                run_id.to_owned(),
                StoredFinalization {
                    revision,
                    finalization: next.clone(),
                },
            );
            Ok((StoreWrite::Written { revision }, true))
        })
    }

    fn load_publication(&self, key: &str) -> Result<Option<StoredPublication>, Self::Error> {
        validate_key(key)?;
        self.with_locked(|snapshot| Ok(snapshot.publications.get(key).cloned()))
    }

    fn record_publication_intent(
        &mut self,
        key: &str,
        event: &SignedCiEvent,
    ) -> Result<bool, Self::Error> {
        validate_key(key)?;
        self.mutate(|snapshot| match snapshot.publications.get(key) {
            None => {
                snapshot
                    .publications
                    .insert(key.to_owned(), StoredPublication::Pending(event.clone()));
                Ok((true, true))
            }
            Some(StoredPublication::Pending(stored)) if stored == event => Ok((false, false)),
            Some(StoredPublication::Accepted { signed, .. }) if signed == event => {
                Ok((false, false))
            }
            Some(_) => Err(StoreError::Conflict),
        })
    }

    fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error> {
        validate_key(key)?;
        if !is_lower_hex(event_id, 64) {
            return Err(StoreError::Conflict);
        }
        self.mutate(|snapshot| {
            let Some(publication) = snapshot.publications.get(key).cloned() else {
                return Err(StoreError::Conflict);
            };
            match publication {
                StoredPublication::Pending(signed) if signed.event_id == event_id => {
                    snapshot.publications.insert(
                        key.to_owned(),
                        StoredPublication::Accepted {
                            signed,
                            relay_event_id: event_id.to_owned(),
                        },
                    );
                    Ok(((), true))
                }
                StoredPublication::Accepted {
                    signed,
                    relay_event_id,
                } if signed.event_id == event_id && relay_event_id == event_id => Ok(((), false)),
                _ => Err(StoreError::Conflict),
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    cursors: BTreeMap<String, u64>,
    runs: BTreeMap<String, StoredRun>,
    #[serde(default)]
    finalizations: BTreeMap<String, StoredFinalization>,
    publications: BTreeMap<String, StoredPublication>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            cursors: BTreeMap::new(),
            runs: BTreeMap::new(),
            finalizations: BTreeMap::new(),
            publications: BTreeMap::new(),
        }
    }
}

impl Snapshot {
    fn validate(&self) -> Result<(), StoreError> {
        if self.schema_version != SCHEMA_VERSION
            || self
                .cursors
                .iter()
                .any(|(key, cursor)| validate_key(key).is_err() || *cursor > MAX_SAFE_INTEGER)
        {
            return Err(StoreError::InvalidSnapshot);
        }
        for (key, stored) in &self.runs {
            if stored.revision == 0
                || stored.revision > MAX_SAFE_INTEGER
                || identity_key(stored.record.identity())? != *key
            {
                return Err(StoreError::InvalidSnapshot);
            }
        }
        for (run_id, stored) in &self.finalizations {
            if stored.revision == 0
                || stored.revision > MAX_SAFE_INTEGER
                || validate_key(run_id).is_err()
                || stored.finalization.validate().is_err()
            {
                return Err(StoreError::InvalidSnapshot);
            }
        }
        for (key, publication) in &self.publications {
            if validate_key(key).is_err() {
                return Err(StoreError::InvalidSnapshot);
            }
            let (signed, relay_id) = match publication {
                StoredPublication::Pending(signed) => (signed, None),
                StoredPublication::Accepted {
                    signed,
                    relay_event_id,
                } => (signed, Some(relay_event_id)),
            };
            if !is_lower_hex(&signed.event_id, 64)
                || !(46101..=46106).contains(&signed.kind)
                || relay_id.is_some_and(|id| id != &signed.event_id)
            {
                return Err(StoreError::InvalidSnapshot);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRun {
    revision: u64,
    record: RunRecord,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFinalization {
    revision: u64,
    finalization: RunFinalization,
}

fn validate_absolute_path(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(StoreError::InvalidPath);
    }
    Ok(())
}

fn validate_directory(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), StoreError> {
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
        || metadata.uid() != expected_uid
    {
        return Err(StoreError::InsecureMetadata);
    }
    Ok(())
}

fn validate_file(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), StoreError> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != FILE_MODE
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
    {
        return Err(StoreError::InsecureMetadata);
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > 1024 || key.contains(['\0', '\r', '\n']) {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn identity_key(identity: &RunIdentity) -> Result<String, StoreError> {
    let bytes = serde_json::to_vec(identity).map_err(|_| StoreError::InvalidSnapshot)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use uuid::Uuid;

    use super::*;

    fn identity() -> RunIdentity {
        RunIdentity::new(
            "11".repeat(32),
            Uuid::parse_str("018f5f36-70ec-7a30-8000-000000000001").expect("uuid"),
            1,
            "repo:owner/project".to_owned(),
            "22".repeat(20),
            "ci".to_owned(),
        )
        .expect("identity")
    }

    fn store() -> (tempfile::TempDir, DurableControlStore) {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(directory.path()).expect("canonical root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let uid = fs::metadata(&root).expect("metadata").uid();
        let store = DurableControlStore::open(root, uid).expect("open store");
        (directory, store)
    }

    fn event(id: &str) -> SignedCiEvent {
        SignedCiEvent {
            event_id: id.repeat(64),
            kind: 46101,
            content: "{}".to_owned(),
            tags: serde_json::json!([]),
            signed_event: serde_json::json!({"id": id.repeat(64)}),
        }
    }

    fn finalization() -> RunFinalization {
        serde_json::from_value(serde_json::json!({
            "run_id": "123e4567-e89b-12d3-a456-426614174011",
            "target_repo_a": format!("30617:{}:buzz", "22".repeat(32)),
            "tip_oid": "44".repeat(20),
            "base_oid": "55".repeat(20),
            "workflow_id": "ci",
            "workflow_digest": "66".repeat(32),
            "request_event_id": "11".repeat(32),
            "attempt": 1,
            "finalized_at": 12,
            "teardown_at": 12,
            "jobs": {
                "test": {
                    "evidence": {
                        "job_id": "test",
                        "attempt": 1,
                        "log_ref": "aa".repeat(32),
                        "artifact_refs": []
                    },
                    "lease": {
                        "job_id": "test",
                        "attempt": 1,
                        "lease_id": "lease-test-1"
                    },
                    "state": "success",
                    "required": true,
                    "skip_policy": "forbid"
                }
            }
        }))
        .expect("finalization fixture")
    }

    #[test]
    fn restart_restores_cursor_run_and_publication() {
        let (directory, mut store) = store();
        let identity = identity();
        let record = RunRecord::queued(identity.clone(), 1).expect("queued");
        assert_eq!(
            store
                .compare_and_swap_run(&identity, None, &record)
                .expect("write"),
            StoreWrite::Written { revision: 1 }
        );
        assert!(store.advance_cursor("channel", 0, 7).expect("cursor"));
        assert!(store
            .record_publication_intent("run:queued", &event("a"))
            .expect("intent"));
        let finalization = finalization();
        let finalization_run_id = "123e4567-e89b-12d3-a456-426614174011";
        assert_eq!(
            store
                .compare_and_swap_finalization(finalization_run_id, None, &finalization)
                .expect("finalization"),
            StoreWrite::Written { revision: 1 }
        );
        drop(store);

        let root = fs::canonicalize(directory.path()).expect("canonical root");
        let uid = fs::metadata(&root).expect("metadata").uid();
        let reopened = DurableControlStore::open(root, uid).expect("reopen");
        assert_eq!(reopened.cursor("channel").expect("cursor"), 7);
        assert_eq!(
            reopened.load_run(&identity).expect("run"),
            Some((1, record))
        );
        assert_eq!(
            reopened
                .load_publication("run:queued")
                .expect("publication"),
            Some(StoredPublication::Pending(event("a")))
        );
        assert_eq!(
            reopened
                .load_finalization(finalization_run_id)
                .expect("finalization"),
            Some((1, finalization))
        );
    }

    #[test]
    fn compare_and_swap_and_publication_conflicts_are_deterministic() {
        let (_directory, mut store) = store();
        let identity = identity();
        let record = RunRecord::queued(identity.clone(), 1).expect("queued");
        assert_eq!(
            store
                .compare_and_swap_run(&identity, Some(1), &record)
                .expect("conflict"),
            StoreWrite::Conflict {
                actual_revision: None
            }
        );
        assert!(store
            .record_publication_intent("key", &event("a"))
            .expect("intent"));
        assert!(!store
            .record_publication_intent("key", &event("a"))
            .expect("replay"));
        assert_eq!(
            store.record_publication_intent("key", &event("b")),
            Err(StoreError::Conflict)
        );
        store
            .accept_publication("key", &"a".repeat(64))
            .expect("accept");
        store
            .accept_publication("key", &"a".repeat(64))
            .expect("idempotent accept");
        assert_eq!(
            store.accept_publication("key", &"b".repeat(64)),
            Err(StoreError::Conflict)
        );
    }
}
