//! Tests enter through the same bounded gate used by macOS Tauri setup.
use super::*;
use crate::app_state::startup::resolve_identity_after_startup_probe;
#[cfg(all(target_os = "macos", feature = "system-keyring"))]
use crate::app_state::startup::KEYRING_STARTUP_TIMEOUT;
use std::sync::mpsc;
use std::time::Duration;

fn resolve_completed(store: &FakeIdentityStore, dir: &std::path::Path) -> ResolvedIdentity {
    let completed = store.probe;
    resolve_identity_after_startup_probe(move || completed, store, dir, Duration::from_secs(1))
        .unwrap()
        .expect("completed probe must enter identity resolution")
}

#[test]
fn completed_unreachable_is_not_reprobed_as_reachable_empty() {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeIdentityStore::reachable_but_empty();
    let keys = Keys::generate();
    let path = dir.path().join("identity.key");
    save_key_file(&path, &keys).unwrap();
    let before = std::fs::read(&path).unwrap();
    let resolved = resolve_identity_after_startup_probe(
        || KeyringProbe::Unreachable,
        &store,
        dir.path(),
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    assert_key_eq(&keys, &resolved.keys);
    assert_eq!(resolved.storage, IdentityStorage::LocalFile);
    assert_eq!(resolved.recovery, RecoveryState::None);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        store.slot.borrow().is_empty(),
        "a second probe would migrate the file"
    );
    assert!(!migration_marker_path(dir.path()).exists());
}

#[test]
fn timeout_and_late_approval_preserve_file_marker_and_keyring() {
    for (file, marker) in [(false, false), (false, true), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let store = FakeIdentityStore::present_with(&nsec);
        if file {
            save_key_file(&path, &keys).unwrap();
        }
        if marker {
            write_migration_marker(&migration_marker_path(dir.path())).unwrap();
        }
        let file_before = std::fs::read(&path).ok();
        let marker_before = std::fs::read(migration_marker_path(dir.path())).ok();
        let keyring_before = store.slot.borrow().clone();
        let (release, blocked) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        let result = resolve_identity_after_startup_probe(
            move || {
                blocked.recv().unwrap();
                finished.send(()).unwrap();
                KeyringProbe::Present
            },
            &store,
            dir.path(),
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(
            result.is_none(),
            "an unfinished read must not activate an identity"
        );
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(std::fs::read(&path).ok(), file_before);
        assert_eq!(
            std::fs::read(migration_marker_path(dir.path())).ok(),
            marker_before
        );
        assert_eq!(*store.slot.borrow(), keyring_before);
        assert!(store.deleted.borrow().is_empty());
    }
}

#[test]
fn disconnected_probe_cannot_create_first_launch_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeIdentityStore::reachable_but_empty();
    assert!(resolve_identity_after_startup_probe(
        || panic!("probe failed"),
        &store,
        dir.path(),
        Duration::from_secs(1),
    )
    .unwrap()
    .is_none());
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    assert!(store.slot.borrow().is_empty());
}

#[test]
fn completed_empty_probe_still_migrates_original_file() {
    let dir = tempfile::tempdir().unwrap();
    let keys = Keys::generate();
    let path = dir.path().join("identity.key");
    save_key_file(&path, &keys).unwrap();
    let store = FakeIdentityStore::reachable_but_empty();
    let resolved = resolve_completed(&store, dir.path());
    assert_key_eq(&keys, &resolved.keys);
    assert_eq!(resolved.storage, IdentityStorage::SystemKeyring);
    assert_eq!(resolved.recovery, RecoveryState::None);
    assert!(!path.exists());
    assert!(migration_marker_path(dir.path()).exists());
    assert_eq!(
        store.slot.borrow().get(IDENTITY_KEY_NAME),
        Some(&keys.secret_key().to_bech32().unwrap())
    );
}

#[cfg(all(target_os = "macos", feature = "system-keyring"))]
#[test]
fn interactive_startup_budget_is_thirty_seconds() {
    assert_eq!(KEYRING_STARTUP_TIMEOUT, Duration::from_secs(30));
}

#[test]
fn valid_keyring_is_used_and_matching_leftover_file_cleaned_up() {
    // A valid keyring entry and a leftover identity.key with the SAME pubkey
    // (stale leftover from a migration whose remove_file previously failed):
    // keyring wins, plaintext is removed without adoption.
    let keyring_keys = Keys::generate();
    let nsec = keyring_keys.secret_key().to_bech32().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    // Same key in file as keyring → stale leftover, not an import.
    save_key_file(&legacy_path, &keyring_keys).unwrap();

    let store = FakeIdentityStore::present_with(&nsec);
    let resolved = resolve_completed(&store, dir.path());

    assert_key_eq(&keyring_keys, &resolved.keys);
    assert_eq!(resolved.recovery, RecoveryState::None);
    assert!(store.deleted.borrow().is_empty());
    assert!(!legacy_path.exists());
}

#[test]
fn unreachable_post_migration_boots_keyring_locked_recovery() {
    // After a migration the file is gone and the marker exists. A later boot
    // with the keyring unreachable must NOT generate a fresh key (that would
    // silently rotate the identity), but must also allow the app to open
    // instead of hard-aborting. The result is a keyring-locked recovery boot:
    // ephemeral key held in memory only, nothing persisted anywhere.
    //
    // Fail-closed semantics are preserved: no identity is ever written to disk
    // or the keyring under the ephemeral key, so no silent rotation occurs.
    // The abort is replaced by a graceful recovery screen.
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    write_migration_marker(&migration_marker_path(dir.path())).unwrap();
    assert!(!legacy_path.exists());

    let store = FakeIdentityStore::unreachable();
    let resolved = resolve_completed(&store, dir.path());

    // KeyringLocked recovery: ephemeral key returned, nothing persisted.
    assert_eq!(resolved.recovery, RecoveryState::KeyringLocked);
    // No identity.key was written.
    assert!(!legacy_path.exists());
    // Keyring store was never called (it is unreachable).
    assert!(store.slot.borrow().is_empty());
    assert!(store.deleted.borrow().is_empty());
}

#[test]
fn unreachable_first_run_generates_to_file_when_no_marker() {
    // Genuine first-EVER launch on a machine whose keyring is down: no file,
    // no marker. There is no prior identity to protect, so generating to the
    // `0o600` file is correct — fail-closed here would block a legitimate
    // first launch.
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    assert!(!legacy_path.exists());
    assert!(!migration_marker_path(dir.path()).exists());

    let store = FakeIdentityStore::unreachable();
    let resolved = resolve_completed(&store, dir.path());

    // A fresh key was generated and persisted to the file (keyring is down).
    let from_file = load_key_file(&legacy_path).unwrap();
    assert_key_eq(&resolved.keys, &from_file);
}

#[test]
fn unreachable_with_valid_file_resolves_to_file_key() {
    // B3.a+b (inputs are indistinguishable at this level): Unreachable + valid
    // identity.key → resolves to the file's key. The keyring is never contacted
    // and the file is kept on disk (no migration when keyring is down).
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    let file_keys = Keys::generate();
    save_key_file(&legacy_path, &file_keys).unwrap();

    let store = FakeIdentityStore::unreachable();
    let resolved = resolve_completed(&store, dir.path());

    assert_key_eq(&file_keys, &resolved.keys);
    assert_eq!(resolved.recovery, RecoveryState::None);
    assert!(
        legacy_path.exists(),
        "identity.key must not be deleted when keyring is unreachable"
    );
    assert!(
        store.slot.borrow().is_empty(),
        "keyring must not be contacted when unreachable"
    );
}

#[test]
fn unreachable_valid_file_with_marker_resolves_to_file_not_locked_recovery() {
    // Unreachable + valid identity.key + marker present → resolves to the file
    // key, NOT KeyringLocked recovery. The locked-recovery branch only fires
    // when the file is ABSENT; a present file is always used as a direct
    // fallback regardless of the marker.
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    let file_keys = Keys::generate();
    save_key_file(&legacy_path, &file_keys).unwrap();
    write_migration_marker(&migration_marker_path(dir.path())).unwrap();

    let store = FakeIdentityStore::unreachable();
    let resolved = resolve_completed(&store, dir.path());

    assert_key_eq(&file_keys, &resolved.keys);
    assert_eq!(
        resolved.recovery,
        RecoveryState::None,
        "must not enter locked-recovery when a valid file is present"
    );
}

#[test]
fn unreachable_corrupt_file_generates_fresh() {
    // B3.c: Unreachable + corrupt identity.key → load_file_or_generate quarantines
    // the corrupt file, generates a fresh key, and saves it to identity.key.
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("identity.key");
    std::fs::write(&legacy_path, b"this-is-not-a-valid-nsec").unwrap();
    assert!(!migration_marker_path(dir.path()).exists());

    let store = FakeIdentityStore::unreachable();
    let resolved = resolve_completed(&store, dir.path());

    assert_eq!(resolved.recovery, RecoveryState::None);
    // A fresh key was saved to identity.key (quarantine renames the corrupt file).
    assert!(
        legacy_path.exists(),
        "fresh key must be saved to identity.key"
    );
    let from_file = load_key_file(&legacy_path).unwrap();
    assert_key_eq(&resolved.keys, &from_file);
}
