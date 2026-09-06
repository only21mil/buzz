//! Resolve the persisted identity before setup starts owner-keyed work.

use super::*;
use tauri::Manager;

impl AppState {
    /// Read recovery flags after identity resolution, preserving its Release/Acquire ordering.
    pub(crate) fn identity_recovery_flags(&self) -> (bool, bool) {
        let identity_lost = self
            .identity_lost
            .load(std::sync::atomic::Ordering::Acquire);
        let keyring_locked = self
            .keyring_locked
            .load(std::sync::atomic::Ordering::Acquire);
        (identity_lost, keyring_locked)
    }
}

/// Resolve the user's identity key from the app data directory and wire
/// the resulting [`RecoveryState`] into `AppState`.
///
/// Priority: `BUZZ_PRIVATE_KEY` env var (already handled in `build_app_state`)
/// → keyring → `{app_data_dir}/identity.key` file → generate + save.
///
/// On success, writes the resolved keys into `state.keys` (with the mutex)
/// before storing the recovery flags (Release), so any thread that reads
/// either flag as `false` with Acquire is guaranteed to see the updated keys.
///
/// Sets `state.identity_lost` on `RecoveryState::Lost` (keyring empty after
/// migration — key gone externally) and `state.keyring_locked` on
/// `RecoveryState::KeyringLocked` (keyring unreachable — key still in keyring
/// but inaccessible this boot). Both states boot with an ephemeral key; the
/// frontend shows different recovery screens for each.
pub fn resolve_persisted_identity(app: &AppHandle, state: &AppState) -> Result<(), String> {
    // Only skip file-based resolution if the env var was present AND parsed
    // successfully. A malformed env var should fall through to the persisted
    // key rather than leaving the app on an ephemeral identity.
    if identity_from_env().is_some() {
        return Ok(());
    }

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app data dir: {e}"))?;
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("create app data dir: {e}"))?;

    #[cfg(all(target_os = "macos", feature = "system-keyring"))]
    let resolved = {
        // SecKeychainFindGenericPassword may wait indefinitely for a locked
        // login session or an unanswered access prompt. Setup runs before the
        // webview can render, so bound its first read-only check. Never put
        // load_or_create_identity on this worker: a late completion could
        // otherwise migrate or create an identity after we entered recovery.
        let store = crate::secret_store::SecretStore::shared(keyring_service());
        let resolved = resolve_identity_after_startup_probe(
            || crate::secret_store::SecretStore::shared(keyring_service()).probe(IDENTITY_KEY_NAME),
            store,
            &data_dir,
            KEYRING_STARTUP_TIMEOUT,
        )?;
        let Some(resolved) = resolved else {
            // An incomplete probe is not evidence that an identity is absent.
            // A completed Unreachable probe follows the file/marker policy.
            // Keep the existing placeholder and storage untouched. Signing
            // and owner-keyed startup work stay disabled until relaunch.
            state
                .keyring_locked
                .store(true, std::sync::atomic::Ordering::Release);
            eprintln!(
                "buzz-desktop: Keychain check did not complete; finish any access prompt and relaunch"
            );
            return Ok(());
        };
        resolved
    };
    #[cfg(not(all(target_os = "macos", feature = "system-keyring")))]
    let resolved = load_or_create_identity(&data_dir)?;
    // Write keys and storage before setting the recovery flags (Release) so
    // any thread that reads a flag as false with Acquire sees consistent data.
    {
        let mut active_keys = state.keys.lock().map_err(|e| e.to_string())?;
        *active_keys = resolved.keys;
        state.set_identity_storage(resolved.storage);
    }
    state.identity_lost.store(
        resolved.recovery == RecoveryState::Lost,
        std::sync::atomic::Ordering::Release,
    );
    state.keyring_locked.store(
        resolved.recovery == RecoveryState::KeyringLocked,
        std::sync::atomic::Ordering::Release,
    );
    Ok(())
}

// Allow time for an interactive ACL prompt while keeping startup bounded.
#[cfg(all(target_os = "macos", feature = "system-keyring"))]
pub(super) const KEYRING_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The macOS startup entry gate. Only a completed read may reach persistence.
/// Pass its exact result onward so an Unreachable result cannot be mistaken for
/// a timeout or replaced by a second, potentially blocking probe.
#[cfg(any(test, all(target_os = "macos", feature = "system-keyring")))]
pub(super) fn resolve_identity_after_startup_probe(
    probe: impl FnOnce() -> crate::secret_store::KeyringProbe + Send + 'static,
    store: &impl IdentityKeyStore,
    data_dir: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<Option<ResolvedIdentity>, String> {
    crate::identity_startup::resolve_after_keyring_probe(
        probe,
        |completed| {
            resolve_identity_from_probe(store, &data_dir.join("identity.key"), data_dir, completed)
        },
        timeout,
    )
}
