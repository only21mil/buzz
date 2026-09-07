//! Resolve the persisted identity before setup starts owner-keyed work.

use super::*;
use tauri::Manager;

pub fn build_app_state() -> AppState {
    // Env var takes precedence (dev/CI). If absent, resolve_persisted_identity()
    // in setup() will replace the ephemeral placeholder with a persisted key.
    let (keys, identity_storage) = match identity_from_env() {
        Some(keys) => {
            eprintln!(
                "buzz-desktop: configured identity pubkey {}",
                keys.public_key().to_hex()
            );
            (keys, IdentityStorage::Environment)
        }
        None => (Keys::generate(), IdentityStorage::Ephemeral),
    };

    app_state_with_identity(keys, identity_storage)
}

/// Construct fixture state without consulting process-global identity settings.
#[cfg(all(test, unix, not(feature = "system-keyring")))]
pub(crate) fn build_ephemeral_test_app_state() -> AppState {
    app_state_with_identity(Keys::generate(), IdentityStorage::Ephemeral)
}

fn app_state_with_identity(keys: Keys, identity_storage: IdentityStorage) -> AppState {
    AppState {
        keys: Mutex::new(keys),
        publication_epoch: Arc::new(Mutex::new(0)),
        identity_storage: AtomicU8::new(identity_storage as u8),
        http_client: reqwest::Client::builder()
            .resolve("localhost", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .pool_idle_timeout(std::time::Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        media_fetch_client: build_media_fetch_client().expect(
            "media_fetch_client must build with redirect::Policy::none(); a \
             redirect-following fallback would forward the minted media auth \
             header across origins (redirect-hop SSRF)",
        ),
        relay_url_override: Mutex::new(None),
        managed_agent_restore_pending: AtomicBool::new(false),
        managed_agent_experiments: crate::managed_agents::ManagedAgentExperimentState::default(),
        shutdown_started: AtomicBool::new(false),
        managed_agent_runtime_transition: Mutex::new(()),
        identity_mutation: Mutex::new(()),
        managed_agents_store_lock: Mutex::new(()),
        channel_templates_store_lock: Mutex::new(()),
        managed_agent_processes: Mutex::new(HashMap::new()),
        session_config_cache: Mutex::new(HashMap::new()),
        channel_member_profile_cache: ChannelMemberProfileCache::default(),
        huddle_state: Mutex::new(HuddleState::default()),
        huddle_audio: Default::default(),
        app_handle: Mutex::new(None),
        media_proxy_port: AtomicU16::new(0),
        prevent_sleep: Arc::new(Mutex::new(
            crate::prevent_sleep::PreventSleepState::default(),
        )),
        keyring_locked: AtomicBool::new(false),
        identity_lost: AtomicBool::new(false),
        reset_failed: AtomicBool::new(false),
        #[cfg(feature = "mesh-llm")]
        mesh_llm_runtime: AsyncMutex::new(None),
        #[cfg(feature = "mesh-llm")]
        mesh_recovery: crate::mesh_llm::MeshRecoveryState::default(),
        #[cfg(feature = "mesh-llm")]
        mesh_coordinator: AsyncMutex::new(None),
        pending_owned_channels: Mutex::new(std::collections::HashSet::new()),
    }
}

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
    state.replace_publication_keys(resolved.keys, Some(resolved.storage))?;
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
