//! Provider launch bound to the captured invocation scope.
use super::*;

/// Deploy an agent to a provider backend. Resolves the binary, calls deploy via
/// spawn_blocking, and persists the result (backend_agent_id or last_error).
///
/// Idempotency: calling deploy on an already-deployed agent sends the same payload
/// again. Providers are expected to handle this as an update-in-place or no-op —
/// the protocol does not include an explicit `undeploy` operation (deferred to v2).
///
/// Returns Ok(()) on success, Err(message) on failure. Either way the record is
/// updated and saved before returning.
#[allow(clippy::too_many_arguments)]
pub(super) async fn deploy_to_provider(
    app: &AppHandle,
    state: &AppState,
    pubkey: &str,
    provider_id: &str,
    config: &serde_json::Value,
    mut agent_json: serde_json::Value,
    cached_binary_path: Option<&str>,
    start_scope: Option<&DeferredAgentStart>,
) -> Result<(), String> {
    // Resolve via discovered candidates only. Cached path must match BOTH
    // "is a discovered candidate" AND "belongs to this provider_id". A tampered
    // record cannot redirect deploys to a different provider's binary.
    let bin_path = cached_binary_path
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .map(|p| p.canonicalize().unwrap_or(p))
        .filter(|canonical| {
            discover_provider_candidates().iter().any(|(id, cp)| {
                id == provider_id && cp.canonicalize().ok().as_ref() == Some(canonical)
            })
        })
        .map_or_else(|| resolve_provider_binary(provider_id), Ok)?;

    apply_replay_floor_payload(
        &mut agent_json,
        start_scope.and_then(|scope| scope.replay_floor_unix),
    )?;
    if let Some(scope) = start_scope {
        scope.validate(state)?;
        scope.validate_payload(&agent_json)?;
    }
    let scoped_app = app.clone();
    let captured_scope = start_scope.cloned();
    let config_clone = config.clone();
    let deploy_result = tokio::task::spawn_blocking(move || {
        use tauri::Manager;
        if let Some(scope) = captured_scope {
            scope.validate(scoped_app.state::<AppState>().inner())?;
            scope.validate_payload(&agent_json)?;
        }
        provider_deploy(&bin_path, &agent_json, &config_clone)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?;

    if let Some(scope) = start_scope {
        scope.validate(state)?;
    }

    // Persist result under lock.
    let _store_guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|e| e.to_string())?;
    let mut records = load_managed_agents(app)?;
    let rec = records
        .iter_mut()
        .find(|r| r.pubkey == pubkey)
        .ok_or_else(|| format!("agent {pubkey} not found"))?;

    match deploy_result {
        Ok(backend_agent_id) => {
            rec.backend_agent_id = Some(backend_agent_id);
            rec.last_started_at = Some(now_iso());
            rec.updated_at = now_iso();
            rec.last_error = None;
        }
        Err(ref e) => {
            rec.last_error = Some(e.clone());
            rec.updated_at = now_iso();
            save_managed_agents(app, &records)?;
            return Err(e.clone());
        }
    }
    save_managed_agents(app, &records)?;
    Ok(())
}
