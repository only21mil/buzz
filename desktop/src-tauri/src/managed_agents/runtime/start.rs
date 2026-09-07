//! Registration of a locally started agent, using a captured deferred scope when supplied.
use super::*;

/// Start a local managed agent using the current workspace without a replay floor.
pub fn start_managed_agent_process(
    app: &AppHandle,
    record: &mut ManagedAgentRecord,
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    owner_hex: Option<&str>,
) -> Result<(), String> {
    start_managed_agent_process_scoped(app, record, runtimes, owner_hex, None)
}

pub(crate) fn start_managed_agent_process_scoped(
    app: &AppHandle,
    record: &mut ManagedAgentRecord,
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    owner_hex: Option<&str>,
    scope: Option<&super::super::deferred_start::DeferredAgentStart>,
) -> Result<(), String> {
    let relay_url = {
        use tauri::Manager;
        let state = app.state::<crate::app_state::AppState>();
        crate::relay::effective_agent_relay_url(
            &record.relay_url,
            &crate::relay::relay_ws_url_with_override(&state),
        )
    };
    let relay_url = scope
        .map(|scope| scope.relay_url.clone())
        .unwrap_or(relay_url);
    let key = ManagedAgentRuntimeKey::new(record.pubkey.clone(), &relay_url)?;
    if let Some(runtime) = runtimes.get_mut(&key) {
        if runtime
            .child
            .try_wait()
            .map_err(|error| format!("failed to inspect running process: {error}"))?
            .is_none()
        {
            return Ok(());
        }

        runtimes.remove(&key);
        super::super::remove_agent_runtime_receipt(app, &key);
    }

    // Scalar PIDs are migration-only and never establish pair liveness.
    record.runtime_pid = None;

    let mut process = spawn_agent_child_with_replay_floor(
        app,
        record,
        &key.relay_url,
        false,
        owner_hex,
        scope.and_then(|scope| scope.replay_floor_unix),
    )?;
    let now = now_iso();
    let receipt = super::super::ManagedAgentRuntimeReceipt {
        key: key.clone(),
        pid: process.child.id(),
        desktop_instance_id: current_instance_id(app),
        started_at: now.clone(),
    };
    if let Err(error) = super::super::write_agent_runtime_receipt(app, &receipt) {
        let _ = terminate_process(process.child.id());
        let _ = process.child.wait();
        return Err(error);
    }

    record.updated_at = now.clone();
    record.last_started_at = Some(now);
    record.last_stopped_at = None;
    record.last_exit_code = None;
    record.last_error = None;
    record.last_error_code = None;

    runtimes.insert(key, ManagedAgentPairRuntime::starting(process));
    Ok(())
}
