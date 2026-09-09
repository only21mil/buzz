use super::*;

/// Kill stale agent processes from a previous session whose PID is still alive
/// but not tracked in the current `runtimes` map. Updates the record fields and
/// returns `true` if any records were modified.
pub fn kill_stale_tracked_processes(
    records: &mut [ManagedAgentRecord],
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    instance_id: &str,
) -> bool {
    kill_stale_tracked_processes_with(
        records,
        runtimes,
        |pid| process_has_buzz_marker(pid, instance_id),
        terminate_process,
    )
}

/// Injectable version of `kill_stale_tracked_processes` for testing.
/// `has_marker(pid)` returns true when the process carries this instance's
/// `BUZZ_MANAGED_AGENT` marker; `kill(pid)` performs the termination.
pub(crate) fn kill_stale_tracked_processes_with(
    records: &mut [ManagedAgentRecord],
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    has_marker: impl Fn(u32) -> bool,
    mut kill: impl FnMut(u32) -> Result<(), String>,
) -> bool {
    use crate::managed_agents::BackendKind;

    let mut changed = false;
    for record in records.iter_mut() {
        if record.backend != BackendKind::Local {
            continue;
        }
        let Some(pid) = record.runtime_pid else {
            continue;
        };
        if !runtimes.keys().any(|key| key.pubkey == record.pubkey) {
            // Name-gate is omitted intentionally: custom harnesses use arbitrary
            // binary names not in KNOWN_AGENT_BINARIES. BUZZ_MANAGED_AGENT is the
            // authoritative ownership proof; terminate only if it matches.
            if has_marker(pid) {
                let _ = kill(pid);
            }
            record.runtime_pid = None;
            record.last_stopped_at = Some(crate::util::now_iso());
            record.updated_at = crate::util::now_iso();
            changed = true;
        }
    }
    changed
}

/// PIDs of every tracked pair child for `pubkey`, ordered by relay URL so
/// repeated calls over the same map pick the same representative.
pub(crate) fn tracked_runtime_pids(
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    pubkey: &str,
) -> Vec<u32> {
    let mut pairs: Vec<(&str, u32)> = runtimes
        .iter()
        .filter(|(key, _)| key.pubkey.eq_ignore_ascii_case(pubkey))
        .map(|(key, runtime)| (key.relay_url.as_str(), runtime.child.id()))
        .collect();
    pairs.sort_unstable();
    pairs.into_iter().map(|(_, pid)| pid).collect()
}

/// The `runtime_pid` a record should carry given the tracked pairs: the
/// current value while it still names a live pair child, else the first
/// tracked pair, else `None`. Callers that stop pairs use this so the record
/// keeps naming a supervised harness when another pair remains.
pub(crate) fn tracked_runtime_pid(
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    record: &ManagedAgentRecord,
) -> Option<u32> {
    let pids = tracked_runtime_pids(runtimes, &record.pubkey);
    record
        .runtime_pid
        .filter(|pid| pids.contains(pid))
        .or_else(|| pids.first().copied())
}

pub fn sync_managed_agent_processes(
    records: &mut [ManagedAgentRecord],
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    _instance_id: &str,
) -> (bool, Vec<String>) {
    sync_managed_agent_processes_with(records, runtimes, process_is_running)
}

/// Injectable version of `sync_managed_agent_processes`. `is_running(pid)`
/// decides whether an untracked `runtime_pid` still names a live process.
pub(crate) fn sync_managed_agent_processes_with(
    records: &mut [ManagedAgentRecord],
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    is_running: impl Fn(u32) -> bool,
) -> (bool, Vec<String>) {
    let mut changed = false;
    let mut exited = Vec::new();

    for (key, runtime) in runtimes.iter_mut() {
        let status = match runtime.child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                if let Some(record) = records
                    .iter_mut()
                    .find(|record| record.pubkey == key.pubkey)
                {
                    record.updated_at = now_iso();
                    record.last_error = Some(format!("failed to inspect process state: {error}"));
                    record.last_error_code = None;
                }
                changed = true;
                exited.push(key.clone());
                continue;
            }
        };

        let Some(status) = status else {
            continue;
        };

        if let Some(record) = records
            .iter_mut()
            .find(|record| record.pubkey == key.pubkey)
        {
            record.updated_at = now_iso();
            record.last_stopped_at = Some(now_iso());
            record.last_exit_code = status.code();
            let log_err = if status.success() {
                None
            } else {
                Some(
                    super::super::meaningful_agent_error_from_log(&runtime.log_path)
                        .unwrap_or_else(|| super::super::storage::AgentLogError {
                            message: format!("harness exited with status {status}"),
                            code: None,
                        }),
                )
            };
            record.last_error = log_err.as_ref().map(|e| e.message.clone());
            record.last_error_code = log_err.as_ref().and_then(|e| e.code);
        }

        changed = true;
        exited.push(key.clone());
    }

    let exited_pubkeys: Vec<String> = exited.iter().map(|key| key.pubkey.clone()).collect();
    let mut reaped_pids = Vec::new();
    for key in exited {
        if let Some(runtime) = runtimes.remove(&key) {
            reaped_pids.push(runtime.child.id());
        }
    }

    // `runtime_pid` mirrors the harness this desktop supervises, so the
    // on-disk record names a PID while a pair child runs. Pair runtimes and
    // receipts stay the authoritative lifecycle source. Clear the field only
    // on a confirmed exit: the pair reaped above, or an untracked PID that no
    // longer runs. An untracked PID that is still alive belongs to a prior
    // session; `kill_stale_tracked_processes` claims or releases it at launch.
    for record in records.iter_mut() {
        if record.backend != crate::managed_agents::BackendKind::Local {
            continue;
        }
        let next = match tracked_runtime_pid(runtimes, record) {
            Some(pid) => Some(pid),
            None => record
                .runtime_pid
                .filter(|pid| !reaped_pids.contains(pid) && is_running(*pid)),
        };
        if next != record.runtime_pid {
            record.runtime_pid = next;
            record.updated_at = now_iso();
            changed = true;
        }
    }

    (changed, exited_pubkeys)
}
