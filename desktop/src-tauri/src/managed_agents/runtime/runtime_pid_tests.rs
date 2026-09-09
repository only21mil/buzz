// ── runtime_pid bookkeeping (Buzz issue 744a2320…, follow-up 3) ────────────
//
// The record's `runtime_pid` names the harness this desktop supervises while
// a pair child runs and is cleared on a confirmed exit. Fixture children are
// inert `/bin/cat` pipe readers, never agent or relay programs.
//
// Lives beside `tests.rs` because that file is already over the desktop
// file-size ratchet and may not grow.

use super::tests::{make_pair_runtime_placeholder, minimal_record};

#[cfg(unix)]
fn live_pair_runtime() -> crate::managed_agents::ManagedAgentPairRuntime {
    use std::process::{Command, Stdio};
    let child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cat for live pair fixture");
    let process = crate::managed_agents::ManagedAgentProcess {
        child,
        log_path: std::path::PathBuf::new(),
        spawn_config: crate::managed_agents::spawn_snapshot::prospective_spawn_config_snapshot(
            &minimal_record(&"cc".repeat(32)),
            &[],
            &[],
            "wss://relay.example",
            &Default::default(),
            crate::managed_agents::AcpSessionPolicy::Channel,
        ),
        setup_mode: false,
        adapter_availability: None,
        start_nonce: "live-fixture".to_string(),
    };
    crate::managed_agents::ManagedAgentPairRuntime::starting(process)
}

#[cfg(unix)]
struct ReapOnDrop<'a>(
    &'a mut std::collections::HashMap<
        crate::managed_agents::ManagedAgentRuntimeKey,
        crate::managed_agents::ManagedAgentPairRuntime,
    >,
);

#[cfg(unix)]
impl Drop for ReapOnDrop<'_> {
    fn drop(&mut self) {
        for (_, mut runtime) in self.0.drain() {
            let _ = runtime.child.kill();
            let _ = runtime.child.wait();
        }
    }
}

#[cfg(unix)]
#[test]
fn sync_records_tracked_pair_pid_and_clears_it_on_confirmed_exit() {
    use crate::managed_agents::ManagedAgentRuntimeKey;
    let pubkey = "dd".repeat(32);
    let key = ManagedAgentRuntimeKey::new(pubkey.clone(), "wss://relay.example").unwrap();
    let mut runtimes = std::collections::HashMap::new();
    let runtime = live_pair_runtime();
    let pid = runtime.child.id();
    runtimes.insert(key.clone(), runtime);
    let mut records = vec![minimal_record(&pubkey)];
    let guard = ReapOnDrop(&mut runtimes);

    // A record loaded without a PID adopts the live pair child.
    let (changed, exited) =
        super::sync_managed_agent_processes_with(&mut records, guard.0, |_| true);
    assert!(
        changed,
        "adopting the pair pid must mark the record changed"
    );
    assert!(exited.is_empty());
    assert_eq!(records[0].runtime_pid, Some(pid));

    // Steady state: nothing moves, nothing is rewritten.
    let (changed, _) = super::sync_managed_agent_processes_with(&mut records, guard.0, |_| true);
    assert!(
        !changed,
        "an unchanged live pair must not rewrite the record"
    );
    assert_eq!(records[0].runtime_pid, Some(pid));

    // Confirmed exit: close the pipe, cat exits, the sweep reaps it.
    drop(guard.0.get_mut(&key).unwrap().child.stdin.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let exited = loop {
        let (_, exited) = super::sync_managed_agent_processes_with(&mut records, guard.0, |_| true);
        if !exited.is_empty() {
            break exited;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fixture child never exited"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(exited, vec![pubkey]);
    assert!(guard.0.is_empty());
    assert_eq!(records[0].runtime_pid, None, "exit must clear runtime_pid");
    assert!(records[0].last_stopped_at.is_some());
}

#[test]
fn sync_keeps_live_untracked_pid_and_clears_dead_one() {
    // An untracked PID belongs to a prior session. While it runs the launch
    // sweep decides its fate; once it is gone the record stops naming it.
    let mut record = minimal_record("pubkey-prior-session");
    record.runtime_pid = Some(4242);
    let mut records = vec![record];
    let mut runtimes = std::collections::HashMap::new();

    let (changed, _) =
        super::sync_managed_agent_processes_with(&mut records, &mut runtimes, |pid| pid == 4242);
    assert!(!changed);
    assert_eq!(records[0].runtime_pid, Some(4242));

    let (changed, _) =
        super::sync_managed_agent_processes_with(&mut records, &mut runtimes, |_| false);
    assert!(changed);
    assert_eq!(records[0].runtime_pid, None);
}

#[test]
fn tracked_runtime_pid_prefers_current_pair_then_first_by_relay() {
    use crate::managed_agents::ManagedAgentRuntimeKey;
    let pubkey = "ee".repeat(32);
    let mut runtimes = std::collections::HashMap::new();
    let alpha = make_pair_runtime_placeholder();
    let beta = make_pair_runtime_placeholder();
    let (alpha_pid, beta_pid) = (alpha.child.id(), beta.child.id());
    runtimes.insert(
        ManagedAgentRuntimeKey::new(pubkey.clone(), "wss://alpha.example").unwrap(),
        alpha,
    );
    runtimes.insert(
        ManagedAgentRuntimeKey::new(pubkey.clone(), "wss://beta.example").unwrap(),
        beta,
    );
    let mut record = minimal_record(&pubkey);

    record.runtime_pid = Some(beta_pid);
    assert_eq!(
        super::tracked_runtime_pid(&runtimes, &record),
        Some(beta_pid)
    );
    record.runtime_pid = None;
    assert_eq!(
        super::tracked_runtime_pid(&runtimes, &record),
        Some(alpha_pid)
    );
    record.runtime_pid = Some(1);
    assert_eq!(
        super::tracked_runtime_pid(&runtimes, &record),
        Some(alpha_pid)
    );

    let other = minimal_record(&"ef".repeat(32));
    assert_eq!(super::tracked_runtime_pid(&runtimes, &other), None);
    for (_, mut runtime) in runtimes.drain() {
        let _ = runtime.child.wait();
    }
}

#[cfg(all(unix, not(feature = "system-keyring")))]
#[test]
fn workspace_stop_leaves_other_community_pair_named_by_runtime_pid() {
    use crate::managed_agents::ManagedAgentRuntimeKey;
    let state = crate::app_state::build_ephemeral_test_app_state();
    *state.relay_url_override.lock().unwrap() = Some("wss://workspace.example".into());
    let app = tauri::test::mock_builder()
        .manage(state)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let handle = app.handle();
    let pubkey = "ab".repeat(32);
    let mut record = minimal_record(&pubkey);
    let mut runtimes = std::collections::HashMap::new();
    let runtime = live_pair_runtime();
    let pid = runtime.child.id();
    runtimes.insert(
        ManagedAgentRuntimeKey::new(pubkey.clone(), "wss://other.example").unwrap(),
        runtime,
    );
    record.runtime_pid = Some(pid);
    let guard = ReapOnDrop(&mut runtimes);

    // No pair is tracked for the workspace relay, so this is the legacy
    // scalar-PID path. The PID names a live pair elsewhere: leave it alone.
    super::stop_managed_agent_workspace_pair(handle, &mut record, guard.0).unwrap();
    assert_eq!(
        record.runtime_pid,
        Some(pid),
        "other community's pair pid kept"
    );
    let child = &mut guard.0.values_mut().next().unwrap().child;
    assert!(
        child.try_wait().unwrap().is_none(),
        "other community's harness must keep running"
    );

    // Draining every pair is a confirmed stop: the record stops naming a PID.
    super::stop_managed_agent_process(handle, &mut record, guard.0).unwrap();
    assert!(guard.0.is_empty());
    assert_eq!(record.runtime_pid, None);
    assert!(record.last_stopped_at.is_some());
}
