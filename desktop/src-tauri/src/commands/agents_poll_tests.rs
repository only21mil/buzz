use super::*;
use crate::managed_agents::poll_read_probe::PollReadProbe;
use std::sync::atomic::{AtomicUsize, Ordering};
use tauri::Manager;

// Own only fixture children; reap them even when an assertion unwinds.
struct PollProcesses(tauri::AppHandle<tauri::test::MockRuntime>);

impl Drop for PollProcesses {
    fn drop(&mut self) {
        let state = self.0.state::<AppState>();
        for (_, mut pair) in state.managed_agent_processes.lock().unwrap().drain() {
            let _ = pair.child.kill();
            let _ = pair.child.wait();
        }
    }
}

#[test]
fn full_agent_poll_reads_global_and_teams_once_per_tick() {
    // This module is disabled with system-keyring: even fixture keys must never
    // reach a host credential store. The test uses no HOME/XDG overrides.
    let probe = PollReadProbe {
        directory: tempfile::tempdir().unwrap(),
        global: AtomicUsize::new(0),
        teams: AtomicUsize::new(0),
    };
    let state = crate::app_state::build_ephemeral_test_app_state();
    *state.relay_url_override.lock().unwrap() = Some("wss://poll.example".into());
    let app = tauri::test::mock_builder()
        .manage(state)
        .manage(probe)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let handle = app.handle();
    let probe = handle.state::<PollReadProbe>();
    let teams = load_teams(handle).unwrap();
    let records: Vec<ManagedAgentRecord> = (0..4)
        .map(|index| {
            serde_json::from_value(serde_json::json!({
                "pubkey": format!("{index:064x}"),
                "name": format!("Poll fixture {index}"),
                "team_id": teams[0].id,
                "relay_url": "wss://legacy.example",
                "acp_command": "buzz-acp",
                "agent_command": "goose",
                "agent_args": [],
                "mcp_command": "",
                "turn_timeout_seconds": 320,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap()
        })
        .collect();
    save_managed_agents(handle, &records).unwrap();
    // Settle built-in merges before counting the two real poll ticks.
    let personas = load_personas(handle).unwrap();
    let _processes = PollProcesses(handle.clone());
    let global = crate::managed_agents::GlobalAgentConfig {
        model: Some("poll-model-first".into()),
        ..Default::default()
    };
    // Two pairs in this workspace and one in another community. These are
    // inert local pipe readers, never agent/provider programs or relay clients.
    for (index, record) in records.iter().take(3).enumerate() {
        let relay = if index == 2 {
            "wss://other.example"
        } else {
            "wss://poll.example"
        };
        let key = crate::managed_agents::ManagedAgentRuntimeKey::new(record.pubkey.clone(), relay)
            .unwrap();
        let process = crate::managed_agents::ManagedAgentProcess {
            child: std::process::Command::new("/bin/cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
            log_path: probe.directory.path().join(format!("{index}.log")),
            spawn_config: crate::managed_agents::spawn_snapshot::prospective_spawn_config_snapshot(
                record,
                &personas,
                &teams,
                &key.relay_url,
                &global,
                crate::managed_agents::acp_session_policy(handle.state::<AppState>().inner()),
            ),
            setup_mode: false,
            adapter_availability: None,
            start_nonce: format!("poll-fixture-{index}"),
        };
        handle
            .state::<AppState>()
            .managed_agent_processes
            .lock()
            .unwrap()
            .insert(
                key,
                crate::managed_agents::ManagedAgentPairRuntime::starting(process),
            );
    }
    let config_path = probe.directory.path().join("global-agent-config.json");
    probe.teams.store(0, Ordering::SeqCst);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for (tick, model) in [(1, "poll-model-first"), (2, "poll-model-second")] {
        std::fs::write(
            &config_path,
            serde_json::json!({ "model": model }).to_string(),
        )
        .unwrap();
        // Execute the exported command, including spawn_blocking, synchronization,
        // actual disk loaders and every record's full summary construction.
        let summaries = runtime
            .block_on(list_managed_agents(handle.clone()))
            .unwrap();
        assert_eq!(summaries.len(), records.len());
        for (index, record) in records.iter().enumerate() {
            let summary = summaries
                .iter()
                .find(|item| item.pubkey == record.pubkey)
                .unwrap();
            assert_eq!(summary.model.as_deref(), Some(model));
            assert_eq!(
                summary.status,
                if index < 2 { "running" } else { "stopped" }
            );
            assert_eq!(summary.needs_restart, index < 2 && tick == 2);
        }
        assert_eq!(
            (
                probe.global.load(Ordering::SeqCst),
                probe.teams.load(Ordering::SeqCst)
            ),
            (tick, tick),
            "(global, team) reads after tick {tick}"
        );
    }
}
