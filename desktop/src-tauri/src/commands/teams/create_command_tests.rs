use super::*;
use crate::managed_agents::{
    retention::{active_retention_scope, get_retained_event, open_retention_db},
    spawn_snapshot::effective_team_instructions,
    ManagedAgentRecord,
};
use tauri::Manager;

struct TestPaths(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl TestPaths {
    fn new(path: &std::path::Path) -> Self {
        let vars = ["HOME", "XDG_DATA_HOME", "BUZZ_PRIVATE_KEY"];
        let saved = vars
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        std::env::set_var("HOME", path);
        std::env::set_var("XDG_DATA_HOME", path);
        std::env::remove_var("BUZZ_PRIVATE_KEY");
        Self(saved)
    }
}

impl Drop for TestPaths {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn instance(persona_id: &str, team_id: Option<&str>) -> ManagedAgentRecord {
    serde_json::from_value(serde_json::json!({
        "pubkey": nostr::Keys::generate().public_key().to_hex(),
        "name": team_id.unwrap_or("unbound"),
        "persona_id": persona_id,
        "team_id": team_id,
        "relay_url": "wss://create-command.example",
        "acp_command": "buzz-acp",
        "agent_command": "goose",
        "agent_args": [],
        "mcp_command": "",
        "turn_timeout_seconds": 320,
        "system_prompt": "Persona instructions",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    }))
    .unwrap()
}

#[test]
fn create_team_command_binds_unbound_instances_and_retains_team() {
    let _guard = crate::managed_agents::lock_path_mutex();
    let temp = tempfile::tempdir().unwrap();
    let _paths = TestPaths::new(temp.path());
    let state = crate::app_state::build_app_state();
    *state.relay_url_override.lock().unwrap() = Some("wss://create-command.example".into());
    let app = tauri::test::mock_builder()
        .manage(state)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let handle = app.handle();
    let personas = load_personas(handle).unwrap();
    let persona = personas.iter().find(|persona| persona.is_active).unwrap();
    let unbound = instance(&persona.id, None);
    let bound = instance(&persona.id, Some("existing-team"));
    save_managed_agents(handle, &[unbound.clone(), bound.clone()]).unwrap();

    // Call the exported command, including its blocking task and real store callbacks.
    let team = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(create_team(
            CreateTeamRequest {
                name: " Created team ".into(),
                description: None,
                instructions: Some(" Follow the team plan. ".into()),
                persona_ids: vec![persona.id.clone()],
            },
            handle.clone(),
        ))
        .unwrap();

    let teams = load_teams(handle).unwrap();
    assert!(teams.iter().any(|stored| stored.id == team.id));
    assert_eq!(team.name, "Created team");
    let records = load_managed_agents(handle).unwrap();
    let updated = records
        .iter()
        .find(|record| record.pubkey == unbound.pubkey)
        .unwrap();
    assert_eq!(updated.team_id.as_deref(), Some(team.id.as_str()));
    assert_eq!(
        effective_team_instructions(updated, &teams).as_deref(),
        Some("Follow the team plan.")
    );
    let preserved = records
        .iter()
        .find(|record| record.pubkey == bound.pubkey)
        .unwrap();
    assert_eq!(preserved.team_id, bound.team_id);

    let scope = active_retention_scope(handle, &handle.state::<AppState>()).unwrap();
    let conn = open_retention_db(&scope.db_path).unwrap();
    let retained = get_retained_event(
        &conn,
        buzz_core_pkg::kind::KIND_TEAM,
        &scope.owner_keys.public_key().to_hex(),
        &team.id,
    )
    .unwrap()
    .unwrap();
    assert!(retained.pending_sync);
    let event: nostr::Event = serde_json::from_str(&retained.raw_event).unwrap();
    event.verify().unwrap();
}
