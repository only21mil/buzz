//! Remote upserts can arrive before their members. Missing dependencies are
//! hydration gaps; explicit local edits and signed deletions own retraction.

use super::*;

/// Refresh a remotely updated team only once every member is available locally.
/// A later member upsert retries this through the persona refresh below.
pub(crate) fn refresh_team_catalog_head<R: tauri::Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    team: &TeamRecord,
    personas: &[AgentDefinition],
) {
    if crate::managed_agents::team_catalog::resolve_team_members(team, personas).is_err() {
        return;
    }
    pending::refresh_shared_team_catalog_head_resolving(app, state, team, personas);
}

/// Retry hydrated projections after a remote member arrives. Other members may
/// still be in flight, including on devices with an older retained witness.
pub(crate) fn refresh_team_catalog_heads_for_inbound_persona<R: tauri::Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    persona_id: &str,
) {
    let result = (|| -> Result<(), String> {
        let teams = load_teams(app)?;
        let personas = load_personas(app)?;
        for team in &teams {
            if !team.is_builtin && team.persona_ids.iter().any(|id| id == persona_id) {
                refresh_team_catalog_head(app, state, team, &personas);
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("buzz-desktop: inbound team-catalog-refresh: {error}");
    }
}
