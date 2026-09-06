//! Managed-agent store and log directories, including app-owned test isolation.
use std::{fs, path::PathBuf};
use tauri::{AppHandle, Manager};

pub fn managed_agents_base_dir<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(probe) = app.try_state::<crate::managed_agents::poll_read_probe::PollReadProbe>() {
        return Ok(probe.directory.path().to_path_buf());
    }
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve app data dir: {error}"))?
        .join("agents");
    fs::create_dir_all(&dir).map_err(|error| format!("failed to create agents dir: {error}"))?;
    Ok(dir)
}

pub(crate) fn managed_agents_store_path<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("managed-agents.json"))
}

pub(super) fn managed_agents_logs_dir<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<PathBuf, String> {
    let dir = managed_agents_base_dir(app)?.join("logs");
    fs::create_dir_all(&dir).map_err(|error| format!("failed to create logs dir: {error}"))?;
    Ok(dir)
}
