use super::media_download::{fetch_blob_bytes, validate_download_url, validate_image_bytes};
use crate::app_state::AppState;
use crate::relay::relay_api_base_url_with_override;
use tauri::State;

/// Fetch relay media bytes for the composer image editor.
///
/// The editor composites the image onto a canvas and needs pixel access.
/// Handing the webview raw bytes over IPC (which it wraps in a same-origin
/// `blob:` URL) keeps the canvas un-tainted without involving CORS — and
/// therefore without any media-proxy header or origin-gate changes.
///
/// Same SSRF validation, size cap, and content policy as the download
/// commands above.
///
/// Returns `tauri::ipc::Response` so the bytes cross IPC as a raw buffer
/// instead of a JSON number array (which would be ~3x the size to
/// serialize and deserialize at the 50 MiB cap).
#[tauri::command]
pub async fn fetch_media_bytes(
    url: String,
    state: State<'_, AppState>,
) -> Result<tauri::ipc::Response, String> {
    let relay_base = relay_api_base_url_with_override(&state);
    validate_download_url(&url, &relay_base)?;

    let bytes = fetch_blob_bytes(&url, &state).await?;
    validate_image_bytes(&bytes)?;
    Ok(tauri::ipc::Response::new(bytes))
}
