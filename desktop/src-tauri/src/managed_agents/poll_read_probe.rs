//! App-scoped test instrumentation, shared by the real loaders and poll fixture.
//! No process-global paths or counters: blocking-worker reads remain isolated
//! from other tests, and every store stays inside this app's temporary directory.
use std::sync::atomic::{AtomicUsize, Ordering};
use tauri::Manager;

pub(crate) struct PollReadProbe {
    pub directory: tempfile::TempDir,
    pub global: AtomicUsize,
    pub teams: AtomicUsize,
}

pub(crate) fn record_read<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    counter: impl FnOnce(&PollReadProbe) -> &AtomicUsize,
) {
    if let Some(probe) = app.try_state::<PollReadProbe>() {
        counter(&probe).fetch_add(1, Ordering::SeqCst);
    }
}
