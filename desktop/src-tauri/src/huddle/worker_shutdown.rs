/// Drain and discard all pending messages until shutdown or disconnect.
/// Shared by both the STT and TTS worker threads for graceful degradation
/// when model files are missing or initialization fails.
pub(crate) fn drain_until_shutdown<T>(
    rx: std::sync::mpsc::Receiver<T>,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}
