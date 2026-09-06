//! Bound the read-only Keychain check before identity resolution may mutate storage.

use std::sync::mpsc;
use std::time::Duration;

/// Return `None` only when the read has not completed within the deadline or fails.
/// A completed result, including an unreachable backend, follows the existing
/// identity resolution policy.
/// The worker receives only a read-only probe. A late result cannot resolve,
/// create, migrate, or activate an identity after startup entered recovery.
pub(crate) fn resolve_after_keyring_probe<P: Send + 'static, T>(
    probe: impl FnOnce() -> P + Send + 'static,
    resolve: impl FnOnce(P) -> Result<T, String>,
    timeout: Duration,
) -> Result<Option<T>, String> {
    let (send, receive) = mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("identity-keychain-probe".into())
        .spawn(move || {
            let _ = send.send(probe());
        })
        .is_err()
    {
        return Ok(None);
    }

    match receive.recv_timeout(timeout) {
        Ok(probe) => resolve(probe).map(Some),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn available_keyring_resolves_existing_identity() {
        let identity = "existing identity";
        assert_eq!(
            resolve_after_keyring_probe(|| true, |_| Ok(identity), Duration::from_secs(1)),
            Ok(Some(identity))
        );
    }

    #[test]
    fn completed_unreachable_result_reaches_resolution_policy() {
        assert_eq!(
            resolve_after_keyring_probe(|| false, Ok, Duration::from_secs(1)),
            Ok(Some(false))
        );
    }

    #[test]
    fn blocked_probe_returns_recovery_and_late_success_cannot_resolve_identity() {
        let (release, blocked) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        let resolved = AtomicBool::new(false);
        let result = resolve_after_keyring_probe(
            move || {
                blocked.recv().unwrap();
                finished.send(()).unwrap();
                true
            },
            |_| {
                resolved.store(true, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(20),
        );
        assert_eq!(result, Ok(None));
        assert!(!resolved.load(Ordering::SeqCst));
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!resolved.load(Ordering::SeqCst));
    }

    #[test]
    fn disconnected_probe_enters_recovery() {
        assert_eq!(
            resolve_after_keyring_probe::<_, ()>(
                || panic!("backend failed"),
                |_| panic!("identity resolution must not run"),
                Duration::from_secs(1),
            ),
            Ok(None)
        );
    }

    #[test]
    fn resolution_failure_is_not_reported_as_success() {
        assert_eq!(
            resolve_after_keyring_probe::<_, ()>(
                || true,
                |_| Err("identity resolution failed".into()),
                Duration::from_secs(1),
            ),
            Err("identity resolution failed".into())
        );
    }
}
