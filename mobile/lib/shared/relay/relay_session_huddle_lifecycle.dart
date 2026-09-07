part of 'relay_session.dart';

/// Foreground Huddles settle before the relay's background disconnect.
extension HuddleRelayLifecycle on RelaySessionNotifier {
  /// Registers work that must settle before the background grace disconnect.
  void Function() registerBeforePause(Future<void> Function() callback) {
    final owner = Object();
    _beforePauseCallbacks[owner] = callback;
    return () => _beforePauseCallbacks.remove(owner);
  }

  /// Called by the app lifecycle provider when the app goes to background.
  void onAppPaused() {
    _backgroundedAt = _now();
    _backgroundGraceTimer?.cancel();
    _backgroundGraceTimer = Timer(
      RelaySessionNotifier._backgroundGraceDuration,
      () => unawaited(_pauseAfterCallbacks()),
    );
  }

  Future<void> _pauseAfterCallbacks() async {
    final callbacks = _beforePauseCallbacks.values.toList();
    try {
      await Future.wait(callbacks.map((callback) => callback()));
    } catch (error) {
      debugPrint('Background cleanup failed: $error');
    }
    if (_backgroundedAt != null) _pauseNow();
  }
}
