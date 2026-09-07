import 'package:hooks_riverpod/hooks_riverpod.dart';

/// Serializes native microphone owners, including their asynchronous teardown.
final microphoneCaptureProvider = Provider((ref) => MicrophoneCapture());

/// Grants one capture lease per application provider scope.
class MicrophoneCapture {
  Object? _owner;

  /// Returns an idempotent release callback, or null while capture is owned.
  void Function()? acquire() {
    if (_owner != null) return null;
    final owner = Object();
    _owner = owner;
    return () {
      if (identical(_owner, owner)) _owner = null;
    };
  }
}
