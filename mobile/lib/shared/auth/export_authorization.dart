import 'package:flutter/services.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:uuid/uuid.dart';

/// Fresh device-auth gate for private-key export.
///
/// Policy (P05 / upstream #5116 port):
/// - Every recovery/private export and every pairing export authorization
///   needs fresh local device authentication (biometric or device passcode).
/// - The gate sits at the actual key read/encrypt/publish step, not at page
///   open. Opening the recovery page proves nothing.
/// - A successful authentication mints a short-lived, single-use grant bound
///   to the identity, the community, the intended action, the confirmed peer,
///   and the pairing transcript/session. Pairing SAS confirmation stays a
///   separate requirement; a grant never replaces it.
/// - Grants expire quickly, are consumed on use, and are cleared on
///   logout, community switch, and app backgrounding.
/// - Any device-auth failure (cancelled, unavailable hardware, no passcode)
///   fails closed: no grant, no key access.
/// - Copying the public key in settings is not an export and stays available.
///
/// The exact expiry lives here so both the implementation and the tests read
/// the same contract value.
const exportGrantTtl = Duration(seconds: 120);

const _exportAuthChannel = 'buzz/device_auth';

/// The sensitive operation a grant authorizes.
enum ExportAction {
  /// Send this phone's identity (nsec) to a paired desktop.
  pairingExport,
}

/// What a grant is bound to. The consumer must pass the same binding at
/// consume time; any mismatch denies the export.
class ExportGrantRequest {
  const ExportGrantRequest({
    required this.communityId,
    required this.identityPubkey,
    required this.action,
    required this.peerPubkey,
    required this.sessionIdHex,
    required this.transcriptHashHex,
  });

  final String communityId;
  final String identityPubkey;
  final ExportAction action;
  final String peerPubkey;
  final String sessionIdHex;
  final String transcriptHashHex;
}

/// A minted, unconsumed export authorization.
class ExportGrant {
  const ExportGrant({
    required this.id,
    required this.request,
    required this.grantedAt,
    required this.expiresAt,
  });

  final String id;
  final ExportGrantRequest request;
  final DateTime grantedAt;
  final DateTime expiresAt;

  bool isExpiredAt(DateTime now) => !now.isBefore(expiresAt);
}

/// Base class for device-auth failures. All of them fail closed.
class ExportAuthException implements Exception {
  const ExportAuthException(this.message);

  final String message;

  @override
  String toString() => 'ExportAuthException: $message';
}

/// The user dismissed the prompt. Nothing was sent.
class ExportAuthCancelled extends ExportAuthException {
  const ExportAuthCancelled()
    : super('Export cancelled. Your identity was not sent.');
}

/// The phone cannot do device auth (no biometric, no passcode, sensor
/// missing). Fail closed: there is no fallback that skips the check.
class ExportAuthUnavailable extends ExportAuthException {
  const ExportAuthUnavailable()
    : super(
        'This phone could not verify it is you, so the identity was not sent.',
      );
}

/// Authentication ran and did not pass.
class ExportAuthFailed extends ExportAuthException {
  const ExportAuthFailed()
    : super('Verification did not pass. Your identity was not sent.');
}

/// A grant was missing, already used, expired, or bound to something else.
class ExportGrantDenied extends ExportAuthException {
  const ExportGrantDenied(super.message);
}

/// Performs the OS device-auth prompt. Kept behind an interface so tests and
/// the pairing flow never touch platform channels directly.
abstract class DeviceAuthGateway {
  /// Whether this phone can currently do device auth at all.
  Future<bool> canAuthenticate();

  /// Show the OS prompt. Returns on success, throws a typed
  /// [ExportAuthException] otherwise. Never returns a key.
  Future<void> authenticate({required String reason});
}

/// OS device auth over the `buzz/device_auth` method channel.
///
/// Android uses BiometricPrompt with device-credential fallback; iOS uses
/// LAContext device-owner authentication (Face ID / Touch ID / passcode).
/// Every platform error maps to a typed failure. Unknown results fail
/// closed as [ExportAuthFailed].
class MethodChannelDeviceAuth implements DeviceAuthGateway {
  MethodChannelDeviceAuth({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel(_exportAuthChannel);

  final MethodChannel _channel;

  @override
  Future<bool> canAuthenticate() async {
    try {
      final result = await _channel.invokeMethod<bool>('canAuthenticate');
      return result ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  @override
  Future<void> authenticate({required String reason}) async {
    try {
      final result = await _channel.invokeMethod<bool>('authenticate', {
        'reason': reason,
      });
      if (result != true) {
        throw const ExportAuthFailed();
      }
    } on ExportAuthException {
      rethrow;
    } on PlatformException catch (e) {
      throw _mapPlatformError(e);
    } on MissingPluginException {
      throw const ExportAuthUnavailable();
    }
  }

  ExportAuthException _mapPlatformError(PlatformException e) {
    switch (e.code) {
      case 'cancelled':
      case 'user_cancel':
      case 'system_cancel':
        return const ExportAuthCancelled();
      case 'not_available':
      case 'no_biometric':
      case 'no_passcode':
      case 'not_enrolled':
      case 'hardware_unavailable':
        return const ExportAuthUnavailable();
      default:
        return const ExportAuthFailed();
    }
  }
}

/// Overrides the device-auth gateway (tests install a fake here).
final deviceAuthGatewayProvider = Provider<DeviceAuthGateway>((ref) {
  return MethodChannelDeviceAuth();
});

/// Clock shape for the injectable grant clock.
typedef ExportClock = DateTime Function();

/// Injectable clock so tests can prove the expiry boundary exactly.
final exportAuthorizationClockProvider = Provider<ExportClock>((ref) {
  return DateTime.now;
});

const _uuid = Uuid();

/// Holds live export grants. Grants live only in memory: they never reach
/// disk, and logout/background/identity change wipes them.
class ExportAuthorizationNotifier extends Notifier<List<ExportGrant>> {
  @override
  List<ExportGrant> build() => const [];

  DateTime get _now => ref.read(exportAuthorizationClockProvider)();

  void _prune(DateTime now) {
    final live = state.where((grant) => !grant.isExpiredAt(now)).toList();
    if (live.length != state.length) state = live;
  }

  /// Run device auth and mint a single-use grant bound to [request].
  ///
  /// Throws [ExportAuthUnavailable] when the phone cannot do device auth,
  /// [ExportAuthCancelled] when the user backs out, and [ExportAuthFailed]
  /// when verification does not pass. All three leave no grant behind.
  Future<ExportGrant> authorizeExport({
    required ExportGrantRequest request,
    String? reason,
  }) async {
    final now = _now;
    _prune(now);
    final gateway = ref.read(deviceAuthGatewayProvider);
    if (!await gateway.canAuthenticate()) {
      throw const ExportAuthUnavailable();
    }
    await gateway.authenticate(
      reason: reason ?? 'Confirm it is you to export your Buzz identity.',
    );
    final grant = ExportGrant(
      id: _uuid.v4(),
      request: request,
      grantedAt: now,
      expiresAt: now.add(exportGrantTtl),
    );
    state = [...state, grant];
    return grant;
  }

  /// Consume the grant for [grantId] after re-checking every binding.
  ///
  /// Returns the grant on success and removes it so it cannot be replayed.
  /// Throws [ExportGrantDenied] when the grant is unknown, already used,
  /// expired, or bound to a different identity/community/action/peer/session.
  /// The optional [now] override exists for boundary tests; callers in
  /// production leave it unset.
  ExportGrant consumeGrant({
    required String grantId,
    required ExportGrantRequest binding,
    DateTime? now,
  }) {
    final at = now ?? _now;
    final index = state.indexWhere((grant) => grant.id == grantId);
    if (index < 0) {
      throw const ExportGrantDenied('Export grant is unknown or used up.');
    }
    final grant = state[index];
    state = [...state]..removeAt(index);
    if (grant.isExpiredAt(at)) {
      throw const ExportGrantDenied('Export approval expired. Start over.');
    }
    final want = grant.request;
    final matches =
        want.communityId == binding.communityId &&
        want.identityPubkey == binding.identityPubkey &&
        want.action == binding.action &&
        want.peerPubkey == binding.peerPubkey &&
        want.sessionIdHex == binding.sessionIdHex &&
        want.transcriptHashHex == binding.transcriptHashHex;
    if (!matches) {
      throw const ExportGrantDenied(
        'Export approval does not match this device, identity, or peer.',
      );
    }
    return grant;
  }

  /// Drop every live grant. Called on logout, community switch, pairing
  /// teardown, and app backgrounding.
  void invalidateAll() {
    if (state.isNotEmpty) state = const [];
  }

  /// Drop grants for one community (identity or session change).
  void invalidateForCommunity(String communityId) {
    final kept = state
        .where((grant) => grant.request.communityId != communityId)
        .toList();
    if (kept.length != state.length) state = kept;
  }
}

final exportAuthorizationProvider =
    NotifierProvider<ExportAuthorizationNotifier, List<ExportGrant>>(
      ExportAuthorizationNotifier.new,
    );
