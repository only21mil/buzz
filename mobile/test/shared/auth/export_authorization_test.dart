import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:buzz/shared/auth/export_authorization.dart';

/// Unit tests for the fresh device-auth export gate (P05 / upstream #5116).
///
/// The contract under test: every private-key export needs a fresh OS
/// prompt; the minted grant is short-lived, single-use, and bound to the
/// identity, community, action, peer, and pairing session. Anything else
/// fails closed.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  group('ExportAuthorization', () {
    late ProviderContainer container;
    late FakeDeviceAuth deviceAuth;
    late MutableClock clock;

    ExportGrantRequest request({
      String communityId = 'community-1',
      String identityPubkey = 'pubkey-1',
      ExportAction action = ExportAction.pairingExport,
      String peerPubkey = 'peer-1',
      String sessionIdHex = 'session-1',
      String transcriptHashHex = 'transcript-1',
    }) => ExportGrantRequest(
      communityId: communityId,
      identityPubkey: identityPubkey,
      action: action,
      peerPubkey: peerPubkey,
      sessionIdHex: sessionIdHex,
      transcriptHashHex: transcriptHashHex,
    );

    setUp(() {
      deviceAuth = FakeDeviceAuth();
      clock = MutableClock(DateTime.utc(2026, 9, 13, 12));
      container = ProviderContainer(
        overrides: [
          deviceAuthGatewayProvider.overrideWithValue(deviceAuth),
          exportAuthorizationClockProvider.overrideWithValue(clock.read),
        ],
      );
      addTearDown(container.dispose);
    });

    test('successful auth mints a bound single-use grant', () async {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      final grant = await notifier.authorizeExport(request: request());

      expect(grant.request.communityId, 'community-1');
      expect(grant.expiresAt.difference(grant.grantedAt), exportGrantTtl);
      expect(deviceAuth.authenticateCalls, 1);

      final consumed = notifier.consumeGrant(
        grantId: grant.id,
        binding: request(),
      );
      expect(consumed.id, grant.id);
      expect(container.read(exportAuthorizationProvider), isEmpty);
    });

    test('the grant TTL starts after the OS prompt returns', () async {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      deviceAuth.onAuthenticate = () async =>
          clock.advance(const Duration(seconds: 45));

      final grant = await notifier.authorizeExport(request: request());

      expect(grant.grantedAt, DateTime.utc(2026, 9, 13, 12, 0, 45));
      expect(grant.expiresAt, grant.grantedAt.add(exportGrantTtl));
      clock.advance(exportGrantTtl - const Duration(seconds: 1));
      expect(grant.isExpiredAt(clock.read()), isFalse);
    });

    test('replay of a consumed grant is denied', () async {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      final grant = await notifier.authorizeExport(request: request());
      notifier.consumeGrant(grantId: grant.id, binding: request());

      expect(
        () => notifier.consumeGrant(grantId: grant.id, binding: request()),
        throwsA(isA<ExportGrantDenied>()),
      );
    });

    test('unknown grant id is denied', () {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      expect(
        () => notifier.consumeGrant(grantId: 'nope', binding: request()),
        throwsA(isA<ExportGrantDenied>()),
      );
    });

    test('cancelled prompt leaves no grant behind', () async {
      deviceAuth.next = const ExportAuthCancelled();
      final notifier = container.read(exportAuthorizationProvider.notifier);

      await expectLater(
        notifier.authorizeExport(request: request()),
        throwsA(isA<ExportAuthCancelled>()),
      );
      expect(container.read(exportAuthorizationProvider), isEmpty);
    });

    test('unavailable hardware fails closed without prompting', () async {
      deviceAuth.canAuthenticateResult = false;
      final notifier = container.read(exportAuthorizationProvider.notifier);

      await expectLater(
        notifier.authorizeExport(request: request()),
        throwsA(isA<ExportAuthUnavailable>()),
      );
      expect(deviceAuth.authenticateCalls, 0);
      expect(container.read(exportAuthorizationProvider), isEmpty);
    });

    test('failed verification mints nothing', () async {
      deviceAuth.next = const ExportAuthFailed();
      final notifier = container.read(exportAuthorizationProvider.notifier);

      await expectLater(
        notifier.authorizeExport(request: request()),
        throwsA(isA<ExportAuthFailed>()),
      );
      expect(container.read(exportAuthorizationProvider), isEmpty);
    });

    test(
      'grant lives before expiry and dies exactly at the boundary',
      () async {
        final notifier = container.read(exportAuthorizationProvider.notifier);
        final first = await notifier.authorizeExport(request: request());
        clock.advance(exportGrantTtl - const Duration(seconds: 1));
        // Still valid one second before the deadline.
        expect(
          notifier.consumeGrant(grantId: first.id, binding: request()).id,
          first.id,
        );

        final second = await notifier.authorizeExport(request: request());
        clock.advance(exportGrantTtl);
        // Exactly at expiresAt the grant is dead (fail closed, not generous).
        expect(
          () => notifier.consumeGrant(grantId: second.id, binding: request()),
          throwsA(isA<ExportGrantDenied>()),
        );
      },
    );

    test('every binding field is enforced', () async {
      final variants = <String, ExportGrantRequest>{
        'community': request(communityId: 'other'),
        'identity': request(identityPubkey: 'other'),
        'peer': request(peerPubkey: 'other'),
        'session': request(sessionIdHex: 'other'),
        'transcript': request(transcriptHashHex: 'other'),
      };
      for (final entry in variants.entries) {
        final notifier = container.read(exportAuthorizationProvider.notifier);
        final grant = await notifier.authorizeExport(request: request());
        expect(
          () => notifier.consumeGrant(grantId: grant.id, binding: entry.value),
          throwsA(isA<ExportGrantDenied>()),
          reason: 'mismatched ${entry.key} must deny the export',
        );
        notifier.invalidateAll();
      }
    });

    test(
      'invalidateAll clears grants (logout / background / teardown)',
      () async {
        final notifier = container.read(exportAuthorizationProvider.notifier);
        final grant = await notifier.authorizeExport(request: request());
        notifier.invalidateAll();

        expect(container.read(exportAuthorizationProvider), isEmpty);
        expect(
          () => notifier.consumeGrant(grantId: grant.id, binding: request()),
          throwsA(isA<ExportGrantDenied>()),
        );
      },
    );

    test('invalidateForCommunity keeps other communities alone', () async {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      final mine = await notifier.authorizeExport(request: request());
      final other = await notifier.authorizeExport(
        request: request(communityId: 'community-2'),
      );

      notifier.invalidateForCommunity('community-1');

      expect(
        () => notifier.consumeGrant(grantId: mine.id, binding: request()),
        throwsA(isA<ExportGrantDenied>()),
      );
      expect(
        notifier
            .consumeGrant(
              grantId: other.id,
              binding: request(communityId: 'community-2'),
            )
            .id,
        other.id,
      );
    });

    test('expired grants are pruned on the next authorize', () async {
      final notifier = container.read(exportAuthorizationProvider.notifier);
      await notifier.authorizeExport(request: request());
      expect(container.read(exportAuthorizationProvider), hasLength(1));
      clock.advance(exportGrantTtl + const Duration(seconds: 1));
      await notifier.authorizeExport(request: request());
      // The stale grant was pruned; only the fresh one remains.
      expect(container.read(exportAuthorizationProvider), hasLength(1));
    });
  });

  group('MethodChannelDeviceAuth', () {
    const channel = MethodChannel('buzz/device_auth');

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    void mockHandler(Future<Object?> Function(MethodCall call) handler) {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) => handler(call));
    }

    test('canAuthenticate reflects the platform answer', () async {
      mockHandler((call) async => true);
      expect(await MethodChannelDeviceAuth().canAuthenticate(), isTrue);

      mockHandler((call) async => false);
      expect(await MethodChannelDeviceAuth().canAuthenticate(), isFalse);
    });

    test('missing plugin fails closed as unavailable', () async {
      mockHandler((call) async => throw MissingPluginException());
      final gateway = MethodChannelDeviceAuth();

      expect(await gateway.canAuthenticate(), isFalse);
      await expectLater(
        gateway.authenticate(reason: 'reason'),
        throwsA(isA<ExportAuthUnavailable>()),
      );
    });

    test('platform error codes map to typed failures', () async {
      final gateway = MethodChannelDeviceAuth();
      final cases = <String, Type>{
        'cancelled': ExportAuthCancelled,
        'user_cancel': ExportAuthCancelled,
        'system_cancel': ExportAuthCancelled,
        'not_available': ExportAuthUnavailable,
        'no_biometric': ExportAuthUnavailable,
        'no_passcode': ExportAuthUnavailable,
        'not_enrolled': ExportAuthUnavailable,
        'hardware_unavailable': ExportAuthUnavailable,
        'auth_failed': ExportAuthFailed,
        'something_new': ExportAuthFailed,
      };
      for (final entry in cases.entries) {
        mockHandler((call) async => throw PlatformException(code: entry.key));
        await expectLater(
          gateway.authenticate(reason: 'reason'),
          throwsA(isA<ExportAuthException>()),
          reason: 'code ${entry.key}',
        );
        try {
          await gateway.authenticate(reason: 'reason');
          fail('expected ${entry.key} to throw');
        } on ExportAuthException catch (e) {
          expect(e.runtimeType, entry.value, reason: 'code ${entry.key}');
        }
      }
    });

    test('false platform result fails closed', () async {
      mockHandler((call) async => false);
      await expectLater(
        MethodChannelDeviceAuth().authenticate(reason: 'reason'),
        throwsA(isA<ExportAuthFailed>()),
      );
    });
  });
}

/// Controllable device-auth stand-in: succeeds unless told otherwise.
class FakeDeviceAuth implements DeviceAuthGateway {
  bool canAuthenticateResult = true;
  ExportAuthException? next;
  int authenticateCalls = 0;
  Future<void> Function()? onAuthenticate;

  @override
  Future<bool> canAuthenticate() async => canAuthenticateResult;

  @override
  Future<void> authenticate({required String reason}) async {
    authenticateCalls += 1;
    assert(reason.isNotEmpty, 'device-auth prompt needs a reason');
    await onAuthenticate?.call();
    final failure = next;
    if (failure != null) throw failure;
  }
}

/// Hand-rolled clock for the expiry boundary tests.
class MutableClock {
  MutableClock(this.current);

  DateTime current;

  DateTime read() => current;

  void advance(Duration delta) {
    current = current.add(delta);
  }
}
