import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:nostr/nostr.dart' as nostr;
import 'package:buzz/features/pairing/pairing_crypto.dart';
import 'package:buzz/features/pairing/pairing_provider.dart';
import 'package:buzz/features/pairing/pairing_socket.dart';
import 'package:buzz/shared/auth/auth.dart';
import 'package:buzz/shared/crypto/ecdh.dart';
import 'package:buzz/shared/crypto/nip44.dart';
import 'package:buzz/shared/relay/relay.dart';

/// Tests for [PairingNotifier]'s legacy `buzz://` payload parsing and
/// SSRF-prevention validation.
///
/// The pairing flow used to validate by calling `GET /api/users/me/profile`
/// over HTTP. That has been replaced with a NIP-42 WebSocket handshake via
/// [RelaySocket], which is constructed directly inside the provider with no
/// dependency-injection hook — so the "happy path" that exercises the
/// network is no longer mockable in a unit test.
///
/// What we still cover here:
///   - Initial state.
///   - Parsing every documented payload format (raw base64, `buzz://`
///     prefix, whitespace).
///   - Failure modes that return BEFORE any network call: invalid base64,
///     wrong shape (non-object, missing fields, missing nsec), and SSRF
///     guards (private IPs, non-http schemes).
///   - `reset()` returning to idle from an error state.
void main() {
  group('PairingNotifier', () {
    late ProviderContainer container;
    late FakeAuthNotifier fakeAuth;

    ProviderContainer createContainer() {
      fakeAuth = FakeAuthNotifier();
      return ProviderContainer(
        overrides: [authProvider.overrideWith(() => fakeAuth)],
      );
    }

    tearDown(() => container.dispose());

    test('starts in idle state', () {
      container = createContainer();
      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.idle);
      expect(state.errorMessage, isNull);
    });

    test(
      'disconnect during connect does not null-dereference the socket',
      () async {
        final notifier = PairingNotifier(
          socketFactory:
              ({
                required wsUrl,
                required ephemeralPrivkey,
                required onMessage,
                required void Function(Object? error) onDisconnected,
              }) => _DisconnectingSocket(disconnectCallback: onDisconnected),
        );
        container = ProviderContainer(
          overrides: [pairingProvider.overrideWith(() => notifier)],
        );
        const code =
            'nostrpair://62287897da61e3fa294b4570575f7db8bea147d6631150f2e4656714c645fb1e'
            '?secret=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
            '&relay=wss%3A%2F%2Fpairing.buzz.xyz&v=1';

        await container.read(pairingProvider.notifier).pair(code);

        expect(container.read(pairingProvider).status, PairingStatus.error);
        expect(
          container.read(pairingProvider).errorMessage,
          contains('internal error'),
        );
      },
    );

    test('payload missing nsec errors before contacting relay', () async {
      container = createContainer();

      // Valid payload shape but no nsec — provider should refuse without
      // attempting any network call.
      final code = _encodePairingCode();
      await container.read(pairingProvider.notifier).pair(code);

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('missing nsec'));
      expect(fakeAuth.lastCommunity, isNull);
    });

    test('accepts buzz scheme prefix', () async {
      container = createContainer();

      final code = 'buzz://${_encodePairingCode()}';
      await container.read(pairingProvider.notifier).pair(code);

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('missing nsec'));
      expect(fakeAuth.lastCommunity, isNull);
    });

    test('invalid base64 sets format error', () async {
      container = createContainer();

      await container.read(pairingProvider.notifier).pair('not-valid!!!');

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('Invalid pairing code'));
    });

    test('base64 with valid JSON but missing fields errors', () async {
      container = createContainer();

      final code = base64Url.encode(utf8.encode(jsonEncode({'foo': 'bar'})));
      await container.read(pairingProvider.notifier).pair(code);

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('Missing relayUrl'));
    });

    test('empty input errors', () async {
      container = createContainer();

      await container.read(pairingProvider.notifier).pair('');

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
    });

    test('rejects private IP relay URLs (SSRF)', () async {
      container = createContainer();

      for (final ip in [
        '10.0.0.1',
        '172.16.0.1',
        '192.168.1.1',
        '169.254.169.254',
      ]) {
        final code = _encodePairingCode(relayUrl: 'http://$ip:3000');
        await container.read(pairingProvider.notifier).pair(code);
        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.error, reason: 'should reject $ip');
        expect(state.errorMessage, contains('private network'));
        container.read(pairingProvider.notifier).reset();
      }
    });

    test('rejects non-http/https schemes', () async {
      container = createContainer();

      final code = _encodePairingCode(relayUrl: 'file:///etc/passwd');
      await container.read(pairingProvider.notifier).pair(code);

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('Invalid pairing code'));
    });

    test('rejects JSON array payload', () async {
      container = createContainer();

      final code = base64Url.encode(utf8.encode(jsonEncode([1, 2, 3])));
      await container.read(pairingProvider.notifier).pair(code);

      final state = container.read(pairingProvider);
      expect(state.status, PairingStatus.error);
      expect(state.errorMessage, contains('not a JSON object'));
    });

    test('reset returns to idle from error state', () async {
      container = createContainer();

      // Trigger an error.
      await container.read(pairingProvider.notifier).pair('not-valid!!!');
      expect(container.read(pairingProvider).status, PairingStatus.error);

      container.read(pairingProvider.notifier).reset();
      expect(container.read(pairingProvider).status, PairingStatus.idle);
    });

    group('desktop identity recovery', () {
      const sourceSecret =
          '09b3065e3570a3a4054660dccd66e12774a99a904fdb0ca02dbc6c3136249506';
      const sessionSecretHex =
          'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      const recoveryPrivkey =
          '1111111111111111111111111111111111111111111111111111111111111111';
      late _ControllableSocket socket;
      late PairingNotifier notifier;
      late String recoveryCode;
      late _AuthenticatedFakeAuthNotifier recoveryAuth;
      late _FakeDeviceAuth deviceAuth;
      late _MutableClock grantClock;

      setUp(() {
        final source = nostr.Keys(sourceSecret);
        recoveryCode =
            'nostrpair://${source.public}'
            '?secret=$sessionSecretHex'
            '&relay=wss%3A%2F%2Fpairing.buzz.xyz&v=1&mode=recover';
        deviceAuth = _FakeDeviceAuth();
        grantClock = _MutableClock(DateTime.utc(2026, 9, 13, 12));
        recoveryAuth = _AuthenticatedFakeAuthNotifier(
          Community.create(
            name: 'Recovery',
            relayUrl: 'https://relay.test',
            pubkey: nostr.Keys(recoveryPrivkey).public,
            nsec: _RecoveryRelayConfig.nsec,
          ),
        );
        notifier = PairingNotifier(
          socketFactory:
              ({
                required wsUrl,
                required ephemeralPrivkey,
                required onMessage,
                required onDisconnected,
              }) {
                socket = _ControllableSocket(
                  ephemeralPrivkey: ephemeralPrivkey,
                  onMessage: onMessage,
                  onDisconnected: onDisconnected,
                );
                return socket;
              },
        );
        container = ProviderContainer(
          overrides: [
            pairingProvider.overrideWith(() => notifier),
            relayConfigProvider.overrideWith(_RecoveryRelayConfig.new),
            authProvider.overrideWith(() => recoveryAuth),
            deviceAuthGatewayProvider.overrideWithValue(deviceAuth),
            exportAuthorizationClockProvider.overrideWithValue(grantClock.read),
          ],
        );
        container.read(pairingProvider);
        notifier = container.read(pairingProvider.notifier);
      });

      /// Lets the async export gate (device auth, grant, publish) finish.
      Future<void> settleExport() async {
        for (var i = 0; i < 50; i++) {
          await Future<void>.delayed(Duration.zero);
        }
      }

      /// Published NIP-44 payloads that carry this phone's nsec.
      List<Map<String, dynamic>> nsecPayloads() => socket
          .decryptedPublishedMessages(sourceSecret)
          .where(
            (message) =>
                message['type'] == 'payload' &&
                message['payload_type'] == 'nsec',
          )
          .toList();

      test('recovery URI enables phone-to-desktop transfer', () async {
        await notifier.pair(recoveryCode);

        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.confirmingSas);
        expect(state.sendsIdentityToDesktop, isTrue);
        expect(state.sasCode, hasLength(6));
        // Opening recovery proves nothing: no device auth runs yet.
        expect(deviceAuth.authenticateCalls, 0);
      });

      test(
        'matching SAS plus device auth sends nsec to the confirmed peer',
        () async {
          await notifier.pair(recoveryCode);
          notifier.confirmSas();
          expect(container.read(pairingProvider).userConfirmedSas, isTrue);

          socket.sendSourceMessage(
            sourceSecret: sourceSecret,
            sessionSecretHex: sessionSecretHex,
            message: {'type': 'sas-confirm'},
            includeTranscriptHash: true,
          );
          await settleExport();

          expect(deviceAuth.authenticateCalls, 1);
          expect(
            container.read(pairingProvider).status,
            PairingStatus.transferring,
          );
          final sentMessages = socket.decryptedPublishedMessages(sourceSecret);
          expect(
            sentMessages.any(
              (message) =>
                  message['type'] == 'payload' &&
                  message['payload_type'] == 'nsec' &&
                  message['payload'] == _RecoveryRelayConfig.nsec,
            ),
            isTrue,
          );
          // The export goes only to the desktop that confirmed SAS.
          final payloadEvents = socket.publishedPayloadEvents();
          expect(payloadEvents, hasLength(2)); // offer + nsec payload
          for (final event in payloadEvents) {
            expect(event.kind, 24134);
            expect(event.pTag, nostr.Keys(sourceSecret).public);
          }

          socket.sendSourceMessage(
            sourceSecret: sourceSecret,
            sessionSecretHex: sessionSecretHex,
            message: {'type': 'complete', 'success': true},
          );
          expect(container.read(pairingProvider).status, PairingStatus.success);
        },
      );

      test('desktop storage failure surfaces an error', () async {
        await notifier.pair(recoveryCode);
        notifier.confirmSas();
        socket.sendSourceMessage(
          sourceSecret: sourceSecret,
          sessionSecretHex: sessionSecretHex,
          message: {'type': 'sas-confirm'},
          includeTranscriptHash: true,
        );
        await settleExport();
        socket.sendSourceMessage(
          sourceSecret: sourceSecret,
          sessionSecretHex: sessionSecretHex,
          message: {'type': 'complete', 'success': false},
        );

        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.error);
        expect(state.errorMessage, contains('could not store'));
      });

      test('SAS confirmation alone never sends the identity', () async {
        await notifier.pair(recoveryCode);
        // User confirms before the desktop does: payload arrives later.
        notifier.confirmSas();
        await settleExport();

        expect(deviceAuth.authenticateCalls, 0);
        expect(nsecPayloads(), isEmpty);
        expect(
          container.read(pairingProvider).status,
          PairingStatus.confirmingSas,
        );
      });

      test('cancelled device auth sends nothing and aborts', () async {
        deviceAuth.next = const ExportAuthCancelled();
        await notifier.pair(recoveryCode);
        notifier.confirmSas();
        socket.sendSourceMessage(
          sourceSecret: sourceSecret,
          sessionSecretHex: sessionSecretHex,
          message: {'type': 'sas-confirm'},
          includeTranscriptHash: true,
        );
        await settleExport();

        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.error);
        expect(state.errorMessage, contains('not sent'));
        expect(nsecPayloads(), isEmpty);
        expect(
          socket
              .decryptedPublishedMessages(sourceSecret)
              .any(
                (message) =>
                    message['type'] == 'abort' &&
                    message['reason'] == 'export_cancelled',
              ),
          isTrue,
        );
      });

      test('unavailable device auth fails closed without prompting', () async {
        deviceAuth.canAuthenticateResult = false;
        await notifier.pair(recoveryCode);
        notifier.confirmSas();
        socket.sendSourceMessage(
          sourceSecret: sourceSecret,
          sessionSecretHex: sessionSecretHex,
          message: {'type': 'sas-confirm'},
          includeTranscriptHash: true,
        );
        await settleExport();

        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.error);
        expect(deviceAuth.authenticateCalls, 0);
        expect(nsecPayloads(), isEmpty);
      });

      test('expired approval denies the export', () async {
        // The user sits on the OS prompt past the grant deadline.
        deviceAuth.onAuthenticate = () async {
          grantClock.advance(exportGrantTtl + const Duration(seconds: 1));
        };
        await notifier.pair(recoveryCode);
        notifier.confirmSas();
        socket.sendSourceMessage(
          sourceSecret: sourceSecret,
          sessionSecretHex: sessionSecretHex,
          message: {'type': 'sas-confirm'},
          includeTranscriptHash: true,
        );
        await settleExport();

        final state = container.read(pairingProvider);
        expect(state.status, PairingStatus.error);
        expect(state.errorMessage, contains('expired'));
        expect(nsecPayloads(), isEmpty);
      });

      test('pairing reset wipes pending export grants', () async {
        await notifier.pair(recoveryCode);
        final grants = container.read(exportAuthorizationProvider.notifier);
        const binding = ExportGrantRequest(
          communityId: 'community-1',
          identityPubkey: 'pubkey-1',
          action: ExportAction.pairingExport,
          peerPubkey: 'peer-1',
          sessionIdHex: 'session-1',
          transcriptHashHex: 'transcript-1',
        );
        final grant = await grants.authorizeExport(request: binding);

        notifier.reset();

        expect(
          () => grants.consumeGrant(grantId: grant.id, binding: binding),
          throwsA(isA<ExportGrantDenied>()),
        );
      });
    });
  });
}

/// Encode a credentials payload the same way the desktop app would.
String _encodePairingCode({
  String relayUrl = 'http://test:3000',
  String? pubkey,
  String? nsec,
}) {
  final json = <String, dynamic>{
    'relayUrl': relayUrl,
    // ignore: use_null_aware_elements
    if (pubkey != null) 'pubkey': pubkey,
    // ignore: use_null_aware_elements
    if (nsec != null) 'nsec': nsec,
  };
  return base64Url.encode(utf8.encode(jsonEncode(json)));
}

/// A fake [AuthNotifier] that records calls instead of touching secure storage.
class FakeAuthNotifier extends AsyncNotifier<AuthState>
    implements AuthNotifier {
  Community? lastCommunity;
  bool signedOut = false;

  @override
  Future<AuthState> build() async =>
      const AuthState(status: AuthStatus.unauthenticated);

  @override
  Future<void> signOut() async {
    signedOut = true;
    state = const AsyncData(AuthState(status: AuthStatus.unauthenticated));
  }

  @override
  Future<void> authenticateWithCommunity(Community community) async {
    lastCommunity = community;
    state = AsyncData(
      AuthState(status: AuthStatus.authenticated, community: community),
    );
  }
}

/// An already-signed-in identity for export-gate tests. The export binding
/// reads the community from [authProvider], so recovery tests need a real
/// community here, not the unauthenticated [FakeAuthNotifier].
class _AuthenticatedFakeAuthNotifier extends AsyncNotifier<AuthState>
    implements AuthNotifier {
  _AuthenticatedFakeAuthNotifier(this.community);

  final Community community;

  @override
  Future<AuthState> build() async =>
      AuthState(status: AuthStatus.authenticated, community: community);

  @override
  Future<void> signOut() async {
    state = const AsyncData(AuthState(status: AuthStatus.unauthenticated));
  }

  @override
  Future<void> authenticateWithCommunity(Community next) async {
    state = AsyncData(
      AuthState(status: AuthStatus.authenticated, community: next),
    );
  }
}

/// Controllable device-auth stand-in for the export gate.
class _FakeDeviceAuth implements DeviceAuthGateway {
  bool canAuthenticateResult = true;
  ExportAuthException? next;
  int authenticateCalls = 0;
  Future<void> Function()? onAuthenticate;

  @override
  Future<bool> canAuthenticate() async => canAuthenticateResult;

  @override
  Future<void> authenticate({required String reason}) async {
    authenticateCalls += 1;
    await onAuthenticate?.call();
    final failure = next;
    if (failure != null) throw failure;
  }
}

/// Hand-rolled clock so tests can push a grant past its deadline.
class _MutableClock {
  _MutableClock(this.current);

  DateTime current;

  DateTime read() => current;

  void advance(Duration delta) {
    current = current.add(delta);
  }
}

class _DisconnectingSocket extends PairingSocket {
  final void Function(Object? error) disconnectCallback;

  _DisconnectingSocket({required this.disconnectCallback})
    : super(
        wsUrl: 'ws://unused',
        ephemeralPrivkey:
            '09b3065e3570a3a4054660dccd66e12774a99a904fdb0ca02dbc6c3136249506',
        onMessage: (_) {},
        onDisconnected: (_) {},
      );

  @override
  Future<void> connect() async {
    disconnectCallback(Exception('Connection closed'));
  }
}

class _RecoveryRelayConfig extends RelayConfigNotifier {
  static final nsec = nostr.Keys(
    '1111111111111111111111111111111111111111111111111111111111111111',
  ).nsec;

  @override
  RelayConfig build() => RelayConfig(baseUrl: 'https://relay.test', nsec: nsec);
}

class _ControllableSocket extends PairingSocket {
  final String ephemeralPrivkey;
  final void Function(List<dynamic> message) relayMessageCallback;
  final List<Map<String, dynamic>> published = [];
  bool _connected = false;
  int _eventSequence = 0;

  _ControllableSocket({
    required this.ephemeralPrivkey,
    required super.onMessage,
    required super.onDisconnected,
  }) : relayMessageCallback = onMessage,
       super(wsUrl: 'ws://unused', ephemeralPrivkey: ephemeralPrivkey);

  @override
  bool get isConnected => _connected;

  @override
  Future<void> connect() async => _connected = true;

  @override
  void subscribe(String subId, int kind, String pubkeyHex) {}

  @override
  void publishEvent(Map<String, dynamic> event) => published.add(event);

  @override
  void dispose() => _connected = false;

  List<Map<String, dynamic>> decryptedPublishedMessages(String sourceSecret) {
    final key = getConversationKey(
      sourceSecret,
      nostr.Keys(ephemeralPrivkey).public,
    );
    return published
        .map(
          (event) =>
              jsonDecode(nip44Decrypt(key, event['content'] as String))
                  as Map<String, dynamic>,
        )
        .toList();
  }

  /// Raw published events that carry an encrypted payload, with the p-tag
  /// recipient exposed so tests can prove the export went to one peer only.
  List<({String pTag, int kind})> publishedPayloadEvents() => published
      .map(
        (event) => (
          pTag: ((event['tags'] as List).single as List).last as String,
          kind: event['kind'] as int,
        ),
      )
      .toList();

  void sendSourceMessage({
    required String sourceSecret,
    required String sessionSecretHex,
    required Map<String, dynamic> message,
    bool includeTranscriptHash = false,
  }) {
    final source = nostr.Keys(sourceSecret);
    final targetPubkey = nostr.Keys(ephemeralPrivkey).public;
    final sessionSecret = hexToBytes(sessionSecretHex);
    final body = Map<String, dynamic>.from(message);
    if (includeTranscriptHash) {
      final shared = ecdhSharedSecret(sourceSecret, targetPubkey);
      final (_, sasInput) = deriveSas(shared, sessionSecret);
      body['transcript_hash'] = bytesToHex(
        deriveTranscriptHash(
          deriveSessionId(sessionSecret),
          hexToBytes(source.public),
          hexToBytes(targetPubkey),
          sasInput,
          sessionSecret,
        ),
      );
    }
    final key = getConversationKey(sourceSecret, targetPubkey);
    final event = nostr.Event.from(
      kind: 24134,
      content: nip44Encrypt(key, jsonEncode(body)),
      tags: [
        ['p', targetPubkey],
      ],
      secretKey: sourceSecret,
      createdAt: 1_700_000_000 + _eventSequence++,
    );
    relayMessageCallback(['EVENT', 'pair', event.toMap()]);
  }
}
