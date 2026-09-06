import 'dart:async';

import 'package:buzz/app.dart';
import 'package:buzz/features/channels/channel.dart';
import 'package:buzz/features/channels/channels_provider.dart';
import 'package:buzz/features/invites/invite_join_provider.dart';
import 'package:buzz/shared/auth/auth.dart';
import 'package:buzz/shared/deeplink/deep_link.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:nostr/nostr.dart' as nostr;

import '../../shared/community/community_storage_test.dart';

const _origin = 'https://a.example';

Channel _channel(
  String slug, {
  bool archived = false,
  String visibility = 'open',
  String channelType = 'stream',
  String? name,
}) => Channel(
  id: desktopStarterChannelId(relayHttpOrigin: _origin, slug: slug),
  name: name ?? slug,
  channelType: channelType,
  visibility: visibility,
  description: '',
  createdBy: 'me',
  createdAt: DateTime.utc(2026),
  memberCount: 1,
  isMember: true,
  archivedAt: archived ? DateTime.utc(2026) : null,
);

class _Config extends RelayConfigNotifier {
  @override
  RelayConfig build() => const RelayConfig(baseUrl: _origin);
}

class _Session extends RelaySessionNotifier {
  @override
  SessionState build() =>
      const SessionState(status: SessionStatus.disconnected);

  void setStatus(SessionStatus value) => state = SessionState(status: value);
}

class _Channels extends ChannelsNotifier {
  int refreshes = 0;

  @override
  Future<List<Channel>> build() async => [
    _channel('general'),
    _channel('welcome-everyone'),
  ];

  @override
  Future<void> refresh({bool fetchDirectory = false}) async {
    expectSync(fetchDirectory, isTrue);
    refreshes++;
  }
}

final _factory = Provider<InviteJoinRecovery Function()>((ref) {
  return () {
    final config = ref.read(relayConfigProvider);
    return buildMobileInviteJoinRecovery(
      ref,
      InviteJoinRecoveryScope(
        relayHttpOrigin: config.baseUrl,
        nsec: config.nsec,
      ),
    );
  };
});

ProviderContainer _container(_Session session, _Channels channels) =>
    ProviderContainer(
      overrides: [
        relayConfigProvider.overrideWith(_Config.new),
        relaySessionProvider.overrideWith(() => session),
        channelsProvider.overrideWith(() => channels),
        activeCommunityProvider.overrideWith((ref) async => null),
      ],
    );

void main() {
  for (final visitOtherCommunity in [false, true]) {
    testWidgets(
      'timed out recovery retries on healthy A, visit B: $visitOtherCommunity',
      (tester) async {
        final session = _Session();
        final channels = _Channels();
        final container = _container(session, channels);

        final first = expectLater(
          container.read(_factory)().ensureStarterChannels(),
          throwsA(isA<TimeoutException>()),
        );
        await tester.pump();
        await tester.pump(const Duration(seconds: 16));
        await first;
        expect(channels.refreshes, 0);

        if (visitOtherCommunity) {
          container
              .read(relayConfigProvider.notifier)
              .update(baseUrl: 'https://b.example');
          session.setStatus(SessionStatus.connected);
          await tester.pump();
          container.read(relayConfigProvider.notifier).update(baseUrl: _origin);
        } else {
          session.setStatus(SessionStatus.connected);
        }
        await tester.pump();
        final retry = container.read(_factory)().ensureStarterChannels();
        await tester.pump();
        expect(await retry, _channel('welcome-everyone').id);
        expect(channels.refreshes, 1);
        container.dispose();
        await tester.pump();
      },
    );
  }

  testWidgets(
    'a successful attempt does not cache a later offline connection',
    (tester) async {
      final session = _Session();
      final channels = _Channels();
      final container = _container(session, channels);
      container.read(relaySessionProvider);
      session.setStatus(SessionStatus.connected);
      final first = container.read(_factory)().ensureStarterChannels();
      await tester.pump();
      await first;
      expect(channels.refreshes, 1);

      session.setStatus(SessionStatus.disconnected);
      var completed = false;
      final retry = container.read(_factory)().ensureStarterChannels().then((
        id,
      ) {
        completed = true;
        return id;
      });
      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      expect(completed, isFalse);
      expect(channels.refreshes, 1);
      session.setStatus(SessionStatus.connected);
      await tester.pump();
      expect(await retry, _channel('welcome-everyone').id);
      expect(channels.refreshes, 2);
      container.dispose();
      await tester.pump();
    },
  );

  for (final changeIdentity in [false, true]) {
    testWidgets(
      'scope change aborts pending recovery and permits fresh retry, identity: $changeIdentity',
      (tester) async {
        final session = _Session();
        final channels = _Channels();
        final container = _container(session, channels);
        final recovery = container.read(_factory)();
        final first = expectLater(
          recovery.ensureStarterChannels(),
          throwsA(isA<StateError>()),
        );
        await tester.pump();
        container
            .read(relayConfigProvider.notifier)
            .update(
              baseUrl: changeIdentity ? _origin : 'https://b.example',
              nsec: changeIdentity ? 'different-test-identity' : null,
            );
        // No session event is needed to abort an obsolete connection wait.
        await tester.pump();
        await first;
        expect(channels.refreshes, 0);
        await expectLater(
          recovery.ensureStarterChannels(),
          throwsA(isA<StateError>()),
        );

        session.setStatus(SessionStatus.connected);
        final retry = container.read(_factory)().ensureStarterChannels();
        await tester.pump();
        expect(await retry, _channel('welcome-everyone').id);
        expect(channels.refreshes, 1);
        container.dispose();
        await tester.pump();
      },
    );
  }

  for (final invalid in [
    (label: 'archived', channel: _channel('general', archived: true)),
    (label: 'private', channel: _channel('general', visibility: 'private')),
    (label: 'forum', channel: _channel('general', channelType: 'forum')),
    (label: 'dm', channel: _channel('general', channelType: 'dm')),
    (label: 'renamed', channel: _channel('general', name: 'unrelated')),
  ]) {
    test(
      'duplicate ${invalid.label} starter retains durable recovery marker',
      () async {
        final keys = nostr.Keys.generate();
        final storage = CommunityStorage(secure: FakeSecureStorage());
        await storage.save(
          Community(
            id: 'recovering',
            name: 'Community A',
            relayUrl: _origin,
            pubkey: keys.public,
            nsec: keys.nsec,
            addedAt: DateTime.utc(2026),
            starterSetupIncomplete: true,
          ),
        );
        var loads = 0;
        var creates = 0;
        final recovery = MobileInviteJoinRecovery(
          loadChannels: () async {
            loads++;
            return [invalid.channel, _channel('welcome-everyone')];
          },
          createChannel:
              ({
                required channelId,
                required name,
                required channelType,
                required visibility,
                description,
                ttlSeconds,
              }) async {
                creates++;
                expect(channelId, invalid.channel.id);
                throw Exception('duplicate: channel already exists');
              },
          joinChannel: (_) async => fail('Invalid starters must not be joined'),
          relayHttpOrigin: _origin,
        );
        final container = ProviderContainer(
          overrides: [
            communityStorageProvider.overrideWithValue(storage),
            inviteJoinRecoveryProvider.overrideWithValue((_) => recovery),
          ],
        );
        addTearDown(container.dispose);
        final notifier = container.read(inviteJoinProvider.notifier);
        await notifier.prepare(
          const InviteDeepLink(relayUrl: 'wss://a.example', code: 'code'),
        );
        await notifier.startStarterSetupRecovery();

        expect(loads, 2);
        expect(creates, 1);
        expect(
          container.read(inviteJoinProvider).status,
          InviteJoinStatus.error,
        );
        expect(
          container.read(inviteJoinProvider).isStarterSetupRecovery,
          isTrue,
        );
        expect((await storage.loadAll()).single.starterSetupIncomplete, isTrue);
      },
    );
  }

  test('valid deterministic duplicate starters remain idempotent', () async {
    var loads = 0;
    var creates = 0;
    final recovery = MobileInviteJoinRecovery(
      loadChannels: () async {
        loads++;
        return loads == 1
            ? []
            : [_channel('general'), _channel('welcome-everyone')];
      },
      createChannel:
          ({
            required channelId,
            required name,
            required channelType,
            required visibility,
            description,
            ttlSeconds,
          }) async {
            creates++;
            throw Exception('duplicate: channel already exists');
          },
      joinChannel: (_) async => fail('Existing memberships are preserved'),
      relayHttpOrigin: _origin,
    );
    expect(
      await recovery.ensureStarterChannels(),
      _channel('welcome-everyone').id,
    );
    expect(
      await recovery.ensureStarterChannels(),
      _channel('welcome-everyone').id,
    );
    expect(creates, 1);
    expect(loads, 3);
  });
}
