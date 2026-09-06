import 'dart:async';

import 'package:buzz/shared/community/community.dart';
import 'package:buzz/shared/community/community_provider.dart';
import 'package:buzz/shared/community/community_storage.dart';
import 'package:buzz/shared/push/dev_push_lease.dart';
import 'package:buzz/shared/push/push_bridge.dart';
import 'package:buzz/shared/push/push_cohort_publication.dart';
import 'package:buzz/shared/push/push_subscription.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:nostr/nostr.dart' as nostr;

import '../community/community_storage_test.dart';

const channel = MethodChannel('buzz/push');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late ProviderContainer container;
  late CommunityStorage storage;
  late CommunityListNotifier notifier;
  late List<Community> communities;
  late List<Map<dynamic, dynamic>> snapshots;
  late List<String> published;
  late Future<Object?> Function(MethodCall) native;

  setUp(() async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    snapshots = [];
    published = [];
    communities = [
      for (final id in ['a', 'b']) _community(id),
    ];
    native = (call) async => switch (call.method) {
      'enrollPush' => _grantMap('a'),
      'endpointGrants' => [
        for (final id in ['a', 'b']) _grantMap(id),
      ],
      _ => null,
    };
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'syncPushSnapshot') {
            snapshots.add(call.arguments as Map<dynamic, dynamic>);
            return null;
          }
          return native(call);
        });
    storage = CommunityStorage(secure: FakeSecureStorage());
    for (final community in communities) {
      await storage.save(community);
    }
    await storage.saveActiveId(communities.first.id);
    container = ProviderContainer(
      overrides: [
        communityStorageProvider.overrideWithValue(storage),
        communityPushLeaseRevocationEnqueuerProvider.overrideWithValue(
          (_) async => false,
        ),
        communityPushLeaseDeactivatorProvider.overrideWithValue(
          (_, {generation}) async {},
        ),
      ],
    );
    await container.read(communityListProvider.future);
    notifier = container.read(communityListProvider.notifier);
  });

  tearDown(() {
    container.dispose();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    debugDefaultTargetPlatformOverride = null;
  });

  Future<BuzzPushEndpointGrant> run({bool failB = false}) =>
      publishBuzzPushCohort(
        notifier: notifier,
        communities: container.read(communityListProvider).requireValue,
        enroll: () => enrollBuzzPush('wss://a.example', 'https://push.example'),
        readGrants: readBuzzPushEndpointGrants,
        descriptorFor: (url) async => _descriptor(url),
        publish: (community, grant, descriptor, generation) async {
          expect(grant.endpointGrant, 'renewed-shared-authority');
          expect(descriptor.origin, community.relayUrl);
          expect(generation, greaterThan(0));
          published.add(community.id);
          if (failB && community.id == 'b') {
            throw StateError('relay disconnected');
          }
        },
      );

  for (final suspendedMethod in ['enrollPush', 'endpointGrants']) {
    for (final mutation in [
      'remove',
      'signout',
      'optout',
      'optout ABA',
      'remove ABA',
      'credentials',
    ]) {
      test(
        '$mutation during $suspendedMethod cannot publish captured authority',
        () async {
          final entered = Completer<void>();
          final resume = Completer<void>();
          final originalNative = native;
          var delayed = false;
          native = (call) async {
            if (call.method == suspendedMethod && !delayed) {
              delayed = true;
              entered.complete();
              await resume.future;
            }
            return originalNative(call);
          };
          final pending = run();
          await entered.future;
          switch (mutation) {
            case 'remove':
            case 'remove ABA':
              await notifier.removeCommunity('a');
              if (mutation == 'remove ABA') {
                await notifier.addCommunity(communities.first);
              }
            case 'signout':
              await notifier.removeActiveCommunityForSignOut();
            case 'optout':
            case 'optout ABA':
              await notifier.setPushNotificationsEnabled('a', false);
              if (mutation == 'optout ABA') {
                await notifier.setPushNotificationsEnabled('a', true);
              }
            case 'credentials':
              await notifier.addCommunity(
                communities.first.copyWith(nsec: nostr.Keys.generate().nsec),
              );
          }
          resume.complete();
          await pending;
          expect(published, ['b']);
          final current = container.read(communityListProvider).requireValue;
          final expectedIds = current
              .where((c) => c.pushNotificationsEnabled)
              .map((c) => c.id)
              .toList();
          expect(
            (snapshots.last['communities'] as List).map((c) => c['id']),
            expectedIds,
          );
          expect((snapshots.last['signingKeys'] as Map).keys, expectedIds);
          expect(
            (await storage.loadAll()).map((c) => c.id),
            current.map((c) => c.id),
          );
        },
      );
    }
  }

  test('disposed lifecycle rejects delayed native completion', () async {
    final entered = Completer<void>();
    final resume = Completer<void>();
    final originalNative = native;
    native = (call) async {
      if (call.method == 'enrollPush') {
        entered.complete();
        await resume.future;
      }
      return originalNative(call);
    };
    final pending = run();
    await entered.future;
    container.dispose();
    final count = snapshots.length;
    resume.complete();
    await pending;
    expect(snapshots.length, count);
    expect(published, isEmpty);
  });

  for (final policyChange in ['changed', 'ABA', 'unchanged']) {
    test(
      '$policyChange policy while descriptor waits preserves newer acceptance',
      () async {
        final entered = Completer<void>();
        final resume = Completer<void>();
        final publications = <(int, String)>[];
        final oldDesired = communities.first.pushSubscriptionState.desired;
        final newDesired = buildDesiredBuzzPushSubscriptions(
          myPubkey: communities.first.pubkey!,
          channelIds: const ['123e4567-e89b-42d3-a456-426614174099'],
          mutedChannelIds: const ['123e4567-e89b-42d3-a456-426614174099'],
        );
        Future<BuzzPushEndpointGrant> publishPolicy({bool delay = false}) =>
            publishBuzzPushCohort(
              notifier: notifier,
              communities: [
                container.read(communityListProvider).requireValue.first,
              ],
              enroll: () =>
                  enrollBuzzPush('wss://a.example', 'https://push.example'),
              readGrants: readBuzzPushEndpointGrants,
              descriptorFor: (url) async {
                if (delay) {
                  entered.complete();
                  await resume.future;
                }
                return _descriptor(url);
              },
              publish: (community, grant, descriptor, generation) async {
                publications.add((
                  generation,
                  buzzPushSubscriptionsFingerprint(
                    community.pushSubscriptionState.desired,
                  ),
                ));
              },
            );
        final pending = publishPolicy(delay: true);
        await entered.future;
        await notifier.updateDesiredPushSubscriptions(
          'a',
          policyChange == 'unchanged' ? oldDesired : newDesired,
        );
        if (policyChange == 'ABA') {
          await notifier.updateDesiredPushSubscriptions('a', oldDesired);
        }
        await publishPolicy();
        final before = container
            .read(communityListProvider)
            .requireValue
            .first
            .pushSubscriptionState;
        expect(before.acceptedGeneration, 1);
        expect(
          buzzPushSubscriptionsFingerprint(before.accepted!),
          buzzPushSubscriptionsFingerprint(before.desired),
        );
        resume.complete();
        await pending;
        final after = (await storage.loadAll()).first.pushSubscriptionState;
        final expectedFingerprint = buzzPushSubscriptionsFingerprint(
          before.desired,
        );
        expect(publications, [
          (1, expectedFingerprint),
          if (policyChange == 'unchanged') (2, expectedFingerprint),
        ]);
        expect(after.generationCursor, policyChange == 'unchanged' ? 2 : 1);
        expect(after.acceptedGeneration, after.generationCursor);
        expect(
          buzzPushSubscriptionsFingerprint(after.accepted!),
          expectedFingerprint,
        );
      },
    );
  }

  for (final restorePolicy in [false, true]) {
    test(
      'late relay acceptance rejects policy change (ABA: $restorePolicy)',
      () async {
        final entered = Completer<void>();
        final resume = Completer<void>();
        final pending = publishBuzzPushCohort(
          notifier: notifier,
          communities: [communities.first],
          enroll: () =>
              enrollBuzzPush('wss://a.example', 'https://push.example'),
          readGrants: readBuzzPushEndpointGrants,
          descriptorFor: (url) async => _descriptor(url),
          publish: (community, grant, descriptor, generation) async {
            entered.complete();
            await resume.future;
          },
        );
        await entered.future;
        await notifier.updateDesiredPushSubscriptions(
          'a',
          buildDesiredBuzzPushSubscriptions(
            myPubkey: communities.first.pubkey!,
          ),
        );
        if (restorePolicy) {
          await notifier.updateDesiredPushSubscriptions(
            'a',
            communities.first.pushSubscriptionState.desired,
          );
        }
        resume.complete();
        await pending;
        final after = (await storage.loadAll()).first.pushSubscriptionState;
        expect(after.generationCursor, 1);
        expect(after.acceptedGeneration, isNull);
        expect(after.accepted, isNull);
      },
    );
  }

  test(
    'late relay acceptance cannot cross opt-out and re-enable ABA',
    () async {
      final entered = Completer<void>();
      final resume = Completer<void>();
      final pending = publishBuzzPushCohort(
        notifier: notifier,
        communities: communities,
        enroll: () => enrollBuzzPush('wss://a.example', 'https://push.example'),
        readGrants: readBuzzPushEndpointGrants,
        descriptorFor: (url) async => _descriptor(url),
        publish: (community, grant, descriptor, generation) async {
          if (community.id == 'a') {
            entered.complete();
            await resume.future;
          }
        },
      );
      await entered.future;
      await notifier.setPushNotificationsEnabled('a', false);
      await notifier.setPushNotificationsEnabled('a', true);
      final before = container
          .read(communityListProvider)
          .requireValue
          .first
          .pushSubscriptionState;
      resume.complete();
      await pending;
      final after = container
          .read(communityListProvider)
          .requireValue
          .first
          .pushSubscriptionState;
      expect(after, before);
      expect(after.generationCursor, greaterThan(1));
    },
  );

  test(
    'renewal republishes A and B and retries partial failure for both',
    () async {
      await expectLater(run(failB: true), throwsStateError);
      expect(published, ['a', 'b']);
      final first = container.read(communityListProvider).requireValue;
      expect(first.first.pushSubscriptionState.acceptedGeneration, 1);
      expect(first.last.pushSubscriptionState.acceptedGeneration, isNull);
      await run();
      expect(published, ['a', 'b', 'a', 'b']);
      for (final community
          in container.read(communityListProvider).requireValue) {
        expect(community.pushSubscriptionState.acceptedGeneration, 2);
      }
    },
  );

  test(
    'native enrollment failure is retryable without snapshot or publication',
    () async {
      final originalNative = native;
      native = (_) async => throw PlatformException(code: 'interrupted');
      final count = snapshots.length;
      await expectLater(run(), throwsA(isA<PlatformException>()));
      expect(snapshots.length, count);
      expect(published, isEmpty);
      native = originalNative;
      await run();
      expect(published, ['a', 'b']);
    },
  );
}

Community _community(String id) {
  final keys = nostr.Keys.generate();
  return Community(
    id: id,
    name: id,
    relayUrl: 'wss://$id.example',
    nsec: keys.nsec,
    pubkey: keys.public,
    pushNotificationsEnabled: true,
    pushSubscriptionState: BuzzPushLeaseSubscriptionState.desired(
      desired: [
        BuzzPushSubscription(
          filter: BuzzPushFilter(kinds: const [9], pTags: [keys.public]),
          notificationClass: 'default',
        ),
      ],
    ),
    addedAt: DateTime(2026),
  );
}

Map<String, Object> _grantMap(String id) => {
  'relayOrigin': 'wss://$id.example',
  'relayPubkey': 'a' * 64,
  'installationId': (id == 'a' ? '1' : '2') * 32,
  'endpointGrant': 'renewed-shared-authority',
  'endpointHash': 'e' * 64,
  'appProfile': buzzDevPushAppProfile,
  'endpointEpoch': 1,
  'generation': 8,
  'expiresAt': 2000000000,
};

BuzzPushLeaseDescriptor _descriptor(String origin) => BuzzPushLeaseDescriptor(
  origin: origin,
  executorKeyId: 'current',
  executorPubkey: 'a' * 64,
  transport: 'apns',
  maxLeaseTtlSeconds: 3600,
  maxContentLength: 4096,
  maxPlaintextLength: 4096,
  maxEndpointLength: 2048,
  maxStringLength: 512,
);
