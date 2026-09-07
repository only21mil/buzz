import 'dart:async';

import 'package:buzz/shared/community/community.dart';
import 'package:buzz/shared/community/community_provider.dart';
import 'package:buzz/shared/community/community_storage.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import 'community_storage_test.dart';

void main() {
  for (final signOut in [false, true]) {
    test(
      'removal journals an in-flight reservation before deleting: signout=$signOut',
      () async {
        final secure = _PausedSecureStorage();
        final storage = CommunityStorage(secure: secure);
        final community = Community.create(
          name: 'A',
          relayUrl: 'wss://a.example',
        ).copyWith(pushNotificationsEnabled: true);
        await storage.save(community);
        await storage.saveActiveId(community.id);
        final snapshots = <List<Community>>[];
        final journaled = <Community>[];
        final container = ProviderContainer(
          overrides: [
            communityStorageProvider.overrideWithValue(storage),
            communitySnapshotWriterProvider.overrideWithValue((values) async {
              snapshots.add(values);
            }),
            communityPushLeaseRevocationEnqueuerProvider.overrideWithValue((
              value,
            ) async {
              journaled.add(value);
              return false;
            }),
          ],
        );
        addTearDown(container.dispose);
        await container.read(communityListProvider.future);
        final notifier = container.read(communityListProvider.notifier);
        secure.pause = true;
        final reservation = notifier.reservePushLeaseGeneration(community.id);
        await secure.entered.future;
        final removal = signOut
            ? notifier.removeActiveCommunityForSignOut()
            : notifier.removeCommunity(community.id);
        await Future<void>.delayed(Duration.zero);
        secure.resume.complete();
        expect(await reservation, 1);
        await removal;
        expect(journaled.single.pushSubscriptionState.generationCursor, 1);
        expect(await storage.loadAll(), isEmpty);
        expect(container.read(communityListProvider).requireValue, isEmpty);
        expect(snapshots.last, isEmpty);
      },
    );
  }
}

class _PausedSecureStorage extends FakeSecureStorage {
  bool pause = false;
  final entered = Completer<void>();
  final resume = Completer<void>();

  @override
  Future<void> write({
    required String key,
    required String? value,
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    if (pause && key == 'buzz_communities') {
      pause = false;
      entered.complete();
      await resume.future;
    }
    await super.write(key: key, value: value);
  }
}
