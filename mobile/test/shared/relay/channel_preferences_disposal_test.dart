import 'dart:async';

import 'package:buzz/features/channels/channel_mutes/channel_mutes_manager.dart';
import 'package:buzz/features/channels/channel_sort/channel_sort_manager.dart';
import 'package:buzz/features/channels/channel_stars/channel_stars_manager.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nostr/nostr.dart' as nostr;
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  for (final name in ['stars', 'mutes', 'sort']) {
    for (final duringHistory in [false, true]) {
      test(
        '$name disposal during ${duringHistory ? 'history' : 'subscribe'}',
        () async {
          SharedPreferences.setMockInitialValues({});
          final prefs = await SharedPreferences.getInstance();
          final keys = nostr.Keys.generate();
          final relay = _DeferredSession(duringHistory);
          var changes = 0;
          late Future<void> Function() initialize;
          late void Function() dispose;
          switch (name) {
            case 'stars':
              final manager = ChannelStarsManager(
                pubkey: keys.public,
                prefs: prefs,
                crypto: ChannelStarsCrypto(keys.nsec, keys.public),
                relaySession: relay,
                signedEventRelay: null,
                remoteEnabled: true,
                onChanged: () => changes++,
              );
              initialize = manager.initialize;
              dispose = () => manager.dispose(flushPending: false);
            case 'mutes':
              final manager = ChannelMutesManager(
                pubkey: keys.public,
                prefs: prefs,
                crypto: ChannelMutesCrypto(keys.nsec, keys.public),
                relaySession: relay,
                signedEventRelay: null,
                remoteEnabled: true,
                onChanged: () => changes++,
              );
              initialize = manager.initialize;
              dispose = () => manager.dispose(flushPending: false);
            case 'sort':
              final manager = ChannelSortManager(
                pubkey: keys.public,
                relayUrl: 'wss://relay.example',
                prefs: prefs,
                crypto: ChannelSortCrypto(keys.nsec, keys.public),
                relaySession: relay,
                signedEventRelay: null,
                remoteEnabled: true,
                onChanged: () => changes++,
              );
              initialize = manager.initialize;
              dispose = manager.dispose;
          }
          final pending = initialize();
          await relay.started.future;
          dispose();
          final changesAtDisposal = changes;
          var cancellations = 0;
          if (duringHistory) {
            relay.history.complete([]);
          } else {
            relay.subscription.complete(() => cancellations++);
          }
          await pending;
          expect(changes, changesAtDisposal);
          expect(relay.subscribeCount, duringHistory ? 0 : 1);
          expect(cancellations, duringHistory ? 0 : 1);
          dispose();
          expect(cancellations, duringHistory ? 0 : 1);
        },
      );
    }
  }
}

class _DeferredSession extends RelaySessionNotifier {
  final bool duringHistory;
  final started = Completer<void>();
  final history = Completer<List<NostrEvent>>();
  final subscription = Completer<void Function()>();
  int subscribeCount = 0;

  _DeferredSession(this.duringHistory);

  @override
  Future<List<NostrEvent>> fetchHistory(
    NostrFilter filter, {
    Duration timeout = const Duration(seconds: 8),
  }) {
    if (duringHistory) {
      started.complete();
      return history.future;
    }
    return Future.value([]);
  }

  @override
  Future<void Function()> subscribe(
    NostrFilter filter,
    void Function(NostrEvent) onEvent, {
    void Function(String message)? onClosed,
  }) {
    subscribeCount++;
    started.complete();
    return subscription.future;
  }
}
