import 'dart:async';

import 'package:buzz/features/channels/channel_typing_provider.dart';
import 'package:buzz/features/profile/presence_cache_provider.dart';
import 'package:buzz/features/profile/user_status_cache_provider.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

void main() {
  final initialize = <String, void Function(ProviderContainer)>{
    'typing': (container) {
      container.listen(channelTypingProvider('channel'), (_, _) {});
    },
    'presence': (container) {
      container.read(presenceCacheProvider.notifier).track(['alice']);
    },
    'user status': (container) {
      container.read(userStatusCacheProvider.notifier).track(['alice']);
    },
  };

  for (final entry in initialize.entries) {
    test(
      '${entry.key} releases a subscription completed after disposal',
      () async {
        final session = _DeferredSession();
        final client = RelayClient(baseUrl: 'http://localhost');
        addTearDown(client.dispose);
        final container = ProviderContainer(
          overrides: [
            relaySessionProvider.overrideWith(() => session),
            relayClientProvider.overrideWithValue(client),
          ],
        );
        entry.value(container);
        expect(session.onEvent, isNotNull);
        container.dispose();

        // The relay can deliver before subscribe() returns its unsubscribe handle.
        expect(
          () => session.onEvent!(
            NostrEvent(
              id: 'late',
              pubkey: 'alice',
              createdAt: 1,
              kind: session.filter!.kinds.single,
              tags: const [
                ['d', 'general'],
              ],
              content: 'online',
              sig: '',
            ),
          ),
          returnsNormally,
        );
        var cancelled = 0;
        session.ready.complete(() => cancelled++);
        await Future<void>.delayed(Duration.zero);
        expect(cancelled, 1);
      },
    );
  }
}

class _DeferredSession extends RelaySessionNotifier {
  final ready = Completer<void Function()>();
  void Function(NostrEvent)? onEvent;
  NostrFilter? filter;

  @override
  SessionState build() => const SessionState(status: SessionStatus.connected);

  @override
  Future<void Function()> subscribe(
    NostrFilter filter,
    void Function(NostrEvent) onEvent, {
    void Function(String message)? onClosed,
  }) {
    this.filter = filter;
    this.onEvent = onEvent;
    return ready.future;
  }
}
