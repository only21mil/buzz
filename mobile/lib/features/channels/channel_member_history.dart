part of 'channels_provider.dart';

extension _ChannelMemberHistory on ChannelsNotifier {
  void _cacheMemberSnapshots(
    Iterable<NostrEvent> events, {
    bool replaceAll = false,
  }) {
    final latestByChannelId = <String, NostrEvent>{};
    for (final event in events) {
      final channelId = event.getTagValue('d');
      if (channelId == null) continue;
      final current = latestByChannelId[channelId];
      if (current == null || event.createdAt > current.createdAt) {
        latestByChannelId[channelId] = event;
      }
    }

    final snapshots = replaceAll
        ? <String, List<ChannelMember>>{}
        : Map<String, List<ChannelMember>>.of(_memberSnapshotsByChannelId);
    snapshots.addAll({
      for (final entry in latestByChannelId.entries)
        entry.key: List.unmodifiable([
          for (final member in membersFromEvent(entry.value))
            ChannelMember(
              pubkey: member.pubkey,
              role: member.role,
              joinedAt: DateTime.fromMillisecondsSinceEpoch(
                entry.value.createdAt * 1000,
                isUtc: true,
              ),
            ),
        ]),
    });
    _memberSnapshotsByChannelId = Map.unmodifiable(snapshots);
  }

  /// Fetches each channel's independent latest-message window in one HTTP
  /// bridge request. The relay preserves NIP-01 per-filter limits while
  /// executing the filters with bounded concurrency, avoiding an unbounded
  /// burst of websocket REQs on communities with many channels.
  Future<List<NostrEvent>> _fetchLastMessageEvents(
    RelaySessionNotifier session,
    List<Channel> channels,
  ) async {
    if (channels.isEmpty) return const [];

    final filters = [
      for (final channel in channels)
        NostrFilter(
          kinds: EventKind.channelMessageEventKinds,
          tags: {
            '#h': [channel.id],
          },
          limit: channel.isDm ? 1 : 20,
        ),
    ];

    return _fetchChannelHistoryBatch(
      session,
      filters,
      operation: 'latest-message query',
    );
  }

  Future<List<NostrEvent>> _fetchChannelHistoryBatch(
    RelaySessionNotifier session,
    List<NostrFilter> filters, {
    required String operation,
  }) async {
    if (filters.isEmpty) return const [];

    try {
      return await session.queryRelay(filters);
    } catch (error) {
      debugPrint(
        '[ChannelsNotifier] batched $operation failed; '
        'using bounded websocket fallback: $error',
      );
    }

    const fallbackConcurrency = 4;
    final events = <NostrEvent>[];
    for (var start = 0; start < filters.length; start += fallbackConcurrency) {
      final end = min(start + fallbackConcurrency, filters.length);
      final results = await Future.wait(
        filters.sublist(start, end).map((filter) async {
          try {
            return await session.fetchHistory(filter);
          } catch (_) {
            return const <NostrEvent>[];
          }
        }),
      );
      for (final result in results) {
        events.addAll(result);
      }
    }
    return events;
  }
}
