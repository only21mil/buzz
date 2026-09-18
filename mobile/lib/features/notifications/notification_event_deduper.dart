import 'dart:collection';

/// Largest id Android accepts for a notification (a positive Java int).
const maxNotificationId = 0x7fffffff;

/// Remembers recently delivered events and hands each one a notification id.
///
/// Ids come from a counter rather than a hash of the event id: a 31-bit hash
/// collides silently and `FLAG_UPDATE_CURRENT` then replaces an unrelated
/// notification. The counter is seeded from the clock so ids from a previous
/// process are unlikely to be reused while its notifications are still shown.
class NotificationEventDeduper {
  NotificationEventDeduper({this.capacity = 1000, int? firstId})
    : assert(capacity > 0),
      assert(firstId == null || (firstId >= 1 && firstId <= maxNotificationId)),
      _nextId = firstId ?? _seedId();

  final int capacity;
  final LinkedHashMap<String, int> _idsByEventId = LinkedHashMap<String, int>();
  int _nextId;

  /// Assigns a notification id to [eventId], or null when it was already seen.
  int? reserve(String eventId) {
    if (_idsByEventId.containsKey(eventId)) return null;
    if (_idsByEventId.length == capacity) {
      _idsByEventId.remove(_idsByEventId.keys.first);
    }
    final id = _nextId;
    _nextId = id == maxNotificationId ? 1 : id + 1;
    _idsByEventId[eventId] = id;
    return id;
  }

  /// Forgets [eventId] after a failed delivery so a later relay copy can retry.
  void remove(String eventId) => _idsByEventId.remove(eventId);

  static int _seedId() =>
      DateTime.now().millisecondsSinceEpoch % maxNotificationId + 1;
}
