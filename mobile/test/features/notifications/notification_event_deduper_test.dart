import 'package:buzz/features/notifications/notification_event_deduper.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('rejects duplicate event IDs', () {
    final deduper = NotificationEventDeduper(capacity: 2);

    expect(deduper.reserve('one'), isNotNull);
    expect(deduper.reserve('one'), isNull);
  });

  test('evicts the oldest event ID at its bound', () {
    final deduper = NotificationEventDeduper(capacity: 2);

    expect(deduper.reserve('one'), isNotNull);
    expect(deduper.reserve('two'), isNotNull);
    expect(deduper.reserve('three'), isNotNull);
    expect(deduper.reserve('two'), isNull);
    expect(deduper.reserve('one'), isNotNull);
  });

  test('allows a failed delivery to release its reservation', () {
    final deduper = NotificationEventDeduper();

    expect(deduper.reserve('one'), isNotNull);
    deduper.remove('one');
    expect(deduper.reserve('one'), isNotNull);
  });

  test('hands out distinct Android-safe ids that wrap before overflow', () {
    final deduper = NotificationEventDeduper(firstId: maxNotificationId - 1);

    expect(deduper.reserve('one'), maxNotificationId - 1);
    expect(deduper.reserve('two'), maxNotificationId);
    expect(deduper.reserve('three'), 1);
    expect(deduper.reserve('four'), 2);

    final seeded = NotificationEventDeduper();
    expect(seeded.reserve('one'), inInclusiveRange(1, maxNotificationId));
  });
}
