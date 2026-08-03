import 'package:buzz/features/notifications/notification_event_deduper.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('rejects duplicate event IDs', () {
    final deduper = NotificationEventDeduper(capacity: 2);

    expect(deduper.add('one'), isTrue);
    expect(deduper.add('one'), isFalse);
  });

  test('evicts the oldest event ID at its bound', () {
    final deduper = NotificationEventDeduper(capacity: 2);

    expect(deduper.add('one'), isTrue);
    expect(deduper.add('two'), isTrue);
    expect(deduper.add('three'), isTrue);
    expect(deduper.add('two'), isFalse);
    expect(deduper.add('one'), isTrue);
  });
}
