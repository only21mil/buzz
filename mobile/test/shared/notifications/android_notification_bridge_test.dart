import 'package:buzz/shared/notifications/notifications.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _channel = MethodChannel('xyz.block.buzz.mobile/notifications');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late List<MethodCall> calls;
  late AndroidNotificationBridge bridge;

  setUp(() {
    calls = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (call) async {
          calls.add(call);
          return switch (call.method) {
            'getStatus' => <String, Object>{
              'permission': 'granted',
              'priorityChannelEnabled': true,
              'activityChannelEnabled': false,
            },
            'getInitialRoute' => 'buzz://message?id=initial',
            _ => null,
          };
        });
    bridge = AndroidNotificationBridge(channel: _channel);
  });

  tearDown(() {
    bridge.dispose();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, null);
  });

  test('maps status and uses the frozen method names', () async {
    final status = await bridge.getStatus();
    final requested = await bridge.requestPermission();
    final ensured = await bridge.ensureChannels();

    expect(status.permission, AndroidNotificationPermission.granted);
    expect(status.priorityChannelEnabled, isTrue);
    expect(status.activityChannelEnabled, isFalse);
    expect(requested.permission, AndroidNotificationPermission.granted);
    expect(ensured.permission, AndroidNotificationPermission.granted);
    expect(calls.map((call) => call.method), [
      'getStatus',
      'requestPermission',
      'getStatus',
      'ensureChannels',
      'getStatus',
    ]);
  });

  test('show sends exactly the frozen argument keys', () async {
    await bridge.show(
      id: 21,
      channel: 'priority',
      title: 'Sats',
      body: 'Ping',
      route: 'buzz://message?id=abc',
    );

    expect(calls.single.method, 'show');
    expect(calls.single.arguments, <String, Object>{
      'id': 21,
      'channel': 'priority',
      'title': 'Sats',
      'body': 'Ping',
      'route': 'buzz://message?id=abc',
    });
  });

  test('exposes initial and incoming tap routes', () async {
    expect(await bridge.getInitialRoute(), 'buzz://message?id=initial');

    final tapped = bridge.notificationTaps.first;
    await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
          _channel.name,
          const StandardMethodCodec().encodeMethodCall(
            const MethodCall('notificationTapped', 'buzz://message?id=tapped'),
          ),
          (_) {},
        );

    expect(
      await tapped.timeout(const Duration(seconds: 1)),
      'buzz://message?id=tapped',
    );
  });

  test('opens Android settings through the frozen method', () async {
    await bridge.openSettings();
    expect(calls.single.method, 'openSettings');
    expect(calls.single.arguments, isNull);
  });
}
