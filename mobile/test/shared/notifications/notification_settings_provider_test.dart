import 'package:buzz/shared/notifications/notifications.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:buzz/shared/theme/theme.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late TargetPlatform? previousPlatform;

  setUp(() {
    previousPlatform = debugDefaultTargetPlatformOverride;
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
  });

  tearDown(() {
    debugDefaultTargetPlatformOverride = previousPlatform;
  });

  Future<ProviderContainer> container({
    Map<String, Object> preferences = const {},
    AndroidNotificationStatus status = const AndroidNotificationStatus(
      permission: AndroidNotificationPermission.notDetermined,
      priorityChannelEnabled: true,
      activityChannelEnabled: true,
    ),
  }) async {
    SharedPreferences.setMockInitialValues(preferences);
    final prefs = await SharedPreferences.getInstance();
    final bridge = _FakeBridge(status);
    final result = ProviderContainer(
      overrides: [
        savedPrefsProvider.overrideWithValue(prefs),
        relayConfigProvider.overrideWith(
          () => _RelayConfigNotifier('https://relay.example'),
        ),
        relaySessionProvider.overrideWith(_DisconnectedSession.new),
        androidNotificationBridgeProvider.overrideWithValue(bridge),
      ],
    );
    addTearDown(result.dispose);
    return result;
  }

  test('defaults master off, priority on, and activity off', () async {
    final scope = await container();
    final bridge = scope.read(androidNotificationBridgeProvider) as _FakeBridge;

    final state = scope.read(notificationSettingsProvider);
    await Future<void>.delayed(Duration.zero);

    expect(state.alertsEnabled, isFalse);
    expect(state.priorityEnabled, isTrue);
    expect(state.activityEnabled, isFalse);
    expect(bridge.permissionRequests, 0);
  });

  test('requests permission only on explicit master enable', () async {
    final scope = await container(
      status: const AndroidNotificationStatus(
        permission: AndroidNotificationPermission.granted,
        priorityChannelEnabled: true,
        activityChannelEnabled: true,
      ),
    );
    final bridge = scope.read(androidNotificationBridgeProvider) as _FakeBridge;
    scope.read(notificationSettingsProvider);
    await Future<void>.delayed(Duration.zero);

    await scope
        .read(notificationSettingsProvider.notifier)
        .setAlertsEnabled(true);

    expect(bridge.permissionRequests, 1);
    expect(bridge.channelEnsures, 1);
    expect(scope.read(notificationSettingsProvider).alertsEnabled, isTrue);
  });

  test('denied permission leaves the master disabled', () async {
    final scope = await container(
      status: const AndroidNotificationStatus(
        permission: AndroidNotificationPermission.denied,
        priorityChannelEnabled: false,
        activityChannelEnabled: false,
      ),
    );
    final bridge = scope.read(androidNotificationBridgeProvider) as _FakeBridge;

    await scope
        .read(notificationSettingsProvider.notifier)
        .setAlertsEnabled(true);

    expect(bridge.permissionRequests, 1);
    expect(bridge.channelEnsures, 0);
    expect(scope.read(notificationSettingsProvider).alertsEnabled, isFalse);
    expect(
      scope.read(notificationSettingsProvider).permission,
      AndroidNotificationPermission.denied,
    );
  });

  test('persists preferences under relay and identity scope', () async {
    final scope = await container();
    final notifier = scope.read(notificationSettingsProvider.notifier);
    notifier.setPriorityEnabled(false);
    notifier.setActivityEnabled(true);

    final prefs = scope.read(savedPrefsProvider);
    expect(
      prefs.getBool(
        'android_notification_settings_v1:https://relay.example:anon:priority',
      ),
      isFalse,
    );
    expect(
      prefs.getBool(
        'android_notification_settings_v1:https://relay.example:anon:activity',
      ),
      isTrue,
    );
  });
}

class _FakeBridge extends AndroidNotificationBridge {
  _FakeBridge(this.status);

  final AndroidNotificationStatus status;
  int permissionRequests = 0;
  int channelEnsures = 0;

  @override
  Future<AndroidNotificationStatus> getStatus() async => status;

  @override
  Future<AndroidNotificationStatus> requestPermission() async {
    permissionRequests++;
    return status;
  }

  @override
  Future<AndroidNotificationStatus> ensureChannels() async {
    channelEnsures++;
    return status;
  }
}

class _RelayConfigNotifier extends RelayConfigNotifier {
  _RelayConfigNotifier(this.url);

  final String url;

  @override
  RelayConfig build() => RelayConfig(baseUrl: url);
}

class _DisconnectedSession extends RelaySessionNotifier {
  @override
  SessionState build() =>
      const SessionState(status: SessionStatus.disconnected);
}
