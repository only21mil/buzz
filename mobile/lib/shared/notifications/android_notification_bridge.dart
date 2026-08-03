import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

const _channelName = 'xyz.block.buzz.mobile/notifications';

enum AndroidNotificationPermission { notDetermined, granted, denied }

@immutable
class AndroidNotificationStatus {
  const AndroidNotificationStatus({
    required this.permission,
    required this.priorityChannelEnabled,
    required this.activityChannelEnabled,
  });

  const AndroidNotificationStatus.unavailable()
    : permission = AndroidNotificationPermission.notDetermined,
      priorityChannelEnabled = false,
      activityChannelEnabled = false;

  final AndroidNotificationPermission permission;
  final bool priorityChannelEnabled;
  final bool activityChannelEnabled;

  factory AndroidNotificationStatus.fromMap(Map<Object?, Object?> value) {
    return AndroidNotificationStatus(
      permission: _parsePermission(value['permission']),
      priorityChannelEnabled: value['priorityChannelEnabled'] == true,
      activityChannelEnabled: value['activityChannelEnabled'] == true,
    );
  }
}

AndroidNotificationPermission _parsePermission(Object? value) {
  return switch (value) {
    'granted' || 'authorized' => AndroidNotificationPermission.granted,
    'denied' ||
    'blocked' ||
    'permanentlyDenied' => AndroidNotificationPermission.denied,
    _ => AndroidNotificationPermission.notDetermined,
  };
}

class AndroidNotificationBridge {
  AndroidNotificationBridge({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel(_channelName) {
    _channel.setMethodCallHandler(_handleMethodCall);
  }

  final MethodChannel _channel;
  final StreamController<String> _notificationTaps =
      StreamController<String>.broadcast();

  Stream<String> get notificationTaps => _notificationTaps.stream;

  Future<AndroidNotificationStatus> getStatus() async {
    final value = await _channel.invokeMethod<Map<Object?, Object?>>(
      'getStatus',
    );
    if (value == null) return const AndroidNotificationStatus.unavailable();
    return AndroidNotificationStatus.fromMap(value);
  }

  Future<AndroidNotificationStatus> requestPermission() async {
    await _channel.invokeMethod<void>('requestPermission');
    return getStatus();
  }

  Future<AndroidNotificationStatus> ensureChannels() async {
    await _channel.invokeMethod<void>('ensureChannels');
    return getStatus();
  }

  Future<void> show({
    required int id,
    required String channel,
    required String title,
    required String body,
    required String route,
  }) {
    return _channel.invokeMethod<void>('show', <String, Object>{
      'id': id,
      'channel': channel,
      'title': title,
      'body': body,
      'route': route,
    });
  }

  Future<void> openSettings() => _channel.invokeMethod<void>('openSettings');

  Future<String?> getInitialRoute() =>
      _channel.invokeMethod<String>('getInitialRoute');

  Future<void> _handleMethodCall(MethodCall call) async {
    if (call.method != 'notificationTapped') return;
    final route = call.arguments;
    if (route is String) _notificationTaps.add(route);
  }

  void dispose() {
    _channel.setMethodCallHandler(null);
    _notificationTaps.close();
  }
}

final androidNotificationBridgeProvider = Provider<AndroidNotificationBridge>((
  ref,
) {
  final bridge = AndroidNotificationBridge();
  ref.onDispose(bridge.dispose);
  return bridge;
});
