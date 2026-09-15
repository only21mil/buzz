import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Static contract for the P05 export-auth platform hooks (MW-7).
///
/// Device-auth adoption needs a FragmentActivity host on Android and an
/// LAContext hook on iOS, while the fork keeps owning its notification
/// bridge lifecycle, activity-alias PendingIntent taps, and permission
/// callbacks. These tests pin that combination so a later edit cannot
/// silently drop either side. They read source (like
/// `dependency_policy_test.dart`) because the behavior itself needs a
/// device; the Dart grant/session lifecycle is covered by runnable tests
/// in `export_authorization_test.dart` and `pairing_provider_test.dart`.
void main() {
  const mainActivity =
      'android/app/src/main/kotlin/xyz/block/buzz/mobile/MainActivity.kt';
  const deviceAuthBridge =
      'android/app/src/main/kotlin/xyz/block/buzz/mobile/DeviceAuthBridge.kt';
  const appDelegate = 'ios/Runner/AppDelegate.swift';
  const infoPlist = 'ios/Runner/Info.plist';

  group('Android export-auth host', () {
    test('MainActivity stays a FragmentActivity', () {
      final source = File(mainActivity).readAsStringSync();
      expect(
        source,
        contains('class MainActivity : FlutterFragmentActivity()'),
      );
      expect(
        source,
        contains('import io.flutter.embedding.android.FlutterFragmentActivity'),
      );
      expect(source, isNot(contains('FlutterActivity()')));
    });

    test('fork notification and permission callbacks survive the switch', () {
      final source = File(mainActivity).readAsStringSync();
      expect(source, contains('notificationBridge?.handlePermissionResult('));
      expect(
        source,
        contains('huddleMediaPlugin?.onRequestPermissionsResult('),
      );
      expect(source, contains('notificationBridge?.handleIntent(intent)'));
      expect(source, contains('notificationBridge?.handleResume()'));
      expect(source, contains('notificationBridge?.dispose()'));
    });

    test('device-auth bridge is owned by the activity lifecycle', () {
      final source = File(mainActivity).readAsStringSync();
      expect(source, contains('deviceAuthBridge = DeviceAuthBridge('));
      expect(source, contains('deviceAuthBridge?.dispose()'));
      expect(source, contains('deviceAuthBridge?.handleActivityResult('));
    });

    test('device auth adds no Google/ML dependencies', () {
      final source = File(deviceAuthBridge).readAsStringSync();
      expect(source, contains('buzz/device_auth'));
      expect(source, contains('canAuthenticate'));
      expect(source, contains('authenticate'));
      // Fail-closed error contract the Dart side maps to typed failures.
      expect(source, contains('"cancelled"'));
      expect(source, contains('"not_available"'));
      final lower = source.toLowerCase();
      for (final forbidden in [
        'mlkit',
        'play-services',
        'firebase',
        'androidx.biometric',
      ]) {
        expect(lower, isNot(contains(forbidden)));
      }
    });
  });

  group('iOS export-auth hook', () {
    test('AppDelegate serves device auth over LAContext', () {
      final source = File(appDelegate).readAsStringSync();
      expect(source, contains('import LocalAuthentication'));
      expect(source, contains('name: "buzz/device_auth"'));
      expect(source, contains('canEvaluatePolicy(.deviceOwnerAuthentication'));
      expect(source, contains('evaluatePolicy(.deviceOwnerAuthentication'));
      // Cancellation and missing enrollment stay typed for Dart.
      expect(source, contains('"cancelled"'));
      expect(source, contains('"not_available"'));
    });

    test('Face ID usage is declared', () {
      final plist = File(infoPlist).readAsStringSync();
      expect(plist, contains('NSFaceIDUsageDescription'));
    });
  });

  group('Dart export gate placement', () {
    test('pairing publishes nsec only behind a consumed grant', () {
      final source = File(
        'lib/features/pairing/pairing_provider.dart',
      ).readAsStringSync();
      expect(source, contains('_authorizeAndSendIdentity'));
      expect(source, contains('authorizeExport('));
      expect(
        source,
        contains('consumeGrant(grantId: grant.id, binding: request)'),
      );
      // No direct publish path may bypass the gate.
      expect(source, isNot(contains('_sendIdentityPayload')));
    });

    test('settings identity row documents pubkey-only copy', () {
      final source = File(
        'lib/features/settings/settings_page/connection_section.dart',
      ).readAsStringSync();
      expect(source, contains('Identity (pubkey)'));
      expect(source, contains('copyToClipboard(context, npub'));
      expect(source, isNot(contains('copyToClipboard(context, nsec')));
    });

    test('grants die on logout, switch, and background', () {
      final auth = File(
        'lib/shared/auth/auth_provider.dart',
      ).readAsStringSync();
      final community = File(
        'lib/shared/community/community_provider.dart',
      ).readAsStringSync();
      final lifecycle = File(
        'lib/shared/relay/app_lifecycle_provider.dart',
      ).readAsStringSync();
      expect(auth, contains('invalidateAll()'));
      expect(community, contains('invalidateAll()'));
      expect(lifecycle, contains('invalidateAll()'));
    });
  });
}
