import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Shared platform contracts retained through the upstream auth migration.
/// Upstream's sensitive-action authorizer and pairing tests replace the fork's
/// custom device-auth channel and consumed-grant implementation assertions.
void main() {
  const mainActivity =
      'android/app/src/main/kotlin/xyz/block/buzz/mobile/MainActivity.kt';
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
  });

  group('iOS export-auth hook', () {
    test('Face ID usage is declared', () {
      final plist = File(infoPlist).readAsStringSync();
      expect(plist, contains('NSFaceIDUsageDescription'));
    });
  });

  group('Dart export gate placement', () {
    test('settings identity row documents pubkey-only copy', () {
      final source = File(
        'lib/features/settings/settings_page/connection_section.dart',
      ).readAsStringSync();
      expect(source, contains('Identity (pubkey)'));
      expect(source, contains('copyToClipboard(context, npub'));
      expect(source, isNot(contains('copyToClipboard(context, nsec')));
    });
  });
}
