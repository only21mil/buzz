#!/usr/bin/env python3
"""Source contracts for unsigned iOS push; never builds or provisions an app."""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text()


class PushSourceContracts(unittest.TestCase):
    def test_ios_identity_and_override_precedence(self):
        for mode in ('Debug', 'Release'):
            config = read(f'mobile/ios/Flutter/{mode}.xcconfig')
            self.assertIn('BUNDLE_IDENTIFIER = com.buzz.buzzMobile\n', config)
            self.assertIn('BUZZ_DEVELOPMENT_TEAM =\n', config)
            self.assertIn('BUZZ_APP_GROUP_IDENTIFIER = group.$(BUNDLE_IDENTIFIER)', config)
            self.assertIn('BUZZ_KEYCHAIN_ACCESS_GROUP = $(BUNDLE_IDENTIFIER)', config)
            self.assertTrue(config.rstrip().endswith('#include? "AppOverrides.xcconfig"'))
        self.assertNotIn('WorktreeOverrides', read('mobile/ios/Flutter/Release.xcconfig'))
        self.assertIn('ios_bundle_id="com.buzz.buzzMobile.${ios_slug}"', read('scripts/mobile-worktree-overrides.sh'))

    def test_extension_flags_and_parent_plugin_context(self):
        project = read('mobile/ios/Runner.xcodeproj/project.pbxproj')
        self.assertEqual(project.count('OTHER_LDFLAGS = "";'), 3)
        self.assertEqual(project.count('PRODUCT_BUNDLE_IDENTIFIER = "$(BUNDLE_IDENTIFIER).NotificationService";'), 3)
        self.assertIn('NotificationService.appex in Embed App Extensions', project)
        self.assertIn('PushSnapshotBridge.swift in Sources', project)
        self.assertIn('HuddleMediaPlugin.swift in Sources', project)
        self.assertIn('VoiceNotePackager.swift in Sources', project)
        for mode in ('Debug', 'Release'):
            self.assertIn('Pods-Runner.', read(f'mobile/ios/Flutter/{mode}.xcconfig'))

    def test_shared_entitlements_and_microphone_preserved(self):
        parent = plistlib.loads((ROOT / 'mobile/ios/Runner/Runner.entitlements').read_bytes())
        extension = plistlib.loads((ROOT / 'mobile/ios/NotificationService/NotificationService.entitlements').read_bytes())
        for key in ('com.apple.security.application-groups', 'keychain-access-groups'):
            self.assertEqual(parent[key], extension[key])
        self.assertTrue(parent['com.apple.developer.usernotifications.communication'])
        info = plistlib.loads((ROOT / 'mobile/ios/Runner/Info.plist').read_bytes())
        self.assertTrue(info['NSMicrophoneUsageDescription'])

    def test_bootstrap_and_native_enrollment_are_connected(self):
        main = read('mobile/lib/main.dart')
        self.assertIn('installBuzzPushMethodHandler()', main)
        self.assertIn('BuzzPushBootstrap(child: app)', main)
        delegate = read('mobile/ios/Runner/AppDelegate.swift')
        for symbol in ('APNsRegistrationBuffer()', 'BuzzPushSnapshotBridge(', 'BuzzDevPushEnrollmentDriver', 'didRegisterForRemoteNotificationsWithDeviceToken', 'packageVoiceNoteForUpload', 'HuddleMediaPlugin(messenger: messenger)'):
            self.assertIn(symbol, delegate)

    def test_migration_ledgers_are_separate_and_content_addressed(self):
        relay = json.loads(read('docs/mobile-push-migration-map.json'))
        self.assertEqual([Path(row['fork_path']).name[:4] for row in relay], ['0037', '0038'])
        gateway = json.loads(read('docs/mobile-push-gateway-migrations.json'))
        self.assertEqual([Path(row['fork_path']).name[:4] for row in gateway], ['0001', '0002', '0003', '0004', '0005'])
        for row in relay + gateway:
            content = (ROOT / row['fork_path']).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), row['fork_sha256'])
            self.assertEqual(hashlib.sha384(content).hexdigest(), row['fork_sqlx_sha384'])
        self.assertIn("CHECK (app_profile = 'buzz-ios-dogfood')", read('schema/schema.sql'))
        self.assertIn("CHECK (app_profile = 'buzz-ios-dogfood')", read('migrations/0038_push_gateway_dogfood_profile.sql'))

    def test_unsigned_ci_waits_for_explicit_runner_admission(self):
        ci = read('.github/workflows/ci.yml')
        job = re.search(r'^  mobile-ios:\n(.*?)(?=^  security:)', ci, re.M | re.S).group(1)
        self.assertIn('fromJSON(vars.BUZZ_IOS_CI_RUNNER_LABELS)', job)
        self.assertIn("vars.BUZZ_IOS_CI_RUNNER_LABELS != ''", job)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', job)
        self.assertIn('persist-credentials: false', job)
        self.assertIn('contents: read', job)
        self.assertNotIn('macos-latest', job)
        self.assertNotIn('secrets.', job)
        self.assertIn('flutter build ios --release --no-codesign --no-pub', job)
        self.assertIn('swift test --package-path mobile/ios/BuzzPushKit', job)


if __name__ == '__main__':
    unittest.main()
