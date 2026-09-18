import 'package:buzz/shared/identity/npub.dart';
import 'package:buzz/shared/profile/user_profile.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('UserProfile label and initial', () {
    const b0b =
        'b0b0000000000000000000000000000000000000000000000000000000000000';

    final cases = <({String? displayName, String label, String initial})>[
      (displayName: null, label: truncateNpub(b0b), initial: 'B'),
      (displayName: '', label: truncateNpub(b0b), initial: 'B'),
      (displayName: '   ', label: truncateNpub(b0b), initial: 'B'),
      (displayName: 'Carol', label: 'Carol', initial: 'C'),
      (displayName: ' Carol ', label: ' Carol ', initial: 'C'),
    ];

    for (final testCase in cases) {
      test('displayName ${testCase.displayName ?? '(null)'}', () {
        final profile = UserProfile(
          pubkey: b0b,
          displayName: testCase.displayName,
        );
        expect(profile.label, testCase.label);
        expect(profile.initial, testCase.initial);
      });
    }
  });
}
