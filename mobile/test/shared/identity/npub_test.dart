import 'package:buzz/features/invites/invite_create_provider.dart';
import 'package:buzz/shared/identity/npub.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nostr/nostr.dart' as nostr;

void main() {
  final keys = nostr.Keys.generate();
  final hex = keys.public;
  final npub = nostr.Nip19.encode(prefix: nostr.Nip19Prefix.npub, data: hex);

  const canonicalHex =
      '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';
  const canonicalNpubValue =
      'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';
  const canonicalCompact = 'npub180c\u2026h6w6';

  group('canonicalNpub', () {
    test('hex encodes to the canonical npub', () {
      expect(canonicalNpub(hex), npub);
    });

    test('uppercase hex encodes to the same npub', () {
      expect(canonicalNpub(hex.toUpperCase()), npub);
    });

    test('lowercase and uppercase npub spellings agree', () {
      expect(canonicalNpub(npub), npub);
      expect(canonicalNpub(npub.toUpperCase()), npub);
    });

    test('surrounding whitespace is ignored', () {
      expect(canonicalNpub('  $hex\n'), npub);
    });

    test('canonicalizes accepted input wrappers', () {
      final inputs = <String>[
        canonicalHex,
        canonicalHex.toUpperCase(),
        '  $canonicalHex \n',
        canonicalNpubValue,
        canonicalNpubValue.toUpperCase(),
      ];
      for (final input in inputs) {
        expect(canonicalNpub(input), canonicalNpubValue, reason: input);
      }
    });

    test('rejects non-identity input', () {
      expect(canonicalNpub(''), isNull);
      expect(canonicalNpub('not a key'), isNull);
      expect(canonicalNpub('a' * 63), isNull);
      expect(canonicalNpub('${hex}00'), isNull);
      expect(canonicalNpub(keys.nsec), isNull);
      expect(
        canonicalNpub(
          nostr.Nip19.encode(prefix: nostr.Nip19Prefix.note, data: hex),
        ),
        isNull,
      );
    });

    test('rejects malformed identities', () {
      expect(canonicalNpub('unknown'), isNull);
      expect(canonicalNpub('a' * 65), isNull);
      expect(canonicalNpub('z' * 64), isNull);
      expect(canonicalNpub('npub1garbage'), isNull);
      final mixedCase =
          '${canonicalNpubValue.substring(0, 20)}'
          '${canonicalNpubValue.substring(20).toUpperCase()}';
      expect(canonicalNpub(mixedCase), isNull);
      final nsec = nostr.Nip19.encode(
        prefix: nostr.Nip19Prefix.nsec,
        data: canonicalHex,
      );
      expect(canonicalNpub(nsec), isNull);
    });

    test('rejects npubs with degenerate payloads', () {
      final short = nostr.Nip19.encode(
        prefix: nostr.Nip19Prefix.npub,
        data: 'ab',
      );
      expect(canonicalNpub(short), isNull);
      expect(canonicalNpub('${npub.substring(0, npub.length - 2)}aa'), isNull);
    });

    test('rejects mixed-case npubs', () {
      final mixed = 'npub1${npub.substring(5).toUpperCase()}';
      expect(mixed, isNot(npub));
      expect(canonicalNpub(mixed), isNull);
    });
  });

  group('truncateNpub', () {
    test('renders the compact npub form', () {
      final compact = truncateNpub(hex);
      expect(
        compact,
        '${npub.substring(0, 8)}…${npub.substring(npub.length - 4)}',
      );
      expect(compact.startsWith('npub1'), isTrue);
    });

    test('renders compact npub label', () {
      expect(truncateNpub(canonicalHex), canonicalCompact);
      expect(truncateNpub(canonicalNpubValue), canonicalCompact);
    });

    test('invalid keys render the unavailable label', () {
      expect(truncateNpub(''), unavailableKeyLabel);
      expect(truncateNpub('bogus'), unavailableKeyLabel);
      expect(truncateNpub(keys.nsec), unavailableKeyLabel);
      expect(truncateNpub('not-a-key'), unavailableKeyLabel);
      expect(truncateNpub('npub1garbage'), unavailableKeyLabel);
    });
  });

  group('isHexPubkey', () {
    test('matches 64-char hex in any case', () {
      expect(isHexPubkey(hex), isTrue);
      expect(isHexPubkey(hex.toUpperCase()), isTrue);
      expect(isHexPubkey(' $hex '), isTrue);
      expect(isHexPubkey(npub), isFalse);
      expect(isHexPubkey(''), isFalse);
    });

    test('accepts 64-char hex only', () {
      expect(isHexPubkey(canonicalHex), isTrue);
      expect(isHexPubkey(canonicalHex.toUpperCase()), isTrue);
      expect(isHexPubkey('short'), isFalse);
    });
  });

  group('copy roundtrip', () {
    test('copied npub parses back to original hex', () {
      final copied = canonicalNpub(canonicalHex);
      expect(parseCommunityInvitePubkey(copied!), canonicalHex);
      expect(parseCommunityInvitePubkey(canonicalHex), canonicalHex);
    });
  });
}
