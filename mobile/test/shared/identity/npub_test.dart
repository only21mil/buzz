import 'package:flutter_test/flutter_test.dart';
import 'package:nostr/nostr.dart' as nostr;
import 'package:buzz/shared/identity/npub.dart';

void main() {
  final keys = nostr.Keys.generate();
  final hex = keys.public;
  final npub = nostr.Nip19.encode(prefix: nostr.Nip19Prefix.npub, data: hex);

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

    test('invalid keys render the unavailable label', () {
      expect(truncateNpub(''), unavailableKeyLabel);
      expect(truncateNpub('bogus'), unavailableKeyLabel);
      expect(truncateNpub(keys.nsec), unavailableKeyLabel);
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
  });
}
