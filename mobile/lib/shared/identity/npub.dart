import 'package:nostr/nostr.dart' as nostr;

/// Neutral label for identity keys that cannot be encoded for display.
///
/// Surfaces show this instead of raw hex or raw input, so a corrupt key
/// never looks like a real identity.
const unavailableKeyLabel = 'Unavailable';

// Public identity display only; bound entries across long-lived sessions.
const _compactNpubCacheSize = 256;
final _compactNpubCache = <String, String>{};

final _hex64 = RegExp(r'^[0-9a-f]{64}$');

/// Canonical full npub for an identity key.
///
/// Accepts a 64-character hex pubkey (any case) or an already-npub string
/// and returns the canonical lowercase npub. Anything else returns null:
/// short or corrupt values, npubs whose decoded payload is not exactly a
/// 64-character identity key, other prefixes (`nsec`, `note`, ...), and
/// mixed-case npubs (invalid Bech32 as written).
///
/// Both valid Bech32 casings display: all-lowercase `npub1...` and
/// all-uppercase `NPUB1...` return the same canonical lowercase npub.
String? canonicalNpub(String input) {
  final trimmed = input.trim();
  if (trimmed.startsWith('npub1') || trimmed.startsWith('NPUB1')) {
    try {
      final decoded = nostr.Nip19.decode(payload: trimmed);
      if (decoded.prefix != nostr.Nip19Prefix.npub) return null;
      final hex = decoded.data.toLowerCase();
      if (!_hex64.hasMatch(hex)) return null;
      return nostr.Nip19.encode(prefix: nostr.Nip19Prefix.npub, data: hex);
    } catch (_) {
      return null;
    }
  }
  final normalized = trimmed.toLowerCase();
  if (!_hex64.hasMatch(normalized)) return null;
  try {
    return nostr.Nip19.encode(prefix: nostr.Nip19Prefix.npub, data: normalized);
  } catch (_) {
    return null;
  }
}

/// Compact identity display for a pubkey: `npub1abcd...wxyz`
/// (first 8 plus last 4 of the full canonical npub).
///
/// Identity surfaces render this form so a displayed prefix always reads as
/// npub-shaped. Invalid keys render [unavailableKeyLabel], never raw hex.
String truncateNpub(String input) {
  final key = input.trim();
  final cached = _compactNpubCache.remove(key);
  if (cached != null) {
    _compactNpubCache[key] = cached;
    return cached;
  }
  final npub = canonicalNpub(key);
  if (npub == null) return unavailableKeyLabel;
  final compact = '${npub.substring(0, 8)}…${npub.substring(npub.length - 4)}';
  if (_compactNpubCache.length == _compactNpubCacheSize) {
    _compactNpubCache.remove(_compactNpubCache.keys.first);
  }
  _compactNpubCache[key] = compact;
  return compact;
}

/// True when [input] is a 64-character hex pubkey (any case).
bool isHexPubkey(String input) => _hex64.hasMatch(input.trim().toLowerCase());
