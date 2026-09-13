import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nostr/nostr.dart' as nostr;
import 'package:buzz/shared/relay/media_auth.dart';

final _blob = 'a' * 64;

String _serverTag(Map<String, String> headers) {
  final encoded = headers['Authorization']!.substring('Nostr '.length);
  final decoded = utf8.decode(base64Url.decode(base64Url.normalize(encoded)));
  final event = jsonDecode(decoded) as Map<String, dynamic>;
  final tags = (event['tags'] as List<dynamic>)
      .map((tag) => (tag as List<dynamic>).cast<String>())
      .toList();
  return tags.firstWhere((tag) => tag.first == 'server').last;
}

MediaGetAuthService _service({
  required String baseUrl,
  DateTime Function()? now,
}) => MediaGetAuthService(
  baseUrl: baseUrl,
  nsec: nostr.Keys.generate().nsec,
  now: now,
);

void main() {
  group('relay media origin gate', () {
    test('https relay signs implicit and explicit 443', () {
      final service = _service(baseUrl: 'https://relay.example');
      expect(
        service.headersFor('https://relay.example/media/$_blob.jpg'),
        isNotEmpty,
      );
      expect(
        service.headersFor('https://relay.example:443/media/$_blob.jpg'),
        isNotEmpty,
      );
    });

    test('http downgrade against an https relay gets no header', () {
      final service = _service(baseUrl: 'https://relay.example');
      expect(
        service.headersFor('http://relay.example/media/$_blob.jpg'),
        isEmpty,
      );
    });

    test('https on port 80 does not match an https relay', () {
      final service = _service(baseUrl: 'https://relay.example');
      expect(
        service.headersFor('https://relay.example:80/media/$_blob.jpg'),
        isEmpty,
      );
    });

    test('https upgrade against an http relay gets no header', () {
      final service = _service(baseUrl: 'http://relay.example:3000');
      expect(
        service.headersFor('https://relay.example:3000/media/$_blob.jpg'),
        isEmpty,
      );
      expect(
        service.headersFor('http://relay.example:3000/media/$_blob.jpg'),
        isNotEmpty,
      );
    });

    test('another host gets no header', () {
      final service = _service(baseUrl: 'https://relay.example');
      expect(
        service.headersFor('https://evil.example/media/$_blob.jpg'),
        isEmpty,
      );
      expect(
        service.headersFor('https://relay.example.evil.com/media/$_blob.jpg'),
        isEmpty,
      );
    });

    test('non-default port mismatch gets no header', () {
      final service = _service(baseUrl: 'https://relay.example:8443');
      expect(
        service.headersFor('https://relay.example/media/$_blob.jpg'),
        isEmpty,
      );
      expect(
        service.headersFor('https://relay.example:9443/media/$_blob.jpg'),
        isEmpty,
      );
    });

    test('matching approved non-default port signs', () {
      final service = _service(baseUrl: 'https://relay.example:8443');
      expect(
        service.headersFor('https://relay.example:8443/media/$_blob.jpg'),
        isNotEmpty,
      );
    });

    test('non-media paths and other schemes get no header', () {
      final service = _service(baseUrl: 'https://relay.example');
      expect(service.headersFor('https://relay.example/avatar.png'), isEmpty);
      expect(
        service.headersFor('https://relay.example/media-evil/$_blob.jpg'),
        isEmpty,
      );
      expect(
        service.headersFor('ftp://relay.example/media/$_blob.jpg'),
        isEmpty,
      );
      expect(service.headersFor('not a url [[[ '), isEmpty);
    });

    test('host comparison ignores case and a trailing dot', () {
      final service = _service(baseUrl: 'https://Relay.Example');
      expect(
        service.headersFor('https://relay.example./media/$_blob.jpg'),
        isNotEmpty,
      );
      expect(
        service.headersFor('https://RELAY.EXAMPLE/media/$_blob.jpg'),
        isNotEmpty,
      );
    });

    test('ipv6 relay signs its own origin only', () {
      final service = _service(baseUrl: 'http://[::1]:3000');
      expect(
        service.headersFor('http://[::1]:3000/media/$_blob.jpg'),
        isNotEmpty,
      );
      expect(service.headersFor('http://[::1]:3001/media/$_blob.jpg'), isEmpty);
      expect(
        service.headersFor('http://127.0.0.1:3000/media/$_blob.jpg'),
        isEmpty,
      );
    });

    test('blossom server tag keeps its own normalization', () {
      expect(
        _serverTag(
          _service(
            baseUrl: 'https://relay.example',
          ).headersFor('https://relay.example:443/media/$_blob.jpg'),
        ),
        'relay.example',
      );
      expect(
        _serverTag(
          _service(
            baseUrl: 'https://relay.example:8443',
          ).headersFor('https://relay.example:8443/media/$_blob.jpg'),
        ),
        'relay.example:8443',
      );
    });
  });

  group('relay media auth memo', () {
    test('reuses headers inside the refresh window, rotates after', () {
      var now = DateTime.fromMillisecondsSinceEpoch(1700000000000);
      final service = _service(
        baseUrl: 'https://relay.example',
        now: () => now,
      );
      final url = 'https://relay.example/media/$_blob.jpg';

      final first = service.headersFor(url);
      expect(first, isNotEmpty);
      now = now.add(const Duration(seconds: 539));
      expect(identical(service.headersFor(url), first), isTrue);
      now = now.add(const Duration(seconds: 2));
      final rotated = service.headersFor(url);
      expect(rotated, isNotEmpty);
      expect(identical(rotated, first), isFalse);
    });

    test('a fresh service drops the previous identity memo', () {
      final url = 'https://relay.example/media/$_blob.jpg';
      final first = _service(baseUrl: 'https://relay.example').headersFor(url);
      final second = _service(baseUrl: 'https://relay.example').headersFor(url);
      expect(first, isNotEmpty);
      expect(second, isNotEmpty);
      expect(identical(first, second), isFalse);
    });
  });
}
