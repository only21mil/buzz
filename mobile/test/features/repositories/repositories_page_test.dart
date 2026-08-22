import 'dart:convert';

import 'package:buzz/features/repositories/repositories_page.dart';
import 'package:buzz/features/repositories/repositories_provider.dart';
import 'package:buzz/features/repositories/repository_detail_page.dart';
import 'package:buzz/features/repositories/repository_models.dart';
import 'package:buzz/shared/relay/relay.dart';
import 'package:buzz/shared/theme/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:hooks_riverpod/misc.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:nostr/nostr.dart' as nostr;

const testRepository = Repository(
  id: 'buzz-mobile',
  name: 'Buzz Mobile',
  description: 'The community mobile client',
  owner: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  createdAt: 100,
  defaultBranch: 'main',
);

const testSnapshot = RepositorySnapshot(
  truncated: false,
  files: [
    RepositoryFile(
      path: 'README.md',
      kind: 'blob',
      size: 34,
      previewContent: '# Buzz Mobile\n\nCommunity chat.',
    ),
    RepositoryFile(
      path: 'main.dart',
      kind: 'blob',
      size: 30,
      previewContent: 'void main() => runApp(Buzz());',
    ),
    RepositoryFile(
      path: 'lib/src/client.dart',
      kind: 'blob',
      size: 12,
      previewContent: 'class Client {}',
    ),
  ],
);

void main() {
  Widget testable({required Widget child, required List<Override> overrides}) {
    return ProviderScope(
      overrides: overrides,
      child: MaterialApp(theme: AppTheme.light(), home: child),
    );
  }

  testWidgets('lists repository announcements from the provider', (
    tester,
  ) async {
    await tester.pumpWidget(
      testable(
        overrides: [
          repositoriesProvider.overrideWith(
            () => _FakeRepositoriesNotifier(const [testRepository]),
          ),
        ],
        child: const RepositoriesPage(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Repositories'), findsOneWidget);
    expect(find.text('Buzz Mobile'), findsOneWidget);
    expect(find.text('The community mobile client'), findsOneWidget);
    expect(
      find.byKey(ValueKey('repository-${testRepository.address}')),
      findsOneWidget,
    );
  });

  testWidgets('opens a snapshot file in a read-only file view', (tester) async {
    await tester.pumpWidget(
      testable(
        overrides: [
          repositorySnapshotProvider.overrideWith(
            () => _FakeRepositorySnapshotNotifier(testSnapshot),
          ),
        ],
        child: const RepositoryDetailPage(repository: testRepository),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('repository-readme')), findsOneWidget);
    expect(find.text('Buzz Mobile'), findsWidgets);
    expect(
      find.byKey(const ValueKey('repository-file-main.dart')),
      findsOneWidget,
    );

    await tester.tap(find.byKey(const ValueKey('repository-file-main.dart')));
    await tester.pumpAndSettle();

    expect(
      find.byKey(const ValueKey('repository-file-preview')),
      findsOneWidget,
    );
    expect(find.text('void main() => runApp(Buzz());'), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
  });

  test('signs the exact snapshot GET URL without a payload tag', () async {
    final keys = nostr.Keys.generate();
    http.Request? captured;
    final client = http_testing.MockClient((request) async {
      captured = request;
      return http.Response(
        jsonEncode({'files': <Object>[], 'truncated': false}),
        200,
      );
    });
    final container = ProviderContainer(
      overrides: [
        relayConfigProvider.overrideWith(
          () => _FakeRelayConfigNotifier(
            const RelayConfig(
              baseUrl: 'https://relay.example/community',
              nsec: null,
            ),
            nsec: keys.nsec,
          ),
        ),
        repositoryHttpClientProvider.overrideWithValue(client),
      ],
    );
    addTearDown(container.dispose);

    await container.read(repositorySnapshotProvider(testRepository).future);

    const expectedUrl =
        'https://relay.example/git/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/buzz-mobile/snapshot?ref=main&commits=20';
    expect(captured?.method, 'GET');
    expect(captured?.url.toString(), expectedUrl);
    final authorization = captured!.headers['Authorization']!;
    final encoded = authorization.substring('Nostr '.length);
    final decoded = utf8.decode(base64Url.decode(base64Url.normalize(encoded)));
    final event = jsonDecode(decoded) as Map<String, dynamic>;
    final tags = (event['tags'] as List<dynamic>)
        .map((tag) => (tag as List<dynamic>).cast<String>())
        .toList();
    expect(tags, anyElement(equals(<String>['u', expectedUrl])));
    expect(tags, anyElement(equals(<String>['method', 'GET'])));
    expect(tags.any((tag) => tag.first == 'payload'), isFalse);
  });
}

class _FakeRepositoriesNotifier extends RepositoriesNotifier {
  _FakeRepositoriesNotifier(this.repositories);

  final List<Repository> repositories;

  @override
  Future<List<Repository>> build() async => repositories;
}

class _FakeRepositorySnapshotNotifier extends RepositorySnapshotNotifier {
  _FakeRepositorySnapshotNotifier(this.snapshot) : super(testRepository);

  final RepositorySnapshot snapshot;

  @override
  Future<RepositorySnapshot> build() async => snapshot;
}

class _FakeRelayConfigNotifier extends RelayConfigNotifier {
  _FakeRelayConfigNotifier(this.config, {required this.nsec});

  final RelayConfig config;
  final String nsec;

  @override
  RelayConfig build() => RelayConfig(baseUrl: config.baseUrl, nsec: nsec);
}
