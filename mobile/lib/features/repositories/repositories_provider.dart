import 'dart:convert';

import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:http/http.dart' as http;

import '../../shared/relay/relay.dart';
import 'repository_models.dart';

class RepositoriesNotifier extends AsyncNotifier<List<Repository>> {
  @override
  Future<List<Repository>> build() async {
    ref.watch(relayConfigProvider);
    return _load();
  }

  Future<List<Repository>> _load() async {
    final config = ref.read(relayConfigProvider);
    if (config.nsec == null || config.nsec!.isEmpty) {
      throw const RepositoryMembershipException();
    }
    try {
      final events = await ref.read(relaySessionProvider.notifier).queryRelay([
        const NostrFilter(kinds: [repositoryAnnouncementKind], limit: 500),
      ]);
      return repositoriesFromEvents(events);
    } on RelayException catch (error) {
      if (error.statusCode == 401 || error.statusCode == 403) {
        throw const RepositoryMembershipException();
      }
      throw const RepositoryRequestException('Could not load repositories.');
    }
  }

  Future<void> refresh() async {
    state = const AsyncLoading();
    state = await AsyncValue.guard(_load);
  }
}

final repositoriesProvider =
    AsyncNotifierProvider<RepositoriesNotifier, List<Repository>>(
      RepositoriesNotifier.new,
    );

final repositoryHttpClientProvider = Provider<http.Client>((ref) {
  final client = http.Client();
  ref.onDispose(client.close);
  return client;
});

class RepositorySnapshotNotifier extends AsyncNotifier<RepositorySnapshot> {
  RepositorySnapshotNotifier(this.repository);

  final Repository repository;

  @override
  Future<RepositorySnapshot> build() async {
    ref.watch(relayConfigProvider);
    return _load();
  }

  Future<RepositorySnapshot> _load() async {
    final config = ref.read(relayConfigProvider);
    final nsec = config.nsec;
    if (nsec == null || nsec.isEmpty) {
      throw const RepositoryMembershipException();
    }
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(repository.owner) ||
        !RegExp(r'^[a-zA-Z0-9._-]{1,64}$').hasMatch(repository.id) ||
        repository.id.startsWith('.') ||
        repository.id.contains('..') ||
        repository.id.endsWith('.git')) {
      throw const RepositoryRequestException(
        'This repository cannot be browsed from its announcement.',
      );
    }

    final base = Uri.parse(config.baseUrl);
    final url = base
        .resolve('/git/${repository.owner}/${repository.id}/snapshot')
        .replace(
          queryParameters: {'ref': repository.defaultBranch, 'commits': '20'},
        )
        .toString();
    late final http.Response response;
    try {
      response = await ref
          .read(repositoryHttpClientProvider)
          .get(
            Uri.parse(url),
            headers: {
              'Authorization': buildNip98AuthHeader(
                method: 'GET',
                url: url,
                nsec: nsec,
              ),
            },
          )
          .timeout(const Duration(seconds: 15));
    } catch (_) {
      throw const RepositoryRequestException(
        'Could not reach the repository snapshot endpoint.',
      );
    }

    if (response.statusCode == 401 || response.statusCode == 403) {
      throw const RepositoryMembershipException();
    }
    if (response.statusCode == 404) {
      try {
        final marker = jsonDecode(response.body);
        if (marker is Map<String, dynamic> && marker['message'] is String) {
          throw RepositoryRequestException(marker['message'] as String);
        }
      } on FormatException {
        // Fall through to the stable message below.
      }
      throw const RepositoryRequestException('Repository snapshot not found.');
    }
    if (response.statusCode == 429) {
      throw const RepositoryRequestException(
        'The relay is busy. Try this repository again shortly.',
      );
    }
    if (response.statusCode == 504) {
      throw const RepositoryRequestException(
        'The relay timed out while reading this repository.',
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw RepositoryRequestException(
        'Repository snapshot failed with HTTP ${response.statusCode}.',
      );
    }

    final dynamic decoded;
    try {
      decoded = jsonDecode(response.body);
    } on FormatException {
      throw const RepositoryRequestException(
        'The repository snapshot was not valid JSON.',
      );
    }
    if (decoded is! Map<String, dynamic>) {
      throw const RepositoryRequestException(
        'The repository snapshot had an unexpected shape.',
      );
    }
    try {
      return RepositorySnapshot.fromJson(decoded);
    } on FormatException {
      throw const RepositoryRequestException(
        'The repository snapshot had an unexpected shape.',
      );
    }
  }

  Future<void> refresh() async {
    state = const AsyncLoading();
    state = await AsyncValue.guard(_load);
  }
}

final repositorySnapshotProvider =
    AsyncNotifierProvider.family<
      RepositorySnapshotNotifier,
      RepositorySnapshot,
      Repository
    >((repository) => RepositorySnapshotNotifier(repository));
