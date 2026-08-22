import 'package:flutter/foundation.dart';

import '../../shared/relay/relay.dart';

const repositoryAnnouncementKind = 30617;

@immutable
class Repository {
  const Repository({
    required this.id,
    required this.name,
    required this.description,
    required this.owner,
    required this.createdAt,
    required this.defaultBranch,
  });

  final String id;
  final String name;
  final String description;
  final String owner;
  final int createdAt;
  final String defaultBranch;

  String get address => '$repositoryAnnouncementKind:$owner:$id';
}

@immutable
class RepositoryFile {
  const RepositoryFile({
    required this.path,
    required this.kind,
    required this.size,
    required this.previewContent,
  });

  factory RepositoryFile.fromJson(Map<String, dynamic> json) {
    final path = json['path'];
    final kind = json['kind'];
    final size = json['size'];
    final preview = json['preview_content'];
    if (path is! String ||
        path.isEmpty ||
        kind is! String ||
        (size != null && (size is! int || size < 0)) ||
        (preview != null && preview is! String)) {
      throw const FormatException('snapshot contains a malformed file');
    }
    return RepositoryFile(
      path: path,
      kind: kind,
      size: size as int?,
      previewContent: preview as String?,
    );
  }

  final String path;
  final String kind;
  final int? size;
  final String? previewContent;

  String get name => path.split('/').last;
}

@immutable
class RepositorySnapshot {
  const RepositorySnapshot({required this.files, required this.truncated});

  factory RepositorySnapshot.fromJson(Map<String, dynamic> json) {
    final rawFiles = json['files'];
    final truncated = json['truncated'];
    if (rawFiles is! List || truncated is! bool) {
      throw const FormatException('snapshot response has an unexpected shape');
    }
    return RepositorySnapshot(
      files: [
        for (final rawFile in rawFiles)
          if (rawFile is Map<String, dynamic>)
            RepositoryFile.fromJson(rawFile)
          else
            throw const FormatException('snapshot contains a malformed file'),
      ],
      truncated: truncated,
    );
  }

  final List<RepositoryFile> files;
  final bool truncated;

  RepositoryFile? get readme {
    for (final file in files) {
      if (!file.path.contains('/') &&
          RegExp(
            r'^readme(?:\..+)?$',
            caseSensitive: false,
          ).hasMatch(file.path)) {
        return file;
      }
    }
    return null;
  }
}

List<Repository> repositoriesFromEvents(List<NostrEvent> events) {
  final latestByAddress = <String, NostrEvent>{};
  for (final event in events) {
    if (event.kind != repositoryAnnouncementKind ||
        !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(event.pubkey)) {
      continue;
    }
    final id = event.getTagValue('d');
    if (id == null || id.isEmpty) continue;
    final owner = event.pubkey.toLowerCase();
    final address = '$owner:$id';
    final previous = latestByAddress[address];
    if (previous == null || event.createdAt > previous.createdAt) {
      latestByAddress[address] = event;
    }
  }

  final repositories = [
    for (final event in latestByAddress.values)
      Repository(
        id: event.getTagValue('d')!,
        name: event.getTagValue('name') ?? event.getTagValue('d')!,
        description: event.getTagValue('description') ?? event.content.trim(),
        owner: event.pubkey.toLowerCase(),
        createdAt: event.createdAt,
        defaultBranch: event.getTagValue('default-branch') ?? 'main',
      ),
  ];
  repositories.sort((a, b) => b.createdAt.compareTo(a.createdAt));
  return repositories;
}

sealed class RepositoryLoadException implements Exception {
  const RepositoryLoadException(this.message);

  final String message;

  @override
  String toString() => message;
}

class RepositoryMembershipException extends RepositoryLoadException {
  const RepositoryMembershipException()
    : super('Repository access requires community membership.');
}

class RepositoryRequestException extends RepositoryLoadException {
  const RepositoryRequestException(super.message);
}
