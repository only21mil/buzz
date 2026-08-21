import 'package:flutter/material.dart';
import 'package:gpt_markdown/gpt_markdown.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../../shared/theme/theme.dart';
import '../../shared/widgets/buzz_loading_indicator.dart';
import '../../shared/widgets/frosted_app_bar.dart';
import '../../shared/widgets/frosted_scaffold.dart';
import 'repositories_provider.dart';
import 'repository_models.dart';
import 'repository_status_view.dart';

class RepositoryDetailPage extends ConsumerWidget {
  const RepositoryDetailPage({required this.repository, super.key});

  final Repository repository;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final snapshot = ref.watch(repositorySnapshotProvider(repository));
    final titleStyle = context.textTheme.titleMedium?.copyWith(
      fontWeight: FontWeight.w600,
    );
    final topInset = frostedAppBarHeight(context, titleStyle: titleStyle);
    return FrostedScaffold(
      backgroundColor: context.colors.surface,
      appBar: FrostedAppBar(
        horizontalInset: Grid.xxs,
        showBottomDivider: true,
        bottomDividerOpacity: 0.06,
        titleStyle: titleStyle,
        title: Text(
          repository.name,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: titleStyle,
        ),
      ),
      body: SafeArea(
        top: false,
        bottom: false,
        child: Padding(
          padding: EdgeInsets.only(top: topInset),
          child: snapshot.when(
            loading: () => const Center(
              child: BuzzLoadingIndicator(
                semanticLabel: 'Loading repository files',
              ),
            ),
            error: (error, _) => RepositoryStatusView(
              membershipRequired: error is RepositoryMembershipException,
              message: error is RepositoryLoadException
                  ? error.message
                  : 'Could not load repository files.',
              onRetry: () => ref
                  .read(repositorySnapshotProvider(repository).notifier)
                  .refresh(),
            ),
            data: (data) =>
                _RepositorySnapshotView(repository: repository, snapshot: data),
          ),
        ),
      ),
    );
  }
}

class _RepositorySnapshotView extends StatelessWidget {
  const _RepositorySnapshotView({
    required this.repository,
    required this.snapshot,
  });

  final Repository repository;
  final RepositorySnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final tree = RepositoryTree.fromFiles(snapshot.files);
    final readme = snapshot.readme;
    return ListView(
      key: const ValueKey('repository-snapshot-view'),
      padding: EdgeInsets.fromLTRB(
        Grid.gutter,
        Grid.xs,
        Grid.gutter,
        MediaQuery.paddingOf(context).bottom + Grid.gutter,
      ),
      children: [
        Text(
          repository.description.isEmpty
              ? repository.address
              : repository.description,
          style: context.textTheme.bodyMedium?.copyWith(
            color: context.colors.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: Grid.sm),
        _SectionCard(
          title: 'Files',
          child: snapshot.files.isEmpty
              ? Padding(
                  padding: const EdgeInsets.all(Grid.xs),
                  child: Text(
                    'This repository has no files yet.',
                    style: context.textTheme.bodySmall?.copyWith(
                      color: context.colors.onSurfaceVariant,
                    ),
                  ),
                )
              : Column(
                  children: [
                    for (final node in tree.children)
                      RepositoryTreeRow(node: node),
                  ],
                ),
        ),
        if (snapshot.truncated) ...[
          const SizedBox(height: Grid.xxs),
          Text(
            'The relay limited this snapshot to its first files.',
            style: context.textTheme.bodySmall?.copyWith(
              color: context.colors.onSurfaceVariant,
            ),
          ),
        ],
        const SizedBox(height: Grid.sm),
        _SectionCard(
          title: readme?.name ?? 'README',
          child: readme?.previewContent == null
              ? Padding(
                  padding: const EdgeInsets.all(Grid.xs),
                  child: Text(
                    readme == null
                        ? 'No README found.'
                        : 'README preview unavailable.',
                    style: context.textTheme.bodySmall?.copyWith(
                      color: context.colors.onSurfaceVariant,
                    ),
                  ),
                )
              : Padding(
                  key: const ValueKey('repository-readme'),
                  padding: const EdgeInsets.all(Grid.xs),
                  child: GptMarkdown(
                    readme!.previewContent!,
                    style: context.textTheme.bodyMedium?.copyWith(
                      color: context.colors.onSurface,
                    ),
                  ),
                ),
        ),
      ],
    );
  }
}

class _SectionCard extends StatelessWidget {
  const _SectionCard({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: Grid.half, bottom: Grid.xxs),
          child: Text(
            title,
            style: context.textTheme.labelMedium?.copyWith(
              color: context.colors.onSurfaceVariant,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Material(
          color: context.colors.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(Radii.card),
          clipBehavior: Clip.antiAlias,
          child: SizedBox(width: double.infinity, child: child),
        ),
      ],
    );
  }
}

class RepositoryTree {
  RepositoryTree._(this.name, this.path, this.file);

  factory RepositoryTree.fromFiles(List<RepositoryFile> files) {
    final root = RepositoryTree._('', '', null);
    for (final file in files) {
      var current = root;
      final parts = file.path.split('/').where((part) => part.isNotEmpty);
      final segments = parts.toList();
      for (var index = 0; index < segments.length; index++) {
        final name = segments[index];
        final path = current.path.isEmpty ? name : '${current.path}/$name';
        final isFile = index == segments.length - 1;
        current = current._children.putIfAbsent(
          name,
          () => RepositoryTree._(name, path, isFile ? file : null),
        );
      }
    }
    return root;
  }

  final String name;
  final String path;
  final RepositoryFile? file;
  final Map<String, RepositoryTree> _children = {};

  bool get isDirectory => file == null;

  List<RepositoryTree> get children {
    final values = _children.values.toList();
    values.sort((a, b) {
      if (a.isDirectory != b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.toLowerCase().compareTo(b.name.toLowerCase());
    });
    return values;
  }
}

class RepositoryTreeRow extends StatelessWidget {
  const RepositoryTreeRow({required this.node, super.key});

  final RepositoryTree node;

  @override
  Widget build(BuildContext context) {
    if (node.isDirectory) {
      return ExpansionTile(
        key: ValueKey('repository-directory-${node.path}'),
        leading: const Icon(LucideIcons.folderClosed, size: 20),
        title: Text(node.name, style: context.textTheme.bodyMedium),
        childrenPadding: const EdgeInsets.only(left: Grid.xs),
        children: [
          for (final child in node.children) RepositoryTreeRow(node: child),
        ],
      );
    }
    final file = node.file!;
    return ListTile(
      key: ValueKey('repository-file-${file.path}'),
      dense: true,
      leading: const Icon(LucideIcons.file, size: 20),
      title: Text(file.name, style: context.textTheme.bodyMedium),
      subtitle: file.size == null
          ? null
          : Text(
              _formatFileSize(file.size!),
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colors.onSurfaceVariant,
              ),
            ),
      trailing: const Icon(LucideIcons.chevronRight, size: 16),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => RepositoryFilePage(file: file)),
      ),
    );
  }
}

class RepositoryFilePage extends ConsumerWidget {
  const RepositoryFilePage({required this.file, super.key});

  final RepositoryFile file;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final titleStyle = context.textTheme.titleMedium?.copyWith(
      fontWeight: FontWeight.w600,
    );
    final topInset = frostedAppBarHeight(context, titleStyle: titleStyle);
    final content = file.previewContent;
    return FrostedScaffold(
      backgroundColor: context.colors.surface,
      appBar: FrostedAppBar(
        horizontalInset: Grid.xxs,
        showBottomDivider: true,
        bottomDividerOpacity: 0.06,
        titleStyle: titleStyle,
        title: Text(
          file.name,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: titleStyle,
        ),
      ),
      body: SafeArea(
        top: false,
        child: Padding(
          padding: EdgeInsets.fromLTRB(
            Grid.gutter,
            topInset + Grid.xs,
            Grid.gutter,
            Grid.gutter,
          ),
          child: content == null
              ? RepositoryStatusView(
                  icon: LucideIcons.fileQuestionMark,
                  message: 'Preview unavailable',
                  detail:
                      'The relay does not include previews for binary or large files.',
                )
              : SingleChildScrollView(
                  key: const ValueKey('repository-file-preview'),
                  scrollDirection: Axis.horizontal,
                  child: SingleChildScrollView(
                    child: SelectableText(
                      content,
                      style: context.textTheme.bodySmall?.copyWith(
                        color: context.colors.onSurface,
                        fontFamily: 'monospace',
                        height: 1.45,
                      ),
                    ),
                  ),
                ),
        ),
      ),
    );
  }
}

String _formatFileSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}
