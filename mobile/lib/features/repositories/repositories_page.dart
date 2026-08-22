import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../../shared/theme/theme.dart';
import '../../shared/widgets/buzz_loading_indicator.dart';
import '../../shared/widgets/frosted_app_bar.dart';
import '../../shared/widgets/frosted_scaffold.dart';
import 'repositories_provider.dart';
import 'repository_detail_page.dart';
import 'repository_models.dart';
import 'repository_status_view.dart';

class RepositoriesPage extends HookConsumerWidget {
  const RepositoriesPage({this.tabReselection, super.key});

  final ValueListenable<int>? tabReselection;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final repositories = ref.watch(repositoriesProvider);
    final scrollController = useScrollController();
    final reducedMotion = MediaQuery.disableAnimationsOf(context);
    useEffect(() {
      final reselection = tabReselection;
      if (reselection == null) return null;
      void scrollToTop() {
        if (!scrollController.hasClients) return;
        final position = scrollController.position;
        if (position.pixels <= position.minScrollExtent + 0.5) return;
        if (reducedMotion) {
          scrollController.jumpTo(position.minScrollExtent);
        } else {
          unawaited(
            scrollController.animateTo(
              position.minScrollExtent,
              duration: const Duration(milliseconds: 260),
              curve: Curves.easeOutCubic,
            ),
          );
        }
      }

      reselection.addListener(scrollToTop);
      return () => reselection.removeListener(scrollToTop);
    }, [tabReselection, scrollController, reducedMotion]);

    final titleStyle = context.textTheme.titleMedium?.copyWith(
      fontSize: 22,
      fontWeight: FontWeight.w600,
      color: navigationPrimaryForeground(context),
    );
    final topInset = frostedAppBarHeight(context, titleStyle: titleStyle);

    return FrostedScaffold(
      backgroundColor: context.colors.surface,
      appBar: FrostedAppBar(
        automaticallyImplyLeading: false,
        horizontalInset: Grid.gutter,
        showBottomDivider: true,
        bottomDividerOpacity: 0.06,
        titleStyle: titleStyle,
        title: Text('Repositories', style: titleStyle),
      ),
      body: SafeArea(
        top: false,
        bottom: false,
        child: Padding(
          padding: EdgeInsets.only(top: topInset),
          child: repositories.when(
            loading: () => const Center(
              child: BuzzLoadingIndicator(
                semanticLabel: 'Loading repositories',
              ),
            ),
            error: (error, _) => RepositoryStatusView(
              membershipRequired: error is RepositoryMembershipException,
              message: error is RepositoryLoadException
                  ? error.message
                  : 'Could not load repositories.',
              onRetry: () => ref.read(repositoriesProvider.notifier).refresh(),
            ),
            data: (items) => items.isEmpty
                ? const RepositoryStatusView(
                    icon: LucideIcons.folderGit2,
                    message: 'No repositories yet',
                    detail:
                        'Repository announcements visible to this community will appear here.',
                  )
                : RefreshIndicator(
                    onRefresh: () =>
                        ref.read(repositoriesProvider.notifier).refresh(),
                    child: ListView.separated(
                      key: const ValueKey('repository-list'),
                      controller: scrollController,
                      padding: EdgeInsets.fromLTRB(
                        Grid.gutter,
                        Grid.xs,
                        Grid.gutter,
                        MediaQuery.paddingOf(context).bottom + Grid.gutter,
                      ),
                      itemCount: items.length,
                      separatorBuilder: (_, _) =>
                          const SizedBox(height: Grid.xs),
                      itemBuilder: (context, index) => _RepositoryRow(
                        repository: items[index],
                        onTap: () => Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: (_) =>
                                RepositoryDetailPage(repository: items[index]),
                          ),
                        ),
                      ),
                    ),
                  ),
          ),
        ),
      ),
    );
  }
}

class _RepositoryRow extends StatelessWidget {
  const _RepositoryRow({required this.repository, required this.onTap});

  final Repository repository;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final subtitle = repository.description.isEmpty
        ? 'Default branch: ${repository.defaultBranch}'
        : repository.description;
    return Material(
      color: context.colors.surfaceContainerHighest,
      borderRadius: BorderRadius.circular(Radii.card),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        key: ValueKey('repository-${repository.address}'),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(Grid.xs),
          child: Row(
            children: [
              Icon(
                LucideIcons.folderGit2,
                size: 24,
                color: context.colors.primary,
              ),
              const SizedBox(width: Grid.xs),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      repository.name,
                      style: context.textTheme.bodyLarge?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: Grid.quarter),
                    Text(
                      subtitle,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: context.textTheme.bodySmall?.copyWith(
                        color: context.colors.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: Grid.half),
              Icon(
                LucideIcons.chevronRight,
                size: 18,
                color: context.colors.onSurfaceVariant,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
