import 'dart:async';

import 'package:flutter/material.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../../shared/theme/theme.dart';

class RepositoryStatusView extends StatelessWidget {
  const RepositoryStatusView({
    required this.message,
    this.icon,
    this.detail,
    this.membershipRequired = false,
    this.onRetry,
    super.key,
  });

  final String message;
  final IconData? icon;
  final String? detail;
  final bool membershipRequired;
  final Future<void> Function()? onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: Grid.gutter),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon ??
                  (membershipRequired
                      ? LucideIcons.lock
                      : LucideIcons.triangleAlert),
              size: Grid.lg,
              color: membershipRequired
                  ? context.colors.onSurfaceVariant
                  : context.colors.error,
            ),
            const SizedBox(height: Grid.xxs),
            Text(
              membershipRequired ? 'Community membership required' : message,
              textAlign: TextAlign.center,
              style: context.textTheme.bodyMedium?.copyWith(
                color: context.colors.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
            if (detail != null || membershipRequired) ...[
              const SizedBox(height: Grid.half),
              Text(
                detail ??
                    'Join this community with a member identity to browse its repositories.',
                textAlign: TextAlign.center,
                style: context.textTheme.bodySmall?.copyWith(
                  color: context.colors.onSurfaceVariant,
                ),
              ),
            ],
            if (onRetry != null && !membershipRequired) ...[
              const SizedBox(height: Grid.xs),
              FilledButton.icon(
                onPressed: () => unawaited(onRetry!()),
                icon: const Icon(LucideIcons.refreshCcw, size: 16),
                label: const Text('Retry'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
