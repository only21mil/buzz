part of '../settings_page.dart';

class _NotificationSettingsSection extends ConsumerWidget {
  const _NotificationSettingsSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(notificationSettingsProvider);
    final sessionStatus = ref.watch(
      relaySessionProvider.select((session) => session.status),
    );
    final isConnected = sessionStatus == SessionStatus.connected;
    final isBlocked =
        settings.permission == AndroidNotificationPermission.denied;
    final selectedChannelDisabled =
        (settings.priorityEnabled && !settings.priorityChannelEnabled) ||
        (settings.activityEnabled && !settings.activityChannelEnabled);
    final status = settings.isRequesting
        ? 'Waiting for Android…'
        : switch ((
            settings.alertsEnabled,
            isBlocked,
            isConnected,
            selectedChannelDisabled,
          )) {
            (_, true, _, _) => 'Blocked',
            (false, _, _, _) => 'Off',
            (true, _, false, _) => 'Paused',
            (true, _, true, true) => 'Limited',
            _ => 'On',
          };

    return AppListCard(
      label: 'Notifications',
      verticalPadding: Grid.twelve,
      children: [
        AppListRow(
          icon: LucideIcons.bell,
          title: 'Alerts',
          subtitle: status == 'Waiting for Android…'
              ? 'Waiting for Android…'
              : status == 'Blocked'
              ? 'Android has blocked Buzz notifications.'
              : status == 'Paused'
              ? 'Paused while Buzz reconnects.'
              : status == 'Limited'
              ? 'A notification category is disabled in Android settings.'
              : 'Alerts require a live Buzz connection.',
          value: status,
          trailing: isBlocked
              ? TextButton(
                  onPressed: () => ref
                      .read(notificationSettingsProvider.notifier)
                      .openSettings(),
                  child: const Text('Android settings'),
                )
              : Switch.adaptive(
                  value: settings.alertsEnabled,
                  onChanged: settings.isRequesting
                      ? null
                      : (enabled) => ref
                            .read(notificationSettingsProvider.notifier)
                            .setAlertsEnabled(enabled),
                ),
        ),
        AppListRow(
          icon: LucideIcons.circleAlert,
          title: 'Mentions & direct messages',
          subtitle:
              'Alert when someone mentions you or sends you a direct message.',
          trailing: Switch.adaptive(
            value: settings.priorityEnabled,
            onChanged: settings.alertsEnabled
                ? (enabled) => ref
                      .read(notificationSettingsProvider.notifier)
                      .setPriorityEnabled(enabled)
                : null,
          ),
        ),
        AppListRow(
          icon: LucideIcons.activity,
          title: 'Channel activity',
          subtitle: 'Alert for new top-level messages in unmuted channels.',
          trailing: Switch.adaptive(
            value: settings.activityEnabled,
            onChanged: settings.alertsEnabled
                ? (enabled) => ref
                      .read(notificationSettingsProvider.notifier)
                      .setActivityEnabled(enabled)
                : null,
          ),
        ),
        AppListRow(
          icon: LucideIcons.eye,
          title: 'Message previews',
          subtitle: settings.previewsEnabled
              ? 'Show sender, channel, and message text in notifications.'
              : 'Hide sender, channel, and message text in notifications.',
          trailing: Switch.adaptive(
            value: settings.previewsEnabled,
            onChanged: settings.alertsEnabled
                ? (enabled) => ref
                      .read(notificationSettingsProvider.notifier)
                      .setPreviewsEnabled(enabled)
                : null,
          ),
        ),
        const AppListRow(
          icon: LucideIcons.wifiOff,
          title: 'Background alerts',
          value: 'Not available',
          subtitle:
              'Buzz does not use Google services. Alerts require a live Buzz connection.',
        ),
      ],
    );
  }
}
