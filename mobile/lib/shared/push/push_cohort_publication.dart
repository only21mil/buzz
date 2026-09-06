import '../community/community.dart';
import '../community/community_provider.dart';
import '../relay/signed_event_relay.dart';
import '../relay/relay_provider.dart';
import 'dev_push_lease.dart';
import 'push_bridge.dart';

/// Enrolls once, then reconciles every captured community sharing the returned
/// gateway authority. A retry republishes the whole cohort after partial failure.
Future<BuzzPushEndpointGrant> publishBuzzPushCohort({
  required CommunityListNotifier notifier,
  required List<Community> communities,
  required Future<BuzzPushEndpointGrant> Function() enroll,
  required Future<List<BuzzPushEndpointGrant>> Function() readGrants,
  Future<BuzzPushLeaseDescriptor> Function(String) descriptorFor =
      fetchBuzzPushLeaseDescriptor,
  Future<void> Function(
    Community,
    BuzzPushEndpointGrant,
    BuzzPushLeaseDescriptor,
    int,
  )?
  publish,
}) async {
  final lifecycles = {
    for (final community in communities)
      if (community.pushNotificationsEnabled)
        community.id: notifier.capturePushLifecycle(community.id),
  };
  final grant = await enroll();
  final grants = await readGrants();
  await notifier.refreshPushSnapshot();
  Object? firstError;
  StackTrace? firstStack;
  for (final community in communities) {
    final lifecycle = lifecycles[community.id];
    if (lifecycle == null ||
        !notifier.isPushLifecycleCurrent(community.id, lifecycle) ||
        community.pushSubscriptionState.desired.isEmpty ||
        community.nsec == null) {
      continue;
    }
    try {
      final descriptor = await descriptorFor(community.relayUrl);
      final matching = grants
          .where(
            (candidate) =>
                candidate.relayOrigin == descriptor.origin &&
                candidate.relayPubkey == grant.relayPubkey &&
                candidate.endpointHash == grant.endpointHash &&
                candidate.appProfile == grant.appProfile &&
                candidate.endpointGrant == grant.endpointGrant,
          )
          .firstOrNull;
      if (matching == null) continue;
      if (!notifier.isPushLifecycleCurrent(community.id, lifecycle)) continue;
      final generation = await notifier.reservePushLeaseGeneration(
        community.id,
        lifecycle: lifecycle,
      );
      if (!notifier.isPushLifecycleCurrent(community.id, lifecycle)) continue;
      await (publish ?? _publish)(community, matching, descriptor, generation);
      await notifier.markPushLeaseAccepted(
        community.id,
        subscriptions: community.pushSubscriptionState.desired,
        generation: generation,
        lifecycle: lifecycle,
      );
    } catch (error, stack) {
      firstError ??= error;
      firstStack ??= stack;
    }
  }
  if (firstError != null) Error.throwWithStackTrace(firstError, firstStack!);
  return grant;
}

Future<void> _publish(
  Community community,
  BuzzPushEndpointGrant grant,
  BuzzPushLeaseDescriptor descriptor,
  int generation,
) async {
  final nsec = community.nsec!;
  final uri = Uri.parse(community.relayUrl);
  final wsUrl = uri
      .replace(
        scheme: switch (uri.scheme) {
          'https' => 'wss',
          'http' => 'ws',
          _ => uri.scheme,
        },
      )
      .toString();
  await publishBuzzDevPushLease(
    grant: grant,
    leaseInstallationId: community.pushLeaseInstallationId,
    leaseGeneration: generation,
    descriptor: descriptor,
    nsec: nsec,
    memberPubkey: community.pubkey ?? pubkeyFromNsec(nsec)!,
    subscriptions: community.pushSubscriptionState.desired,
    submit: ({required kind, required content, required tags, createdAt}) =>
        submitSignedEventOnce(
          wsUrl: wsUrl,
          nsec: nsec,
          kind: kind,
          content: content,
          tags: tags,
          createdAt: createdAt,
        ),
  );
}
