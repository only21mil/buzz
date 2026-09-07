import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../community/community.dart';
import '../community/community_provider.dart';
import '../relay/relay_provider.dart';
import '../relay/relay_session.dart';
import 'push_cohort_publication.dart';
import 'dev_push_lease.dart';
import 'push_bridge.dart';
import 'push_lease_revocation_outbox.dart';
import 'push_relay_capability_provider.dart';
import 'push_subscription.dart';

const _pushBootstrapRetryDelay = Duration(seconds: 5);

@visibleForTesting
class BuzzPushAttemptGate {
  BuzzPushAttemptGate({this.retryDelay = _pushBootstrapRetryDelay});

  final Duration retryDelay;
  Object? _attempt;
  Object? _owner;

  Object get owner => _owner!;
  Timer? _retryTimer;

  bool tryBegin(Object attempt) {
    if (_attempt == attempt) return false;
    _retryTimer?.cancel();
    _retryTimer = null;
    _attempt = attempt;
    _owner = Object();
    return true;
  }

  void failed(Object attempt, {Object? owner, required VoidCallback retry}) {
    if (_attempt != attempt || (owner != null && !identical(owner, _owner))) {
      return;
    }
    _attempt = null;
    _retryTimer?.cancel();
    _retryTimer = Timer(retryDelay, () {
      _retryTimer = null;
      if (_attempt == null) retry();
    });
  }

  void retryAfter(
    Object attempt, {
    Object? owner,
    required Duration delay,
    required VoidCallback retry,
  }) {
    if (_attempt != attempt || (owner != null && !identical(owner, _owner))) {
      return;
    }
    _retryTimer?.cancel();
    _retryTimer = Timer(delay, () {
      _retryTimer = null;
      if (_attempt != attempt || (owner != null && !identical(owner, _owner))) {
        return;
      }
      _attempt = null;
      retry();
    });
  }

  void complete(Object attempt, {Object? owner}) {
    if (_attempt != attempt || (owner != null && !identical(owner, _owner))) {
      return;
    }
    _retryTimer?.cancel();
    _retryTimer = null;
    _attempt = null;
  }

  void dispose() => _retryTimer?.cancel();
}

@visibleForTesting
String buzzPushPublicationAttemptKey({
  required String communityId,
  required String relayBaseUrl,
  required String token,
  required BuzzPushLeaseDescriptor descriptor,
  required List<BuzzPushSubscription> subscriptions,
}) => [
  communityId,
  relayBaseUrl,
  token,
  descriptor.executorKeyId,
  descriptor.executorPubkey,
  buzzPushSubscriptionsFingerprint(subscriptions),
].join('|');

@visibleForTesting
bool buzzPushLifecycleEnabled({
  required Community? community,
  required BuzzPushLeaseDescriptor? descriptor,
}) => community?.pushNotificationsEnabled == true && descriptor != null;

@visibleForTesting
Future<int> publishBuzzPushLeaseRecoverably({
  required Future<int> Function() reserveGeneration,
  required Future<void> Function(int generation) publish,
  required Future<void> Function(int generation) markAccepted,
}) async {
  final generation = await reserveGeneration();
  await publish(generation);
  await markAccepted(generation);
  return generation;
}

/// Starts the push lifecycle only after authenticated relay connectivity and a
/// push-capable NIP-11 descriptor are both present.
class BuzzPushBootstrap extends HookConsumerWidget {
  const BuzzPushBootstrap({required this.child, super.key});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    useListenable(apnsDeviceToken);
    final registrationAttempt = useMemoized(BuzzPushAttemptGate.new);
    final publicationAttempt = useMemoized(BuzzPushAttemptGate.new);
    final tombstoneAttempt = useMemoized(BuzzPushAttemptGate.new);
    final registrationRetry = useState(0);
    final publicationRetry = useState(0);
    final tombstoneRetry = useState(0);
    final revocationOutbox = ref.watch(buzzPushLeaseRevocationOutboxProvider);
    final session = ref.watch(relaySessionProvider);
    final communities = ref.watch(communityListProvider).value ?? const [];
    final config = ref.watch(relayConfigProvider);
    final community = ref.watch(activeCommunityProvider).value;
    final memberPubkey = ref.watch(myPubkeyProvider);
    final descriptor = ref.watch(currentRelayPushDescriptorProvider).value;
    final communityLifecycle = community == null
        ? null
        : ref
              .read(communityListProvider.notifier)
              .capturePushLifecycle(community.id);

    useEffect(() {
      final listener = AppLifecycleListener(
        onResume: () => _runRevocationOutbox(revocationOutbox.trigger),
      );
      _runRevocationOutbox(revocationOutbox.start);
      return listener.dispose;
    }, [revocationOutbox]);

    useEffect(() {
      if (session.status == SessionStatus.connected) {
        _runRevocationOutbox(revocationOutbox.trigger);
      }
      return null;
    }, [revocationOutbox, session.status]);

    useEffect(
      () => () {
        registrationAttempt.dispose();
        publicationAttempt.dispose();
        tombstoneAttempt.dispose();
      },
      const [],
    );

    useEffect(
      () {
        final pendingCommunities = communities
            .where(
              (candidate) =>
                  !candidate.pushNotificationsEnabled &&
                  candidate.pushSubscriptionState.pendingTombstoneGeneration !=
                      null,
            )
            .toList();
        if (session.status != SessionStatus.connected ||
            pendingCommunities.isEmpty) {
          return null;
        }
        const attempt = 'pending-tombstones';
        if (!tombstoneAttempt.tryBegin(attempt)) return null;
        unawaited(() async {
          try {
            Object? firstError;
            StackTrace? firstStack;
            for (final pendingCommunity in pendingCommunities) {
              try {
                await ref
                    .read(communityListProvider.notifier)
                    .retryPendingPushLeaseTombstone(
                      pendingCommunity.id,
                      advanceGeneration: true,
                    );
              } catch (error, stack) {
                firstError ??= error;
                firstStack ??= stack;
              }
            }
            if (firstError != null) {
              Error.throwWithStackTrace(firstError, firstStack!);
            }
            tombstoneAttempt.complete(attempt);
          } catch (error, stack) {
            tombstoneAttempt.failed(
              attempt,
              retry: () {
                if (context.mounted) tombstoneRetry.value += 1;
              },
            );
            debugPrint('Push lease tombstone retry failed: $error');
            debugPrintStack(stackTrace: stack);
          }
        }());
        return null;
      },
      [
        session.status,
        for (final candidate in communities)
          '${candidate.id}|${candidate.pushNotificationsEnabled}|'
              '${candidate.pushSubscriptionState.pendingTombstoneGeneration}',
        tombstoneRetry.value,
      ],
    );

    useEffect(
      () {
        if (!_ready(session, config, community, memberPubkey) ||
            !buzzPushLifecycleEnabled(
              community: community,
              descriptor: descriptor,
            )) {
          return null;
        }
        final activeCommunity = community!;
        final activeDescriptor = descriptor!;
        final lifecycle = ref
            .read(communityListProvider.notifier)
            .capturePushLifecycle(activeCommunity.id);
        final attempt = ('${activeCommunity.id}|${config.baseUrl}', lifecycle);
        if (!registrationAttempt.tryBegin(attempt)) return null;
        final owner = registrationAttempt.owner;
        unawaited(() async {
          try {
            await startBuzzPushRegistrationIfCapable(
              activeDescriptor,
              startRegistration: startBuzzPushRegistration,
            );
          } catch (error, stack) {
            registrationAttempt.failed(
              attempt,
              owner: owner,
              retry: () {
                if (context.mounted) registrationRetry.value += 1;
              },
            );
            debugPrint('Push registration bootstrap failed: $error');
            debugPrintStack(stackTrace: stack);
          }
        }());
        return null;
      },
      [
        session.status,
        config.baseUrl,
        community?.id,
        communityLifecycle,
        community?.pushNotificationsEnabled,
        memberPubkey,
        descriptor,
        registrationRetry.value,
      ],
    );

    final token = apnsDeviceToken.value;
    useEffect(
      () {
        if (!_ready(session, config, community, memberPubkey) ||
            !buzzPushLifecycleEnabled(
              community: community,
              descriptor: descriptor,
            ) ||
            token == null) {
          return null;
        }
        final activeCommunity = community!;
        final activeDescriptor = descriptor!;
        final state = activeCommunity.pushSubscriptionState;
        if (state.desired.isEmpty) return null;
        final notifier = ref.read(communityListProvider.notifier);
        final attempt = (
          buzzPushPublicationAttemptKey(
            communityId: activeCommunity.id,
            relayBaseUrl: config.baseUrl,
            token: token,
            descriptor: activeDescriptor,
            subscriptions: state.desired,
          ),
          notifier.capturePushLifecycle(activeCommunity.id),
        );
        if (!publicationAttempt.tryBegin(attempt)) return null;
        final owner = publicationAttempt.owner;
        unawaited(() async {
          try {
            final grant = await publishBuzzPushCohort(
              notifier: notifier,
              communities: communities,
              enroll: () => enrollBuzzPush(config.wsUrl, Env.pushGatewayUrl),
              readGrants: readBuzzPushEndpointGrants,
            );
            final renewInMilliseconds =
                grant.expiresAt * 1000 -
                DateTime.now().millisecondsSinceEpoch -
                const Duration(minutes: 5).inMilliseconds;
            publicationAttempt.retryAfter(
              attempt,
              owner: owner,
              delay: Duration(
                milliseconds: renewInMilliseconds > 1000
                    ? renewInMilliseconds
                    : 1000,
              ),
              retry: () {
                if (context.mounted) publicationRetry.value += 1;
              },
            );
          } catch (error, stack) {
            publicationAttempt.failed(
              attempt,
              owner: owner,
              retry: () {
                if (context.mounted) publicationRetry.value += 1;
              },
            );
            debugPrint('Push lease bootstrap failed: $error');
            debugPrintStack(stackTrace: stack);
          }
        }());
        return null;
      },
      [
        session.status,
        config.baseUrl,
        community?.id,
        communityLifecycle,
        community?.pushSubscriptionState,
        memberPubkey,
        descriptor,
        token,
        publicationRetry.value,
      ],
    );

    return child;
  }

  static bool _ready(
    SessionState session,
    RelayConfig config,
    Community? community,
    String? memberPubkey,
  ) =>
      session.status == SessionStatus.connected &&
      community != null &&
      config.nsec != null &&
      config.nsec!.isNotEmpty &&
      memberPubkey != null &&
      memberPubkey.isNotEmpty;
}

void _runRevocationOutbox(Future<void> Function() operation) {
  unawaited(
    operation().catchError((Object error, StackTrace stackTrace) {
      reportPushLeaseCleanupError(error, stackTrace);
    }),
  );
}
