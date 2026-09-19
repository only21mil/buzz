import { sendChannelMessage } from "./lib/scopedChannelMessage";
import {
  assertPublicationScope,
  capturePublicationScope,
  type PublicationScope,
} from "@/shared/api/publicationScope";
import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import {
  CancelledError,
  type QueryClient,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

import {
  channelMessagesKey,
  channelWindowKey,
} from "@/features/messages/lib/messageQueryKeys";
import {
  buildReplyTags,
  normalizeMentionPubkeys,
  resolveReplyRootId,
} from "@/features/messages/lib/threading";
import {
  mergeHeadTransactionLiveSummaries,
  mergeChannelWindowOverlayEvents,
  projectChannelWindowMessages,
  refreshChannelWindowMessages,
  seedChannelWindowStoreFromSnapshot,
} from "@/features/messages/lib/projectChannelWindow";
import {
  beginHeadTransaction,
  clearHeadTransaction,
  createHeadTransactionAccess,
  finishHeadTransaction,
  type ChannelSubscriptionGeneration,
} from "@/features/messages/lib/headWindowTransaction";
import { reconcileChannelWindowMessages } from "@/features/messages/lib/channelWindowReconciliation";
import { appendChannelSubscriptionEvent } from "@/features/messages/lib/channelSubscriptionEvent";
import { removeChannelWindowMessage } from "@/features/messages/lib/messageMutationProjection";
import {
  channelHeadCacheScope,
  channelHeadHydration,
  consumeHydratedChannel,
} from "@/features/messages/lib/channelHeadCache";
import { storeChannelHeadCache } from "@/shared/api/tauriChannelHeadCache";
import {
  mergeMessages,
  mergeTimelineCacheMessages,
} from "@/features/messages/lib/messageMerge";

export { mergeMessages, mergeTimelineCacheMessages };
import { splitOutgoingTags } from "@/features/messages/lib/imetaMediaMarkdown";
import { messageMentionPubkeys } from "@/features/messages/lib/messageMentionPubkeys";
import { buildSentFromThreadTag } from "@/features/messages/lib/sentFromThread";
import {
  clearTimeoutState,
  recordTimeoutFromRejection,
} from "@/features/moderation/lib/timeoutStore";
import { relayClient, setVisibleChannel } from "@/shared/api/relayClient";
import { customEmojiQueryKey } from "@/features/custom-emoji/hooks";
import { channelsQueryKey } from "@/features/channels/hooks";
import { reactionEmojiUrl } from "@/shared/api/customEmoji";
import type { CustomEmoji } from "@/shared/lib/remarkCustomEmoji";
import { addReaction, deleteMessage, removeReaction } from "@/shared/api/tauri";
import { getChannelWindowEvents } from "@/shared/api/channelWindow";
import type { Channel, Identity, RelayEvent } from "@/shared/api/types";
import {
  emptyChannelWindowStore,
  flattenChannelWindowEvents,
  mergeLiveChannelWindowEvent,
  replaceNewestChannelWindow,
  type ChannelWindowStore,
} from "@/features/messages/lib/channelWindowStore";
import { fetchAuxBackfillEvents } from "@/features/messages/lib/auxBackfill";
import {
  captureMessageSnapshotScope,
  isMessageSnapshotScopeCurrent,
  readMessageSnapshot,
  writeMessageSnapshot,
} from "@/features/messages/lib/messageSnapshot";
import { parseChannelWindowResponse } from "@/features/messages/lib/channelWindowResponse";
import { KIND_STREAM_MESSAGE } from "@/shared/constants/kinds";

type MessageQueryContext = {
  optimisticId: string;
  channelId: string;
};

export type { ChannelSubscriptionGeneration };

type ChannelHistoryRequest = Readonly<{
  channelId: string;
  queryClient: QueryClient;
  token: symbol;
}>;

const channelHistoryRequests = new WeakMap<QueryClient, Map<string, symbol>>();

function beginChannelHistoryRequest(
  queryClient: QueryClient,
  channelId: string,
): ChannelHistoryRequest {
  let requests = channelHistoryRequests.get(queryClient);
  if (!requests) {
    requests = new Map();
    channelHistoryRequests.set(queryClient, requests);
  }
  const token = Symbol(channelId);
  requests.set(channelId, token);
  return { channelId, queryClient, token };
}

function isChannelHistoryRequestCurrent(
  request: ChannelHistoryRequest,
): boolean {
  return (
    channelHistoryRequests.get(request.queryClient)?.get(request.channelId) ===
    request.token
  );
}

function finishChannelHistoryRequest(request: ChannelHistoryRequest): void {
  if (!isChannelHistoryRequestCurrent(request)) return;
  const requests = channelHistoryRequests.get(request.queryClient);
  requests?.delete(request.channelId);
  if (requests?.size === 0) channelHistoryRequests.delete(request.queryClient);
}

export function snapshotContext(
  relayUrl?: string | null,
  signerPubkey?: string | null,
): { relayUrl: string; signerPubkey: string } | null {
  return relayUrl && signerPubkey ? { relayUrl, signerPubkey } : null;
}

/** Resolve only a cached parent, using the native resolver's NIP-10 marker order. */
export function resolveCachedReplyRootId(
  parentEventId: string,
  messageCaches: readonly RelayEvent[][],
): string | null {
  const validId = /^[0-9a-f]{64}$/i;
  if (!validId.test(parentEventId)) return null;
  for (const messages of messageCaches) {
    const parent = messages.find((event) => event.id === parentEventId);
    if (!parent) continue;
    let root: string | undefined;
    let reply: string | undefined;
    for (const tag of parent.tags) {
      if (tag[0] !== "e" || tag.length < 4) continue;
      if (tag[3] === "root") root = tag[1];
      if (tag[3] === "reply") reply = tag[1];
    }
    const resolved = root ?? reply ?? parentEventId;
    return validId.test(resolved) ? resolved : null;
  }
  return null;
}

export function createOptimisticMessage(
  channelId: string,
  content: string,
  identity: Identity,
  currentMessages: RelayEvent[],
  mentionPubkeys: string[] = [],
  parentEventId: string | null = null,
  mediaTags: string[][] = [],
  sentFromThreadRootId: string | null = null,
  sentFromThreadRootExcerpt: string | null = null,
): RelayEvent {
  const localKey = `optimistic-${crypto.randomUUID()}`;
  const tags: string[][] = [];

  if (parentEventId) {
    tags.push(
      ...buildReplyTags(
        channelId,
        identity.pubkey,
        parentEventId,
        resolveReplyRootId(parentEventId, currentMessages),
        mentionPubkeys,
      ),
    );
  } else {
    tags.push(["h", channelId]);
    tags.push(["p", identity.pubkey]);
    for (const pubkey of normalizeMentionPubkeys(
      mentionPubkeys,
      identity.pubkey,
    )) {
      tags.push(["p", pubkey]);
    }
  }

  for (const tag of mediaTags) {
    tags.push(tag);
  }
  if (sentFromThreadRootId) {
    tags.push(
      buildSentFromThreadTag(sentFromThreadRootId, sentFromThreadRootExcerpt),
    );
  }

  return {
    id: localKey,
    localKey,
    pubkey: identity.pubkey,
    created_at: Math.floor(Date.now() / 1_000),
    kind: KIND_STREAM_MESSAGE,
    tags,
    content,
    sig: "",
    pending: true,
  };
}

/**
 * Resolves the effective target channel for a send operation.
 *
 * When `capturedChannelId` is supplied (non-null), the target is looked up from
 * `channelsCache` — this pins the send to the compose-time channel regardless
 * of any subsequent navigation. If the id is supplied but resolves to nothing,
 * returns `null` (caller should throw — don't silently fall back to the live
 * channel). When `capturedChannelId` is null, the caller didn't capture one and
 * the closed-over `fallbackChannel` is the intended target.
 *
 * Exported for unit testing.
 */
export function resolveEffectiveChannel(
  capturedChannelId: string | null | undefined,
  channelsCache: Channel[] | undefined,
  fallbackChannel: Channel | null,
): Channel | null {
  if (capturedChannelId == null) {
    return fallbackChannel;
  }
  return channelsCache?.find((c) => c.id === capturedChannelId) ?? null;
}

/**
 * Resolves a send target captured as either the channel object itself or its id.
 * A relay-returned channel remains authoritative even when the shared channel
 * list is temporarily stale and does not contain it.
 *
 * Exported for unit testing.
 */
export function resolveSendChannel(
  targetChannel: Channel | undefined,
  capturedChannelId: string | null | undefined,
  channelsCache: Channel[] | undefined,
  fallbackChannel: Channel | null,
): Channel | null {
  return (
    targetChannel ??
    resolveEffectiveChannel(capturedChannelId, channelsCache, fallbackChannel)
  );
}

/**
 * Resolves the thread reply target from a submit-time captured context or,
 * for callers that predate the capture pattern, from live refs.
 *
 * When `threadContext` is supplied (non-null), its values are used exclusively
 * — no live-ref reads occur. This is the race-free path: the context was
 * captured synchronously at submit time before any async awaits.
 *
 * When `threadContext` is null/undefined (legacy callers), falls back to
 * `liveReplyTargetId ?? liveThreadHeadId`.
 *
 * Returns null when no parentEventId can be resolved (caller should bail).
 */
export function resolveThreadReplyTarget(
  threadContext:
    | { parentEventId: string | null; threadHeadId: string | null }
    | null
    | undefined,
  liveReplyTargetId: string | null | undefined,
  liveThreadHeadId: string | null | undefined,
): { parentEventId: string; threadHeadId: string | null } | null {
  if (threadContext != null) {
    // Captured context: use exclusively — no ?? fallback to live refs.
    if (!threadContext.parentEventId) {
      return null;
    }
    return {
      parentEventId: threadContext.parentEventId,
      threadHeadId: threadContext.threadHeadId,
    };
  }
  // Legacy path: read from live refs.
  const parentEventId = liveReplyTargetId ?? liveThreadHeadId ?? null;
  if (!parentEventId) {
    return null;
  }
  return {
    parentEventId,
    threadHeadId: liveThreadHeadId ?? null,
  };
}

export function useChannelWindowQuery(channel: Channel | null) {
  const queryClient = useQueryClient();
  const queryKey = channelWindowKey(channel?.id ?? "none");
  return useQuery({
    enabled: channel !== null && channel.channelType !== "forum",
    queryKey,
    queryFn: () =>
      queryClient.getQueryData<ChannelWindowStore>(queryKey) ??
      emptyChannelWindowStore(),
    staleTime: Number.POSITIVE_INFINITY,
  });
}

export function reconcileFetchedChannelWindow(
  queryClient: QueryClient,
  channelId: string,
  events: Awaited<ReturnType<typeof getChannelWindowEvents>>,
  previousMessages: RelayEvent[],
  signal: AbortSignal,
): RelayEvent[] {
  // Tauri invokes cannot be canceled after dispatch. A replacement refetch can
  // therefore win while this older request is still in flight. Never let that
  // canceled request commit its stale page into the authoritative window.
  signal.throwIfAborted();
  const windowKey = channelWindowKey(channelId);
  const page = parseChannelWindowResponse(events, channelId, null);
  const current =
    queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
    emptyChannelWindowStore();
  const next = replaceNewestChannelWindow(current, page);
  queryClient.setQueryData(windowKey, next);
  const scope = channelHeadCacheScope(queryClient);
  if (scope) {
    void storeChannelHeadCache(scope, channelId, events).catch((error) => {
      console.warn("Failed to persist channel head", channelId, error);
    });
  }
  return reconcileChannelWindowMessages(next, previousMessages);
}

export function useChannelMessagesQuery(
  channel: Channel | null,
  subscriptionGeneration: ChannelSubscriptionGeneration | true | null = true,
  snapshotContext: { relayUrl: string; signerPubkey: string } | null = null,
) {
  const queryClient = useQueryClient();
  const snapshotChannelId = channel?.id ?? null;
  const snapshotRelayUrl = snapshotContext?.relayUrl ?? null;
  const snapshotSignerPubkey = snapshotContext?.signerPubkey ?? null;
  const queryKey = channelMessagesKey(snapshotChannelId ?? "none");
  const windowKey = channelWindowKey(snapshotChannelId ?? "none");
  const snapshotScope = useMemo(
    () =>
      snapshotChannelId && snapshotRelayUrl && snapshotSignerPubkey
        ? captureMessageSnapshotScope(
            snapshotRelayUrl,
            snapshotSignerPubkey,
            snapshotChannelId,
          )
        : null,
    [snapshotChannelId, snapshotRelayUrl, snapshotSignerPubkey],
  );

  return useQuery({
    enabled:
      subscriptionGeneration !== null &&
      (subscriptionGeneration === true ||
        subscriptionGeneration.guard.current) &&
      channel !== null &&
      channel.channelType !== "forum",
    queryKey,
    meta: { subscriptionGated: subscriptionGeneration !== true },
    queryFn: async ({ signal }) => {
      if (!channel) throw new Error("No channel selected.");
      const generationToken =
        subscriptionGeneration === true ? null : subscriptionGeneration;
      const historyRequest = beginChannelHistoryRequest(
        queryClient,
        channel.id,
      );
      const requireCurrentRequest = () => {
        const isCurrent =
          !signal.aborted &&
          (snapshotScope === null ||
            isMessageSnapshotScopeCurrent(snapshotScope)) &&
          isChannelHistoryRequestCurrent(historyRequest) &&
          (generationToken === null ||
            (generationToken.channelId === snapshotChannelId &&
              generationToken.guard.current));
        if (!isCurrent) throw new CancelledError({ silent: true });
      };
      const headTransaction = createHeadTransactionAccess(
        generationToken,
        requireCurrentRequest,
      );

      try {
        await channelHeadHydration(queryClient);
        headTransaction.requireCurrent();
        const hydrated = consumeHydratedChannel(queryClient, channel.id);
        // Explicit subscription generations must fetch to close the live gap.
        if (hydrated && subscriptionGeneration === true) {
          return queryClient.getQueryData<RelayEvent[]>(queryKey) ?? [];
        }

        const snapshot = snapshotScope
          ? readMessageSnapshot(snapshotScope)
          : null;
        let currentWindow =
          queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
          seedChannelWindowStoreFromSnapshot(snapshot ?? []);
        const liveSummaryBaseline = currentWindow.liveSummaries;
        if (!queryClient.getQueryData<ChannelWindowStore>(windowKey)) {
          headTransaction.requireCurrent();
          queryClient.setQueryData(windowKey, currentWindow);
        }

        const events = await getChannelWindowEvents(channel.id);
        headTransaction.requireCurrent();
        const page = parseChannelWindowResponse(events, channel.id, null);
        currentWindow =
          queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
          currentWindow;
        const freshWindow = headTransaction.merge(
          mergeHeadTransactionLiveSummaries(
            replaceNewestChannelWindow(currentWindow, page),
            liveSummaryBaseline,
            currentWindow.liveSummaries,
          ),
        );
        const freshMessages = reconcileChannelWindowMessages(
          freshWindow,
          queryClient.getQueryData<RelayEvent[]>(queryKey) ?? [],
        );
        headTransaction.requireCurrent();
        const headScope = channelHeadCacheScope(queryClient);
        if (headScope) {
          void storeChannelHeadCache(headScope, channel.id, events).catch(
            (error) => {
              console.warn("Failed to persist channel head", channel.id, error);
            },
          );
        }
        queryClient.setQueryData(windowKey, freshWindow);
        queryClient.setQueryData(queryKey, freshMessages);

        let auxEvents: RelayEvent[];
        try {
          const mergedWindow = flattenChannelWindowEvents(freshWindow);
          auxEvents = await fetchAuxBackfillEvents(
            channel.id,
            mergedWindow,
            mergedWindow,
          );
        } catch (error) {
          headTransaction.requireCurrent();
          console.error(
            "Failed to backfill auxiliary events for channel",
            channel.id,
            error,
          );
          const latestWindow = headTransaction.merge(
            queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
              freshWindow,
          );
          const latestMessages = reconcileChannelWindowMessages(
            latestWindow,
            queryClient.getQueryData<RelayEvent[]>(queryKey) ?? freshMessages,
          );
          headTransaction.requireCurrent();
          queryClient.setQueryData(windowKey, latestWindow);
          queryClient.setQueryData(queryKey, latestMessages);
          return latestMessages;
        }

        headTransaction.requireCurrent();
        const latestWindow =
          queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
          freshWindow;
        const closedWindow = headTransaction.merge(
          mergeChannelWindowOverlayEvents(latestWindow, auxEvents),
        );
        const closedMessages = reconcileChannelWindowMessages(
          closedWindow,
          queryClient.getQueryData<RelayEvent[]>(queryKey) ?? freshMessages,
        );
        headTransaction.requireCurrent();
        queryClient.setQueryData(windowKey, closedWindow);
        queryClient.setQueryData(queryKey, closedMessages);
        headTransaction.requireCurrent();
        if (snapshotScope) {
          writeMessageSnapshot(
            snapshotScope,
            flattenChannelWindowEvents(closedWindow),
          );
        }
        return closedMessages;
      } finally {
        headTransaction.finish();
        finishChannelHistoryRequest(historyRequest);
      }
    },
    initialData: () => {
      if (!snapshotScope) return undefined;
      const snapshot = readMessageSnapshot(snapshotScope);
      if (!snapshot || !isMessageSnapshotScopeCurrent(snapshotScope)) {
        return undefined;
      }
      const currentWindow =
        queryClient.getQueryData<ChannelWindowStore>(windowKey);
      queryClient.setQueryData(
        windowKey,
        currentWindow
          ? mergeChannelWindowOverlayEvents(currentWindow, snapshot)
          : seedChannelWindowStoreFromSnapshot(snapshot),
      );
      return snapshot;
    },
    initialDataUpdatedAt: 0,
    staleTime: 5 * 60 * 1_000,
    gcTime: 60 * 60 * 1_000,
  });
}

export function useChannelSubscription(channel: Channel | null) {
  const queryClient = useQueryClient();
  const channelId = channel?.id ?? null;
  const channelType = channel?.channelType ?? null;
  const activeSubscriptionRef = useRef<ChannelSubscriptionGeneration | null>(
    null,
  );
  const subscriptionSequenceRef = useRef(0);
  const [readySubscription, setReadySubscription] =
    useState<ChannelSubscriptionGeneration | null>(null);
  const refreshNewestWindow = useEffectEvent(
    async (token: ChannelSubscriptionGeneration) => {
      await queryClient.cancelQueries({
        queryKey: channelMessagesKey(token.channelId),
        exact: true,
      });
      if (!token.guard.current) return;
      await refreshChannelWindowMessages(
        queryClient,
        token.channelId,
        () => token.guard.current,
      );
    },
  );

  const appendMessage = useEffectEvent(
    (event: RelayEvent, generationToken: ChannelSubscriptionGeneration) => {
      appendChannelSubscriptionEvent(queryClient, event, generationToken);
    },
  );

  // Notify the relay client which channel is currently visible so its live
  // subscriptions are replayed first on reconnect, reducing latency on
  // degraded networks.
  useEffect(() => {
    if (!channelId || channelType === "forum") return;
    setVisibleChannel(channelId);
    return () => {
      setVisibleChannel(null);
    };
  }, [channelId, channelType]);

  useEffect(() => {
    if (!channelId || !channelType || channelType === "forum") {
      return;
    }

    let isDisposed = false;
    let isReady = false;
    subscriptionSequenceRef.current += 1;
    const generationToken = Object.freeze({
      channelId,
      channelType,
      generation: subscriptionSequenceRef.current,
      guard: { current: true },
      headTransaction: { version: 1, active: true, events: [] },
    });
    activeSubscriptionRef.current = generationToken;
    let cleanup: (() => Promise<void>) | undefined;
    const disposeSubscription = () => {
      const dispose = cleanup;
      cleanup = undefined;
      if (dispose) void dispose();
    };
    const disposeReconnectListener = relayClient.subscribeToReconnects(() => {
      if (!isReady || isDisposed || !generationToken.guard.current) return;
      const headTransactionVersion = beginHeadTransaction(generationToken);
      void refreshNewestWindow(generationToken).catch((error) => {
        finishHeadTransaction(generationToken, headTransactionVersion);
        if (!isDisposed && generationToken.guard.current) {
          console.error(
            "Failed to refresh channel window after reconnecting",
            channelId,
            error,
          );
        }
      });
    });

    relayClient
      .subscribeToChannelLive(channelId, (event) => {
        if (!isDisposed && generationToken.guard.current) {
          appendMessage(event, generationToken);
        }
      })
      .then(async (dispose) => {
        if (isDisposed || !generationToken.guard.current) {
          void dispose();
          return;
        }

        cleanup = dispose;
        const historyQueryKey = channelMessagesKey(channelId);
        const query = queryClient
          .getQueryCache()
          .find({ queryKey: historyQueryKey, exact: true });
        if (query?.meta?.subscriptionGated !== true) {
          await refreshChannelWindowMessages(
            queryClient,
            channelId,
            () => generationToken.guard.current,
          );
          if (isDisposed || !generationToken.guard.current) return;
          isReady = true;
          setReadySubscription(generationToken);
          return;
        }
        await queryClient.cancelQueries({
          queryKey: historyQueryKey,
          exact: true,
        });
        if (isDisposed || !generationToken.guard.current) {
          disposeSubscription();
          return;
        }
        await queryClient.invalidateQueries({
          queryKey: historyQueryKey,
          exact: true,
          refetchType: "none",
        });
        if (isDisposed || !generationToken.guard.current) {
          disposeSubscription();
          return;
        }
        isReady = true;
        setReadySubscription(generationToken);
      })
      .catch((error) => {
        disposeSubscription();
        if (!isDisposed && generationToken.guard.current) {
          console.error("Failed to subscribe to channel", channelId, error);
          const query = queryClient
            .getQueryCache()
            .find({ queryKey: channelMessagesKey(channelId), exact: true });
          if (query?.meta?.subscriptionGated !== true) {
            void refreshChannelWindowMessages(
              queryClient,
              channelId,
              () => generationToken.guard.current,
            ).catch((refreshError) => {
              console.error(
                "Failed to refresh channel after subscription failure",
                channelId,
                refreshError,
              );
            });
          }
        }
      });

    return () => {
      isDisposed = true;
      generationToken.guard.current = false;
      clearHeadTransaction(generationToken);
      if (activeSubscriptionRef.current === generationToken) {
        activeSubscriptionRef.current = null;
      }
      disposeReconnectListener();
      disposeSubscription();
    };
  }, [channelId, channelType, queryClient]);

  const activeSubscription = activeSubscriptionRef.current;
  // Render only compares current props with committed subscription state.
  // Guard invalidation belongs exclusively to effect cleanup so abandoned
  // renders cannot poison the subscription that remains committed.
  return readySubscription === activeSubscription &&
    activeSubscription?.guard.current &&
    activeSubscription.channelId === channelId &&
    activeSubscription.channelType === channelType
    ? activeSubscription
    : null;
}

export function useSubscribedMessages(
  channel: Channel | null,
  context: { relayUrl: string; signerPubkey: string } | null,
) {
  const subscriptionGeneration = useChannelSubscription(channel);
  return useChannelMessagesQuery(channel, subscriptionGeneration, context);
}

export function useSendMessageMutation(
  channel: Channel | null,
  identity: Identity | undefined,
) {
  const queryClient = useQueryClient();

  return useMutation<
    RelayEvent,
    Error,
    {
      publicationScope?: PublicationScope;
      channelId?: string;
      targetChannel?: Channel;
      content: string;
      mentionPubkeys?: string[];
      parentEventId?: string | null;
      mediaTags?: string[][];
      forceRest?: boolean;
      sentFromThreadRootId?: string | null;
      sentFromThreadRootExcerpt?: string | null;
      transport?: "auto" | "http";
    },
    MessageQueryContext | undefined
  >({
    mutationFn: async ({
      publicationScope = capturePublicationScope(),
      channelId: capturedChannelId,
      targetChannel,
      content,
      mentionPubkeys,
      parentEventId,
      mediaTags,
      forceRest,
      sentFromThreadRootId,
      sentFromThreadRootExcerpt,
      transport = "auto",
    }) => {
      assertPublicationScope(publicationScope);
      // Prefer a channel captured by the caller at compose time. Otherwise,
      // resolve a captured id from the shared channel cache so navigation
      // cannot redirect the message. Legacy callers without either value use
      // the closed-over `channel`.
      const effectiveChannel = resolveSendChannel(
        targetChannel,
        capturedChannelId,
        queryClient.getQueryData<Channel[]>(channelsQueryKey),
        channel,
      );

      if (effectiveChannel == null) {
        if (capturedChannelId != null) {
          throw new Error("Channel is no longer available.");
        }
        throw new Error("This channel does not support message sending yet.");
      }

      if (effectiveChannel.channelType === "forum") {
        throw new Error("This channel does not support message sending yet.");
      }

      if (!identity) {
        throw new Error("No identity available for sending messages.");
      }

      // `mediaTags` arrives as the merged outgoing tag set (imeta + NIP-30
      // emoji). Split it so each kind goes to its own validated Tauri arg —
      // emoji tags must NOT ride the imeta-only `media` channel (that gate
      // rejects any non-imeta prefix, which silently dropped emoji sends).
      const {
        mediaTags: imetaTags,
        emojiTags,
        mentionTags,
        linkPreviewTags,
      } = splitOutgoingTags(mediaTags);
      const recipientPubkeys = messageMentionPubkeys(
        effectiveChannel,
        identity.pubkey,
        mentionPubkeys,
      );
      if (sentFromThreadRootId && parentEventId) {
        throw new Error(
          "A thread message can only be sent as a top-level message.",
        );
      }

      const sentFromThreadTag = sentFromThreadRootId
        ? buildSentFromThreadTag(
            sentFromThreadRootId,
            sentFromThreadRootExcerpt,
          )
        : undefined;

      // Captured sends use the native epoch fence until the shared WebSocket
      // publisher accepts publicationScope again.
      // Messages carrying media OR custom-emoji tags MUST go through REST so
      // the relay's tag validation runs. The WebSocket path emits no extra
      // tags, so emoji-only messages would otherwise lose their emoji tag.
      if (
        publicationScope !== undefined ||
        forceRest ||
        transport === "http" ||
        parentEventId ||
        imetaTags.length > 0 ||
        emojiTags.length > 0 ||
        linkPreviewTags.length > 0
      ) {
        const cachedMessages =
          queryClient.getQueryData<RelayEvent[]>(
            channelMessagesKey(effectiveChannel.id),
          ) ?? [];
        const threadCaches = queryClient
          .getQueriesData<RelayEvent[]>({
            queryKey: ["thread-replies", effectiveChannel.id],
          })
          .flatMap(([, events]) => (events ? [events] : []));
        const suppliedRootEventId = parentEventId
          ? resolveCachedReplyRootId(parentEventId, [
              cachedMessages,
              ...threadCaches,
            ])
          : null;
        const result = await sendChannelMessage(
          effectiveChannel.id,
          content,
          parentEventId ?? null,
          imetaTags,
          recipientPubkeys,
          undefined,
          emojiTags,
          mentionTags,
          linkPreviewTags,
          suppliedRootEventId,
          sentFromThreadTag,
          publicationScope,
        );

        // Build tags matching relay-emitted shape: h, author p, mention ps, reply es, imeta, emoji.
        // For replies, buildReplyTags already includes ["p", author] and ["h", channel].
        // For non-replies (media-only), we add them ourselves.
        const replyTags = parentEventId
          ? buildReplyTags(
              effectiveChannel.id,
              identity.pubkey,
              parentEventId,
              result.rootEventId ?? parentEventId,
              recipientPubkeys,
            )
          : [];
        const baseTags = parentEventId
          ? replyTags // buildReplyTags includes h + author p + mention ps
          : [
              ["h", effectiveChannel.id],
              ["p", identity.pubkey],
            ]; // non-reply: add ourselves

        return {
          id: result.eventId,
          pubkey: identity.pubkey,
          created_at: result.createdAt,
          kind: KIND_STREAM_MESSAGE,
          tags: [
            ...baseTags,
            // For non-replies, add mention p-tags here (replies get them via buildReplyTags)
            ...(!parentEventId
              ? normalizeMentionPubkeys(recipientPubkeys, identity.pubkey).map(
                  (pk) => ["p", pk],
                )
              : []),
            ...imetaTags,
            ...emojiTags,
            ...mentionTags,
            ...linkPreviewTags,
            ...(sentFromThreadTag ? [sentFromThreadTag] : []),
          ],
          content: content.trim(),
          sig: "",
        };
      }

      return relayClient.sendMessage(
        effectiveChannel.id,
        content,
        recipientPubkeys,
        [...mentionTags, ...(sentFromThreadTag ? [sentFromThreadTag] : [])],
      );
    },
    onMutate: async ({
      channelId: capturedChannelId,
      targetChannel,
      content,
      mentionPubkeys,
      parentEventId,
      mediaTags,
      sentFromThreadRootId,
      sentFromThreadRootExcerpt,
    }) => {
      // Mirror mutationFn's target resolution so the optimistic message lands
      // in the cache for the same channel as the real send. A caller-supplied
      // channel remains valid even when a stale channel-list read omitted it.
      const effectiveChannel = resolveSendChannel(
        targetChannel,
        capturedChannelId,
        queryClient.getQueryData<Channel[]>(channelsQueryKey),
        channel,
      );

      if (
        !effectiveChannel ||
        !identity ||
        effectiveChannel.channelType === "forum"
      ) {
        return undefined;
      }

      const queryKey = channelMessagesKey(effectiveChannel.id);
      const windowKey = channelWindowKey(effectiveChannel.id);
      // The rendered timeline is projected from the channel-window cache. Cancel
      // both reads before snapshotting either cache so an older window response
      // cannot replace the optimistic row between onMutate and onSuccess.
      await Promise.all([
        queryClient.cancelQueries({ queryKey }),
        queryClient.cancelQueries({ queryKey: windowKey }),
      ]);

      const currentMessages =
        queryClient.getQueryData<RelayEvent[]>(queryKey) ?? [];
      const currentWindow =
        queryClient.getQueryData<ChannelWindowStore>(windowKey);
      const optimisticMessage = createOptimisticMessage(
        effectiveChannel.id,
        content.trim(),
        identity,
        currentMessages,
        mentionPubkeys ?? [],
        parentEventId ?? null,
        mediaTags ?? [],
        sentFromThreadRootId ?? null,
        sentFromThreadRootExcerpt ?? null,
      );

      const nextWindow = mergeLiveChannelWindowEvent(
        currentWindow ?? emptyChannelWindowStore(),
        optimisticMessage,
      );
      queryClient.setQueryData(windowKey, nextWindow);
      projectChannelWindowMessages(queryClient, effectiveChannel.id);

      return {
        optimisticId: optimisticMessage.id,
        channelId: effectiveChannel.id,
      };
    },
    onError: (error, _variables, context) => {
      // A community timeout surfaces here as the relay's `OK false` reason.
      // Record it so the composer can show the timeout chip and block further
      // sends until it expires; other errors fall through to the caller.
      recordTimeoutFromRejection(error?.message);
      if (!context) {
        return;
      }

      removeChannelWindowMessage(
        queryClient,
        context.channelId,
        context.optimisticId,
      );
    },
    onSuccess: (message, _variables, context) => {
      // An accepted send proves the write-block is lifted; clear any recorded
      // timeout so the chip and disable state fall away immediately.
      clearTimeoutState();
      if (!context) {
        return;
      }

      const windowKey = channelWindowKey(context.channelId);
      const current =
        queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
        emptyChannelWindowStore();
      const withoutPending: ChannelWindowStore = {
        ...current,
        liveOverlay: current.liveOverlay.filter(
          (event) => event.id !== context.optimisticId,
        ),
      };
      const next = mergeLiveChannelWindowEvent(withoutPending, {
        ...message,
        localKey: context.optimisticId,
      });
      queryClient.setQueryData(windowKey, next);
      projectChannelWindowMessages(queryClient, context.channelId);
    },
  });
}

export function useToggleReactionMutation() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    Error,
    {
      eventId: string;
      emoji: string;
      remove: boolean;
    }
  >({
    mutationFn: async ({ eventId, emoji, remove }) => {
      if (remove) {
        await removeReaction(eventId, emoji);
        return;
      }

      // Custom-emoji reaction: emoji is `:shortcode:`. Resolve its image URL
      // from the cached community palette so the kind:7 carries the NIP-30
      // `["emoji", shortcode, url]` tag. Unicode reactions resolve to no URL.
      const emojiUrl = reactionEmojiUrl(
        emoji,
        queryClient.getQueryData<CustomEmoji[]>(customEmojiQueryKey),
      );
      await addReaction(eventId, emoji, emojiUrl);
    },
  });
}

export function useDeleteMessageMutation(channel: Channel | null) {
  const queryClient = useQueryClient();

  return useMutation<void, Error, { eventId: string }>({
    mutationFn: async ({ eventId }) => {
      if (!channel) {
        throw new Error("No channel selected.");
      }
      await deleteMessage(channel.id, eventId);
    },
    onSuccess: (_data, { eventId }) => {
      if (!channel) return;
      removeChannelWindowMessage(queryClient, channel.id, eventId);
    },
    onError: (error) => {
      toast.error(`Failed to delete message: ${error.message}`);
    },
  });
}

export { useEditMessageMutation } from "./useEditMessageMutation";
