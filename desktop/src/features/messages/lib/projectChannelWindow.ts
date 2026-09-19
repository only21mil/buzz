import type { QueryClient } from "@tanstack/react-query";

import type { RelayEvent } from "@/shared/api/types";
import {
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
} from "@/shared/constants/kinds";
import { channelMessagesKey, channelWindowKey } from "./messageQueryKeys";
import {
  emptyChannelWindowStore,
  mergeHeadTransactionChannelWindowEvent,
  mergeLiveChannelWindowEvent,
  mergeLiveThreadSummary,
  type ChannelWindowStore,
  type LiveThreadSummary,
} from "./channelWindowStore";
import { reconcileChannelWindowMessages } from "./channelWindowReconciliation";
import { channelHeadHydration } from "./channelHeadCache";

const TIMELINE_KINDS: ReadonlySet<number> = new Set(
  CHANNEL_TIMELINE_CONTENT_KINDS,
);
const AUX_KINDS: ReadonlySet<number> = new Set(CHANNEL_AUX_EVENT_KINDS);

/** Merge bounded timeline/aux events through the store's existing live paths. */
export function mergeChannelWindowOverlayEvents(
  store: ChannelWindowStore,
  events: RelayEvent[],
): ChannelWindowStore {
  return events.reduce((current, event) => {
    if (TIMELINE_KINDS.has(event.kind)) {
      return mergeLiveChannelWindowEvent(current, event);
    }
    if (AUX_KINDS.has(event.kind)) {
      return mergeLiveChannelWindowEvent(current, event, false);
    }
    return current;
  }, store);
}

/** Replay only events captured during the exact active head transaction. */
export function mergeHeadTransactionChannelWindowEvents(
  store: ChannelWindowStore,
  events: RelayEvent[],
): ChannelWindowStore {
  return events.reduce((current, event) => {
    if (TIMELINE_KINDS.has(event.kind)) {
      return mergeHeadTransactionChannelWindowEvent(current, event);
    }
    if (AUX_KINDS.has(event.kind)) {
      return mergeHeadTransactionChannelWindowEvent(current, event, false);
    }
    return current;
  }, store);
}

/** Carry only summaries that changed after the authoritative head read began. */
export function mergeHeadTransactionLiveSummaries(
  store: ChannelWindowStore,
  baseline: Record<string, LiveThreadSummary>,
  latest: Record<string, LiveThreadSummary>,
): ChannelWindowStore {
  return Object.entries(latest).reduce((current, [rootId, summary]) => {
    return baseline[rootId]?.eventId === summary.eventId
      ? current
      : mergeLiveThreadSummary(current, rootId, summary);
  }, store);
}

/** Seed an unresolved channel window from a bounded durable snapshot. */
export function seedChannelWindowStoreFromSnapshot(
  events: RelayEvent[],
): ChannelWindowStore {
  return mergeChannelWindowOverlayEvents(emptyChannelWindowStore(), events);
}

/** Keep the rendered timeline cache aligned with its authoritative window. */
export function projectChannelWindowMessages(
  queryClient: QueryClient,
  channelId: string,
) {
  const window =
    queryClient.getQueryData<ChannelWindowStore>(channelWindowKey(channelId)) ??
    emptyChannelWindowStore();
  queryClient.setQueryData<RelayEvent[]>(
    channelMessagesKey(channelId),
    (messages = []) => reconcileChannelWindowMessages(window, messages),
  );
}

export async function refreshChannelWindowMessages(
  queryClient: QueryClient,
  channelId: string,
  isCurrent: () => boolean = () => true,
) {
  const queryKey = channelMessagesKey(channelId);
  // Sequence behind persisted-head hydration. While the channel query is parked
  // on that gate it has no data, so TanStack would dedupe this invalidation
  // onto it — and that fetch returns the seeded snapshot, never asking the
  // relay. A seeded query is recognisable by data at `dataUpdatedAt` 0; let its
  // snapshot fetch settle (consuming the mount gate) before invalidating, so
  // the refetch is a distinct authoritative window fetch. Concurrent callers
  // (subscribe settlement + reconnect) wake on the same promise, so the seeded
  // branch must join an authoritative fetch already in flight rather than
  // cancel and replace it. Cold and warm channels carry no such marker and
  // dedupe/cancel exactly as before.
  await channelHeadHydration(queryClient);
  const query = queryClient.getQueryCache().find({ queryKey, exact: true });
  const seeded =
    query?.state.data !== undefined && query.state.dataUpdatedAt === 0;
  if (seeded) {
    await query.promise?.catch(() => {});
  }
  await queryClient.invalidateQueries(
    { queryKey, exact: true, refetchType: "active" },
    { cancelRefetch: !seeded, throwOnError: true },
  );
  if (!isCurrent()) return;
  projectChannelWindowMessages(queryClient, channelId);
}
