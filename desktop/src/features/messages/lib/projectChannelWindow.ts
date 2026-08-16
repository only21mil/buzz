import type { QueryClient } from "@tanstack/react-query";

import type { RelayEvent } from "@/shared/api/types";
import {
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
} from "@/shared/constants/kinds";
import { channelMessagesKey, channelWindowKey } from "./messageQueryKeys";
import {
  emptyChannelWindowStore,
  mergeLiveChannelWindowEvent,
  type ChannelWindowStore,
} from "./channelWindowStore";
import { reconcileChannelWindowMessages } from "./channelWindowReconciliation";

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
  await queryClient.invalidateQueries({
    queryKey: channelMessagesKey(channelId),
    exact: true,
    refetchType: "active",
  });
  if (!isCurrent()) return;
  projectChannelWindowMessages(queryClient, channelId);
}
