import type { QueryClient } from "@tanstack/react-query";

import type { RelayEvent } from "@/shared/api/types";
import { channelMessagesKey, channelWindowKey } from "./messageQueryKeys";
import {
  removeChannelWindowEvent,
  type ChannelWindowStore,
} from "./channelWindowStore";
import { projectChannelWindowMessages } from "./projectChannelWindow";

/**
 * Remove one local mutation row without restoring a stale cache snapshot.
 * The window is authoritative when present, so later live projections cannot
 * resurrect a removed row and concurrent live rows remain intact.
 */
export function removeChannelWindowMessage(
  queryClient: QueryClient,
  channelId: string,
  eventId: string,
): void {
  const windowKey = channelWindowKey(channelId);
  const current = queryClient.getQueryData<ChannelWindowStore>(windowKey);
  queryClient.setQueryData<RelayEvent[]>(
    channelMessagesKey(channelId),
    (messages = []) => messages.filter((message) => message.id !== eventId),
  );
  if (!current) {
    return;
  }

  const next = removeChannelWindowEvent(current, eventId);
  if (next !== current) {
    queryClient.setQueryData(windowKey, next);
  }
  projectChannelWindowMessages(queryClient, channelId);
}
