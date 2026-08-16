import type { QueryClient } from "@tanstack/react-query";

import type { RelayEvent } from "@/shared/api/types";
import {
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
  KIND_CHANNEL_THREAD_SUMMARY,
  KIND_SYSTEM_MESSAGE,
} from "@/shared/constants/kinds";
import {
  bufferHeadTransactionEvent,
  type ChannelSubscriptionGeneration,
} from "./headWindowTransaction";
import { channelWindowKey, threadRepliesKey } from "./messageQueryKeys";
import { mergeMessages } from "./messageMerge";
import { projectChannelWindowMessages } from "./projectChannelWindow";
import {
  emptyChannelWindowStore,
  mergeLiveChannelWindowEvent,
  type ChannelWindowStore,
} from "./channelWindowStore";
import { reconcileLiveThreadSummary } from "./threadSummaryReconciliation";
import { getThreadReference, isBroadcastReply } from "./threading";

const TIMELINE_KINDS = new Set<number>(CHANNEL_TIMELINE_CONTENT_KINDS);
const AUX_KINDS = new Set<number>(CHANNEL_AUX_EVENT_KINDS);

/** Apply one live event only to the subscription generation that delivered it. */
export function appendChannelSubscriptionEvent(
  queryClient: QueryClient,
  event: RelayEvent,
  generationToken: ChannelSubscriptionGeneration,
): void {
  if (!generationToken.guard.current) return;
  const channelId = generationToken.channelId;
  if (event.kind === KIND_CHANNEL_THREAD_SUMMARY) {
    reconcileLiveThreadSummary(queryClient, channelId, event);
    return;
  }
  const isTimelineRow = TIMELINE_KINDS.has(event.kind);
  const threadReference = isTimelineRow ? getThreadReference(event.tags) : null;
  if (threadReference?.parentId != null) {
    const rootId = threadReference.rootId;
    if (rootId) {
      queryClient.setQueryData<RelayEvent[]>(
        threadRepliesKey(channelId, rootId),
        (current = []) => mergeMessages(current, event),
      );
    }
    if (!isBroadcastReply(event.tags)) return;
  }
  if (!isTimelineRow && !AUX_KINDS.has(event.kind)) return;
  if (!isTimelineRow) {
    queryClient.setQueriesData<RelayEvent[]>(
      { queryKey: ["thread-replies", channelId] },
      (current = []) => mergeMessages(current, event),
    );
  }
  bufferHeadTransactionEvent(generationToken, event);

  const windowKey = channelWindowKey(channelId);
  const current =
    queryClient.getQueryData<ChannelWindowStore>(windowKey) ??
    emptyChannelWindowStore();
  const next = mergeLiveChannelWindowEvent(current, event, isTimelineRow);
  if (next !== current) {
    queryClient.setQueryData(windowKey, next);
    projectChannelWindowMessages(queryClient, channelId);
  }

  if (event.kind !== KIND_SYSTEM_MESSAGE) return;
  try {
    const payload = JSON.parse(event.content) as { type?: string };
    if (
      payload.type === "member_joined" ||
      payload.type === "member_left" ||
      payload.type === "member_removed"
    ) {
      void queryClient.invalidateQueries({
        queryKey: ["channels", channelId, "members"],
      });
      void queryClient.invalidateQueries({
        queryKey: ["channels"],
        exact: true,
      });
    }
  } catch {
    // Non-JSON system message — ignore.
  }
}
