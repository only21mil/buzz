import {
  getThreadReference,
  isBroadcastReply,
} from "@/features/messages/lib/threading";
import { isHighPriorityEventForUser } from "@/features/notifications/lib/shouldNotify";
import type { Channel, RelayEvent } from "@/shared/api/types";

/** Classify an admitted unread event identically for live and startup catch-up. */
export function observedUnreadPriority(
  event: RelayEvent,
  channelType: Channel["channelType"] | undefined,
  pubkey: string | null,
) {
  const isThreadedReply =
    getThreadReference(event.tags).parentId !== null &&
    !isBroadcastReply(event.tags);
  return {
    isThreadedReply,
    isHighPriority:
      channelType === "dm" ||
      isThreadedReply ||
      (pubkey !== null && isHighPriorityEventForUser(event, pubkey)),
  };
}
