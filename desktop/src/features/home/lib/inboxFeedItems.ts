import type { FeedItem } from "@/shared/api/types";
import { KIND_REMINDER } from "@/shared/constants/kinds";

/**
 * Kind 40007 stream reminders arrive in the home feed under needs_action, but
 * the Inbox lists reminders from the dedicated NIP-ER query instead (see
 * useHomePersonalInbox), so those feed rows never render. The Inbox nav badge
 * has to apply the same rule: a feed item the Inbox never shows cannot be
 * opened or marked read, and would keep the badge lit with no channel dot.
 */
export function isInboxListedFeedItem(item: Pick<FeedItem, "kind">): boolean {
  return item.kind !== KIND_REMINDER;
}
