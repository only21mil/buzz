import {
  hasSameMessageAuthor,
  isWithinGroupingWindow,
} from "@/features/messages/lib/messageGrouping";
import type { MainTimelineEntry } from "@/features/messages/lib/threadPanel";
import type { TimelineMessage } from "@/features/messages/types";

type ThreadReplyAncestor = {
  message: TimelineMessage;
};

export type MessageThreadPanelRenderItem = {
  collapseDepthGuideAncestors: readonly TimelineMessage[];
  connectsToVisibleChild: boolean;
  continuationDepths: readonly number[];
  entry: MainTimelineEntry;
  index: number;
  isContinuation: boolean;
};

type BuildMessageThreadPanelRenderItemsOptions = {
  entries: readonly MainTimelineEntry[];
  firstUnreadReplyId?: string | null;
  isHuddleTranscript: boolean;
  threadHead: TimelineMessage;
};

/**
 * Marks rows whose next visible node at the same or a shallower depth is a
 * sibling. The reverse stack visits each row once. It replaces the former
 * forward scan, which revisited the rest of a wide thread for every row.
 */
export function buildLaterVisibleSiblingFlags(
  entries: readonly MainTimelineEntry[],
): boolean[] {
  const flags = new Array<boolean>(entries.length).fill(false);
  const candidateDepths: number[] = [];

  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const depth = entries[index].message.depth;

    while (
      candidateDepths.length > 0 &&
      candidateDepths[candidateDepths.length - 1] > depth
    ) {
      candidateDepths.pop();
    }

    flags[index] = candidateDepths[candidateDepths.length - 1] === depth;
    if (!flags[index]) {
      candidateDepths.push(depth);
    }
  }

  return flags;
}

export function buildMessageThreadPanelRenderItems({
  entries,
  firstUnreadReplyId,
  isHuddleTranscript,
  threadHead,
}: BuildMessageThreadPanelRenderItemsOptions): MessageThreadPanelRenderItem[] {
  const hasLaterVisibleSibling = buildLaterVisibleSiblingFlags(entries);
  const ancestorStack: ThreadReplyAncestor[] = [{ message: threadHead }];
  const ancestorByDepth = new Map<number, TimelineMessage>([
    [threadHead.depth, threadHead],
  ]);
  const activeContinuationDepths: number[] = [];
  let previousGroupMessage: TimelineMessage | null = threadHead;

  return entries.map((entry, index) => {
    const message = entry.message;
    while (
      ancestorStack.length > 0 &&
      ancestorStack[ancestorStack.length - 1].message.depth >= message.depth
    ) {
      const removedAncestor = ancestorStack.pop();
      if (
        removedAncestor &&
        ancestorByDepth.get(removedAncestor.message.depth) ===
          removedAncestor.message
      ) {
        ancestorByDepth.delete(removedAncestor.message.depth);
      }
    }

    const directParentDepth = message.depth - 1;
    while (
      activeContinuationDepths.length > 0 &&
      activeContinuationDepths[activeContinuationDepths.length - 1] >=
        directParentDepth
    ) {
      activeContinuationDepths.pop();
    }

    let retainedDepthCount = 0;
    for (const activeDepth of activeContinuationDepths) {
      if (ancestorByDepth.has(activeDepth + 1)) {
        activeContinuationDepths[retainedDepthCount] = activeDepth;
        retainedDepthCount += 1;
      }
    }
    activeContinuationDepths.length = retainedDepthCount;

    const directParent = ancestorByDepth.get(directParentDepth);
    if (
      directParentDepth > 0 &&
      directParent &&
      hasLaterVisibleSibling[index]
    ) {
      activeContinuationDepths.push(directParentDepth);
    }

    const continuationDepths = [...activeContinuationDepths];
    const collapseDepthGuideAncestors = continuationDepths.flatMap((depth) => {
      const ancestor = ancestorByDepth.get(depth);
      return ancestor ? [ancestor] : [];
    });
    const nextEntry = entries[index + 1];
    const connectsToVisibleChild =
      nextEntry != null && nextEntry.message.depth > message.depth;
    const startsUnreadSection = index > 0 && message.id === firstUnreadReplyId;
    const isContinuation =
      !isHuddleTranscript &&
      !startsUnreadSection &&
      entry.summary === null &&
      hasSameMessageAuthor(previousGroupMessage, message) &&
      isWithinGroupingWindow(
        previousGroupMessage?.createdAt,
        message.createdAt,
      );

    if (connectsToVisibleChild && !entry.summary) {
      const ancestor = { message };
      ancestorStack.push(ancestor);
      ancestorByDepth.set(message.depth, message);
    }

    previousGroupMessage = entry.summary !== null ? null : message;

    return {
      collapseDepthGuideAncestors,
      connectsToVisibleChild,
      continuationDepths,
      entry,
      index,
      isContinuation,
    };
  });
}
