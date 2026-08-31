import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

import { channelMessagesKey } from "@/features/messages/lib/messageQueryKeys";
import { mergeMessages } from "@/features/messages/hooks";
import {
  getChannelIdFromTags,
  getThreadReference,
} from "@/features/messages/lib/threading";
import { getEventById } from "@/shared/api/tauri";
import type { Channel, RelayEvent } from "@/shared/api/types";

const MAX_CONCURRENT_ANCESTOR_REQUESTS = 8;
const ANCESTOR_RETRY_BASE_DELAY_MS = 5_000;
const ANCESTOR_RETRY_MAX_DELAY_MS = 60_000;

type TimerHandle = ReturnType<typeof setTimeout>;

type MissingAncestorSchedulerOptions<T> = {
  load: (eventId: string) => Promise<T>;
  onLoaded: (eventId: string, value: T) => void;
  onError?: (eventId: string, error: unknown) => void;
  maxConcurrency?: number;
  retryBaseDelayMs?: number;
  retryMaxDelayMs?: number;
  now?: () => number;
  setTimer?: (callback: () => void, delayMs: number) => TimerHandle;
  clearTimer?: (handle: TimerHandle) => void;
};

export type MissingAncestorScheduler = {
  dispose: () => void;
  enqueue: (eventIds: Iterable<string>) => void;
  forgetKnown: (eventIds: Iterable<string>) => void;
  snapshot: () => {
    coolingDown: number;
    inFlight: number;
    queued: number;
  };
};

/**
 * Schedule missing-ancestor reads without dropping overflow or retrying failures
 * on every React render. Failed IDs remain in cooldown state until their next
 * retry time; queued work starts only when a bounded request slot is available.
 */
export function createMissingAncestorScheduler<T>({
  load,
  onLoaded,
  onError,
  maxConcurrency = MAX_CONCURRENT_ANCESTOR_REQUESTS,
  retryBaseDelayMs = ANCESTOR_RETRY_BASE_DELAY_MS,
  retryMaxDelayMs = ANCESTOR_RETRY_MAX_DELAY_MS,
  now = Date.now,
  setTimer: scheduleTimer = setTimeout,
  clearTimer: cancelTimer = clearTimeout,
}: MissingAncestorSchedulerOptions<T>): MissingAncestorScheduler {
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new Error("Missing ancestor concurrency must be a positive integer.");
  }

  const queue: string[] = [];
  const queuedIds = new Set<string>();
  const inFlightIds = new Set<string>();
  const ignoredInFlightIds = new Set<string>();
  const retryById = new Map<string, { attempt: number; retryAfter: number }>();
  let disposed = false;
  let retryTimer: TimerHandle | null = null;
  let retryTimerDueAt: number | null = null;

  const clearRetryTimer = () => {
    if (retryTimer !== null) {
      cancelTimer(retryTimer);
      retryTimer = null;
      retryTimerDueAt = null;
    }
  };

  const queueId = (eventId: string) => {
    if (disposed || queuedIds.has(eventId) || inFlightIds.has(eventId)) return;
    queuedIds.add(eventId);
    queue.push(eventId);
  };

  const scheduleNextRetry = () => {
    if (disposed) return;

    let earliestRetryAt = Number.POSITIVE_INFINITY;
    for (const [eventId, retry] of retryById) {
      if (!queuedIds.has(eventId) && !inFlightIds.has(eventId)) {
        earliestRetryAt = Math.min(earliestRetryAt, retry.retryAfter);
      }
    }
    if (!Number.isFinite(earliestRetryAt)) {
      clearRetryTimer();
      return;
    }
    if (
      retryTimer !== null &&
      retryTimerDueAt !== null &&
      retryTimerDueAt <= earliestRetryAt
    ) {
      return;
    }

    clearRetryTimer();
    retryTimerDueAt = earliestRetryAt;
    retryTimer = scheduleTimer(
      () => {
        retryTimer = null;
        retryTimerDueAt = null;
        if (disposed) return;

        const currentTime = now();
        for (const [eventId, retry] of retryById) {
          if (retry.retryAfter <= currentTime) queueId(eventId);
        }
        drain();
        scheduleNextRetry();
      },
      Math.max(0, earliestRetryAt - now()),
    );
  };

  const complete = (eventId: string) => {
    inFlightIds.delete(eventId);
    ignoredInFlightIds.delete(eventId);
    if (!disposed) {
      drain();
      scheduleNextRetry();
    }
  };

  const run = (eventId: string) => {
    inFlightIds.add(eventId);
    let request: Promise<T>;
    try {
      request = load(eventId);
    } catch (error) {
      request = Promise.reject(error);
    }
    void request
      .then(
        (value) => {
          if (!disposed && !ignoredInFlightIds.has(eventId)) {
            retryById.delete(eventId);
            onLoaded(eventId, value);
          }
        },
        (error: unknown) => {
          if (!disposed && !ignoredInFlightIds.has(eventId)) {
            const attempt = (retryById.get(eventId)?.attempt ?? 0) + 1;
            const retryDelay = Math.min(
              retryMaxDelayMs,
              retryBaseDelayMs * 2 ** Math.min(attempt - 1, 30),
            );
            retryById.set(eventId, {
              attempt,
              retryAfter: now() + retryDelay,
            });
            onError?.(eventId, error);
          }
        },
      )
      .finally(() => complete(eventId));
  };

  function drain() {
    while (!disposed && inFlightIds.size < maxConcurrency && queue.length > 0) {
      const eventId = queue.shift();
      if (!eventId || !queuedIds.delete(eventId)) continue;

      const retry = retryById.get(eventId);
      if (retry && retry.retryAfter > now()) continue;
      run(eventId);
    }
  }

  return {
    dispose() {
      disposed = true;
      clearRetryTimer();
      queue.length = 0;
      queuedIds.clear();
      retryById.clear();
    },
    enqueue(eventIds) {
      const currentTime = now();
      for (const eventId of eventIds) {
        const retry = retryById.get(eventId);
        if (retry && retry.retryAfter > currentTime) continue;
        queueId(eventId);
      }
      drain();
      scheduleNextRetry();
    },
    forgetKnown(eventIds) {
      for (const eventId of eventIds) {
        retryById.delete(eventId);
        queuedIds.delete(eventId);
        if (inFlightIds.has(eventId)) ignoredInFlightIds.add(eventId);
      }
      scheduleNextRetry();
    },
    snapshot() {
      return {
        coolingDown: retryById.size,
        inFlight: inFlightIds.size,
        queued: queuedIds.size,
      };
    },
  };
}

export function useLoadMissingAncestors(
  activeChannel: Channel | null,
  resolvedMessages: RelayEvent[],
) {
  const queryClient = useQueryClient();
  const schedulerRef = React.useRef<MissingAncestorScheduler | null>(null);
  const activeChannelId = activeChannel?.id ?? null;
  const activeChannelType = activeChannel?.channelType ?? null;

  React.useEffect(() => {
    if (!activeChannelId || activeChannelType === "forum") {
      schedulerRef.current = null;
      return;
    }

    const scheduler = createMissingAncestorScheduler({
      load: getEventById,
      onLoaded: (_eventId, event) => {
        if (getChannelIdFromTags(event.tags) !== activeChannelId) return;
        queryClient.setQueryData<RelayEvent[]>(
          channelMessagesKey(activeChannelId),
          (current = []) => mergeMessages(current, event),
        );
      },
      onError: (eventId, error) => {
        console.error("Failed to load ancestor event", eventId, error);
      },
    });
    schedulerRef.current = scheduler;

    return () => {
      scheduler.dispose();
      if (schedulerRef.current === scheduler) schedulerRef.current = null;
    };
  }, [activeChannelId, activeChannelType, queryClient]);

  React.useEffect(() => {
    const scheduler = schedulerRef.current;
    if (!scheduler || !activeChannelId || activeChannelType === "forum") {
      return;
    }

    const knownEventIds = new Set(
      resolvedMessages.map((message) => message.id),
    );
    scheduler.forgetKnown(knownEventIds);
    const missingAncestorIds = new Set<string>();

    for (const message of resolvedMessages) {
      const thread = getThreadReference(message.tags);
      for (const eventId of [thread.parentId, thread.rootId]) {
        if (eventId && !knownEventIds.has(eventId))
          missingAncestorIds.add(eventId);
      }
    }
    scheduler.enqueue(missingAncestorIds);
  }, [activeChannelId, activeChannelType, resolvedMessages]);
}
