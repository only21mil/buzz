import type { VListHandle } from "virtua";

/**
 * Retain at most one bounded initial page around the visual tail. Channel
 * windows normally open with 50 messages, so the same hard limit protects the
 * first reading surface while a remounted, deeply cached channel never hands
 * Virtua an unbounded keepMounted list. The first scroll settle replaces this
 * seed with the normal viewport-relative retention window.
 */
export const INITIAL_TIMELINE_RETENTION_LIMIT = 50;

export function initialRetainedTimelineKeys(
  keys: readonly string[],
): ReadonlySet<string> {
  return new Set(keys.slice(-INITIAL_TIMELINE_RETENTION_LIMIT));
}

export function retainedTimelineIndices(
  keys: readonly string[],
  retainedKeys: ReadonlySet<string>,
): number[] {
  if (retainedKeys.size === 0) return [];
  return keys.flatMap((key, index) => (retainedKeys.has(key) ? [index] : []));
}

/**
 * Keep a wide ID-keyed neighborhood around the reader plus the visual tail.
 * The wider eviction band adds hysteresis, so small direction changes do not
 * churn mounted rows. Virtua continues to own measured sizes and spacer math.
 */
export function nextRetainedTimelineKeys(
  keys: readonly string[],
  previous: ReadonlySet<string>,
  list: VListHandle,
): ReadonlySet<string> {
  const viewportSize = Math.max(list.viewportSize, 1);
  const offset = list.scrollOffset;
  const indexAt = (target: number) =>
    list.findItemIndex(Math.min(list.scrollSize, Math.max(0, target)));
  const admissionStart = indexAt(offset - viewportSize * 8);
  const admissionEnd = indexAt(offset + viewportSize * 9);
  const evictionStart = indexAt(offset - viewportSize * 12);
  const evictionEnd = indexAt(offset + viewportSize * 13);
  const tailStart = indexAt(list.scrollSize - viewportSize * 3);
  const next = new Set<string>();

  for (let index = evictionStart; index <= evictionEnd; index += 1) {
    const key = keys[index];
    if (key && previous.has(key)) next.add(key);
  }
  for (let index = admissionStart; index <= admissionEnd; index += 1) {
    const key = keys[index];
    if (key) next.add(key);
  }
  for (let index = tailStart; index < keys.length; index += 1) {
    const key = keys[index];
    if (key) next.add(key);
  }

  return next.size === previous.size &&
    [...next].every((key) => previous.has(key))
    ? previous
    : next;
}
