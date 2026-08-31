import assert from "node:assert/strict";
import test from "node:test";

import {
  INITIAL_TIMELINE_RETENTION_LIMIT,
  initialRetainedTimelineKeys,
  nextRetainedTimelineKeys,
  retainedTimelineIndices,
} from "./timelineRetention.ts";

function fixedHeightList({ itemCount, rowHeight, scrollOffset, viewportSize }) {
  const scrollSize = itemCount * rowHeight;
  return {
    findItemIndex(offset) {
      return Math.min(itemCount - 1, Math.floor(offset / rowHeight));
    },
    scrollOffset,
    scrollSize,
    viewportSize,
  };
}

test("fresh 600-item timeline retains only a bounded visual tail", () => {
  const keys = Array.from({ length: 600 }, (_, index) => `message-${index}`);
  const retainedKeys = initialRetainedTimelineKeys(keys);

  assert.equal(retainedKeys.size, INITIAL_TIMELINE_RETENTION_LIMIT);
  assert.deepEqual(
    retainedTimelineIndices(keys, retainedKeys),
    Array.from(
      { length: INITIAL_TIMELINE_RETENTION_LIMIT },
      (_, index) => keys.length - INITIAL_TIMELINE_RETENTION_LIMIT + index,
    ),
  );
});

test("a normal initial channel window remains protected during first scroll", () => {
  const keys = Array.from({ length: 50 }, (_, index) => `item-${index}`);
  const retainedKeys = initialRetainedTimelineKeys(keys);

  assert.deepEqual(
    retainedTimelineIndices(keys, retainedKeys),
    keys.map((_, index) => index),
  );
});

test("an empty initial timeline has no retained keys", () => {
  assert.equal(initialRetainedTimelineKeys([]).size, 0);
});

test("scroll settle retains the reader neighborhood and visual tail", () => {
  const keys = Array.from({ length: 600 }, (_, index) => `message-${index}`);
  const list = fixedHeightList({
    itemCount: keys.length,
    rowHeight: 80,
    scrollOffset: 24_000,
    viewportSize: 800,
  });

  const retained = nextRetainedTimelineKeys(
    keys,
    initialRetainedTimelineKeys(keys),
    list,
  );

  assert.ok(retained.has("message-300"));
  assert.ok(retained.has("message-599"));
  assert.ok(retained.size < keys.length);
});

test("retained indices preserve timeline order", () => {
  const keys = ["a", "b", "c", "d"];
  const retained = new Set(["d", "b"]);

  assert.deepEqual(retainedTimelineIndices(keys, retained), [1, 3]);
});
