import assert from "node:assert/strict";
import test from "node:test";

import {
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

test("fresh 600-item timeline leaves keepMounted empty", () => {
  const keys = Array.from({ length: 600 }, (_, index) => `message-${index}`);
  const retainedKeys = initialRetainedTimelineKeys();

  assert.equal(retainedKeys.size, 0);
  assert.deepEqual(retainedTimelineIndices(keys, retainedKeys), []);
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
    initialRetainedTimelineKeys(),
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
