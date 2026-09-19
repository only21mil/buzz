import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readWatermark,
  writeWatermark,
  resetReminderWatermarks,
} from "./reminderWatermarks.ts";

test("reminder polls preserve independent persisted community watermarks", (t) => {
  const previous = globalThis.window;
  const stored = new Map();
  globalThis.window = {
    localStorage: {
      getItem: (key) => stored.get(key) ?? null,
      setItem: (key, value) => stored.set(key, value),
    },
  };
  t.after(() => {
    globalThis.window = previous;
    resetReminderWatermarks();
  });
  writeWatermark("A", "USER", 100);
  writeWatermark("B", "user", 200);
  resetReminderWatermarks();
  assert.equal(readWatermark("A", "user"), 100);
  assert.equal(readWatermark("B", "USER"), 200);
});

test("community reset clears fallback watermarks when storage is unavailable", (t) => {
  const previous = globalThis.window;
  globalThis.window = {
    localStorage: {
      getItem: () => null,
      setItem: () => {
        throw new Error("denied");
      },
    },
  };
  t.mock.method(console, "warn", () => {});
  t.mock.method(Date, "now", () => 300000);
  t.after(() => {
    globalThis.window = previous;
    resetReminderWatermarks();
  });
  writeWatermark("A", "user", 100);
  assert.equal(readWatermark("A", "user"), 100);
  resetReminderWatermarks();
  assert.equal(readWatermark("A", "user"), 300);
});
