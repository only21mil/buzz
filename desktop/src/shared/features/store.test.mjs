import assert from "node:assert/strict";
import test from "node:test";
import { getOverrides, setOverride, clearOverride } from "./store.ts";

test("thread session opt-in persists and clears independently", () => {
  const data = new Map();
  const previous = globalThis.window;
  globalThis.window = {
    localStorage: {
      getItem: (key) => data.get(key) ?? null,
      setItem: (key, value) => data.set(key, value),
    },
  };
  try {
    assert.equal(getOverrides().threadScopedAcpSessions, undefined);
    setOverride("projects", true);
    setOverride("threadScopedAcpSessions", true);
    assert.deepEqual(getOverrides(), {
      projects: true,
      threadScopedAcpSessions: true,
    });
    setOverride("threadScopedAcpSessions", false);
    assert.equal(getOverrides().threadScopedAcpSessions, false);
    clearOverride("threadScopedAcpSessions");
    assert.deepEqual(getOverrides(), { projects: true });
  } finally {
    globalThis.window = previous;
  }
});
