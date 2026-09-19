import assert from "node:assert/strict";
import { test } from "node:test";
import { clearTrayAgentActivity } from "./trayMenu.ts";

test("tray teardown absorbs a rejected native invoke and warns", async (t) => {
  const previousWindow = globalThis.window;
  t.after(() => {
    globalThis.window = previousWindow;
  });
  const calls = [];
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async (command) => {
        calls.push(command);
        throw new Error("tray unavailable");
      },
    },
  };
  const warn = t.mock.method(console, "warn", () => {});
  await assert.doesNotReject(clearTrayAgentActivity());
  assert.deepEqual(calls, ["clear_tray_agent_activity"]);
  assert.equal(warn.mock.callCount(), 1);
});
