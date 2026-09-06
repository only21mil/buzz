import assert from "node:assert/strict";
import test, { mock } from "node:test";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useTrayMenu } from "./useTrayMenu.ts";
import {
  resetActiveAgentTurnsStore,
  syncAgentTurnsFromEvents,
  getActiveTurnsForAgent,
} from "../features/agents/activeAgentTurnsStore.ts";

const agent = "a".repeat(64);
const channels = [{ id: "channel", name: "General" }];
const goChannel = async () => {};
const openCreateChannel = () => {};

test("hidden native tray advances elapsed time and expires a silent agent", async () => {
  const dom = new JSDOM("<div id='root'></div>");
  const original = {
    window: globalThis.window,
    document: globalThis.document,
    isTauri: globalThis.isTauri,
    IS_REACT_ACT_ENVIRONMENT: globalThis.IS_REACT_ACT_ENVIRONMENT,
  };
  Object.assign(globalThis, {
    window: dom.window,
    document: dom.window.document,
    isTauri: true,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  Object.defineProperty(document, "visibilityState", { value: "hidden" });
  const updates = [];
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1,
    unregisterCallback: () => {},
    invoke: async (command, args) => {
      if (command === "update_tray_agent_activity") {
        updates.push(args);
        return;
      }
      if (command === "plugin:event|listen") return 1;
      if (
        command === "take_tray_actions" ||
        command === "list_managed_agents" ||
        command === "list_relay_agents"
      )
        return [];
      return null;
    },
  };
  const epoch = Date.parse("2026-08-01T00:00:00Z");
  mock.timers.enable({ apis: ["Date", "setInterval"], now: epoch });
  resetActiveAgentTurnsStore();
  syncAgentTurnsFromEvents(agent, [
    {
      seq: 1,
      timestamp: new Date(epoch).toISOString(),
      kind: "turn_started",
      agentIndex: 0,
      channelId: "channel",
      sessionId: "session",
      turnId: "turn",
      payload: null,
    },
  ]);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  client.setQueryData(["managed-agents"], []);
  client.setQueryData(["relay-agents"], []);
  const root = createRoot(document.getElementById("root"));
  function Harness() {
    useTrayMenu({ channels, goChannel, openCreateChannel });
    return null;
  }
  try {
    await act(async () =>
      root.render(
        React.createElement(
          QueryClientProvider,
          { client },
          React.createElement(Harness),
        ),
      ),
    );
    const initial = updates.at(-1).activities[0].elapsed;
    await act(async () => mock.timers.tick(1000));
    assert.notEqual(updates.at(-1).activities[0].elapsed, initial);
    await act(async () => mock.timers.tick(10 * 60_000));
    assert.equal(getActiveTurnsForAgent(agent).length, 0);
    assert.deepEqual(updates.at(-1).activities, []);
  } finally {
    await act(async () => root.unmount());
    client.clear();
    resetActiveAgentTurnsStore();
    mock.timers.reset();
    dom.window.close();
    Object.assign(globalThis, original);
  }
});
