import assert from "node:assert/strict";
import test, { mock } from "node:test";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { relayClient } from "@/shared/api/relayClient.ts";
import { useTtsSubscription } from "./useTtsSubscription.ts";

const self = { current: "self" };
test("hidden huddle refresh fails closed and recovers without stopping its live subscription", async () => {
  const dom = new JSDOM("<div id='root'></div>");
  const previous = {
    window: globalThis.window,
    document: globalThis.document,
    IS_REACT_ACT_ENVIRONMENT: globalThis.IS_REACT_ACT_ENVIRONMENT,
  };
  const subscribe = relayClient.subscribeLive;
  Object.assign(globalThis, {
    window: dom.window,
    document: dom.window.document,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  let visible = "visible";
  Object.defineProperty(document, "visibilityState", { get: () => visible });
  let unavailable = false;
  let membershipLoads = 0;
  const spoken = [];
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1,
    unregisterCallback: () => {},
    invoke: async (command, args) => {
      if (command === "get_huddle_agent_pubkeys") {
        membershipLoads++;
        if (unavailable) throw new Error("membership unavailable");
        return ["bot"];
      }
      if (command === "get_huddle_state") return { tts_enabled: true };
      if (command === "speak_agent_message") spoken.push(args.text);
      return 1;
    },
  };
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  let deliver;
  let unsubscribed = false;
  relayClient.subscribeLive = async (_filter, callback) => {
    deliver = callback;
    return async () => {
      unsubscribed = true;
    };
  };
  mock.timers.enable({
    apis: ["Date", "setInterval"],
    now: Date.parse("2026-08-01T00:00:00Z"),
  });
  window.setInterval = globalThis.setInterval;
  window.clearInterval = globalThis.clearInterval;
  const root = createRoot(document.getElementById("root"));
  function Harness() {
    useTtsSubscription("huddle", self);
    return null;
  }
  const message = (id, content) => ({
    id,
    pubkey: "bot",
    kind: 9,
    created_at: Math.floor(Date.now() / 1000),
    content,
    tags: [["h", "huddle"]],
    sig: "sig",
  });
  try {
    await act(async () => root.render(React.createElement(Harness)));
    await act(async () => deliver(message("first", "first")));
    assert.deepEqual(spoken, ["first"]);
    unavailable = true;
    visible = "hidden";
    document.dispatchEvent(new window.Event("visibilitychange"));
    await act(async () => mock.timers.tick(60_000));
    assert.ok(membershipLoads >= 3);
    await act(async () => deliver(message("failed", "failed")));
    assert.deepEqual(spoken, ["first"]);
    assert.equal(unsubscribed, false);
    unavailable = false;
    await act(async () => mock.timers.tick(30_000));
    await act(async () => deliver(message("recovered", "recovered")));
    assert.ok(spoken.includes("recovered"));
  } finally {
    await act(async () => root.unmount());
    relayClient.subscribeLive = subscribe;
    mock.timers.reset();
    dom.window.close();
    Object.assign(globalThis, previous);
  }
});
