import assert from "node:assert/strict";
import test, { mock } from "node:test";
import { JSDOM } from "jsdom";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { relayClient } from "@/shared/api/relayClient";
import { useDurableDraftBridge } from "./useDurableDraftQueue.ts";
import { durableDraftStore } from "./durableDraftQueue.ts";

const settle = () => new Promise((resolve) => setImmediate(resolve));
const owner = "a".repeat(64);
const sender = "b".repeat(64);
const request = (id, identity = owner) => ({
  id: String(id).padStart(64, "0"),
  pubkey: sender,
  kind: 14201,
  created_at: 99,
  tags: [
    ["r", `request-${id}`],
    ["h", "channel"],
    ["agent", sender],
    ["p", identity],
    ["v", "1"],
  ],
  content: "ciphertext",
  sig: "fixture",
});
function Hook({ identity, relay }) {
  useDurableDraftBridge(identity, relay);
  return null;
}

test("mounted bridge uses real IPC adapters with no managed agents, offline restart, pagination and identity fence", async () => {
  const dom = new JSDOM("<div id='root'></div>", {
    url: "https://desktop.example",
  });
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  globalThis.isTauri = true;
  const rows = Array.from({ length: 205 }, (_, id) => request(id));
  const terminal = {
    ...rows[0],
    id: "f".repeat(64),
    kind: 14202,
    pubkey: owner,
    tags: [
      ["p", owner],
      ["v", "1"],
      ["e", rows[0].id],
      ["generation", "1"],
      ["state", "rejected"],
    ],
  };
  const persisted = new Map([
    [rows[0].id, rows[0]],
    [terminal.id, terminal],
  ]);
  const calls = [];
  let deferredDecrypt;
  let releaseDecrypt;
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      calls.push([command, args]);
      if (command === "agent_draft_queue")
        return {
          events: args.owner === owner ? [...persisted.values()] : [],
          operations: [],
        };
      if (command === "agent_draft_backfill") {
        if (args.owner !== owner) return [];
        return rows
          .filter(
            (event) => args.beforeId === undefined || event.id > args.beforeId,
          )
          .slice(0, args.limit);
      }
      if (command === "agent_draft_receive") {
        persisted.set(args.event.id, args.event);
        return null;
      }
      if (command === "decrypt_observer_event") {
        const event = JSON.parse(args.eventJson);
        if (event.id === deferredDecrypt)
          await new Promise((resolve) => {
            releaseDecrypt = resolve;
          });
        return {
          payload: {
            type: "agent_management_request",
            action: "create",
            requestId: event.tags.find(([key]) => key === "r")[1],
            request: {
              channelId: "channel",
              displayName: "Draft",
              systemPrompt: "Prompt",
            },
          },
        };
      }
      throw new Error(`Unexpected side effect ${command}`);
    },
  };
  let connection;
  let live;
  let disposed = 0;
  mock.method(relayClient, "getConnectionState", () => "disconnected");
  mock.method(relayClient, "subscribeToConnectionState", (listener) => {
    connection = listener;
    return () => {};
  });
  mock.method(relayClient, "subscribeLive", async (filter, listener) => {
    assert.deepEqual(filter.kinds, [14201, 14202]);
    assert.equal(filter.limit, 0);
    live = listener;
    return async () => {
      disposed++;
    };
  });
  const root = createRoot(document.getElementById("root"));
  try {
    await act(async () => {
      root.render(
        React.createElement(Hook, {
          identity: owner,
          relay: "wss://one.example",
        }),
      );
      await settle();
    });
    assert.equal(durableDraftStore.getSnapshot().items.length, 1);
    assert.equal(durableDraftStore.getSnapshot().items[0].decision, "rejected");
    assert.equal(durableDraftStore.getSnapshot().ready, false);
    await act(async () => {
      connection("connected");
      await settle();
    });
    assert.equal(durableDraftStore.getSnapshot().items.length, 205);
    assert.equal(durableDraftStore.getSnapshot().ready, true);
    const pages = calls.filter(
      ([command]) => command === "agent_draft_backfill",
    );
    assert.equal(pages.length, 2);
    assert.equal(pages[1][1].beforeId, rows[199].id);
    assert.equal(pages[1][1].until, 99);
    assert.ok(
      pages.every(
        ([, args]) =>
          args.owner === owner && args.relayUrl === "wss://one.example",
      ),
    );
    const late = request(999);
    deferredDecrypt = late.id;
    await act(async () => {
      live(late);
      await settle();
    });
    await act(async () => {
      root.render(
        React.createElement(Hook, {
          identity: "c".repeat(64),
          relay: "wss://two.example",
        }),
      );
      await settle();
    });
    releaseDecrypt();
    await act(async () => {
      await settle();
    });
    assert.equal(durableDraftStore.getSnapshot().items.length, 0);
    assert.equal(
      durableDraftStore.getSnapshot().scope.relayUrl,
      "wss://two.example",
    );
    assert.ok(disposed >= 1);
    assert.ok(
      calls.every(([command]) =>
        [
          "agent_draft_queue",
          "agent_draft_backfill",
          "agent_draft_receive",
          "decrypt_observer_event",
        ].includes(command),
      ),
    );
  } finally {
    await act(async () => {
      root.unmount();
      await settle();
    });
    mock.restoreAll();
    dom.window.close();
    delete globalThis.window;
    delete globalThis.document;
    delete globalThis.isTauri;
    delete globalThis.IS_REACT_ACT_ENVIRONMENT;
  }
});
