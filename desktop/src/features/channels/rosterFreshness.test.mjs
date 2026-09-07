import assert from "node:assert/strict";
import test from "node:test";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useChannelMembersQuery, invalidateChannelState } from "./hooks.ts";
import {
  channelMembersQueryKey,
  invalidateChannelMembersRosters,
} from "./rosterFreshness.ts";

test("warm roster remounts avoid reads; membership and direct-write invalidation refresh exactly that roster", async () => {
  const dom = new JSDOM("<div id='root'></div>");
  const before = {
    window: globalThis.window,
    document: globalThis.document,
    IS_REACT_ACT_ENVIRONMENT: globalThis.IS_REACT_ACT_ENVIRONMENT,
  };
  const calls = [];
  Object.assign(globalThis, {
    window: dom.window,
    document: dom.window.document,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      calls.push({ command, channelId: args.channelId });
      return { members: [] };
    },
  };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const key = channelMembersQueryKey("a");
  const root = createRoot(document.getElementById("root"));
  function Roster({ id }) {
    useChannelMembersQuery(id);
    return null;
  }
  async function render(id) {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client },
          React.createElement(Roster, { id }),
        ),
      );
      await new Promise((resolve) => setImmediate(resolve));
    });
  }
  try {
    client.setQueryData(key, [], { updatedAt: Date.now() - 60_000 });
    client.setQueryData(channelMembersQueryKey("b"), [], {
      updatedAt: Date.now() - 60_000,
    });
    for (const id of ["a", "b", "a", "b", "a"]) await render(id);
    assert.deepEqual(calls, []);
    await act(async () => invalidateChannelState(client, "a"));
    assert.equal(calls.length, 2); // Existing broad + exact channel invalidations.
    await act(async () => invalidateChannelMembersRosters(client, ["a", "a"]));
    assert.equal(calls.length, 3);
    assert.ok(calls.every((call) => call.channelId === "a"));
  } finally {
    await act(async () => root.unmount());
    client.clear();
    dom.window.close();
    Object.assign(globalThis, before);
  }
});
