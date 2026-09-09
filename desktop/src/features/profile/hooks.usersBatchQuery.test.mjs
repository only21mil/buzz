import assert from "node:assert/strict";
import { after, afterEach, beforeEach, test } from "node:test";
import { JSDOM } from "jsdom";
import * as React from "react";
import {
  QueryClient,
  QueryClientProvider,
  timeoutManager,
} from "@tanstack/react-query";

// Cancelled queries may schedule GC after removal. Keep those timers from
// holding the Node process open; their timing and cancellation stay intact.
timeoutManager.setTimeoutProvider({
  setTimeout: (callback, delay) => setTimeout(callback, delay).unref(),
  clearTimeout,
  setInterval: (callback, delay) => setInterval(callback, delay).unref(),
  clearInterval,
});

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
Object.assign(globalThis, {
  window: dom.window,
  document: dom.window.document,
  localStorage: dom.window.localStorage,
  HTMLElement: dom.window.HTMLElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});
const { act, cleanup, renderHook, waitFor } = await import(
  "@testing-library/react"
);
const { useUsersBatchQuery, evictUsersBatchEntries } = await import(
  "./hooks.ts"
);
const { CommunitiesProvider } = await import(
  "../communities/useCommunities.tsx"
);
const { applyLiveQueryCache } = await import(
  "../../shared/api/liveQueryCache.ts"
);
const { invalidateProfileBatchCoalescer } = await import(
  "./lib/profileBatchCoalescer.ts"
);
const { readCachedUserLabels, writeCachedUserLabels } = await import(
  "./lib/userLabelStorage.ts"
);

const self = "a".repeat(64),
  peer = "b".repeat(64),
  other = "c".repeat(64);
const relayUrl = "wss://relay.example";
let client;
let calls;
let release;
const summary = (name) => ({
  display_name: name,
  avatar_url: `${name}.png`,
  nip05_handle: null,
  owner_pubkey: null,
});

beforeEach(() => {
  invalidateProfileBatchCoalescer();
  localStorage.clear();
  localStorage.setItem(
    "buzz-communities",
    JSON.stringify([{ id: "community", name: "Test", relayUrl }]),
  );
  client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  client.setQueryData(["identity"], { pubkey: self });
  calls = [];
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      assert.equal(command, "get_users_batch");
      calls.push(args.pubkeys);
      return calls.length === 1
        ? pending
        : {
            profiles: {
              [other]: summary("Other"),
              [peer]: summary("Refetched"),
            },
            missing: [],
          };
    },
    transformCallback: () => 1,
  };
});
afterEach(() => {
  cleanup();
  client.clear();
  invalidateProfileBatchCoalescer();
});
after(() => dom.window.close());
function wrapper({ children }) {
  return React.createElement(
    QueryClientProvider,
    { client },
    React.createElement(CommunitiesProvider, null, children),
  );
}
async function resolvePending(response) {
  await act(async () => {
    release(response);
    // Drain the transport, coalescer and cancelled query continuations.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

for (const response of [
  { profiles: { [peer]: summary("Old") }, missing: [] },
  { profiles: {}, missing: [peer] },
]) {
  test(`live profile fences a late batch ${response.missing.length ? "miss" : "profile"} before entry and label writes`, async () => {
    writeCachedUserLabels(relayUrl, { [peer]: { displayName: "Prior" } });
    const { result, rerender } = renderHook(
      ({ pubkeys }) => useUsersBatchQuery(pubkeys),
      {
        wrapper,
        initialProps: { pubkeys: [peer] },
      },
    );
    await waitFor(() => assert.equal(calls.length, 1));
    await act(async () =>
      applyLiveQueryCache(
        client,
        {
          id: "live-profile",
          pubkey: peer,
          kind: 0,
          created_at: 1002,
          tags: [],
          content: JSON.stringify({ display_name: "New", picture: "New.png" }),
          sig: "",
        },
        self,
      ),
    );
    assert.equal(
      client.getQueryData(["users-batch-entry", peer]).summary.displayName,
      "New",
    );
    await resolvePending(response);
    assert.equal(
      client.getQueryData(["users-batch-entry", peer]).summary.displayName,
      "New",
    );
    assert.equal(
      client.getQueryData(["users-batch-entry", peer]).summary.avatarUrl,
      "New.png",
    );
    assert.equal(
      client.getQueryData(["user-profile", peer]).displayName,
      "New",
    );
    assert.equal(
      readCachedUserLabels(relayUrl, [peer]).profiles[peer].displayName,
      "Prior",
    );

    rerender({ pubkeys: [peer, other] });
    await waitFor(() => {
      assert.equal(result.current.isSuccess, true);
      assert.equal(result.current.isPlaceholderData, false);
    });
    assert.deepEqual(calls, [[peer], [other]]);
    assert.equal(result.current.data.profiles[peer].displayName, "New");
    assert.equal(result.current.data.profiles[peer].avatarUrl, "New.png");

    // Existing explicit invalidation must still refetch the per-author entry.
    await act(async () => {
      evictUsersBatchEntries(client, [peer]);
      await client.invalidateQueries({
        queryKey: ["users-batch", peer, other],
        exact: true,
      });
    });
    await waitFor(() =>
      assert.equal(result.current.data.profiles[peer].displayName, "Refetched"),
    );
    assert.deepEqual(calls, [[peer], [other], [peer]]);
  });
}

test("identity invalidation rejects a pending hook batch without recreating cleared caches or labels", async () => {
  const { unmount } = renderHook(() => useUsersBatchQuery([peer]), { wrapper });
  await waitFor(() => assert.equal(calls.length, 1));
  await act(async () => {
    invalidateProfileBatchCoalescer();
    unmount();
    client.clear();
    localStorage.clear();
  });
  await resolvePending({ profiles: { [peer]: summary("Old") }, missing: [] });
  assert.equal(client.getQueryData(["users-batch-entry", peer]), undefined);
  assert.equal(client.getQueryData(["user-profile", peer]), undefined);
  assert.equal(readCachedUserLabels(relayUrl, [peer]), undefined);
});
