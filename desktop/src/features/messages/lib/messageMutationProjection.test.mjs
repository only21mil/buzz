import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";

import { appendChannelSubscriptionEvent } from "./channelSubscriptionEvent.ts";
import {
  emptyChannelWindowStore,
  flattenChannelWindowEvents,
  mergeLiveChannelWindowEvent,
  replaceNewestChannelWindow,
} from "./channelWindowStore.ts";
import { removeChannelWindowMessage } from "./messageMutationProjection.ts";

const channelId = "channel";

function event(id, createdAt, overrides = {}) {
  return {
    id: id.padEnd(64, "0"),
    pubkey: "a".repeat(64),
    created_at: createdAt,
    kind: 9,
    tags: [["h", channelId]],
    content: id,
    sig: "b".repeat(128),
    ...overrides,
  };
}

function page(rows) {
  return {
    startCursor: null,
    rows: rows.map((item) => ({ event: item, thread: null })),
    aux: [],
    nextCursor: null,
    hasMore: false,
  };
}

function generation() {
  return {
    channelId,
    channelType: "stream",
    generation: 1,
    guard: { current: true },
    headTransaction: { version: 1, active: false, events: [] },
  };
}

test("failed optimistic send removes only its pending row", () => {
  const queryClient = new QueryClient();
  const retained = event("retained", 100);
  const pending = event("optimistic", 110, {
    pending: true,
    localKey: "optimistic",
  });
  const live = event("concurrent-live", 120);
  let window = replaceNewestChannelWindow(
    emptyChannelWindowStore(),
    page([retained]),
  );
  window = mergeLiveChannelWindowEvent(window, pending);
  queryClient.setQueryData(["channel-window", channelId], window);

  appendChannelSubscriptionEvent(queryClient, live, generation());
  removeChannelWindowMessage(queryClient, channelId, pending.id);

  const current = queryClient.getQueryData(["channel-window", channelId]);
  assert.deepEqual(
    flattenChannelWindowEvents(current).map((item) => item.id),
    [retained.id, live.id],
  );
  assert.deepEqual(
    queryClient
      .getQueryData(["channel-messages", channelId])
      .map((item) => item.id),
    [retained.id, live.id],
  );
  queryClient.clear();
});

test("delete removes the authoritative row before later live projection", () => {
  const queryClient = new QueryClient();
  const deleted = event("deleted", 100);
  const retained = event("retained", 110);
  queryClient.setQueryData(
    ["channel-window", channelId],
    replaceNewestChannelWindow(
      emptyChannelWindowStore(),
      page([retained, deleted]),
    ),
  );

  removeChannelWindowMessage(queryClient, channelId, deleted.id);
  appendChannelSubscriptionEvent(
    queryClient,
    event("later-live", 120),
    generation(),
  );

  const current = queryClient.getQueryData(["channel-window", channelId]);
  assert.deepEqual(
    flattenChannelWindowEvents(current).map((item) => item.id),
    [retained.id, event("later-live", 120).id],
  );
  assert.deepEqual(
    queryClient
      .getQueryData(["channel-messages", channelId])
      .map((item) => item.id),
    [retained.id, event("later-live", 120).id],
  );
  queryClient.clear();
});
