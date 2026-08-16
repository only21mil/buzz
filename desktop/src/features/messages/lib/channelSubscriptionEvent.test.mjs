import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";

import { appendChannelSubscriptionEvent } from "./channelSubscriptionEvent.ts";

function event(channelId, id) {
  return {
    id: id.repeat(64),
    pubkey: "a".repeat(64),
    created_at: 1_700_000_000,
    kind: 9,
    tags: [["h", channelId]],
    content: "live",
    sig: "b".repeat(128),
  };
}

test("live writes use the delivering subscription channel", () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const firstEvent = event("channel-b", "1");
  const firstGeneration = {
    channelId: "channel-a",
    channelType: "stream",
    generation: 1,
    guard: { current: true },
    headTransaction: { version: 1, active: false, events: [] },
  };
  const secondEvent = event("channel-a", "2");
  const secondGeneration = {
    ...firstGeneration,
    channelId: "channel-b",
    generation: 2,
  };

  appendChannelSubscriptionEvent(queryClient, firstEvent, firstGeneration);
  appendChannelSubscriptionEvent(queryClient, secondEvent, secondGeneration);

  assert.deepEqual(
    queryClient
      .getQueryData(["channel-messages", "channel-a"])
      .map((candidate) => candidate.id),
    [firstEvent.id],
  );
  assert.deepEqual(
    queryClient
      .getQueryData(["channel-messages", "channel-b"])
      .map((candidate) => candidate.id),
    [secondEvent.id],
  );
  queryClient.clear();
});

test("live summaries use the delivering subscription channel", () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const rootId = "f".repeat(64);
  const summary = {
    ...event("channel-b", "3"),
    kind: 39005,
    tags: [
      ["h", "channel-b"],
      ["e", rootId],
    ],
    content: JSON.stringify({
      reply_count: 1,
      descendant_count: 2,
      last_reply_at: 1_700_000_000,
      participants: [],
    }),
  };
  const generation = {
    channelId: "channel-a",
    channelType: "stream",
    generation: 1,
    guard: { current: true },
    headTransaction: { version: 1, active: true, events: [] },
  };

  appendChannelSubscriptionEvent(queryClient, summary, generation);

  assert.equal(
    queryClient.getQueryData(["channel-window", "channel-a"]).liveSummaries[
      rootId
    ].eventId,
    summary.id,
  );
  assert.equal(
    queryClient.getQueryData(["channel-window", "channel-b"]),
    undefined,
  );
  assert.deepEqual(generation.headTransaction.events, []);
  queryClient.clear();
});
