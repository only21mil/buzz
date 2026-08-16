import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayMessageReadCommands } from "./relayMessageReads.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const TIMELINE_KINDS = [
  9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006, 48100,
];

function event(id, createdAt = 100) {
  return {
    id,
    pubkey: "a".repeat(64),
    created_at: createdAt,
    kind: 9,
    tags: [],
    content: id,
    sig: "f".repeat(128),
  };
}

afterEach(() => resetRegistryForTests());

test("get_thread_replies mirrors filters, caps, and full-page cursor shape", async () => {
  const calls = [];
  const events = [event("reply-a", 10), event("reply-b", 10)];
  registerRelayMessageReadCommands({
    async fetchEvents(filter) {
      calls.push(filter);
      return events;
    },
    async fetchFirstEvent() {
      return null;
    },
  });

  assert.deepEqual(
    await dispatch("get_thread_replies", {
      rootEventId: "root",
      channelId: "channel",
      limit: 2,
      depthLimit: 8,
      cursor: { created_at: 9, event_id: "prior" },
    }),
    {
      events,
      next_cursor: { created_at: 10, event_id: "reply-b" },
    },
  );
  assert.deepEqual(calls[0], {
    "#e": ["root"],
    kinds: TIMELINE_KINDS,
    depth_limit: 8,
    limit: 2,
    "#h": ["channel"],
    thread_cursor: 9,
    thread_cursor_id: "prior",
  });
});

test("get_thread_replies applies native defaults and omits optional filters", async () => {
  let seen;
  registerRelayMessageReadCommands({
    async fetchEvents(filter) {
      seen = filter;
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
  });

  assert.deepEqual(
    await dispatch("get_thread_replies", { rootEventId: "root" }),
    { events: [], next_cursor: null },
  );
  assert.deepEqual(seen, {
    "#e": ["root"],
    kinds: TIMELINE_KINDS,
    depth_limit: 64,
    limit: 200,
  });
});

test("get_channel_window returns the flat relay array with composite cursor", async () => {
  const response = [event("row"), event("summary")];
  let seen;
  registerRelayMessageReadCommands({
    async fetchEvents(filter) {
      seen = filter;
      return response;
    },
    async fetchFirstEvent() {
      return null;
    },
  });

  assert.strictEqual(
    await dispatch("get_channel_window", {
      channelId: "channel",
      limitRows: 999,
      cursor: { created_at: 88, event_id: "cursor-id" },
    }),
    response,
  );
  assert.deepEqual(seen, {
    "#h": ["channel"],
    kinds: TIMELINE_KINDS,
    limit: 200,
    top_level: true,
    include_summaries: true,
    include_aux: true,
    until: 88,
    before_id: "cursor-id",
  });
});

test("get_event uses the native kind allowlist and returns JSON", async () => {
  const found = event("target");
  let seen;
  registerRelayMessageReadCommands({
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent(filter) {
      seen = filter;
      return found;
    },
  });

  assert.equal(
    await dispatch("get_event", { eventId: "target" }),
    JSON.stringify(found),
  );
  assert.deepEqual(seen, {
    ids: ["target"],
    kinds: [
      0, 1, 3, 5, 7, 9, 30078, 40002, 40003, 40008, 40099, 40100, 45001, 45003,
      48100,
    ],
    limit: 1,
  });
});

test("get_event preserves the native missing-event error", async () => {
  registerRelayMessageReadCommands({
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
  });

  await assert.rejects(
    dispatch("get_event", { eventId: "missing" }),
    /event not found/,
  );
});
