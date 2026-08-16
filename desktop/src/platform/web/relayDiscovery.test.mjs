import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayDiscoveryCommands } from "./relayDiscovery.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const PUBKEY = "a".repeat(64);

function event({
  id,
  kind,
  createdAt,
  tags = [],
  content = "",
  pubkey = PUBKEY,
}) {
  return {
    id,
    pubkey,
    created_at: createdAt,
    kind,
    tags,
    content,
    sig: "f".repeat(128),
  };
}

afterEach(() => resetRegistryForTests());

test("get_forum_posts pages newest-first and applies author link suppression", async () => {
  const calls = [];
  const older = event({
    id: "older",
    kind: 45001,
    createdAt: 10,
    tags: [["h", "forum"]],
    content: "Older",
  });
  const newer = event({
    id: "newer",
    kind: 45001,
    createdAt: 20,
    tags: [["h", "forum"]],
    content: "Newer",
  });
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      if (filter.kinds[0] === 40003) {
        return [
          event({
            id: "edit",
            kind: 40003,
            createdAt: 30,
            tags: [
              ["e", "newer"],
              ["link-preview", "none"],
            ],
          }),
        ];
      }
      return [older, newer];
    },
  };
  registerRelayDiscoveryCommands(client);

  const result = await dispatch("get_forum_posts", {
    channelId: "forum",
    limit: 50,
    before: 100,
  });

  assert.deepEqual(calls[0], {
    kinds: [45001],
    "#h": ["forum"],
    limit: 50,
    until: 100,
  });
  assert.deepEqual(calls[1], {
    kinds: [40003],
    "#e": ["newer", "older"],
    limit: 100,
  });
  assert.deepEqual(
    result.messages.map((post) => post.event_id),
    ["newer", "older"],
  );
  assert.deepEqual(result.messages[0].tags.at(-1), ["link-preview", "none"]);
  assert.deepEqual(result.messages[0].thread_summary, {
    reply_count: 0,
    descendant_count: 0,
    last_reply_at: null,
    participants: [],
  });
  assert.equal(result.messages[0].sig, "f".repeat(128));
  assert.equal(result.next_cursor, 10);
});

test("get_forum_thread maps NIP-10 parents, depth, and chronological replies", async () => {
  const calls = [];
  const root = event({
    id: "root",
    kind: 45001,
    createdAt: 10,
    tags: [["h", "forum"]],
    content: "Topic",
  });
  const nested = event({
    id: "nested",
    kind: 45003,
    createdAt: 30,
    tags: [
      ["h", "forum"],
      ["e", "root", "", "root"],
      ["e", "direct", "", "reply"],
    ],
  });
  const direct = event({
    id: "direct",
    kind: 45003,
    createdAt: 20,
    tags: [
      ["h", "forum"],
      ["e", "root", "", "reply"],
    ],
  });
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      if (filter.ids) return [root];
      if (filter.kinds[0] === 40003) return [];
      return [nested, direct];
    },
  };
  registerRelayDiscoveryCommands(client);

  const result = await dispatch("get_forum_thread", {
    channelId: "forum",
    eventId: "root",
    limit: 1,
    cursor: "ignored",
  });

  assert.deepEqual(calls.slice(0, 2), [
    { ids: ["root"], kinds: [9, 40002, 45001, 45003], limit: 1 },
    { kinds: [9, 45003], "#e": ["root"], "#h": ["forum"], limit: 500 },
  ]);
  assert.deepEqual(
    result.replies.map((reply) => reply.event_id),
    ["direct", "nested"],
  );
  assert.deepEqual(
    result.replies.map((reply) => ({
      parent: reply.parent_event_id,
      root: reply.root_event_id,
      depth: reply.depth,
    })),
    [
      { parent: "root", root: "root", depth: 1 },
      { parent: "direct", root: "root", depth: 2 },
    ],
  );
  assert.equal(result.total_replies, 2);
  assert.equal(result.next_cursor, null);
});

test("get_forum_thread rejects a missing root with the desktop error", async () => {
  registerRelayDiscoveryCommands({
    async fetchEvents() {
      return [];
    },
  });
  await assert.rejects(
    dispatch("get_forum_thread", { channelId: "forum", eventId: "missing" }),
    /forum thread root event not found/,
  );
});
