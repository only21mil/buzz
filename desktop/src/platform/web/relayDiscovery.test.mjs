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

test("get_forum_posts preserves relay order and applies author link suppression", async () => {
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
    async queryEvents(filters) {
      calls.push(filters);
      if (filters[0].kinds[0] === 40003) {
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
          event({
            id: "owner-edit",
            kind: 40003,
            createdAt: 31,
            pubkey: "b".repeat(64),
            tags: [
              ["e", "older"],
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

  assert.deepEqual(calls[0], [
    {
      kinds: [45001],
      "#h": ["forum"],
      limit: 50,
      until: 100,
    },
  ]);
  assert.deepEqual(calls[1], [
    {
      kinds: [40003],
      "#e": ["older", "newer"],
    },
  ]);
  assert.deepEqual(
    result.messages.map((post) => post.event_id),
    ["older", "newer"],
  );
  assert.deepEqual(result.messages[1].tags.at(-1), ["link-preview", "none"]);
  assert.equal(
    result.messages[0].tags.some((tag) => tag[0] === "link-preview"),
    false,
  );
  assert.deepEqual(result.messages[0].thread_summary, {
    reply_count: 0,
    descendant_count: 0,
    last_reply_at: null,
    participants: [],
  });
  assert.equal(result.messages[0].sig, "f".repeat(128));
  assert.equal(result.next_cursor, 20);
});

test("get_forum_thread atomically queries and preserves relay reply order", async () => {
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
    async queryEvents(filters) {
      calls.push(filters);
      if (filters[0].kinds[0] === 40003) return [];
      return [nested, root, direct];
    },
  };
  registerRelayDiscoveryCommands(client);

  const result = await dispatch("get_forum_thread", {
    channelId: "forum",
    eventId: "root",
    limit: 1,
    cursor: "ignored",
  });

  assert.deepEqual(calls[0], [
    { ids: ["root"], kinds: [9, 40002, 45001, 45003], limit: 1 },
    { kinds: [9, 45003], "#e": ["root"], "#h": ["forum"] },
  ]);
  assert.deepEqual(calls[1], [
    { kinds: [40003], "#e": ["nested", "root", "direct"] },
  ]);
  assert.deepEqual(
    result.replies.map((reply) => reply.event_id),
    ["nested", "direct"],
  );
  assert.deepEqual(
    result.replies.map((reply) => ({
      parent: reply.parent_event_id,
      root: reply.root_event_id,
      depth: reply.depth,
    })),
    [
      { parent: "direct", root: "root", depth: 2 },
      { parent: "root", root: "root", depth: 1 },
    ],
  );
  assert.equal(result.total_replies, 2);
  assert.equal(result.next_cursor, null);
});

test("get_forum_thread rejects a missing root with the desktop error", async () => {
  registerRelayDiscoveryCommands({
    async queryEvents() {
      return [];
    },
  });
  await assert.rejects(
    dispatch("get_forum_thread", { channelId: "forum", eventId: "missing" }),
    /forum thread root event not found/,
  );
});
