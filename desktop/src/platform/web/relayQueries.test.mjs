import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayQueryCommands } from "./relayQueries.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const PUBKEY = "a".repeat(64);
const identity = {
  pubkey: () => PUBKEY,
  sign(request) {
    return JSON.stringify({
      ...request,
      id: "signed-event",
      pubkey: PUBKEY,
      created_at: 100,
      sig: "f".repeat(128),
    });
  },
};

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

test("get_profile returns authoritative kind-0 metadata", async () => {
  const profile = event({
    id: "1",
    kind: 0,
    createdAt: 10,
    content: JSON.stringify({
      name: "sats",
      about: "builder",
      picture: "https://example.test/avatar.png",
      nip05: "sats@example.test",
    }),
  });
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, { kinds: [0], authors: [PUBKEY], limit: 1 });
      return profile;
    },
    async fetchEvents() {
      return [];
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(await dispatch("get_profile"), {
    pubkey: PUBKEY,
    display_name: "sats",
    avatar_url: "https://example.test/avatar.png",
    about: "builder",
    nip05_handle: "sats@example.test",
    owner_pubkey: null,
    has_profile_event: true,
  });
});

test("update_profile read-merges, signs, publishes, and returns canonical metadata", async () => {
  let profile = event({
    id: "prior",
    kind: 0,
    createdAt: 10,
    content: JSON.stringify({
      display_name: "Old name",
      name: "legacy-alias",
      about: "kept",
      nip05: "sats@example.test",
    }),
  });
  const published = [];
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, { kinds: [0], authors: [PUBKEY], limit: 1 });
      return profile;
    },
    async fetchEvents() {
      return [];
    },
    async publishEvent(signed, timeoutMessage, sendErrorMessage) {
      published.push({ signed, timeoutMessage, sendErrorMessage });
      profile = signed;
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("update_profile", {
      displayName: "Sats",
      avatarUrl: "https://example.test/new.png",
    }),
    {
      pubkey: PUBKEY,
      display_name: "Sats",
      avatar_url: "https://example.test/new.png",
      about: "kept",
      nip05_handle: "sats@example.test",
      owner_pubkey: null,
      has_profile_event: true,
    },
  );
  assert.deepEqual(JSON.parse(published[0].signed.content), {
    display_name: "Sats",
    name: "legacy-alias",
    picture: "https://example.test/new.png",
    about: "kept",
    nip05: "sats@example.test",
  });
  assert.equal(published[0].signed.kind, 0);
  assert.deepEqual(published[0].signed.tags, []);
});

test("get_channels merges membership, metadata, visibility, and last-message events", async () => {
  const calls = [];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents(filters) {
      calls.push(filters);
      if (Array.isArray(filters)) {
        assert.deepEqual(filters, [
          { kinds: [39002], "#p": [PUBKEY], limit: 1000 },
          { kinds: [39000], limit: 1000 },
          {
            kinds: [30622],
            authors: [PUBKEY],
            "#p": [PUBKEY],
            limit: 10,
          },
        ]);
        return [
          event({
            id: "membership",
            kind: 39002,
            createdAt: 20,
            tags: [
              ["d", "member-channel"],
              ["p", PUBKEY],
              ["p", "b".repeat(64)],
            ],
          }),
          event({
            id: "metadata-member",
            kind: 39000,
            createdAt: 10,
            tags: [
              ["d", "member-channel"],
              ["name", "Members"],
              ["about", "Private room"],
              ["private"],
            ],
          }),
          event({
            id: "metadata-open",
            kind: 39000,
            createdAt: 11,
            tags: [["d", "open-channel"], ["name", "Open"], ["public"]],
          }),
          event({
            id: "metadata-hidden-dm",
            kind: 39000,
            createdAt: 12,
            tags: [
              ["d", "hidden-dm"],
              ["t", "dm"],
            ],
          }),
          event({
            id: "visibility",
            kind: 30622,
            createdAt: 30,
            tags: [
              ["p", PUBKEY],
              ["h", "hidden-dm"],
            ],
          }),
        ];
      }
      return [
        event({
          id: "message",
          kind: 9,
          createdAt: 40,
          tags: [["h", "member-channel"]],
        }),
      ];
    },
  };
  registerRelayQueryCommands(identity, client);

  const channels = await dispatch("get_channels");
  assert.equal(channels.length, 2);
  assert.deepEqual(channels[0], {
    id: "member-channel",
    name: "Members",
    channel_type: "stream",
    visibility: "private",
    description: "Private room",
    topic: null,
    purpose: null,
    member_count: 2,
    member_pubkeys: [PUBKEY, "b".repeat(64)],
    last_message_at: new Date(40_000).toISOString(),
    archived_at: null,
    participants: [PUBKEY, "b".repeat(64)],
    participant_pubkeys: [PUBKEY, "b".repeat(64)],
    is_member: true,
    ttl_seconds: null,
    ttl_deadline: null,
  });
  assert.equal(channels[1].id, "open-channel");
  assert.equal(channels[1].is_member, false);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], {
    kinds: [9, 40002],
    "#h": ["member-channel", "open-channel", "hidden-dm"],
    limit: 100,
  });
});

test("get_channels skips the dependent request when metadata is absent", async () => {
  let fetchEventsCalls = 0;
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents(filters) {
      fetchEventsCalls += 1;
      assert.equal(Array.isArray(filters), true);
      return [];
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(await dispatch("get_channels"), []);
  assert.equal(fetchEventsCalls, 1);
});

test("create_channel publishes kind 9007 and returns canonical metadata", async () => {
  let createdId = null;
  const client = {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent(filter) {
      if (filter.kinds[0] === 39000 && createdId) {
        return event({
          id: "metadata",
          kind: 39000,
          createdAt: 101,
          tags: [
            ["d", createdId],
            ["name", "welcome"],
            ["about", "Private welcome"],
            ["private"],
          ],
        });
      }
      return null;
    },
    async publishEvent(signed) {
      assert.equal(signed.kind, 9007);
      createdId = signed.tags.find((tag) => tag[0] === "h")?.[1];
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  const channel = await dispatch("create_channel", {
    name: "Welcome",
    channelType: "stream",
    visibility: "private",
    description: "Private welcome",
  });
  assert.equal(channel.id, createdId);
  assert.equal(channel.name, "welcome");
  assert.equal(channel.visibility, "private");
  assert.equal(channel.is_member, true);
});

test("get_channel_members maps NIP-29 p-tag roles", async () => {
  const client = {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, {
        kinds: [39002],
        "#d": ["channel-id"],
        limit: 1,
      });
      return event({
        id: "members",
        kind: 39002,
        createdAt: 10,
        tags: [
          ["d", "channel-id"],
          ["p", PUBKEY, "", "owner"],
          ["p", "b".repeat(64), "", "bot"],
        ],
      });
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("get_channel_members", { channelId: "channel-id" }),
    {
      members: [
        {
          pubkey: PUBKEY,
          role: "owner",
          is_agent: false,
          joined_at: null,
          display_name: null,
        },
        {
          pubkey: "b".repeat(64),
          role: "bot",
          is_agent: true,
          joined_at: null,
          display_name: null,
        },
      ],
      next_cursor: null,
    },
  );
});

test("ensure_starter_channels joins an existing public starter channel", async () => {
  const published = [];
  const client = {
    async fetchEvents(filter) {
      if (Array.isArray(filter)) {
        return [
          event({
            id: "general-metadata",
            kind: 39000,
            createdAt: 10,
            tags: [["d", "general-id"], ["name", "general"], ["public"]],
          }),
          event({
            id: "welcome-metadata",
            kind: 39000,
            createdAt: 10,
            tags: [
              ["d", "welcome-id"],
              ["name", "welcome-everyone"],
              ["public"],
            ],
          }),
        ];
      }
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(signed) {
      published.push(signed);
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  const channels = await dispatch("ensure_starter_channels");
  assert.deepEqual(
    published.map((event) => [event.kind, event.tags]),
    [
      [9021, [["h", "general-id"]]],
      [9021, [["h", "welcome-id"]]],
    ],
  );
  assert.equal(
    channels.every((channel) => channel.is_member),
    true,
  );
});

test("update_channel publishes kind 9002 and returns canonical details", async () => {
  let metadata = event({
    id: "before",
    kind: 39000,
    createdAt: 10,
    tags: [
      ["d", "welcome-id"],
      ["name", "welcome"],
      ["about", "Old description"],
      ["private"],
      ["ttl", "3600"],
    ],
  });
  let published = null;
  const client = {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent() {
      return metadata;
    },
    async publishEvent(signed) {
      published = signed;
      metadata = event({
        id: "after",
        kind: 39000,
        createdAt: 20,
        tags: [
          ["d", "welcome-id"],
          ["name", "welcome"],
          ["about", "Private welcome"],
          ["private"],
        ],
      });
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  const detail = await dispatch("update_channel", {
    input: {
      channelId: "welcome-id",
      description: "Private welcome",
      ttlSeconds: null,
    },
  });
  assert.equal(published.kind, 9002);
  assert.deepEqual(published.tags, [
    ["h", "welcome-id"],
    ["about", "Private welcome"],
    ["ttl", ""],
  ]);
  assert.equal(detail.description, "Private welcome");
  assert.equal(detail.ttl_seconds, null);
  assert.equal(detail.created_by, PUBKEY);
  assert.equal(detail.updated_at, new Date(20_000).toISOString());
});

test("get_user_profile resolves another pubkey and get_users_batch maps profile summaries", async () => {
  const other = "b".repeat(64);
  const missing = "c".repeat(64);
  const profile = event({
    id: "other-profile",
    kind: 0,
    createdAt: 20,
    pubkey: other,
    content: JSON.stringify({
      display_name: "Other user",
      picture: "https://example.test/other.png",
      about: "hello",
      nip05: "other@example.test",
    }),
  });
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, { kinds: [0], authors: [other], limit: 1 });
      return profile;
    },
    async fetchEvents(filter) {
      assert.deepEqual(filter, {
        kinds: [0],
        authors: [other, missing],
        limit: 2,
      });
      return [profile];
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(await dispatch("get_user_profile", { pubkey: other }), {
    pubkey: other,
    display_name: "Other user",
    avatar_url: "https://example.test/other.png",
    about: "hello",
    nip05_handle: "other@example.test",
    owner_pubkey: null,
    has_profile_event: true,
  });
  assert.deepEqual(
    await dispatch("get_users_batch", { pubkeys: [other, missing] }),
    {
      profiles: {
        [other]: {
          display_name: "Other user",
          name: null,
          avatar_url: "https://example.test/other.png",
          nip05_handle: "other@example.test",
          owner_pubkey: null,
          is_agent: false,
        },
      },
      missing: [missing],
    },
  );
});

test("get_users_batch uses one history request for N sender pubkeys", async () => {
  const pubkeys = ["b".repeat(64), "c".repeat(64), "d".repeat(64)];
  let fetchEventsCalls = 0;
  let fetchFirstEventCalls = 0;
  const client = {
    async fetchFirstEvent() {
      fetchFirstEventCalls += 1;
      return null;
    },
    async fetchEvents(filter) {
      fetchEventsCalls += 1;
      assert.deepEqual(filter, {
        kinds: [0],
        authors: pubkeys,
        limit: pubkeys.length,
      });
      return [];
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(await dispatch("get_users_batch", { pubkeys }), {
    profiles: {},
    missing: pubkeys,
  });
  assert.equal(fetchEventsCalls, 1);
  assert.equal(fetchFirstEventCalls, 0);
});

test("get_channel_messages_before forwards the composite keyset and returns the oldest cursor", async () => {
  const page = [
    event({ id: "1".repeat(64), kind: 9, createdAt: 50 }),
    event({ id: "2".repeat(64), kind: 40002, createdAt: 49 }),
  ];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents() {
      return [];
    },
    async queryEvents(filters) {
      assert.deepEqual(filters, [
        {
          "#h": ["channel-id"],
          kinds: [
            9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006,
            48100,
          ],
          until: 51,
          limit: 2,
          before_id: "0".repeat(64),
        },
      ]);
      return page;
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("get_channel_messages_before", {
      channelId: "channel-id",
      before: 51,
      beforeId: "0".repeat(64),
      limit: 2,
    }),
    {
      events: page,
      next_cursor: { created_at: 49, event_id: "2".repeat(64) },
    },
  );
});

test("get_channel_window mirrors the relay bridge read-model filter", async () => {
  const response = [event({ id: "window", kind: 39006, createdAt: 60 })];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents() {
      return [];
    },
    async queryEvents(filters) {
      assert.deepEqual(filters, [
        {
          "#h": ["channel-id"],
          kinds: [
            9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006,
            48100,
          ],
          limit: 50,
          top_level: true,
          include_summaries: true,
          include_aux: true,
        },
      ]);
      return response;
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("get_channel_window", {
      channelId: "channel-id",
      limitRows: 50,
      cursor: null,
    }),
    response,
  );
});

test("send_channel_message resolves NIP-10 roots, signs, publishes, and returns raw result", async () => {
  const rootId = "1".repeat(64);
  const parentId = "2".repeat(64);
  const mention = "b".repeat(64);
  let published = null;
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, {
        ids: [parentId],
        kinds: [9, 40002, 45001, 45003, 48100],
        limit: 1,
      });
      return event({
        id: parentId,
        kind: 9,
        createdAt: 90,
        tags: [["e", rootId, "", "root"]],
      });
    },
    async fetchEvents() {
      return [];
    },
    async publishEvent(signed) {
      published = signed;
      return signed;
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("send_channel_message", {
      channelId: "11111111-1111-4111-8111-111111111111",
      content: "  hello  ",
      parentEventId: parentId,
      mentionPubkeys: [mention.toUpperCase(), mention],
      mediaTags: [["imeta", "url https://example.test/file.png"]],
      emojiTags: [["emoji", "wave", "https://example.test/wave.png"]],
      mentionTags: [["mention", mention]],
      linkPreviewTags: [["link-preview", "none"]],
      kind: null,
    }),
    {
      event_id: "signed-event",
      parent_event_id: parentId,
      root_event_id: rootId,
      depth: 2,
      created_at: 100,
    },
  );
  assert.equal(published.kind, 9);
  assert.equal(published.content, "hello");
  assert.deepEqual(published.tags, [
    ["h", "11111111-1111-4111-8111-111111111111"],
    ["e", rootId, "", "root"],
    ["e", parentId, "", "reply"],
    ["p", mention],
    ["imeta", "url https://example.test/file.png"],
    ["mention", mention],
    ["emoji", "wave", "https://example.test/wave.png"],
    ["link-preview", "none"],
  ]);
});

test("search_messages forwards prefix search and maps raw relay events", async () => {
  const hit = event({
    id: "hit",
    kind: 9,
    createdAt: 42,
    content: "hello world",
    tags: [["h", "channel-id"]],
  });
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents() {
      return [];
    },
    async queryEvents(filters) {
      assert.deepEqual(filters, [
        {
          kinds: [9, 40002, 45001, 45003],
          search: "hello",
          search_mode: "prefix",
          limit: 10,
          "#h": ["channel-id"],
        },
      ]);
      return [hit];
    },
  };
  registerRelayQueryCommands(identity, client);

  assert.deepEqual(
    await dispatch("search_messages", {
      q: " hello ",
      channelId: "channel-id",
      limit: 10,
    }),
    {
      hits: [
        {
          event_id: "hit",
          content: "hello world",
          kind: 9,
          pubkey: PUBKEY,
          channel_id: "channel-id",
          channel_name: null,
          created_at: 42,
          score: 1,
        },
      ],
      found: 1,
    },
  );
});
