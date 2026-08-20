import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayChannelAdminCommands } from "./relayChannelAdmin.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const CHANNEL_ID = "550e8400-e29b-41d4-a716-446655440000";
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

function metadataEvent(overrides = {}) {
  return {
    id: "metadata",
    pubkey: PUBKEY,
    created_at: 1_700_000_000,
    kind: 39000,
    tags: [
      ["d", CHANNEL_ID],
      ["name", "admins"],
      ["about", "Operate the relay"],
      ["topic", "Release day"],
      ["purpose", "Coordinate safely"],
      ["t", "forum"],
      ["private"],
      ["archived", "true"],
      ["ttl", "3600"],
      ["ttl_deadline", "2026-08-16T00:00:00Z"],
    ],
    content: "",
    sig: "f".repeat(128),
    ...overrides,
  };
}

afterEach(() => resetRegistryForTests());

test("get_channel_details returns canonical kind-39000 metadata", async () => {
  const event = metadataEvent();
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, {
        kinds: [39000],
        "#d": [CHANNEL_ID],
        limit: 1,
      });
      return event;
    },
    async publishEvent() {
      throw new Error("unexpected publish");
    },
  };
  registerRelayChannelAdminCommands(identity, client);

  const timestamp = "2023-11-14T22:13:20Z";
  assert.deepEqual(
    await dispatch("get_channel_details", { channelId: CHANNEL_ID }),
    {
      id: CHANNEL_ID,
      name: "admins",
      channel_type: "forum",
      visibility: "private",
      description: "Operate the relay",
      topic: "Release day",
      topic_set_by: null,
      topic_set_at: null,
      purpose: "Coordinate safely",
      purpose_set_by: null,
      purpose_set_at: null,
      created_by: PUBKEY,
      created_at: timestamp,
      updated_at: timestamp,
      archived_at: timestamp,
      member_count: 0,
      topic_required: false,
      max_members: null,
      nip29_group_id: null,
      ttl_seconds: 3600,
      ttl_deadline: "2026-08-16T00:00:00Z",
    },
  );
});

test("get_channel_details preserves Rust conversion errors", async () => {
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent() {
      throw new Error("unexpected publish");
    },
  };
  registerRelayChannelAdminCommands(identity, client);
  await assert.rejects(
    dispatch("get_channel_details", { channelId: CHANNEL_ID }),
    /channel not found/,
  );

  client.fetchFirstEvent = async () => metadataEvent({ tags: [] });
  await assert.rejects(
    dispatch("get_channel_details", { channelId: CHANNEL_ID }),
    /kind:39000 missing required `d` tag/,
  );
});

test("channel metadata and lifecycle commands publish exact signed events", async () => {
  const published = [];
  const client = {
    async fetchFirstEvent() {
      throw new Error("unexpected query");
    },
    async publishEvent(event, timeoutMessage, sendErrorMessage) {
      published.push({ event, timeoutMessage, sendErrorMessage });
      return event;
    },
  };
  registerRelayChannelAdminCommands(identity, client);

  await dispatch("set_channel_topic", {
    channelId: CHANNEL_ID,
    topic: "Ship it",
  });
  await dispatch("set_channel_purpose", {
    channelId: CHANNEL_ID,
    purpose: "Coordinate releases",
  });
  await dispatch("archive_channel", { channelId: CHANNEL_ID });
  await dispatch("unarchive_channel", { channelId: CHANNEL_ID });
  await dispatch("delete_channel", { channelId: CHANNEL_ID });

  assert.deepEqual(
    published.map(({ event }) => ({
      kind: event.kind,
      content: event.content,
      tags: event.tags,
    })),
    [
      {
        kind: 9002,
        content: "",
        tags: [
          ["h", CHANNEL_ID],
          ["topic", "Ship it"],
        ],
      },
      {
        kind: 9002,
        content: "",
        tags: [
          ["h", CHANNEL_ID],
          ["purpose", "Coordinate releases"],
        ],
      },
      {
        kind: 9002,
        content: "",
        tags: [
          ["h", CHANNEL_ID],
          ["archived", "true"],
        ],
      },
      {
        kind: 9002,
        content: "",
        tags: [
          ["h", CHANNEL_ID],
          ["archived", "false"],
        ],
      },
      { kind: 9008, content: "", tags: [["h", CHANNEL_ID]] },
    ],
  );
  assert.deepEqual(
    published.map(({ timeoutMessage, sendErrorMessage }) => [
      timeoutMessage,
      sendErrorMessage,
    ]),
    [
      [
        "Timed out while setting the channel topic.",
        "Failed while setting the channel topic.",
      ],
      [
        "Timed out while setting the channel purpose.",
        "Failed while setting the channel purpose.",
      ],
      [
        "Timed out while archiving the channel.",
        "Failed while archiving the channel.",
      ],
      [
        "Timed out while unarchiving the channel.",
        "Failed while unarchiving the channel.",
      ],
      [
        "Timed out while deleting the channel.",
        "Failed while deleting the channel.",
      ],
    ],
  );
});

test("mutations reject invalid channel UUIDs before signing or publishing", async () => {
  let publishCount = 0;
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent() {
      publishCount += 1;
    },
  };
  registerRelayChannelAdminCommands(identity, client);

  await assert.rejects(
    dispatch("archive_channel", { channelId: "not-a-uuid" }),
    /invalid channel UUID: not-a-uuid/,
  );
  assert.equal(publishCount, 0);
});
