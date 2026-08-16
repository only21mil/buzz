import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayMembershipCommands } from "./relayMembership.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const CHANNEL_ID = "123E4567-E89B-12D3-A456-426614174000";
const CANONICAL_CHANNEL_ID = CHANNEL_ID.toLowerCase();
const PUBKEY_A = "A".repeat(64);
const PUBKEY_B = "b".repeat(64);

const identity = {
  sign(request) {
    return JSON.stringify({
      ...request,
      id: `signed-${request.kind}-${request.tags[1]?.[1] ?? "self"}`,
      pubkey: PUBKEY_B,
      created_at: 100,
      sig: "f".repeat(128),
    });
  },
};

afterEach(() => resetRegistryForTests());

function recordingClient(rejectPubkey) {
  const published = [];
  return {
    published,
    async publishEvent(event) {
      const pubkey = event.tags.find((tag) => tag[0] === "p")?.[1];
      if (rejectPubkey !== undefined && pubkey === rejectPubkey) {
        throw new Error("relay denied member");
      }
      published.push(event);
      return event;
    },
  };
}

test("join_channel and leave_channel publish self-service NIP-29 events", async () => {
  const client = recordingClient();
  registerRelayMembershipCommands(identity, client);

  assert.equal(
    await dispatch("join_channel", { channelId: CHANNEL_ID }),
    undefined,
  );
  assert.equal(
    await dispatch("leave_channel", { channelId: CHANNEL_ID }),
    undefined,
  );
  assert.deepEqual(
    client.published.map(({ kind, content, tags }) => ({
      kind,
      content,
      tags,
    })),
    [
      { kind: 9021, content: "", tags: [["h", CANONICAL_CHANNEL_ID]] },
      { kind: 9022, content: "", tags: [["h", CANONICAL_CHANNEL_ID]] },
    ],
  );
});

test("add_channel_members publishes sequentially and reports partial success", async () => {
  const client = recordingClient(PUBKEY_B);
  registerRelayMembershipCommands(identity, client);

  assert.deepEqual(
    await dispatch("add_channel_members", {
      channelId: CHANNEL_ID,
      pubkeys: [PUBKEY_A, "bad", PUBKEY_B],
      role: "admin",
    }),
    {
      added: [PUBKEY_A],
      errors: [
        {
          pubkey: "bad",
          error: "pubkey must be a 64-character hex string (got 3 chars)",
        },
        { pubkey: PUBKEY_B, error: "relay denied member" },
      ],
    },
  );
  assert.deepEqual(client.published[0].tags, [
    ["h", CANONICAL_CHANNEL_ID],
    ["p", PUBKEY_A.toLowerCase()],
    ["role", "admin"],
  ]);
});

test("member adds omit the role tag while role changes include it", async () => {
  const client = recordingClient();
  registerRelayMembershipCommands(identity, client);

  await dispatch("add_channel_members", {
    channelId: CHANNEL_ID,
    pubkeys: [PUBKEY_A],
    role: "member",
  });
  assert.equal(
    await dispatch("change_channel_member_role", {
      channelId: CHANNEL_ID,
      pubkey: PUBKEY_A,
      role: "member",
    }),
    undefined,
  );
  assert.deepEqual(
    client.published.map(({ kind, tags }) => ({ kind, tags })),
    [
      {
        kind: 9000,
        tags: [
          ["h", CANONICAL_CHANNEL_ID],
          ["p", PUBKEY_A.toLowerCase()],
        ],
      },
      {
        kind: 9000,
        tags: [
          ["h", CANONICAL_CHANNEL_ID],
          ["p", PUBKEY_A.toLowerCase()],
          ["role", "member"],
        ],
      },
    ],
  );
});

test("remove_channel_member publishes kind 9001 and role validation fails closed", async () => {
  const client = recordingClient();
  registerRelayMembershipCommands(identity, client);

  assert.equal(
    await dispatch("remove_channel_member", {
      channelId: CHANNEL_ID,
      pubkey: PUBKEY_A,
    }),
    undefined,
  );
  assert.deepEqual(client.published[0].tags, [
    ["h", CANONICAL_CHANNEL_ID],
    ["p", PUBKEY_A.toLowerCase()],
  ]);
  await assert.rejects(
    dispatch("change_channel_member_role", {
      channelId: CHANNEL_ID,
      pubkey: PUBKEY_A,
      role: "owner",
    }),
    /cannot assign owner role/,
  );
  await assert.rejects(
    dispatch("add_channel_members", {
      channelId: CHANNEL_ID,
      pubkeys: [PUBKEY_A],
      role: "owner",
    }),
    /invalid role: owner/,
  );
  assert.equal(client.published.length, 1);
});
