import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayQueryCommands } from "./relayQueries.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const PUBKEY = "a".repeat(64);
const identity = { pubkey: () => PUBKEY };

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

test("get_channels merges membership, metadata, visibility, and last-message events", async () => {
  const calls = [];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async fetchEvents(filter) {
      calls.push(filter);
      if (filter.kinds[0] === 39002) {
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
        ];
      }
      if (filter.kinds[0] === 39000) {
        return [
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
        ];
      }
      if (filter.kinds[0] === 30622) {
        assert.deepEqual(filter.authors, [PUBKEY]);
        return [
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
  assert.equal(calls.length, 4);
});
