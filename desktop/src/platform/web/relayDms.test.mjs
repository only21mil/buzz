import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayDmCommands } from "./relayDms.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const SELF = "a".repeat(64);
const OTHER = "b".repeat(64);

function relayEvent({ id, createdAt, tags }) {
  return {
    id,
    pubkey: "c".repeat(64),
    created_at: createdAt,
    kind: 39000,
    tags,
    content: "",
    sig: "f".repeat(128),
  };
}

function identity(signedRequests) {
  return {
    pubkey: () => SELF,
    sign(request) {
      signedRequests.push(request);
      return JSON.stringify({
        ...request,
        id: `signed-${signedRequests.length}`,
        pubkey: SELF,
        created_at: 100,
        sig: "f".repeat(128),
      });
    },
  };
}

afterEach(() => resetRegistryForTests());

test("open_dm signs kind 41010 and resolves the exact canonical DM metadata", async () => {
  const signedRequests = [];
  const publishes = [];
  const stale = relayEvent({
    id: "f",
    createdAt: 10,
    tags: [
      ["d", "dm-id"],
      ["name", "Old DM"],
      ["hidden"],
      ["private"],
      ["p", SELF],
      ["p", OTHER],
    ],
  });
  const current = relayEvent({
    id: "e",
    createdAt: 20,
    tags: [
      ["d", "dm-id"],
      ["name", "DM"],
      ["about", "private chat"],
      ["hidden"],
      ["private"],
      ["t", "dm"],
      ["p", SELF],
      ["p", OTHER],
      ["ttl", "3600"],
      ["ttl_deadline", "2026-08-15T20:00:00Z"],
    ],
  });
  const distractor = relayEvent({
    id: "other",
    createdAt: 30,
    tags: [["d", "other-dm"], ["hidden"], ["p", SELF], ["p", "d".repeat(64)]],
  });
  const client = {
    async publishEvent(event, timeoutMessage, sendErrorMessage) {
      publishes.push({ event, timeoutMessage, sendErrorMessage });
      return event;
    },
    async fetchEvents(filter) {
      assert.deepEqual(filter, {
        kinds: [39000],
        "#p": [SELF],
        limit: 1000,
      });
      return [stale, distractor, current];
    },
  };
  registerRelayDmCommands(identity(signedRequests), client);

  const result = await dispatch("open_dm", { pubkeys: [OTHER.toUpperCase()] });

  assert.deepEqual(signedRequests, [
    { kind: 41010, content: "", tags: [["p", OTHER]] },
  ]);
  assert.equal(publishes[0].timeoutMessage, "Timed out while opening the DM.");
  assert.equal(publishes[0].sendErrorMessage, "Failed while opening the DM.");
  assert.deepEqual(result, {
    id: "dm-id",
    name: "DM",
    channel_type: "dm",
    visibility: "private",
    description: "private chat",
    topic: null,
    purpose: null,
    member_count: 0,
    member_pubkeys: [],
    last_message_at: null,
    archived_at: null,
    participants: [SELF, OTHER],
    participant_pubkeys: [SELF, OTHER],
    is_member: true,
    ttl_seconds: 3600,
    ttl_deadline: "2026-08-15T20:00:00Z",
  });
});

test("hide_dm signs and publishes the Rust kind 41012 wire shape", async () => {
  const signedRequests = [];
  const publishes = [];
  const client = {
    async fetchEvents() {
      throw new Error("hide_dm must not query");
    },
    async publishEvent(event, timeoutMessage, sendErrorMessage) {
      publishes.push({ event, timeoutMessage, sendErrorMessage });
      return event;
    },
  };
  registerRelayDmCommands(identity(signedRequests), client);

  assert.equal(await dispatch("hide_dm", { channelId: "dm-id" }), undefined);
  assert.deepEqual(signedRequests, [
    { kind: 41012, content: "", tags: [["h", "dm-id"]] },
  ]);
  assert.equal(publishes[0].timeoutMessage, "Timed out while hiding the DM.");
  assert.equal(publishes[0].sendErrorMessage, "Failed while hiding the DM.");
});

test("open_dm rejects malformed pubkeys before signing or publishing", async () => {
  const signedRequests = [];
  const client = {
    async fetchEvents() {
      throw new Error("must not query");
    },
    async publishEvent() {
      throw new Error("must not publish");
    },
  };
  registerRelayDmCommands(identity(signedRequests), client);

  await assert.rejects(
    dispatch("open_dm", { pubkeys: ["not-a-pubkey"] }),
    /pubkey must be a 64-character hex string/,
  );
  await assert.rejects(
    dispatch("open_dm", { pubkeys: [] }),
    /dm_open requires at least one pubkey/,
  );
  assert.deepEqual(signedRequests, []);
});
