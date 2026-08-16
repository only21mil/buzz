import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { dispatch, resetRegistryForTests } from "./registry.ts";
import { registerRelayPeopleCommands } from "./relayPeople.ts";

const PUBKEY = "a".repeat(64);
const OTHER = "b".repeat(64);
const AGENT =
  "84bb077142c301d471a33a995b2209dbe37889d01be031e6b09ddc65731b1962";
const OWNER =
  "84bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0";
const OWNER_SIGNATURE =
  "a3db0ff16417a7892d905433583272b67ac4d26c10fd06273a9534fac523fb9a2d2f28965770e19e50ca7f8b7f3ff9f0fa3b9035ac93e7604e8ee5df278679bc";
const identity = {
  pubkey: () => PUBKEY,
  sign(request) {
    return JSON.stringify({
      ...request,
      id: "signed-contact-list",
      pubkey: PUBKEY,
      created_at: 100,
      sig: "f".repeat(128),
    });
  },
};

function event({
  id,
  pubkey = PUBKEY,
  createdAt = 10,
  kind = 0,
  tags = [],
  content = "",
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

test("search_users sends a prefix NIP-50 filter and applies desktop ranking", async () => {
  const calls = [];
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      return [
        event({ id: "substring", content: '{"display_name":"malice"}' }),
        event({
          id: "exact",
          pubkey: OTHER,
          content: '{"display_name":"ali"}',
        }),
        event({
          id: "about-only",
          content: '{"display_name":"bob","about":"ali"}',
        }),
      ];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value) {
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);

  const response = await dispatch("search_users", {
    query: " Ali ",
    limit: 8,
    cursor: null,
  });
  assert.deepEqual(calls, [
    { kinds: [0], search: "ali", search_mode: "prefix", limit: 8, page: 1 },
  ]);
  assert.deepEqual(
    response.users.map((user) => user.display_name),
    ["ali", "malice"],
  );
  assert.equal(response.users[0].owner_pubkey, null);
  assert.equal(response.users[0].is_agent, false);
});

test("search_users empty-query listing dedupes latest profiles and sorts labels", async () => {
  const client = {
    async fetchEvents() {
      return [
        event({ id: "old", createdAt: 1, content: '{"display_name":"Zed"}' }),
        event({ id: "new", createdAt: 2, content: '{"display_name":"Aaron"}' }),
        event({ id: "bob", pubkey: OTHER, content: '{"display_name":"Bob"}' }),
      ];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value) {
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);
  const response = await dispatch("search_users", {
    query: "",
    limit: 2,
    cursor: null,
  });
  assert.deepEqual(
    response.users.map((user) => user.display_name),
    ["Aaron", "Bob"],
  );
});

test("search_users verifies NIP-OA ownership and rejects a forged attestation", async () => {
  const client = {
    async fetchEvents() {
      return [
        event({
          id: "valid-agent",
          pubkey: AGENT,
          tags: [["auth", OWNER, "", OWNER_SIGNATURE]],
          content: '{"display_name":"Agent"}',
        }),
        event({
          id: "forged-agent",
          pubkey: OTHER,
          tags: [["auth", OWNER, "", OWNER_SIGNATURE]],
          content: '{"display_name":"Forged"}',
        }),
      ];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value) {
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);
  const response = await dispatch("search_users", {
    query: "",
    limit: 8,
    cursor: null,
  });
  const valid = response.users.find((user) => user.pubkey === AGENT);
  const forged = response.users.find((user) => user.pubkey === OTHER);
  assert.equal(valid.owner_pubkey, OWNER);
  assert.equal(valid.is_agent, true);
  assert.equal(forged.owner_pubkey, null);
  assert.equal(forged.is_agent, false);
});

test("get_presence keeps the latest valid status and fails closed on query errors", async () => {
  let fail = false;
  const client = {
    async fetchEvents(filter) {
      assert.deepEqual(filter, {
        kinds: [20001],
        authors: [PUBKEY, OTHER],
        limit: 1_000,
      });
      if (fail) throw new Error("ephemeral history unavailable");
      return [
        event({
          id: "new",
          kind: 20001,
          createdAt: 20,
          tags: [["p", OTHER]],
          content: "away",
        }),
        event({
          id: "old",
          kind: 20001,
          createdAt: 10,
          tags: [["p", OTHER]],
          content: "online",
        }),
        event({ id: "invalid", kind: 20001, createdAt: 30, content: "busy" }),
      ];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value) {
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);
  assert.deepEqual(
    await dispatch("get_presence", { pubkeys: [PUBKEY, OTHER] }),
    { [OTHER]: "away" },
  );
  fail = true;
  assert.deepEqual(
    await dispatch("get_presence", { pubkeys: [PUBKEY, OTHER] }),
    {},
  );
});

test("get_contact_list returns a canonical event or desktop empty fallback", async () => {
  let found = event({
    id: "contacts",
    kind: 3,
    tags: [["p", OTHER]],
    content: "metadata",
  });
  const client = {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, { kinds: [3], authors: [PUBKEY], limit: 1 });
      return found;
    },
    async publishEvent(value) {
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);
  assert.deepEqual(await dispatch("get_contact_list", { pubkey: PUBKEY }), {
    id: "contacts",
    pubkey: PUBKEY,
    created_at: 10,
    tags: [["p", OTHER]],
    content: "metadata",
  });
  found = null;
  assert.deepEqual(await dispatch("get_contact_list", { pubkey: PUBKEY }), {
    id: "",
    pubkey: PUBKEY,
    created_at: 0,
    tags: [],
    content: "",
  });
});

test("set_contact_list validates, lowercases, dedupes, signs, and publishes kind 3", async () => {
  const published = [];
  const client = {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value, timeoutMessage, sendErrorMessage) {
      published.push({ value, timeoutMessage, sendErrorMessage });
      return value;
    },
  };
  registerRelayPeopleCommands(identity, client);
  const result = await dispatch("set_contact_list", {
    contacts: [
      {
        pubkey: OTHER.toUpperCase(),
        relay_url: "wss://relay.example",
        petname: "bob",
      },
      { pubkey: OTHER, relay_url: null, petname: null },
    ],
  });
  assert.deepEqual(published[0].value.tags, [
    ["p", OTHER, "wss://relay.example", "bob"],
  ]);
  assert.equal(published[0].value.kind, 3);
  assert.equal(published[0].value.content, "");
  assert.deepEqual(result, {
    event_id: "signed-contact-list",
    accepted: true,
    message: "",
  });
});

test("set_contact_list rejects malformed pubkeys before signing", async () => {
  registerRelayPeopleCommands(identity, {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(value) {
      return value;
    },
  });
  await assert.rejects(
    dispatch("set_contact_list", { contacts: [{ pubkey: "nope" }] }),
    /64-character hex string/,
  );
});
