import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { registerRelayQueryCommands } from "./relayQueries.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const secret = (value) =>
  Uint8Array.from({ length: 32 }, (_, index) => (index === 31 ? value : 0));
const agentKey = secret(2);
const ownerKey = secret(1);
const agent = getPublicKey(agentKey);
const owner = getPublicKey(ownerKey);
const bot = getPublicKey(secret(3));
const human = getPublicKey(secret(4));

function auth(conditions = "", key = ownerKey, target = agent) {
  return [
    "auth",
    getPublicKey(key),
    conditions,
    bytesToHex(
      schnorr.sign(
        sha256(utf8ToBytes(`nostr:agent-auth:${target}:${conditions}`)),
        key,
      ),
    ),
  ];
}

function profile({
  tags = [auth()],
  created_at = 100,
  content = '{"display_name":"Sats"}',
  kind = 0,
} = {}) {
  // Roundtrip removes nostr-tools' verified-symbol cache, like a relay frame.
  return JSON.parse(
    JSON.stringify(
      finalizeEvent({ kind, created_at, content, tags }, agentKey),
    ),
  );
}

function install(
  profiles,
  tags = [
    ["p", agent, "", "admin"],
    ["p", bot, "", "bot"],
    ["p", human],
  ],
) {
  const calls = [];
  registerRelayQueryCommands(
    {},
    {
      async fetchFirstEvent(filter) {
        assert.deepEqual(filter, {
          kinds: [39002],
          "#d": ["channel-id"],
          limit: 1,
        });
        return { tags };
      },
      async fetchEvents(filter) {
        calls.push(filter);
        return typeof profiles === "function" ? profiles(filter) : profiles;
      },
    },
  );
  return calls;
}

const members = () =>
  dispatch("get_channel_members", { channelId: "channel-id" });
afterEach(() => resetRegistryForTests());

test("channel members batch-join signed owner profiles for non-bot roles", async () => {
  const calls = install([
    profile({ tags: [auth("kind=0&created_at>99&created_at<101")] }),
  ]);
  assert.deepEqual(await members(), {
    members: [
      {
        pubkey: agent,
        role: "admin",
        is_agent: true,
        joined_at: null,
        display_name: "Sats",
      },
      {
        pubkey: bot,
        role: "bot",
        is_agent: true,
        joined_at: null,
        display_name: null,
      },
      {
        pubkey: human,
        role: "member",
        is_agent: false,
        joined_at: null,
        display_name: null,
      },
    ],
    next_cursor: null,
  });
  assert.deepEqual(calls, [
    { kinds: [0], authors: [agent, bot, human], limit: 3 },
  ]);
});

test("ownership verification rejects invalid attestations and signatures", async (t) => {
  const wrongSignature = auth();
  wrongSignature[3] = "0".repeat(128);
  const uppercaseOwner = auth();
  uppercaseOwner[1] = owner.toUpperCase();
  const uppercaseSignature = auth();
  uppercaseSignature[3] = uppercaseSignature[3].toUpperCase();
  const invalidEvent = profile();
  invalidEvent.sig = "0".repeat(128);
  const tamperedEvent = profile();
  tamperedEvent.content = "{}";
  const cases = [
    ["missing auth", profile({ tags: [] })],
    ["duplicate auth", profile({ tags: [auth(), auth()] })],
    ["malformed second auth", profile({ tags: [auth(), ["auth"]] })],
    ["malformed first auth", profile({ tags: [["auth"], auth()] })],
    ["extra fields", profile({ tags: [[...auth(), "extra"]] })],
    ["wrong owner signature", profile({ tags: [wrongSignature] })],
    ["uppercase owner", profile({ tags: [uppercaseOwner] })],
    ["uppercase signature", profile({ tags: [uppercaseSignature] })],
    ["self-attestation", profile({ tags: [auth("", agentKey)] })],
    [
      "signature for another agent",
      profile({ tags: [auth("", ownerKey, human)] }),
    ],
    ["bad event signature", invalidEvent],
    ["tampered event content", tamperedEvent],
    ["wrong event kind", profile({ kind: 1 })],
  ];
  for (const conditions of [
    "kind=9",
    "created_at<100",
    "created_at>100",
    "created_at<101&created_at<99",
    "kind=01",
    "created_at<4294967296",
    "kind=65536",
    "unknown=1",
    "kind=0&",
    " kind=0",
  ]) {
    cases.push([conditions, profile({ tags: [auth(conditions)] })]);
  }
  for (const [name, event] of cases) {
    await t.test(name, async () => {
      resetRegistryForTests();
      install([event]);
      const result = await members();
      assert.equal(result.members[0].is_agent, false);
      assert.equal(result.members[1].is_agent, true);
    });
  }
});

test("newest profile can remove ownership; malformed content does not remove valid provenance", async () => {
  install([
    profile({ created_at: 101, tags: [], content: '{"name":"Human"}' }),
    profile(),
  ]);
  assert.deepEqual((await members()).members[0], {
    pubkey: agent,
    role: "admin",
    is_agent: false,
    joined_at: null,
    display_name: "Human",
  });
  resetRegistryForTests();
  install([profile({ content: "{" })]);
  const result = (await members()).members[0];
  assert.equal(result.is_agent, true);
  assert.equal(result.display_name, null);
});

test("equal-time profiles use NIP-33 event-id ordering independent of relay order", async () => {
  const profiles = [profile(), profile({ tags: [] })];
  const expected =
    profiles.toSorted((a, b) => a.id.localeCompare(b.id))[0].tags.length === 1;
  for (const events of [profiles, profiles.toReversed()]) {
    resetRegistryForTests();
    install(events);
    assert.equal((await members()).members[0].is_agent, expected);
  }
});

test("complete roster batches stay bounded, deduplicate members, and survive failed batches", async () => {
  const pubkeys = Array.from({ length: 1000 }, (_, index) =>
    index.toString(16).padStart(64, "0"),
  );
  pubkeys.push(agent);
  let active = 0;
  const calls = install(
    async (filter) => {
      assert.equal(active++, 0);
      await Promise.resolve();
      active--;
      if (filter.authors[0] === pubkeys[0])
        throw new Error("profile relay unavailable");
      return filter.authors.includes(agent) ? [profile()] : [];
    },
    [...pubkeys, agent].map((key) => ["p", key]),
  );
  const result = await members();
  assert.equal(result.members.length, 1001);
  assert.deepEqual(
    calls.map((call) => call.limit),
    [500, 500, 1],
  );
  assert.deepEqual(
    calls.flatMap((call) => call.authors),
    pubkeys,
  );
  assert.equal(result.members.at(-1).is_agent, true);
  assert.equal(result.members[0].is_agent, false);
});

test("empty rosters skip profiles and failed enrichment retains bot membership", async () => {
  const calls = install([], []);
  assert.deepEqual(await members(), { members: [], next_cursor: null });
  assert.deepEqual(calls, []);
  resetRegistryForTests();
  install(() => {
    throw new Error("offline");
  });
  assert.deepEqual(
    (await members()).members.map((member) => member.is_agent),
    [false, true, false],
  );
});
