import assert from "node:assert/strict";
import test from "node:test";
import {
  addOwnedChannelAgents,
  getOwnedAgentsToAdd,
} from "./ownedChannelAgents.ts";
const owner = "aa".repeat(32);
const a = "bb".repeat(32);
const b = "cc".repeat(32);
const agent = (pubkey, ownerPubkey = owner) => ({
  pubkey,
  ownerPubkey,
  name: "Scout",
});

test("owned-agent selection excludes existing and foreign identities and deduplicates keys, not names", () => {
  const agents = [
    agent(a.toUpperCase()),
    agent(a),
    agent(b),
    agent("dd".repeat(32), "ee".repeat(32)),
  ];
  assert.deepEqual(
    getOwnedAgentsToAdd(agents, owner.toUpperCase(), new Set()).map(
      (x) => x.pubkey,
    ),
    [a, b],
  );
  assert.deepEqual(
    getOwnedAgentsToAdd(agents, owner, new Set([a.toUpperCase()])).map(
      (x) => x.pubkey,
    ),
    [b],
  );
  assert.deepEqual(getOwnedAgentsToAdd(agents, null, new Set()), []);
});

test("batch retains accepted additions across individual failures and only retries unsuccessful identities", async () => {
  const calls = [];
  const result = await addOwnedChannelAgents(
    "channel",
    [agent(a), agent(a.toUpperCase()), agent(b)],
    async (input) => {
      calls.push(input);
      return input.pubkeys[0] === a
        ? {
            added: [a],
            errors: [{ pubkey: a, error: "Profile refresh failed" }],
          }
        : { added: [], errors: [{ pubkey: b, error: "Denied" }] };
    },
  );
  assert.equal(calls.length, 2);
  assert.ok(
    calls.every((call) => call.role === "bot" && call.channelId === "channel"),
  );
  assert.deepEqual(result.added, [a]);
  assert.deepEqual(
    result.errors.map((e) => e.error),
    ["Profile refresh failed", "Denied"],
  );
  const retry = getOwnedAgentsToAdd(
    [agent(a), agent(b)],
    owner,
    new Set(result.added),
  );
  assert.deepEqual(
    retry.map((x) => x.pubkey),
    [b],
  );
});

test("batch continues after thrown failures and treats unconfirmed responses as failures", async () => {
  let count = 0;
  const result = await addOwnedChannelAgents(
    "channel",
    [agent(a), agent(b)],
    async () => {
      if (++count === 1) throw new Error("Disconnected");
      return { added: [], errors: [] };
    },
  );
  assert.deepEqual(result.added, []);
  assert.deepEqual(
    result.errors.map((e) => e.error),
    ["Disconnected", "The relay did not confirm membership."],
  );
});
