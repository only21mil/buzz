import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

import { getUsersBatchCoalesced } from "./profileBatchCoalescer.ts";

const ALICE = "a".repeat(64);
const BOB = "b".repeat(64);
const CAROL = "c".repeat(64);

function rawProfile(displayName) {
  return {
    display_name: displayName,
    avatar_url: null,
    nip05_handle: null,
    owner_pubkey: null,
  };
}

beforeEach(() => {
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async () => {
        throw new Error("Tauri invoke stub was not installed by the test");
      },
      transformCallback: () => 1,
    },
  };
});

test("overlapping same-turn profile batches share one union transport call", async () => {
  const calls = [];
  window.__TAURI_INTERNALS__.invoke = async (command, args) => {
    calls.push({ command, pubkeys: args.pubkeys });
    return {
      profiles: {
        [ALICE]: rawProfile("Alice"),
        [BOB]: rawProfile("Bob"),
      },
      missing: [CAROL],
    };
  };

  const header = getUsersBatchCoalesced("wss://relay.example", [ALICE, BOB]);
  const messages = getUsersBatchCoalesced("wss://relay.example", [BOB, CAROL]);
  const owners = getUsersBatchCoalesced("wss://relay.example", [ALICE]);
  const [headerResult, messageResult, ownerResult] = await Promise.all([
    header,
    messages,
    owners,
  ]);

  assert.deepEqual(calls, [
    {
      command: "get_users_batch",
      pubkeys: [ALICE, BOB, CAROL],
    },
  ]);
  assert.deepEqual(Object.keys(headerResult.profiles), [ALICE, BOB]);
  assert.deepEqual(headerResult.missing, []);
  assert.deepEqual(Object.keys(messageResult.profiles), [BOB]);
  assert.deepEqual(messageResult.missing, [CAROL]);
  assert.deepEqual(Object.keys(ownerResult.profiles), [ALICE]);
  assert.deepEqual(ownerResult.missing, []);
});

test("a failed coalesced batch rejects every caller and a later request retries", async () => {
  let calls = 0;
  window.__TAURI_INTERNALS__.invoke = async () => {
    calls += 1;
    if (calls === 1) throw new Error("relay unavailable");
    return { profiles: { [CAROL]: rawProfile("Carol") }, missing: [] };
  };

  const first = getUsersBatchCoalesced("wss://relay.example", [ALICE]);
  const overlapping = getUsersBatchCoalesced("wss://relay.example", [
    ALICE,
    BOB,
  ]);
  const rejected = await Promise.allSettled([first, overlapping]);
  assert.deepEqual(
    rejected.map((result) => result.status),
    ["rejected", "rejected"],
  );

  const retry = await getUsersBatchCoalesced("wss://relay.example", [CAROL]);
  assert.equal(calls, 2);
  assert.equal(retry.profiles[CAROL].displayName, "Carol");
});
