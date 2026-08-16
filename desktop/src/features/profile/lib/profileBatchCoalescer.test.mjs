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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function flushMicrotasks() {
  for (let index = 0; index < 4; index += 1) await Promise.resolve();
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

test("an overlapping caller reuses covered pubkeys while transport is unresolved", async () => {
  const request = deferred();
  const calls = [];
  window.__TAURI_INTERNALS__.invoke = async (_command, args) => {
    calls.push(args.pubkeys);
    return request.promise;
  };

  const first = getUsersBatchCoalesced("wss://relay.example", [ALICE, BOB]);
  await flushMicrotasks();
  assert.deepEqual(calls, [[ALICE, BOB]]);

  const overlapping = getUsersBatchCoalesced("wss://relay.example", [BOB]);
  await flushMicrotasks();
  assert.deepEqual(calls, [[ALICE, BOB]]);

  request.resolve({
    profiles: {
      [ALICE]: rawProfile("Alice"),
      [BOB]: rawProfile("Bob"),
    },
    missing: [],
  });
  const [firstResult, overlappingResult] = await Promise.all([
    first,
    overlapping,
  ]);
  assert.equal(firstResult.profiles[ALICE].displayName, "Alice");
  assert.equal(firstResult.profiles[BOB].displayName, "Bob");
  assert.deepEqual(Object.keys(overlappingResult.profiles), [BOB]);
});

test("an overlapping caller transports only its uncovered pubkeys", async () => {
  const firstRequest = deferred();
  const uncoveredRequest = deferred();
  const calls = [];
  window.__TAURI_INTERNALS__.invoke = async (_command, args) => {
    calls.push(args.pubkeys);
    return calls.length === 1 ? firstRequest.promise : uncoveredRequest.promise;
  };

  const first = getUsersBatchCoalesced("wss://relay.example", [ALICE, BOB]);
  await flushMicrotasks();
  const overlapping = getUsersBatchCoalesced("wss://relay.example", [
    BOB,
    CAROL,
  ]);
  await flushMicrotasks();
  assert.deepEqual(calls, [[ALICE, BOB], [CAROL]]);

  firstRequest.resolve({
    profiles: {
      [ALICE]: rawProfile("Alice"),
      [BOB]: rawProfile("Bob"),
    },
    missing: [],
  });
  uncoveredRequest.resolve({
    profiles: { [CAROL]: rawProfile("Carol") },
    missing: [],
  });
  const [firstResult, overlappingResult] = await Promise.all([
    first,
    overlapping,
  ]);
  assert.deepEqual(Object.keys(firstResult.profiles), [ALICE, BOB]);
  assert.deepEqual(Object.keys(overlappingResult.profiles), [BOB, CAROL]);
});

test("a failed coalesced batch rejects every caller and a later request retries", async () => {
  let calls = 0;
  window.__TAURI_INTERNALS__.invoke = async () => {
    calls += 1;
    if (calls === 1) throw new Error("relay unavailable");
    return { profiles: { [ALICE]: rawProfile("Alice") }, missing: [] };
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

  const retry = await getUsersBatchCoalesced("wss://relay.example", [ALICE]);
  assert.equal(calls, 2);
  assert.equal(retry.profiles[ALICE].displayName, "Alice");
});
