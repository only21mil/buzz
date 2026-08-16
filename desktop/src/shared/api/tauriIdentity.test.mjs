import assert from "node:assert/strict";
import test from "node:test";
import { finalizeEvent } from "nostr-tools/pure";

const storage = new Map();
let invokeHandler = async () => undefined;

globalThis.window = {
  localStorage: {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
    key: (index) => [...storage.keys()][index] ?? null,
    get length() {
      return storage.size;
    },
  },
  __TAURI_INTERNALS__: {
    invoke: (command, args) => invokeHandler(command, args),
  },
};
globalThis.localStorage = globalThis.window.localStorage;

const snapshots = await import("@/features/messages/lib/messageSnapshot");
const profileBatches = await import(
  "@/features/profile/lib/profileBatchCoalescer"
);
const identityApi = await import("./tauriIdentity.ts");

const RELAY = "wss://relay.example.com";
const SIGNER_A = "a".repeat(64);
const SIGNER_B = "b".repeat(64);
const EVENT_SECRET = new Uint8Array(32).fill(13);

function makeEvent(channelId = "private") {
  return finalizeEvent(
    {
      created_at: 1_700_000_000,
      kind: 9,
      tags: [["h", channelId]],
      content: "private message",
    },
    EVENT_SECRET,
  );
}

function rawIdentity(pubkey) {
  return { pubkey, display_name: "Test" };
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

function capture(signer = SIGNER_A) {
  const scope = snapshots.captureMessageSnapshotScope(RELAY, signer, "private");
  assert.ok(scope);
  return scope;
}

function seed(signer = SIGNER_A) {
  const scope = capture(signer);
  assert.equal(snapshots.writeMessageSnapshot(scope, [makeEvent()]), true);
  return scope;
}

test("successful identity import purges all buckets and invalidates stale writes", async () => {
  snapshots.removeAllMessageSnapshots();
  profileBatches.invalidateProfileBatchCoalescer();
  storage.clear();
  const staleA = seed();
  const pendingBatch = deferred();
  let profileCalls = 0;
  invokeHandler = async (command) => {
    if (command === "get_users_batch") {
      profileCalls += 1;
      return pendingBatch.promise;
    }
    if (command === "import_identity") return rawIdentity(SIGNER_B);
    throw new Error(`Unexpected command: ${command}`);
  };

  const staleProfiles = profileBatches.getUsersBatchCoalesced(RELAY, SIGNER_A, [
    SIGNER_A,
  ]);
  await flushMicrotasks();
  const imported = await identityApi.importIdentity("nsec-test");
  await assert.rejects(staleProfiles, /identity change/);
  pendingBatch.resolve({ profiles: {}, missing: [SIGNER_A] });
  await flushMicrotasks();
  assert.equal(imported.pubkey, SIGNER_B);
  assert.equal(profileCalls, 1);
  assert.equal(storage.has(snapshots.messageSnapshotKey(staleA)), false);
  assert.equal(snapshots.writeMessageSnapshot(staleA, [makeEvent()]), false);
  assert.equal(snapshots.readMessageSnapshot(capture(SIGNER_B)), null);
});

test("failed identity import leaves the current identity snapshot intact", async () => {
  snapshots.removeAllMessageSnapshots();
  profileBatches.invalidateProfileBatchCoalescer();
  storage.clear();
  const current = seed();
  const before = snapshots.readMessageSnapshot(current);
  assert.ok(before);
  const pendingBatch = deferred();
  invokeHandler = async (command) => {
    if (command === "get_users_batch") return pendingBatch.promise;
    if (command === "import_identity") throw new Error("import failed");
    throw new Error(`Unexpected command: ${command}`);
  };

  const currentProfiles = profileBatches.getUsersBatchCoalesced(
    RELAY,
    SIGNER_A,
    [SIGNER_A],
  );
  await flushMicrotasks();
  await assert.rejects(identityApi.importIdentity("bad-nsec"));
  pendingBatch.resolve({ profiles: {}, missing: [SIGNER_A] });
  assert.deepEqual(await currentProfiles, {
    profiles: {},
    missing: [SIGNER_A],
  });
  assert.deepEqual(snapshots.readMessageSnapshot(current), before);
});

test("successful identity replacement purges snapshots before resolving", async () => {
  snapshots.removeAllMessageSnapshots();
  profileBatches.invalidateProfileBatchCoalescer();
  storage.clear();
  const stale = seed();
  const pendingBatch = deferred();
  invokeHandler = async (command) => {
    if (command === "get_users_batch") return pendingBatch.promise;
    if (command === "persist_current_identity") return rawIdentity(SIGNER_B);
    throw new Error(`Unexpected command: ${command}`);
  };

  const staleProfiles = profileBatches.getUsersBatchCoalesced(RELAY, SIGNER_A, [
    SIGNER_A,
  ]);
  await flushMicrotasks();
  await identityApi.persistCurrentIdentity();
  await assert.rejects(staleProfiles, /identity change/);
  pendingBatch.resolve({ profiles: {}, missing: [SIGNER_A] });
  assert.equal(storage.has(snapshots.messageSnapshotKey(stale)), false);
  assert.equal(snapshots.writeMessageSnapshot(stale, [makeEvent()]), false);
});

test("sign-out invalidates and purges before native restart can begin", async () => {
  snapshots.removeAllMessageSnapshots();
  profileBatches.invalidateProfileBatchCoalescer();
  storage.clear();
  const stale = seed();
  const pendingBatch = deferred();
  const staleProfiles = profileBatches.getUsersBatchCoalesced(RELAY, SIGNER_A, [
    SIGNER_A,
  ]);
  invokeHandler = async (command) => {
    if (command === "get_users_batch") return pendingBatch.promise;
    assert.equal(command, "sign_out");
    assert.equal(storage.has(snapshots.messageSnapshotKey(stale)), false);
    assert.equal(snapshots.writeMessageSnapshot(stale, [makeEvent()]), false);
    await assert.rejects(staleProfiles, /identity change/);
  };

  await flushMicrotasks();
  await identityApi.signOut();
  pendingBatch.resolve({ profiles: {}, missing: [SIGNER_A] });
});
