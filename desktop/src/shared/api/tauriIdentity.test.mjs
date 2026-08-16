import assert from "node:assert/strict";
import test from "node:test";

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
const identityApi = await import("./tauriIdentity.ts");

const RELAY = "wss://relay.example.com";
const SIGNER_A = "a".repeat(64);
const SIGNER_B = "b".repeat(64);

function makeEvent(channelId = "private") {
  return {
    id: "c".repeat(64),
    pubkey: SIGNER_A,
    created_at: 1_700_000_000,
    kind: 9,
    tags: [["h", channelId]],
    content: "private message",
    sig: "d".repeat(128),
  };
}

function rawIdentity(pubkey) {
  return { pubkey, display_name: "Test" };
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
  storage.clear();
  const staleA = seed();
  invokeHandler = async (command) => {
    assert.equal(command, "import_identity");
    return rawIdentity(SIGNER_B);
  };

  const imported = await identityApi.importIdentity("nsec-test");
  assert.equal(imported.pubkey, SIGNER_B);
  assert.equal(storage.has(snapshots.messageSnapshotKey(staleA)), false);
  assert.equal(snapshots.writeMessageSnapshot(staleA, [makeEvent()]), false);
  assert.equal(snapshots.readMessageSnapshot(capture(SIGNER_B)), null);
});

test("failed identity import leaves the current identity snapshot intact", async () => {
  snapshots.removeAllMessageSnapshots();
  storage.clear();
  const current = seed();
  invokeHandler = async () => {
    throw new Error("import failed");
  };

  await assert.rejects(identityApi.importIdentity("bad-nsec"));
  assert.deepEqual(snapshots.readMessageSnapshot(current), [makeEvent()]);
});

test("successful identity replacement purges snapshots before resolving", async () => {
  snapshots.removeAllMessageSnapshots();
  storage.clear();
  const stale = seed();
  invokeHandler = async (command) => {
    assert.equal(command, "persist_current_identity");
    return rawIdentity(SIGNER_B);
  };

  await identityApi.persistCurrentIdentity();
  assert.equal(storage.has(snapshots.messageSnapshotKey(stale)), false);
  assert.equal(snapshots.writeMessageSnapshot(stale, [makeEvent()]), false);
});

test("sign-out invalidates and purges before native restart can begin", async () => {
  snapshots.removeAllMessageSnapshots();
  storage.clear();
  const stale = seed();
  invokeHandler = async (command) => {
    assert.equal(command, "sign_out");
    assert.equal(storage.has(snapshots.messageSnapshotKey(stale)), false);
    assert.equal(snapshots.writeMessageSnapshot(stale, [makeEvent()]), false);
  };

  await identityApi.signOut();
});
