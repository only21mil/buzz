import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { verifyEvent } from "nostr-tools/pure";
import { assertNoIdentityKeyEgress } from "../../shared/lib/keyBackupEgress.ts";
import {
  BrowserIdentityManager,
  registerIdentityCommands,
} from "./identity.ts";
import { readNcryptsecLogN } from "./identityCrypto.ts";
import { DirectNip49Codec } from "./nip49Client.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

class MemoryIdentityStore {
  value = null;
  failSave = false;

  async load() {
    return this.value;
  }

  async save(identity, deviceKey) {
    if (this.failSave) throw new Error("storage write failed");
    this.value = { ...identity, deviceKey };
  }

  async clear() {
    if (this.failSave) throw new Error("storage write failed");
    this.value = null;
  }
}

afterEach(() => resetRegistryForTests());

test("browser identity is encrypted durably and reloads the same key", async () => {
  const store = new MemoryIdentityStore();
  const codec = new DirectNip49Codec();
  const first = await BrowserIdentityManager.create(store, codec);
  const initial = first.identity();

  assert.equal(initial.storage, "indexed-db");
  assert.equal(initial.lost, false);
  assert.equal(store.value.pubkey, initial.pubkey);
  assert.match(store.value.ncryptsec, /^ncryptsec1/);
  assert.equal(readNcryptsecLogN(store.value.ncryptsec), 10);

  const reloaded = await BrowserIdentityManager.create(store, codec);
  assert.equal(reloaded.pubkey(), initial.pubkey);
});

test("sign_event preserves the camelCase contract and explicit epoch zero", async () => {
  const manager = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    new DirectNip49Codec(),
  );
  registerIdentityCommands(manager);
  const raw = await dispatch("get_identity");
  assert.deepEqual(Object.keys(raw).sort(), [
    "display_name",
    "locked",
    "lost",
    "pubkey",
    "reset_failed",
    "storage",
  ]);

  const event = JSON.parse(
    await dispatch("sign_event", {
      kind: 1,
      content: "hello",
      createdAt: 0,
      tags: [["client", "buzz"]],
    }),
  );
  assert.equal(event.created_at, 0);
  assert.equal(event.pubkey, manager.pubkey());
  assert.equal(verifyEvent(event), true);
});

test("create_auth_event signs the exact relay and challenge tags", async () => {
  const manager = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    new DirectNip49Codec(),
  );
  registerIdentityCommands(manager);
  const event = JSON.parse(
    await dispatch("create_auth_event", {
      relayUrl: "wss://relay.example",
      challenge: "challenge-1",
    }),
  );
  assert.equal(event.kind, 22242);
  assert.deepEqual(event.tags, [
    ["relay", "wss://relay.example"],
    ["challenge", "challenge-1"],
  ]);
  assert.equal(verifyEvent(event), true);
});

test("identity import persists before replacing the active signer", async () => {
  const store = new MemoryIdentityStore();
  const manager = await BrowserIdentityManager.create(
    store,
    new DirectNip49Codec(),
  );
  const originalPubkey = manager.pubkey();
  store.failSave = true;

  await assert.rejects(
    manager.importIdentity("01".padStart(64, "0")),
    /storage write failed/,
  );
  assert.equal(manager.pubkey(), originalPubkey);
});

test("egress guard retains current and prior raw identity secrets only", async () => {
  const manager = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    new DirectNip49Codec(),
  );
  const prior = "01".padStart(64, "0");
  const current = "02".padStart(64, "0");
  const unrelated = "03".padStart(64, "0");

  await manager.importIdentity(prior);
  await manager.importIdentity(current);

  assert.throws(
    () => assertNoIdentityKeyEgress(prior, "test payload"),
    /local identity secret must never be transmitted/,
  );
  assert.throws(
    () => assertNoIdentityKeyEgress(current.toUpperCase(), "test payload"),
    /local identity secret must never be transmitted/,
  );
  assert.doesNotThrow(() =>
    assertNoIdentityKeyEgress(unrelated, "test event id"),
  );
});

test("sign_out zeroes and forgets retained identity secrets", async () => {
  const store = new MemoryIdentityStore();
  const manager = await BrowserIdentityManager.create(
    store,
    new DirectNip49Codec(),
  );
  const secret = "04".padStart(64, "0");
  await manager.importIdentity(secret);
  assert.throws(
    () => assertNoIdentityKeyEgress(secret, "test payload"),
    /local identity secret must never be transmitted/,
  );

  let reloads = 0;
  registerIdentityCommands(manager, () => {
    reloads += 1;
  });
  await dispatch("sign_out");
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(store.value, null);
  assert.equal(manager.identity().lost, true);
  assert.throws(() => manager.getNsec(), /import your identity first/);
  assert.doesNotThrow(() =>
    assertNoIdentityKeyEgress(secret, "signed-out test payload"),
  );
  assert.equal(reloads, 1);
});

test("ncryptsec import decrypts then re-encrypts under the device key", async () => {
  const codec = new DirectNip49Codec();
  const source = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    codec,
  );
  const portable = await source.createBackup("portable password");
  const target = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    codec,
  );

  await target.importIdentity(portable, "portable password");
  assert.equal(target.pubkey(), source.pubkey());
  assert.equal(target.identity().storage, "indexed-db");
});

test("an explicitly adopted recovery identity becomes durable", async () => {
  const store = new MemoryIdentityStore();
  store.load = async () => {
    throw new Error("stored identity is corrupt");
  };
  const manager = await BrowserIdentityManager.create(
    store,
    new DirectNip49Codec(),
  );
  assert.equal(manager.identity().lost, true);
  assert.equal(manager.identity().storage, "ephemeral");

  const persisted = await manager.persistCurrentIdentity();
  assert.equal(persisted.lost, false);
  assert.equal(persisted.storage, "indexed-db");
  assert.equal(store.value.pubkey, persisted.pubkey);
});

test("backup passphrase generation honors bounded word count and separator", async () => {
  const manager = await BrowserIdentityManager.create(
    new MemoryIdentityStore(),
    new DirectNip49Codec(),
  );
  registerIdentityCommands(manager);
  const passphrase = await dispatch("generate_backup_passphrase", {
    words: 4,
    separator: "-",
  });
  assert.match(passphrase, /^[0-9a-f]{8}(?:-[0-9a-f]{8}){3}$/);
});
