import assert from "node:assert/strict";
import test from "node:test";
import {
  isProjectSnapshotRow,
  projectSnapshotKey,
  readProjectSnapshot,
  removeProjectSnapshotForRelay,
  writeProjectSnapshot,
} from "./projectSnapshot.ts";
import { hasAuthoritativeHomeBinding } from "./lib/projectHomeChannel.ts";
const owner = "a".repeat(64);
const home = "11111111-1111-4111-8111-111111111111";
const scope = { relayOrigin: "https://relay.example", pubkey: owner };
const event = (kind, tags, id) => ({
  kind,
  tags,
  id: id.repeat(64),
  pubkey: owner,
  created_at: 1,
  content: "",
  sig: "0".repeat(128),
});
const events = [
  event(
    30621,
    [
      ["d", "app"],
      ["name", "App"],
      ["a", `30617:${owner}:app`],
      ["buzz-channel", home],
    ],
    "1",
  ),
  event(
    30617,
    [
      ["d", "app"],
      ["name", "App"],
      ["buzz-channel", home],
    ],
    "2",
  ),
];
function storage() {
  const map = new Map();
  return {
    get length() {
      return map.size;
    },
    key: (n) => [...map.keys()][n] ?? null,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, val) => map.set(key, val),
    removeItem: (key) => map.delete(key),
  };
}

test("raw scoped snapshots rebuild display rows without granting home authority", () => {
  const store = storage();
  writeProjectSnapshot(scope, events, store, 1000);
  const rows = readProjectSnapshot(scope, store, 1100);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, "App");
  assert.equal(isProjectSnapshotRow(rows[0]), true);
  assert.equal(hasAuthoritativeHomeBinding(rows[0]), false);
});
test("wrong identity/relay, copied payload and malformed events are rejected", () => {
  const store = storage();
  writeProjectSnapshot(scope, events, store, 1000);
  const other = { ...scope, pubkey: "b".repeat(64) };
  const wrongRelay = { ...scope, relayOrigin: "https://other.example" };
  assert.equal(readProjectSnapshot(other, store, 1100), undefined);
  assert.equal(readProjectSnapshot(wrongRelay, store, 1100), undefined);
  store.setItem(
    projectSnapshotKey(other),
    store.getItem(projectSnapshotKey(scope)),
  );
  assert.equal(readProjectSnapshot(other, store, 1100), undefined);
  const value = JSON.parse(store.getItem(projectSnapshotKey(scope)));
  value.events[0].tags = [["name", {}]];
  store.setItem(projectSnapshotKey(scope), JSON.stringify(value));
  assert.equal(readProjectSnapshot(scope, store, 1100), undefined);
});
test("expired/future snapshots fail closed and community removal clears every identity", () => {
  const store = storage();
  writeProjectSnapshot(scope, events, store, 1000);
  writeProjectSnapshot(
    { ...scope, pubkey: "b".repeat(64) },
    events,
    store,
    1000,
  );
  assert.equal(readProjectSnapshot(scope, store, 999), undefined);
  assert.equal(
    readProjectSnapshot(scope, store, 1000 + 24 * 60 * 60_000 + 1),
    undefined,
  );
  removeProjectSnapshotForRelay("wss://relay.example", store);
  assert.equal(store.length, 0);
});
test("storage failures never fail a live operation", () => {
  const store = {
    getItem() {
      throw Error("denied");
    },
    setItem() {
      throw Error("quota");
    },
  };
  assert.doesNotThrow(() => writeProjectSnapshot(scope, events, store));
  assert.equal(readProjectSnapshot(scope, store), undefined);
});
