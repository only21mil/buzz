import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { IndexedDbQueryCacheStorage } from "./queryCacheStorage.ts";

const originalIndexedDb = globalThis.indexedDB;
afterEach(() => {
  if (originalIndexedDb === undefined) delete globalThis.indexedDB;
  else globalThis.indexedDB = originalIndexedDb;
});

// Serialize complete transactions, as IndexedDB does for this object store.
// Reads and writes use the production adapter, with only the database replaced.
function database() {
  const values = new Map();
  let tail = Promise.resolve();
  const db = {
    transaction(_name, mode = "readonly") {
      const requests = [];
      const writable = () => assert.equal(mode, "readwrite");
      const store = {
        get(key) {
          const request = {};
          requests.push(() => {
            request.result = values.get(key);
            request.onsuccess?.();
          });
          return request;
        },
        put(value, key) {
          writable();
          requests.push(() => values.set(key, value));
        },
        clear() {
          writable();
          requests.push(() => values.clear());
        },
      };
      const tx = { objectStore: () => store };
      tail = tail.then(() => {
        for (const run of requests) run();
        tx.oncomplete?.();
      });
      return tx;
    },
  };
  return { values, db };
}

function tab(db) {
  globalThis.indexedDB = {};
  const storage = new IndexedDbQueryCacheStorage();
  storage.open = async () => db;
  return storage;
}

test("a tab's delayed first save cannot recreate a snapshot after another tab logs out", async () => {
  const { values, db } = database();
  values.set("scope", "private data");
  const oldTab = tab(db),
    signingOutTab = tab(db);
  assert.equal(await oldTab.read("scope"), "private data");
  await signingOutTab.clear();
  await oldTab.write("scope", "late old data");
  assert.equal(values.has("scope"), false);
  assert.equal(await oldTab.read("scope"), null);
  // A new session can read the new generation and persist its own data.
  const newTab = tab(db);
  await newTab.read("scope");
  await newTab.write("scope", "new session");
  assert.equal(values.get("scope"), "new session");
  assert.equal(await oldTab.read("scope"), null);
  await oldTab.write("scope", "old session overwrite");
  assert.equal(values.get("scope"), "new session");
});

test("logout serializes with an already queued save and fences every later write", async () => {
  const { values, db } = database();
  const oldTab = tab(db),
    signingOutTab = tab(db);
  await oldTab.read("scope");
  const save = oldTab.write("scope", "private data");
  const clear = signingOutTab.clear();
  await Promise.all([save, clear]);
  await oldTab.write("scope", "late data");
  assert.equal(values.has("scope"), false);
  await signingOutTab.write("scope", "next identity");
  assert.equal(values.get("scope"), "next identity");
});

test("an uninitialized writer cannot adopt the current generation on first save", async () => {
  const { values, db } = database();
  await tab(db).write("scope", "unscoped data");
  assert.equal(values.has("scope"), false);
});
