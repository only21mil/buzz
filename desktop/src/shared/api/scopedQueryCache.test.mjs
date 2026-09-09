import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { ScopedQueryCache, queryCacheScopeKey } from "./scopedQueryCache.ts";
const alice = "a".repeat(64),
  bob = "b".repeat(64);
const key = (pubkey = alice, relay = "wss://relay.test") =>
  queryCacheScopeKey(relay, pubkey);
const client = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
class Store {
  values = new Map();
  async read(key) {
    return this.values.get(key) ?? null;
  }
  async write(key, value) {
    this.values.set(key, value);
  }
  async clear() {
    this.values.clear();
  }
}

test("cache keys isolate relay and identity and normalize equivalent URLs", () => {
  assert.equal(
    key(alice, "wss://RELAY.test/"),
    key(alice, "https://relay.test"),
  );
  assert.notEqual(key(), key(bob));
  assert.notEqual(key(), key(alice, "wss://other.test"));
  assert.throws(() => key(""), /identity/);
  assert.throws(() => key(alice, "wss://name:password@relay.test"), /relay/);
});

test("warm data renders while background revalidation waits on network", async () => {
  const cache = new ScopedQueryCache(new Store());
  const first = client(),
    attachment = cache.attach(first, key());
  await attachment.ready;
  first.setQueryData(["channels"], [{ id: "cached" }]);
  first.setQueryData(["identity"], { secret: "must not persist" });
  attachment.stop();
  const second = client(),
    restored = cache.attach(second, key());
  assert.deepEqual(second.getQueryData(["channels"]), [{ id: "cached" }]);
  assert.equal(second.getQueryData(["identity"]), undefined);
  await restored.ready;
  const refresh = deferred();
  let requests = 0;
  const observer = new QueryObserver(second, {
    queryKey: ["channels"],
    queryFn: () => {
      requests += 1;
      return refresh.promise;
    },
  });
  const unsubscribe = observer.subscribe(() => {});
  assert.equal(requests, 1);
  assert.deepEqual(observer.getCurrentResult().data, [{ id: "cached" }]);
  assert.equal(observer.getCurrentResult().isFetching, true);
  refresh.resolve([{ id: "fresh" }]);
  await second.getQueryCache().find({ queryKey: ["channels"] }).promise;
  assert.deepEqual(observer.getCurrentResult().data, [{ id: "fresh" }]);
  unsubscribe();
  restored.stop();
});

test("disk restore never exposes another relay or identity", async () => {
  const store = new Store(),
    producer = new ScopedQueryCache(store);
  const first = client(),
    attached = producer.attach(first, key());
  await attached.ready;
  first.setQueryData(["channel-messages", "private"], [{ id: "private" }]);
  attached.stop();
  await new Promise((resolve) => setImmediate(resolve));
  for (const scope of [key(bob), key(alice, "wss://other.test"), key()]) {
    const next = client(),
      reader = new ScopedQueryCache(store).attach(next, scope);
    await reader.ready;
    assert.equal(
      next.getQueryData(["channel-messages", "private"])?.[0].id,
      scope === key() ? "private" : undefined,
    );
    reader.stop();
  }
});

test("logout fences pending writes, responses and a late hydrate", async () => {
  const store = new Store(),
    cache = new ScopedQueryCache(store);
  const old = client(),
    attached = cache.attach(old, key());
  await attached.ready;
  old.setQueryData(["channels"], [{ id: "private" }]);
  const response = deferred();
  const pending = old
    .fetchQuery({ queryKey: ["profile"], queryFn: () => response.promise })
    .catch(() => {});
  const clearing = cache.clear();
  response.resolve({ pubkey: alice });
  await clearing;
  await pending;
  assert.equal(old.getQueryCache().getAll().length, 0);
  assert.equal(store.values.size, 0);
  const next = client(),
    restore = deferred();
  store.read = () => restore.promise;
  const late = cache.attach(next, key()),
    cleared = cache.clear();
  restore.resolve(
    JSON.stringify({
      version: 1,
      scope: key(),
      savedAt: Date.now(),
      state: { mutations: [], queries: [] },
    }),
  );
  await late.ready;
  await cleared;
  next.setQueryData(["channels"], [{ id: "stale-callback" }]);
  late.stop();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(store.values.size, 0);
});

test("clear keeps observers of queries the cache never persisted", async () => {
  const cache = new ScopedQueryCache(new Store());
  const live = client(),
    attached = cache.attach(live, key());
  await attached.ready;
  live.setQueryData(["channels"], [{ id: "private" }]);
  live.setQueryData(["identity"], { pubkey: alice });
  const observer = new QueryObserver(live, {
    queryKey: ["identity"],
    queryFn: () => ({ pubkey: alice }),
    staleTime: Infinity,
  });
  const seen = [];
  const unsubscribe = observer.subscribe((result) => seen.push(result.data));
  await cache.clear();
  assert.equal(live.getQueryData(["channels"]), undefined);
  live.setQueryData(["identity"], { pubkey: bob });
  assert.equal(observer.getCurrentResult().data?.pubkey, bob);
  assert.equal(seen.at(-1)?.pubkey, bob);
  unsubscribe();
});

test("storage read failures miss safely and failed deletion reaches logout", async () => {
  const store = {
    read: async () => {
      throw new Error("unavailable");
    },
    write: async () => {},
    clear: async () => {
      throw new Error("clear failed");
    },
  };
  const cache = new ScopedQueryCache(store);
  await cache.attach(client(), key()).ready;
  await assert.rejects(cache.clear(), /clear failed/);
});
