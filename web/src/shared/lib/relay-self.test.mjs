import assert from "node:assert/strict";
import test from "node:test";

import {
  getRelaySelf,
  isRelaySelfPubkey,
  resetRelaySelfCache,
} from "./relay-self.mjs";

const PUBKEY = "a".repeat(64);

function stubFetch(handler) {
  const prev = globalThis.fetch;
  globalThis.fetch = handler;
  return () => {
    globalThis.fetch = prev;
  };
}

test("isRelaySelfPubkey accepts 64-char lowercase hex only", () => {
  assert.equal(isRelaySelfPubkey(PUBKEY), true);
  assert.equal(isRelaySelfPubkey("A".repeat(64)), false);
  assert.equal(isRelaySelfPubkey("a".repeat(63)), false);
  assert.equal(isRelaySelfPubkey(""), false);
  assert.equal(isRelaySelfPubkey(null), false);
  assert.equal(isRelaySelfPubkey(undefined), false);
  assert.equal(isRelaySelfPubkey(42), false);
});

test("getRelaySelf returns the NIP-11 self pubkey", async () => {
  resetRelaySelfCache();
  const restore = stubFetch(async (url, init) => {
    assert.equal(url, "https://relay.example/info");
    assert.equal(init.headers.Accept, "application/nostr+json");
    return new Response(JSON.stringify({ self: PUBKEY }), { status: 200 });
  });
  try {
    assert.equal(await getRelaySelf("https://relay.example"), PUBKEY);
  } finally {
    restore();
  }
});

test("getRelaySelf returns null when the relay advertises no self", async () => {
  resetRelaySelfCache();
  const restore = stubFetch(
    async () => new Response(JSON.stringify({ name: "Buzz" }), { status: 200 }),
  );
  try {
    assert.equal(await getRelaySelf("https://relay.example"), null);
  } finally {
    restore();
  }
});

test("getRelaySelf returns null for a malformed self value", async () => {
  resetRelaySelfCache();
  const restore = stubFetch(
    async () =>
      new Response(JSON.stringify({ self: "not-a-pubkey" }), { status: 200 }),
  );
  try {
    assert.equal(await getRelaySelf("https://relay.example"), null);
  } finally {
    restore();
  }
});

test("getRelaySelf rejects on HTTP errors and retries afterwards", async () => {
  resetRelaySelfCache();
  let calls = 0;
  const restore = stubFetch(async () => {
    calls += 1;
    return new Response("oops", { status: 500 });
  });
  try {
    await assert.rejects(() => getRelaySelf("https://relay.example"));
    await assert.rejects(() => getRelaySelf("https://relay.example"));
    assert.equal(calls, 2);
  } finally {
    restore();
  }
});

test("getRelaySelf rejects on a malformed document", async () => {
  resetRelaySelfCache();
  const restore = stubFetch(
    async () => new Response(JSON.stringify([1, 2]), { status: 200 }),
  );
  try {
    await assert.rejects(() => getRelaySelf("https://relay.example"));
  } finally {
    restore();
  }
});

test("getRelaySelf caches the in-flight request per base URL", async () => {
  resetRelaySelfCache();
  let calls = 0;
  const restore = stubFetch(async () => {
    calls += 1;
    return new Response(JSON.stringify({ self: PUBKEY }), { status: 200 });
  });
  try {
    const [a, b] = await Promise.all([
      getRelaySelf("https://relay.example"),
      getRelaySelf("https://relay.example"),
    ]);
    assert.equal(a, PUBKEY);
    assert.equal(b, PUBKEY);
    assert.equal(calls, 1);
  } finally {
    restore();
  }
});
