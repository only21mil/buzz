import assert from "node:assert/strict";
import test from "node:test";

const listeners = new Map();
const previousSelf = globalThis.self;
globalThis.self = {
  addEventListener(type, listener) {
    listeners.set(type, listener);
  },
  clients: {
    claim: async () => undefined,
    get: async () => undefined,
    matchAll: async () => [],
  },
  location: { origin: "https://relay.example" },
  skipWaiting: async () => undefined,
};

const {
  authenticatedMediaFetch,
  authenticatedRequest,
  shouldAuthenticateMediaRequest,
} = await import("../../../public/media-auth-sw.js");

test("worker targets only same-origin media GET and HEAD", () => {
  assert.equal(
    shouldAuthenticateMediaRequest(
      new Request("https://relay.example/media/a.png"),
    ),
    true,
  );
  assert.equal(
    shouldAuthenticateMediaRequest(
      new Request("https://relay.example/media/a.png", { method: "HEAD" }),
    ),
    true,
  );
  assert.equal(
    shouldAuthenticateMediaRequest(
      new Request("https://relay.example/upload", { method: "PUT" }),
    ),
    false,
  );
  assert.equal(
    shouldAuthenticateMediaRequest(
      new Request("https://external.example/media/a.png"),
    ),
    false,
  );
});

test("authenticated request preserves Range and injects the short-lived header", () => {
  const request = new Request("https://relay.example/media/a.mp4", {
    headers: { Range: "bytes=10-20" },
  });
  const authenticated = authenticatedRequest(request, "Nostr signed");
  assert.equal(authenticated.headers.get("Range"), "bytes=10-20");
  assert.equal(authenticated.headers.get("Authorization"), "Nostr signed");
  assert.equal(authenticated.redirect, "manual");
  assert.equal(authenticated.credentials, "same-origin");
  assert.equal(authenticated.mode, "same-origin");
});

test("missing signing fails closed without making a network request", async () => {
  let fetches = 0;
  const response = await authenticatedMediaFetch(
    { request: new Request("https://relay.example/media/a.png") },
    async () => undefined,
    async () => {
      fetches += 1;
      return new Response();
    },
  );
  assert.equal(response.status, 401);
  assert.equal(fetches, 0);
});

test.after(() => {
  globalThis.self = previousSelf;
});
