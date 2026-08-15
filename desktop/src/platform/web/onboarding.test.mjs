import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  fetchBrowserJoinPolicy,
  joinPolicyUrl,
  registerOnboardingCommands,
} from "./onboarding.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

afterEach(() => resetRegistryForTests());

test("join policy URLs preserve relay base paths and reject unsafe inputs", () => {
  assert.equal(
    joinPolicyUrl("wss://relay.example/base/?ignored=yes#fragment").href,
    "https://relay.example/base/api/join-policy",
  );
  assert.equal(
    joinPolicyUrl("ws://localhost:3000/").href,
    "http://localhost:3000/api/join-policy",
  );
  assert.throws(() => joinPolicyUrl("https://relay.example"), /ws:\/\//);
  assert.throws(
    () => joinPolicyUrl("wss://user:secret@relay.example"),
    /must not contain credentials/,
  );
});

test("onboarding commands dispatch policy fetches and an empty browser runtime catalog", async () => {
  const calls = [];
  registerOnboardingCommands(async (url, init) => {
    calls.push({ url: url.href, init });
    return Response.json({ policy: { version: "v1" } });
  });

  assert.deepEqual(await dispatch("discover_acp_providers"), []);
  assert.deepEqual(
    await dispatch("fetch_join_policy", {
      relayUrl: "wss://relay.example/community",
    }),
    { version: "v1" },
  );
  assert.equal(calls[0].url, "https://relay.example/community/api/join-policy");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.redirect, "manual");
  assert.equal(calls[0].init.signal instanceof AbortSignal, true);
});

test("join policy fetch maps 404 to null and refuses redirects", async () => {
  assert.equal(
    await fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async () => new Response(null, { status: 404 }),
    ),
    null,
  );
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async () => new Response(null, { status: 307 }),
    ),
    /HTTP 307/,
  );
});

test("join policy fetch rejects malformed and declared-oversized responses", async () => {
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async () => new Response("not-json"),
    ),
    /malformed join policy/,
  );
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async () =>
        new Response("{}", {
          headers: { "content-length": String(4 * 1024 * 1024 + 1) },
        }),
    ),
    /oversized join policy/,
  );
});

test("join policy fetch enforces the streamed response limit", async () => {
  const chunk = new Uint8Array(2 * 1024 * 1024 + 1);
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(chunk);
      controller.enqueue(chunk);
      controller.close();
    },
  });
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async () => new Response(body),
    ),
    /oversized join policy/,
  );
});

test("join policy fetch aborts after its timeout", async () => {
  let observedSignal;
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async (_url, init) => {
        observedSignal = init.signal;
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener(
            "abort",
            () => reject(new DOMException("aborted", "AbortError")),
            { once: true },
          );
        });
      },
      5,
    ),
    /request timed out/,
  );
  assert.equal(observedSignal.aborted, true);
});

test("join policy timeout remains active while reading the response body", async () => {
  let streamController;
  let observedSignal;
  const body = new ReadableStream({
    start(controller) {
      streamController = controller;
      controller.enqueue(new TextEncoder().encode('{"policy":'));
    },
  });
  await assert.rejects(
    fetchBrowserJoinPolicy(
      { relayUrl: "wss://relay.example" },
      async (_url, init) => {
        observedSignal = init.signal;
        init.signal.addEventListener(
          "abort",
          () =>
            streamController.error(new DOMException("aborted", "AbortError")),
          { once: true },
        );
        return new Response(body);
      },
      5,
    ),
    /request timed out/,
  );
  assert.equal(observedSignal.aborted, true);
});
