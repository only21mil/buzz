import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { afterEach, test } from "node:test";

import { buildNip98Authorization, nip98Fetch } from "./nip98.ts";
import { register, resetRegistryForTests } from "./registry.ts";

afterEach(() => {
  resetRegistryForTests();
});

function decodeAuthorization(header) {
  assert.match(header, /^Nostr /);
  return JSON.parse(Buffer.from(header.slice(6), "base64").toString("utf8"));
}

test("NIP-98 signs the exact URL, method, body digest, and nonce", async () => {
  let signedTemplate;
  register("sign_event", (template) => {
    signedTemplate = template;
    return JSON.stringify({
      ...template,
      created_at: 1_786_799_999,
      id: "a".repeat(64),
      pubkey: "b".repeat(64),
      sig: "c".repeat(128),
    });
  });

  const body = '{"filters":[{"kinds":[9]}]}';
  const authorization = await buildNip98Authorization(
    {
      url: "https://relay.example.test/query?limit=20",
      method: "post",
      body,
    },
    { nonce: () => "fixed-nonce" },
  );
  const payload = createHash("sha256").update(body).digest("hex");

  assert.deepEqual(signedTemplate, {
    kind: 27235,
    content: "",
    tags: [
      ["u", "https://relay.example.test/query?limit=20"],
      ["method", "POST"],
      ["payload", payload],
      ["nonce", "fixed-nonce"],
    ],
  });
  assert.deepEqual(decodeAuthorization(authorization), {
    ...signedTemplate,
    created_at: 1_786_799_999,
    id: "a".repeat(64),
    pubkey: "b".repeat(64),
    sig: "c".repeat(128),
  });
});

test("NIP-98 fetch hashes and sends the same body bytes", async () => {
  const body = '{"name":"café"}';
  register("sign_event", (template) =>
    JSON.stringify({
      ...template,
      created_at: 1_786_799_999,
      id: "d".repeat(64),
      pubkey: "e".repeat(64),
      sig: "f".repeat(128),
    }),
  );
  let observed;
  const response = await nip98Fetch(
    {
      url: "https://relay.example.test/events",
      method: "POST",
      body,
      headers: { "Content-Type": "application/json" },
    },
    {
      nonce: () => "fetch-nonce",
      fetch: async (url, init) => {
        observed = { url, init };
        return new Response(null, { status: 204 });
      },
    },
  );

  assert.equal(response.status, 204);
  assert.equal(observed.url, "https://relay.example.test/events");
  assert.equal(observed.init.body, body);
  assert.equal(observed.init.method, "POST");
  assert.match(observed.init.headers.get("Authorization"), /^Nostr /);
  assert.equal(observed.init.headers.get("Content-Type"), "application/json");
});

test("NIP-98 snapshots a mutable body once for signing and transmission", async () => {
  const body = new TextEncoder().encode("original body");
  let signedTemplate;
  register("sign_event", async (template) => {
    signedTemplate = template;
    body.fill(120);
    await Promise.resolve();
    return JSON.stringify({
      ...template,
      created_at: 1_786_799_999,
      id: "1".repeat(64),
      pubkey: "2".repeat(64),
      sig: "3".repeat(128),
    });
  });
  let transmitted;

  await nip98Fetch(
    {
      url: "https://relay.example.test/events",
      method: "POST",
      body,
    },
    {
      nonce: () => "snapshot-nonce",
      fetch: async (_url, init) => {
        transmitted = init.body;
        return new Response(null, { status: 204 });
      },
    },
  );

  const payloadTag = signedTemplate.tags.find(([name]) => name === "payload");
  assert.ok(payloadTag);
  assert.ok(transmitted instanceof Uint8Array);
  assert.notEqual(transmitted, body);
  assert.equal(
    payloadTag[1],
    createHash("sha256").update(transmitted).digest("hex"),
  );
  assert.equal(new TextDecoder().decode(transmitted), "original body");
});

test("NIP-98 blocks encrypted key backups before signing or fetching", async () => {
  let calls = 0;
  register("sign_event", () => {
    calls += 1;
    throw new Error("must not sign");
  });
  await assert.rejects(
    buildNip98Authorization({
      url: "https://relay.example.test/events",
      method: "POST",
      body: ["NCR", "YPTSEC1", "SECRET"].join(""),
    }),
    /local key backup must never be transmitted/,
  );
  assert.equal(calls, 0);
});

test("NIP-98 blocks encrypted key backups in URLs and caller headers", async () => {
  let calls = 0;
  register("sign_event", () => {
    calls += 1;
    throw new Error("must not sign");
  });

  await assert.rejects(
    buildNip98Authorization({
      url: `https://relay.example.test/${["ncr", "yptsec1secret"].join("")}`,
      method: "GET",
    }),
    /local key backup must never be transmitted/,
  );
  await assert.rejects(
    nip98Fetch({
      url: "https://relay.example.test/events",
      method: "POST",
      headers: { "X-Key-Material": ["NCR", "YPTSEC1SECRET"].join("") },
    }),
    /local key backup must never be transmitted/,
  );
  assert.equal(calls, 0);
});
