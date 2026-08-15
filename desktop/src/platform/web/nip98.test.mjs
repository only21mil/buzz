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
