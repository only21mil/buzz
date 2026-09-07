import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { test } from "node:test";
import ts from "typescript";
import * as scopes from "./publicationScope.ts";

const PUBKEY = "a".repeat(64);
const RELAY = "wss://relay.example";
const event = {
  id: "id",
  pubkey: PUBKEY,
  tags: [["h", "channel"]],
  content: "captured",
};
function deferred() {
  let resolve;
  const promise = new Promise((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
function load(file, dependencies) {
  const exports = {};
  runInNewContext(
    ts.transpileModule(readFileSync(new URL(file, import.meta.url), "utf8"), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
      },
    }).outputText,
    {
      exports,
      Map,
      Set,
      Error,
      Promise,
      window: { setTimeout, clearTimeout },
      require: (key) => dependencies[key] ?? {},
    },
  );
  return exports;
}
function harness({
  admission = Promise.resolve(),
  invoke = async () => {},
} = {}) {
  scopes.setPublicationScope(PUBKEY, RELAY, true);
  const scope = scopes.capturePublicationScope();
  const { RelayClient } = load("./relayClientSession.ts", {
    "./publicationScope": scopes,
    "./preparePublicationScope": {
      preparePublicationScope: async (scope) => scope,
    },
    "@tauri-apps/api/core": { invoke },
    "@/shared/api/relayRateLimitGate": { waitForRateLimit: () => admission },
    "@/shared/api/relayClientTimings": { PUBLISH_TIMEOUT_MS: 1000 },
  });
  // Execute production publication/sendRaw/retry methods, with socket creation
  // and recovery supplied independently of Tauri or a live relay.
  const client = Object.create(RelayClient.prototype);
  client.pendingEvents = new Map();
  client.wsId = 42;
  client.relayUrl = RELAY;
  client.ensureConnected = async () => {};
  client.recoverFromSocketFailure = (error) => error;
  return { scope, client };
}

test("publication suspended by admission rejects an identity/community switch", async () => {
  const gate = deferred();
  let sends = 0;
  const { scope, client } = harness({
    admission: gate.promise,
    invoke: async () => {
      sends += 1;
    },
  });
  const pending = client.publishEvent(event, "timeout", "failure", scope);
  scopes.setPublicationScope("b".repeat(64), "wss://other.example");
  gate.resolve();
  await assert.rejects(pending, /identity or community changed/);
  assert.equal(sends, 0);
});

test("reconnect retry cannot move the signed event onto another scope", async () => {
  const reconnect = deferred();
  const entered = deferred();
  let sends = 0;
  const { scope, client } = harness({
    invoke: async () => {
      sends += 1;
      throw new Error("socket closed");
    },
  });
  client.ensureConnected = async () => {
    entered.resolve();
    await reconnect.promise;
  };
  const pending = client.publishEvent(event, "timeout", "failure", scope);
  await entered.promise;
  scopes.setPublicationScope(PUBKEY, "wss://other.example");
  client.wsId = 99;
  client.relayUrl = "wss://other.example";
  reconnect.resolve();
  await assert.rejects(pending, /identity or community changed/);
  assert.equal(
    sends,
    1,
    "only the original failed transport attempt is permitted",
  );
  assert.equal(client.pendingEvents.size, 0);
});

test("actual signer and socket relay are checked independently of frontend scope", async () => {
  let sends = 0;
  const { scope, client } = harness({
    invoke: async () => {
      sends += 1;
    },
  });
  await assert.rejects(
    client.publishEvent(
      { ...event, pubkey: "b".repeat(64) },
      "timeout",
      "failure",
      scope,
    ),
    /signer changed/,
  );
  client.relayUrl = "wss://other.example";
  await assert.rejects(
    client.publishEvent(event, "timeout", "failure", scope),
    /relay changed/,
  );
  assert.equal(sends, 0);
});

test("connection preparation cannot sign after the authored scope changes", async () => {
  scopes.setPublicationScope(PUBKEY, RELAY, true);
  const expectedScope = scopes.capturePublicationScope();
  const gate = deferred();
  let signs = 0;
  const { sendScopedRelayMessage } = load("./relayPublication.ts", {
    "./publicationScope": scopes,
    "./preparePublicationScope": {
      preparePublicationScope: async (scope) => scope,
    },
    "./tauri": {
      signRelayEvent: async () => {
        signs += 1;
        return event;
      },
    },
    "@/shared/constants/kinds": { KIND_STREAM_MESSAGE: 9 },
  });
  const pending = sendScopedRelayMessage(
    () => gate.promise,
    async () => event,
    {
      channelId: "channel",
      content: "captured",
      mentionPubkeys: [],
      extraTags: [],
      expectedScope,
    },
  );
  scopes.setPublicationScope("b".repeat(64), RELAY);
  gate.resolve();
  await assert.rejects(pending, /identity or community changed/);
  assert.equal(signs, 0);
});
