import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { test } from "node:test";
import ts from "typescript";
import * as scopes from "./publicationScope.ts";

const PUBKEY = "a".repeat(64);
const RELAY = "wss://relay.example/Team";
function harness(invokeTauri) {
  scopes.setPublicationScope(PUBKEY, RELAY, true);
  const exports = {};
  runInNewContext(
    ts.transpileModule(
      readFileSync(
        new URL("./preparePublicationScope.ts", import.meta.url),
        "utf8",
      ),
      {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
        },
      },
    ).outputText,
    {
      exports,
      Object,
      Number,
      Error,
      require: (key) =>
        ({
          "@tauri-apps/api/core": { isTauri: () => true },
          "./tauri": { invokeTauri },
          "./publicationScope": scopes,
        })[key],
    },
  );
  return exports.preparePublicationScope;
}

test("native epoch is captured once and survives later publication calls unchanged", async () => {
  let calls = 0;
  const prepare = harness(async (command) => {
    assert.equal(command, "get_message_publication_scope");
    calls += 1;
    return { pubkey: PUBKEY, relayUrl: RELAY, nativeEpoch: 41 };
  });
  const original = scopes.capturePublicationScope();
  const bound = await prepare(original);
  assert.equal(bound.nativeEpoch, 41);
  assert.equal(bound.generation, original.generation);
  assert.equal(Object.isFrozen(bound), true);
  assert.equal(
    await prepare(bound),
    bound,
    "publication must not refresh away a revoked native epoch",
  );
  assert.equal(calls, 1);
});

test("renderer ABA during native snapshot IPC cannot adopt the returned epoch", async () => {
  let release;
  const snapshot = new Promise((resolve) => {
    release = resolve;
  });
  const prepare = harness(async () => snapshot);
  const pending = prepare(scopes.capturePublicationScope());
  scopes.setPublicationScope("b".repeat(64), "wss://other.example");
  scopes.setPublicationScope(PUBKEY, RELAY);
  release({ pubkey: PUBKEY, relayUrl: RELAY, nativeEpoch: 43 });
  await assert.rejects(pending, /identity or community changed/);
});

for (const snapshot of [
  { pubkey: "b".repeat(64), relayUrl: RELAY, nativeEpoch: 41 },
  { pubkey: PUBKEY, relayUrl: "wss://relay.example/team", nativeEpoch: 41 },
  { pubkey: PUBKEY, relayUrl: RELAY, nativeEpoch: undefined },
]) {
  test(`invalid native snapshot is rejected before preparation: ${JSON.stringify(snapshot)}`, async () => {
    const prepare = harness(async () => snapshot);
    await assert.rejects(
      prepare(scopes.capturePublicationScope()),
      /signer changed|relay changed|Invalid native publication epoch/,
    );
  });
}
