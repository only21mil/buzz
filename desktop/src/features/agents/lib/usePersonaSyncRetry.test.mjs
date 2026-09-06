import assert from "node:assert/strict";
import test, { mock, afterEach, beforeEach } from "node:test";
import { relayClient } from "@/shared/api/relayClient";
import {
  KIND_PERSONA,
  KIND_TEAM,
  KIND_TEAM_CATALOG,
  KIND_MANAGED_AGENT,
} from "@/shared/constants/kinds";
import { startPersonaSync } from "./usePersonaSync.ts";

const settle = () => new Promise((resolve) => setImmediate(resolve));
const event = (id, kind) => ({
  id,
  kind,
  pubkey: "owner",
  created_at: 1,
  tags: [["d", id]],
  content: "{}",
  sig: "signature",
});
let cancelled;
beforeEach(() => {
  globalThis.isTauri = true;
  cancelled = false;
  mock.timers.enable({ apis: ["setTimeout"] });
});
afterEach(() => {
  cancelled = true;
  mock.reset();
  mock.timers.reset();
  delete globalThis.window;
});
function start(history, apply) {
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: (_cmd, args) => {
        assert.equal(args.arrivalRelayUrl, "wss://captured.example");
        return apply(JSON.parse(args.eventJson));
      },
    },
  };
  mock.method(relayClient, "fetchEvents", () => Promise.resolve(history));
  let receive;
  mock.method(relayClient, "subscribeLive", (_filter, listener) => {
    receive = listener;
    return Promise.resolve(async () => {});
  });
  startPersonaSync("owner", "wss://captured.example", () => cancelled);
  return (value) => receive(value);
}

test("failed history save is retried before buffered catalog operations, without losing its duplicate", async () => {
  const applied = [];
  let failed = false;
  let releaseRetry;
  const retry = new Promise((resolve) => {
    releaseRetry = resolve;
  });
  const persona = event("persona", KIND_PERSONA);
  const receive = start([event("team", KIND_TEAM), persona], async ({ id }) => {
    applied.push(id);
    if (id === "persona" && !failed) {
      failed = true;
      throw new Error("transient native save failure");
    }
    if (id === "persona") await retry;
  });
  await settle();
  receive(persona);
  receive(event("catalog", KIND_TEAM_CATALOG));
  await settle();
  assert.deepEqual(
    applied,
    ["team", "persona"],
    "failed save must hold the live boundary",
  );
  mock.timers.tick(500);
  await settle();
  assert.deepEqual(
    applied,
    ["team", "persona", "persona"],
    "retry must finish before draining live events",
  );
  releaseRetry();
  await settle();
  assert.deepEqual(
    applied,
    ["team", "persona", "persona", "catalog"],
    "successful events are deduplicated only after saving",
  );
  assert.equal(
    relayClient.fetchEvents.mock.callCount(),
    1,
    "retry keeps the original failed batch",
  );
});

test("live save failure retries in order before dependent team and catalog operations", async () => {
  const applied = [];
  let failures = 1;
  const receive = start([], async ({ id }) => {
    applied.push(id);
    if (id === "member" && failures-- > 0) throw new Error("save failed");
  });
  await settle();
  receive(event("member", KIND_PERSONA));
  receive(event("team", KIND_TEAM));
  receive(event("catalog", KIND_TEAM_CATALOG));
  await settle();
  assert.deepEqual(applied, ["member"]);
  mock.timers.tick(500);
  await settle();
  assert.deepEqual(applied, ["member", "member", "team", "catalog"]);
});

test("exhausted native saves keep queued and future dependencies held while runtime policy stays live", async () => {
  const applied = [];
  const receive = start([], async ({ id }) => {
    applied.push(id);
    if (id === "member") throw new Error("disk unavailable");
  });
  await settle();
  receive(event("member", KIND_PERSONA));
  receive(event("team", KIND_TEAM));
  await settle();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    mock.timers.tick(2000);
    await settle();
  }
  receive(event("catalog", KIND_TEAM_CATALOG));
  receive(event("runtime", KIND_MANAGED_AGENT));
  await settle();
  assert.deepEqual(applied, ["member", "member", "member", "runtime"]);
});

test("cancelled subscription does not apply a pending retry or buffered catalog operation", async () => {
  const applied = [];
  const receive = start([event("member", KIND_PERSONA)], async ({ id }) => {
    applied.push(id);
    throw new Error("save failed");
  });
  await settle();
  receive(event("catalog", KIND_TEAM_CATALOG));
  cancelled = true;
  mock.timers.tick(2000);
  await settle();
  assert.deepEqual(applied, ["member"]);
});
