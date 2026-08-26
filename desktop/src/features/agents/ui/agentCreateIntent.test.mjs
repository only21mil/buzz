import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveAgentReviewCreateIntent,
  resolveCreateIntent,
} from "./agentCreateIntent.ts";

test("resolveCreateIntent defaults to quick-start for un-migrated callers", () => {
  // PersonaDialog's duplicate path calls handleSubmit without an intent until
  // B3 migrates it; the default must preserve today's create-then-start
  // behavior or duplicate silently becomes definition-only.
  assert.equal(resolveCreateIntent(undefined), "definition_start");
});

test("resolveCreateIntent passes explicit intents through", () => {
  assert.equal(resolveCreateIntent("definition"), "definition");
  assert.equal(resolveCreateIntent("definition_stopped"), "definition_stopped");
  assert.equal(resolveCreateIntent("definition_start"), "definition_start");
});

test("owner review creates stopped by default and preserves explicit Start now", () => {
  assert.equal(
    resolveAgentReviewCreateIntent("create-stopped"),
    "definition_stopped",
  );
  assert.equal(resolveAgentReviewCreateIntent("start-now"), "definition_start");
});
