import assert from "node:assert/strict";
import test from "node:test";

import { shouldObserveManagedAgents } from "./observerRelayStore.ts";

test("observer ingestion opens for a cold stopped managed agent", () => {
  assert.equal(
    shouldObserveManagedAgents([{ pubkey: "aa", status: "stopped" }]),
    true,
  );
});

test("observer ingestion stays closed when there are no owned agents", () => {
  // The observer subscription now starts unconditionally (even with zero
  // managed agents) so owner-signed draft frames reach the review surface.
  // shouldObserveManagedAgents still reports whether there are managed
  // agents, but the subscription no longer gates on it.
  assert.equal(shouldObserveManagedAgents([]), false);
});
