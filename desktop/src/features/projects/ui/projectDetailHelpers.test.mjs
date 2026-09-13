import assert from "node:assert/strict";
import { test } from "node:test";

import { fetchTitleForSyncStatus } from "./projectDetailHelpers.ts";

test("fetch title reports the fetch error when the poll fetch failed", () => {
  assert.equal(
    fetchTitleForSyncStatus({
      fetchFailed: true,
      fetchError: "fatal: unable to connect",
      pullBlockReason: "Local branch is up to date.",
    }),
    "fatal: unable to connect",
  );
});

test("fetch title falls back to a stale notice when the error is empty", () => {
  assert.equal(
    fetchTitleForSyncStatus({
      fetchFailed: true,
      fetchError: null,
      pullBlockReason: null,
    }),
    "Remote state may be stale. The last fetch failed.",
  );
});

test("fetch title passes through the pull reason on a fresh poll", () => {
  assert.equal(
    fetchTitleForSyncStatus({
      fetchFailed: false,
      fetchError: null,
      pullBlockReason: "Local branch is up to date.",
    }),
    "Local branch is up to date.",
  );
});

test("fetch title defaults when there is no status yet", () => {
  assert.equal(fetchTitleForSyncStatus(null), "Check for remote changes");
  assert.equal(fetchTitleForSyncStatus(undefined), "Check for remote changes");
});
