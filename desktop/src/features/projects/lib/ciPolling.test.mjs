import assert from "node:assert/strict";
import test from "node:test";

import { CI_REFETCH_INTERVAL_MS, ciRefetchInterval } from "./ciPolling.ts";

test("CI polling waits for initial discovery and stops for terminal empty results", () => {
  assert.equal(ciRefetchInterval(undefined), CI_REFETCH_INTERVAL_MS);
  assert.equal(ciRefetchInterval({ statuses: [], failures: [] }), false);
  assert.equal(
    ciRefetchInterval({
      statuses: [],
      failures: [{ kind: "conflict", http_status: 409 }],
    }),
    false,
  );
  assert.equal(
    ciRefetchInterval({
      statuses: [],
      failures: [{ kind: "http", http_status: 422 }],
    }),
    false,
  );
});

test("CI polling continues only for active or retryable outcomes", () => {
  assert.equal(
    ciRefetchInterval({
      statuses: [{ state: "pending" }],
      failures: [],
    }),
    CI_REFETCH_INTERVAL_MS,
  );
  for (const failure of [
    { kind: "transport" },
    { kind: "unavailable", http_status: 503 },
    { kind: "http", http_status: 429 },
  ]) {
    assert.equal(
      ciRefetchInterval({ statuses: [], failures: [failure] }),
      CI_REFETCH_INTERVAL_MS,
    );
  }
  assert.equal(
    ciRefetchInterval({
      statuses: [{ state: "green" }, { state: "red" }],
      failures: [{ kind: "unparseable" }],
    }),
    false,
  );
});
