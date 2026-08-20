import assert from "node:assert/strict";
import test from "node:test";

import {
  clearTimeoutState,
  getTimeoutSnapshot,
  recordTimeoutFromRejection,
} from "./timeoutStore.ts";

test.beforeEach(() => clearTimeoutState());
test.afterEach(() => clearTimeoutState());

test("clearing a timeout removes an unknown-expiry process-wide block", () => {
  assert.equal(
    recordTimeoutFromRejection("restricted: you are timed out until soon"),
    true,
  );
  assert.deepEqual(getTimeoutSnapshot(), {
    active: true,
    expiresAtMs: null,
  });

  clearTimeoutState();

  assert.deepEqual(getTimeoutSnapshot(), {
    active: false,
    expiresAtMs: null,
  });
});
