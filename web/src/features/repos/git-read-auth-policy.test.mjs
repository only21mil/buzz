import assert from "node:assert/strict";
import test from "node:test";

import { gitReadAuthOptions } from "./git-read-auth-policy.ts";

test("git reads require the browser member identity", () => {
  assert.deepEqual(gitReadAuthOptions, { requireNip07: true });
});
