import assert from "node:assert/strict";
import test from "node:test";

import {
  releaseObjectUrl,
  releaseObjectUrls,
  waitForVisiblePaint,
} from "./objectUrlLifecycle.ts";

test("object URLs are released exactly once across overlapping owners", () => {
  const revoked = [];
  const released = new Set();
  const revoke = (url) => revoked.push(url);

  releaseObjectUrl("blob:first", released, revoke);
  releaseObjectUrls(
    [
      { previewUrl: "blob:first" },
      { previewUrl: "data:image/png;base64,abc" },
      { previewUrl: "blob:second" },
    ],
    released,
    revoke,
  );
  releaseObjectUrl("blob:second", released, revoke);

  assert.deepEqual(revoked, ["blob:first", "blob:second"]);
});

test("hidden documents do not wait on a suspended animation frame", async () => {
  let requested = false;
  await waitForVisiblePaint("hidden", () => {
    requested = true;
    return 1;
  });
  assert.equal(requested, false);
});

test("visible paint wait is bounded when requestAnimationFrame never fires", async () => {
  const started = Date.now();
  await waitForVisiblePaint("visible", () => 1, 10);
  assert.ok(Date.now() - started < 200);
});
