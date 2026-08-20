import assert from "node:assert/strict";
import test from "node:test";

import { createCommunityApplyQueue } from "./communityApplyQueue.ts";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

test("community applies finish in request order", async () => {
  const queue = createCommunityApplyQueue();
  const firstGate = deferred();
  const events = [];

  const first = queue.run(async () => {
    events.push("start:first");
    await firstGate.promise;
    events.push("finish:first");
  });
  const second = queue.run(async () => {
    events.push("start:second");
    events.push("finish:second");
  });

  await Promise.resolve();
  assert.deepEqual(events, ["start:first"]);

  firstGate.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(events, [
    "start:first",
    "finish:first",
    "start:second",
    "finish:second",
  ]);
});

test("a rejected apply does not poison the queue", async () => {
  const queue = createCommunityApplyQueue();
  const failure = new Error("relay unavailable");
  const first = queue.run(async () => {
    throw failure;
  });
  const second = queue.run(async () => "applied");

  await assert.rejects(first, failure);
  assert.equal(await second, "applied");
});

test("a queued stale apply can skip before crossing IPC", async () => {
  const queue = createCommunityApplyQueue();
  const firstGate = deferred();
  let cancelled = false;
  let applyCalls = 0;

  const first = queue.run(async () => {
    await firstGate.promise;
  });
  const stale = queue.run(async () => {
    if (cancelled) return;
    applyCalls += 1;
  });

  cancelled = true;
  firstGate.resolve();
  await Promise.all([first, stale]);
  assert.equal(applyCalls, 0);
});
