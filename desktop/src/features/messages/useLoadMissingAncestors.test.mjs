import assert from "node:assert/strict";
import test from "node:test";

import { createMissingAncestorScheduler } from "./useLoadMissingAncestors.ts";

function createFakeClock() {
  let currentTime = 0;
  let nextTimerId = 1;
  const timers = new Map();

  const runDueTimers = () => {
    while (true) {
      const next = [...timers.entries()]
        .filter(([, timer]) => timer.dueAt <= currentTime)
        .sort((left, right) => left[1].dueAt - right[1].dueAt)[0];
      if (!next) return;
      timers.delete(next[0]);
      next[1].callback();
    }
  };

  return {
    advance(delayMs) {
      currentTime += delayMs;
      runDueTimers();
    },
    clearTimer(timerId) {
      timers.delete(timerId);
    },
    now() {
      return currentTime;
    },
    setTimer(callback, delayMs) {
      const timerId = nextTimerId;
      nextTimerId += 1;
      timers.set(timerId, {
        callback,
        dueAt: currentTime + delayMs,
      });
      return timerId;
    },
  };
}

async function flushUntil(predicate, message) {
  for (let attempt = 0; attempt < 10_000; attempt += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  assert.fail(message);
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

test("missing ancestor scheduling bounds concurrency and retains 1,000 failures through cooldown", async () => {
  const clock = createFakeClock();
  const eventIds = Array.from(
    { length: 1_000 },
    (_, index) => `event-${index}`,
  );
  const callsById = new Map();
  let activeRequests = 0;
  let peakActiveRequests = 0;
  let totalCalls = 0;

  const scheduler = createMissingAncestorScheduler({
    clearTimer: clock.clearTimer,
    load: async (eventId) => {
      totalCalls += 1;
      callsById.set(eventId, (callsById.get(eventId) ?? 0) + 1);
      activeRequests += 1;
      peakActiveRequests = Math.max(peakActiveRequests, activeRequests);
      await Promise.resolve();
      activeRequests -= 1;
      throw new Error("permanently missing");
    },
    maxConcurrency: 8,
    now: clock.now,
    onError: () => {},
    onLoaded: () => assert.fail("permanently missing ancestor resolved"),
    retryBaseDelayMs: 5_000,
    retryMaxDelayMs: 60_000,
    setTimer: clock.setTimer,
  });

  scheduler.enqueue(eventIds);
  for (let update = 0; update < 5; update += 1) {
    scheduler.enqueue(eventIds);
  }
  assert.deepEqual(scheduler.snapshot(), {
    coolingDown: 0,
    inFlight: 8,
    queued: 992,
  });

  await flushUntil(
    () => totalCalls === 1_000 && scheduler.snapshot().inFlight === 0,
    "initial ancestor queue did not drain",
  );
  assert.equal(peakActiveRequests, 8);
  assert.equal(callsById.size, 1_000);
  assert.ok([...callsById.values()].every((count) => count === 1));
  assert.deepEqual(scheduler.snapshot(), {
    coolingDown: 1_000,
    inFlight: 0,
    queued: 0,
  });

  for (let update = 0; update < 5; update += 1) {
    scheduler.enqueue(eventIds);
  }
  await Promise.resolve();
  assert.equal(totalCalls, 1_000, "render updates bypassed the cooldown");

  clock.advance(4_999);
  await Promise.resolve();
  assert.equal(totalCalls, 1_000);
  clock.advance(1);
  await flushUntil(
    () => totalCalls === 2_000 && scheduler.snapshot().inFlight === 0,
    "cooled-down ancestors were not retried",
  );
  assert.equal(peakActiveRequests, 8);
  assert.ok([...callsById.values()].every((count) => count === 2));

  for (let update = 0; update < 5; update += 1) {
    scheduler.enqueue(eventIds);
  }
  await Promise.resolve();
  assert.equal(totalCalls, 2_000, "an ID retried twice in one cooldown");
  scheduler.dispose();
});

test("disposing a scheduler drops queued work and ignores in-flight results", async () => {
  const firstRequest = deferred();
  let loaded = false;
  let calls = 0;
  const scheduler = createMissingAncestorScheduler({
    load: () => {
      calls += 1;
      return firstRequest.promise;
    },
    maxConcurrency: 1,
    onLoaded: () => {
      loaded = true;
    },
  });

  scheduler.enqueue(["in-flight", "queued"]);
  assert.equal(calls, 1);
  scheduler.dispose();
  firstRequest.resolve({ id: "in-flight" });
  await flushUntil(
    () => scheduler.snapshot().inFlight === 0,
    "disposed request did not settle",
  );

  assert.equal(calls, 1);
  assert.equal(loaded, false);
  assert.deepEqual(scheduler.snapshot(), {
    coolingDown: 0,
    inFlight: 0,
    queued: 0,
  });
});

test("an ancestor that becomes known while loading is not merged or retried", async () => {
  const request = deferred();
  let errors = 0;
  let loaded = 0;
  const scheduler = createMissingAncestorScheduler({
    load: () => request.promise,
    onError: () => {
      errors += 1;
    },
    onLoaded: () => {
      loaded += 1;
    },
  });

  scheduler.enqueue(["already-arrived"]);
  scheduler.forgetKnown(["already-arrived"]);
  request.resolve({ id: "already-arrived" });
  await flushUntil(
    () => scheduler.snapshot().inFlight === 0,
    "known request did not settle",
  );

  assert.equal(loaded, 0);
  assert.equal(errors, 0);
  assert.deepEqual(scheduler.snapshot(), {
    coolingDown: 0,
    inFlight: 0,
    queued: 0,
  });
  scheduler.dispose();
});
