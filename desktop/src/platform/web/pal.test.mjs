import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { Channel, invoke } from "./shims/core.ts";
import { emit, listen, once } from "./shims/event.ts";
import {
  CapabilityUnavailableError,
  dispatch,
  getUnregisteredCommandMissCount,
  register,
  resetRegistryForTests,
} from "./registry.ts";

afterEach(() => {
  resetRegistryForTests();
});

test("registry dispatches registered commands and unregisters safely", async () => {
  const unregister = register("sum", (body) => {
    assert.deepEqual(body, { left: 20, right: 22 });
    return 42;
  });

  assert.equal(await dispatch("sum", { left: 20, right: 22 }), 42);
  unregister();

  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await assert.rejects(
      dispatch("sum"),
      (error) =>
        error instanceof CapabilityUnavailableError &&
        error.capability === "sum",
    );
  } finally {
    console.error = originalConsoleError;
  }
  assert.equal(getUnregisteredCommandMissCount(), 1);
});

test("core invoke preserves raw request and response bodies", async () => {
  const request = new Uint8Array([0, 1, 127, 255]);
  const response = new Uint8Array([255, 3, 2, 1]).buffer;
  register("raw", (body, options) => {
    assert.strictEqual(body, request);
    assert.deepEqual(options, { headers: { "x-test": "raw" } });
    return response;
  });

  assert.strictEqual(
    await invoke("raw", request, { headers: { "x-test": "raw" } }),
    response,
  );
});

test("Channel exposes the id and replaceable onmessage duck type", () => {
  const received = [];
  const channel = new Channel((message) => received.push(`first:${message}`));

  assert.equal(typeof channel.id, "number");
  channel.onmessage("one");
  channel.onmessage = (message) => received.push(`second:${message}`);
  channel.onmessage("two");

  assert.deepEqual(received, ["first:one", "second:two"]);
});

test("event shim supports listen, unlisten, emit, and once", async () => {
  const received = [];
  const unlisten = await listen("pal-event", (event) => {
    received.push(event.payload);
  });
  await emit("pal-event", { count: 1 });
  unlisten();
  await emit("pal-event", { count: 2 });

  let onceCount = 0;
  await once("pal-once", () => {
    onceCount += 1;
  });
  await emit("pal-once");
  await emit("pal-once");

  assert.deepEqual(received, [{ count: 1 }]);
  assert.equal(onceCount, 1);
});
