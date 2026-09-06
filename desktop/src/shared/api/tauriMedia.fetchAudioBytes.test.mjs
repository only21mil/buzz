import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { test } from "node:test";
import ts from "typescript";

const source = readFileSync(
  new URL("./tauriMedia.ts", import.meta.url),
  "utf8",
);
const start = source.indexOf("export async function fetchAudioBytes(");
const end = source.indexOf("/** Read plain text", start);
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function harness({ cancelGate, abortOnInvoke } = {}) {
  const calls = [];
  const nativeTokens = new Map();
  const native = deferred();
  const exports = {};
  runInNewContext(
    ts.transpileModule(source.slice(start, end), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
      },
    }).outputText,
    {
      exports,
      DOMException,
      crypto,
      Uint8Array,
      invokeTauri: async (command, { requestId }) => {
        calls.push(command);
        if (command === "fetch_audio_bytes") {
          abortOnInvoke?.();
          return native.promise;
        }
        // Mirror synchronous native cancel/release while the fetch command's
        // asynchronous body is still waiting to reach begin_media_fetch.
        if (command === "cancel_media_fetch") {
          if (cancelGate) await cancelGate.promise;
          nativeTokens.set(requestId, true);
        }
        if (command === "release_media_fetch") nativeTokens.delete(requestId);
      },
    },
  );
  return { calls, nativeTokens, native, fetch: exports.fetchAudioBytes };
}

for (const outcome of ["resolve", "reject"]) {
  test(`abort retains native cancellation and scheduler ownership until IPC ${outcome}`, async () => {
    const h = harness();
    const controller = new AbortController();
    let settled = false;
    const pending = h.fetch(
      "https://relay.example/media/audio.ogg",
      controller.signal,
    );
    const checked = assert.rejects(pending, { name: "AbortError" });
    void pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    controller.abort();
    await new Promise(setImmediate);
    assert.equal(settled, false, "scheduler must retain its active slot");
    assert.deepEqual(h.calls, ["fetch_audio_bytes", "cancel_media_fetch"]);
    assert.equal(
      h.nativeTokens.size,
      1,
      "delayed native begin must see cancellation",
    );
    // Native begin observes the cancelled token and completes without HTTP.
    h.nativeTokens.clear();
    if (outcome === "resolve") h.native.resolve(new ArrayBuffer(0));
    else h.native.reject(new Error("native cancellation"));
    await checked;
    assert.equal(h.nativeTokens.size, 0);
    assert.equal(h.calls.at(-1), "release_media_fetch");
  });
}

test("late cancel acknowledgement is released after native completion", async () => {
  const cancelGate = deferred();
  const h = harness({ cancelGate });
  const controller = new AbortController();
  const pending = h.fetch(
    "https://relay.example/media/audio.ogg",
    controller.signal,
  );
  const checked = assert.rejects(pending, { name: "AbortError" });
  controller.abort();
  h.native.resolve(new ArrayBuffer(0));
  await new Promise(setImmediate);
  assert.equal(h.calls.includes("release_media_fetch"), false);
  cancelGate.resolve();
  await checked;
  assert.equal(h.nativeTokens.size, 0);
});

test("native failure releases ownership; already-aborted input invokes nothing", async () => {
  const h = harness();
  const controller = new AbortController();
  const pending = h.fetch(
    "https://relay.example/media/audio.ogg",
    controller.signal,
  );
  h.native.reject(new Error("native failure"));
  await assert.rejects(pending, /native failure/);
  assert.equal(h.calls.at(-1), "release_media_fetch");
  controller.abort();
  const count = h.calls.length;
  await assert.rejects(h.fetch("unused", controller.signal), {
    name: "AbortError",
  });
  assert.equal(h.calls.length, count);
});

test("abort during initial invocation still reaches native cancellation", async () => {
  const controller = new AbortController();
  const h = harness({ abortOnInvoke: () => controller.abort() });
  const pending = h.fetch(
    "https://relay.example/media/audio.ogg",
    controller.signal,
  );
  h.native.resolve(new ArrayBuffer(0));
  await assert.rejects(pending, { name: "AbortError" });
  assert.deepEqual(h.calls, [
    "fetch_audio_bytes",
    "cancel_media_fetch",
    "release_media_fetch",
  ]);
});

test("scheduler keeps all three slots while cancelled native commands have not begun", async () => {
  const { scheduleAudioMediaLoad, getAudioMediaLoadSchedulerSnapshot } =
    await import("../../features/messages/lib/audioMediaLoadScheduler.ts");
  const h = harness();
  const loads = Array.from({ length: 3 }, () =>
    scheduleAudioMediaLoad((signal) =>
      h.fetch("https://relay.example/media/audio.ogg", signal),
    ),
  );
  const cancelled = loads.map((load) =>
    assert.rejects(load.promise, { name: "AbortError" }),
  );
  await new Promise(setImmediate);
  for (const load of loads) load.cancel();
  const next = scheduleAudioMediaLoad((signal) =>
    h.fetch("https://relay.example/media/next.ogg", signal),
  );
  await new Promise(setImmediate);
  assert.deepEqual(getAudioMediaLoadSchedulerSnapshot(), {
    active: 3,
    queued: 1,
  });
  assert.equal(
    h.calls.filter((command) => command === "fetch_audio_bytes").length,
    3,
  );
  h.native.resolve(new ArrayBuffer(0));
  await Promise.all([...cancelled, next.promise]);
  await new Promise(setImmediate);
  assert.deepEqual(getAudioMediaLoadSchedulerSnapshot(), {
    active: 0,
    queued: 0,
  });
  assert.equal(h.nativeTokens.size, 0);
});
