import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { JSDOM } from "jsdom";
import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";
import { uploadMediaFile } from "../../../shared/api/tauriMedia.ts";
import { registerMediaCommands } from "../../../platform/web/mediaUpload.ts";
import {
  register,
  resetRegistryForTests,
} from "../../../platform/web/registry.ts";
import { BrowserWorkspace } from "../../../platform/web/workspace.ts";
import { invoke as browserInvoke } from "../../../platform/web/shims/core.ts";
import { useMediaUpload } from "./useMediaUpload.ts";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "https://relay.example/app/",
});
const previousFetch = globalThis.fetch;
const cap = 100 * 1024 * 1024;
const calls = [];
const requests = [];
let native = false;
const secret = generateSecretKey();
let signGate;
let signingStarted;
function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function descriptor(sha256 = "a".repeat(64), size = 3) {
  return {
    url: `https://relay.example/media/${sha256}.png`,
    sha256,
    size,
    type: "image/png",
    uploaded: 1,
  };
}
function file(size = 3, read = async () => Uint8Array.from([1, 2, 3]).buffer) {
  let reads = 0;
  return {
    name: "photo 🐝.png",
    type: "image/png",
    size,
    arrayBuffer() {
      reads++;
      return read();
    },
    get reads() {
      return reads;
    },
  };
}

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1,
    invoke: async (command, body, options) => {
      if (command.startsWith("plugin:event|")) return 1;
      const request = native
        ? Promise.resolve(descriptor())
        : browserInvoke(command, body, options);
      calls.push({ command, body, options, request });
      return request;
    },
  };
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
});
beforeEach(() => {
  native = false;
  globalThis.isTauri = false;
  calls.length = 0;
  requests.length = 0;
  signGate = undefined;
  signingStarted = deferred();
  resetRegistryForTests();
  registerMediaCommands(new BrowserWorkspace());
  register("sign_event", async (body) => {
    signingStarted.resolve();
    if (signGate) await signGate.promise;
    return JSON.stringify(
      finalizeEvent(
        {
          kind: body.kind,
          content: body.content,
          created_at: body.createdAt,
          tags: body.tags,
        },
        secret,
      ),
    );
  });
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init });
    return Response.json(
      descriptor(init.headers.get("X-SHA-256"), init.body.byteLength),
    );
  };
});
afterEach(async () => {
  const { cleanup } = await import("@testing-library/react");
  cleanup();
});
after(() => {
  globalThis.fetch = previousFetch;
  delete globalThis.isTauri;
  dom.window.close();
});

async function start(result, path, selected) {
  const { act } = await import("@testing-library/react");
  await act(async () => {
    if (path === "drop") {
      void result.current.handleDrop({
        preventDefault() {},
        dataTransfer: { files: [selected] },
      });
    } else if (path === "paste") {
      result.current.handlePaste({
        preventDefault() {},
        clipboardData: {
          items: [{ kind: "file", getAsFile: () => selected }],
        },
      });
    } else if (path === "editor paste") {
      void result.current.uploadFile(selected);
    } else {
      await result.current.handlePaperclip();
      const input = document.querySelector('input[type="file"]');
      Object.defineProperty(input, "files", {
        configurable: true,
        value: [selected],
      });
      input.dispatchEvent(new window.Event("change"));
    }
  });
}

for (const path of ["drop", "paste", "editor paste", "deferred paperclip"]) {
  test(`${path} rejects oversized metadata before reading or invoking`, async () => {
    const { renderHook } = await import("@testing-library/react");
    const { result } = renderHook(() =>
      useMediaUpload({ deferUploadsUntilSend: true }),
    );
    const selected = file(cap + 1);
    await start(result, path, selected);
    assert.equal(selected.reads, 0);
    assert.equal(calls.length, 0);
    assert.equal(requests.length, 0);
    assert.equal(result.current.uploadState.status, "error");
    assert.match(result.current.uploadState.message, /Maximum is 100MB/);
    assert.equal(result.current.isUploading, false);
  });
  test(`${path} cancellation during file read cannot invoke later`, async () => {
    const { act, renderHook } = await import("@testing-library/react");
    const { result } = renderHook(() =>
      useMediaUpload({ deferUploadsUntilSend: true }),
    );
    const gate = deferred();
    const selected = file(3, () => gate.promise);
    await start(result, path, selected);
    assert.equal(selected.reads, 1);
    assert.equal(result.current.isUploading, true);
    act(() =>
      result.current.cancelUpload(result.current.uploadingPreviews[0].id),
    );
    await act(async () => {
      gate.resolve(new ArrayBuffer(3));
    });
    assert.equal(calls.length, 0);
    assert.equal(requests.length, 0);
    assert.equal(result.current.isUploading, false);
    assert.deepEqual(result.current.pendingImeta, []);
    assert.notEqual(result.current.uploadState.status, "error");
  });
  test(`${path} normal upload keeps filename, bytes and progress ID`, async () => {
    const { act, renderHook } = await import("@testing-library/react");
    const { result } = renderHook(() =>
      useMediaUpload({ deferUploadsUntilSend: true }),
    );
    const selected = file();
    await start(result, path, selected);
    await act(async () => {
      await calls[0].request;
    });
    assert.equal(selected.reads, 1);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, "upload_media_bytes_raw");
    assert.match(
      atob(calls[0].options.headers["x-buzz-progress-id"]),
      /^composer-upload-\d+$/,
    );
    assert.equal(calls[0].options.signal.aborted, false);
    assert.deepEqual([...requests[0].init.body], [1, 2, 3]);
    assert.equal(result.current.pendingImeta[0].filename, selected.name);
    assert.equal(result.current.isUploading, false);
  });
}

test("composer cancel during PAL signing prevents sending and permits retry", async () => {
  const { act, renderHook } = await import("@testing-library/react");
  const { result } = renderHook(() => useMediaUpload());
  signGate = deferred();
  await start(result, "drop", file());
  await act(async () => {
    await signingStarted.promise;
  });
  const id = result.current.uploadingPreviews[0].id;
  act(() => result.current.cancelUpload(id));
  assert.equal(calls[0].options.signal.aborted, true);
  await act(async () => {
    signGate.resolve();
    await assert.rejects(calls[0].request, { name: "AbortError" });
  });
  assert.equal(requests.length, 0);
  await uploadMediaFile(file(), `composer-upload-${id}`);
  assert.equal(requests.length, 1);
});

test("composer cancellation reaches the active browser request", async () => {
  const { act, renderHook } = await import("@testing-library/react");
  const { result } = renderHook(() => useMediaUpload());
  const sent = deferred();
  let requestSignal;
  globalThis.fetch = (_url, init) =>
    new Promise((_resolve, reject) => {
      requestSignal = init.signal;
      init.signal.addEventListener("abort", () => reject(init.signal.reason), {
        once: true,
      });
      sent.resolve();
    });
  await start(result, "drop", file());
  await act(async () => {
    await sent.promise;
  });
  await act(async () =>
    result.current.cancelUpload(result.current.uploadingPreviews[0].id),
  );
  assert.equal(requestSignal.aborted, true);
  assert.deepEqual(result.current.pendingImeta, []);
  assert.equal(result.current.isUploading, false);
  assert.notEqual(result.current.uploadState.status, "error");
});

for (const nativeMode of [false, true]) {
  test(`${nativeMode ? "native" : "browser"} already-aborted input does not read or invoke`, async () => {
    native = nativeMode;
    globalThis.isTauri = nativeMode;
    const controller = new AbortController();
    controller.abort();
    const selected = file();
    await assert.rejects(
      uploadMediaFile(selected, "aborted", controller.signal),
      /cancelled/,
    );
    assert.equal(selected.reads, 0);
    assert.equal(calls.length, 0);
  });
}

for (const action of ["draft replacement", "unmount"]) {
  test(`${action} cancels a pending composer read`, async () => {
    const { act, renderHook } = await import("@testing-library/react");
    const { result, unmount } = renderHook(() => useMediaUpload());
    const gate = deferred();
    await start(
      result,
      "drop",
      file(3, () => gate.promise),
    );
    act(() => {
      if (action === "unmount") unmount();
      else result.current.setPendingImeta([]);
    });
    await act(async () => {
      gate.resolve(new ArrayBuffer(3));
    });
    assert.equal(calls.length, 0);
  });
}

test("exact browser metadata cap is accepted without a large allocation", async () => {
  const selected = file(cap);
  await uploadMediaFile(selected, "boundary");
  assert.equal(selected.reads, 1);
  assert.equal(requests.length, 1);
});

test("native adapter retains raw IPC and does not impose the browser cap", async () => {
  native = true;
  globalThis.isTauri = true;
  const selected = file(cap + 1);
  await uploadMediaFile(selected, "native", new AbortController().signal);
  assert.equal(selected.reads, 1);
  assert.deepEqual([...calls[0].body], [1, 2, 3]);
  assert.deepEqual(Object.keys(calls[0].options), ["headers"]);
});

test("duplicate progress ID rejection cannot steal another caller's controller", async () => {
  signGate = deferred();
  const owner = new AbortController();
  const duplicate = new AbortController();
  const first = uploadMediaFile(file(), "same-id", owner.signal);
  await signingStarted.promise;
  await assert.rejects(
    uploadMediaFile(file(), "same-id", duplicate.signal),
    /already active/,
  );
  duplicate.abort();
  signGate.resolve();
  await first;
  assert.equal(requests.length, 1);
  assert.equal(requests[0].init.signal.aborted, false);
  owner.abort();
  assert.equal(
    requests[0].init.signal.aborted,
    false,
    "settlement removes caller listener",
  );
});
