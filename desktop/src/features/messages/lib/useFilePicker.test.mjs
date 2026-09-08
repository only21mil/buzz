import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, before, test } from "node:test";
import { runInNewContext } from "node:vm";
import { JSDOM } from "jsdom";
import * as React from "react";
import ts from "typescript";
import { useFilePicker } from "./useFilePicker.ts";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
before(() =>
  Object.assign(globalThis, {
    document: dom.window.document,
    window: dom.window,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  }),
);
afterEach(async () => (await import("@testing-library/react")).cleanup());
after(() => dom.window.close());
const file = (name = "one.mp4", type = "video/mp4") =>
  new dom.window.File(["x"], name, { type });
const input = () => document.querySelector('input[type="file"]');
function select(node, files) {
  Object.defineProperty(node, "files", { configurable: true, value: files });
  node.dispatchEvent(new dom.window.Event("change"));
}
async function picker() {
  const { act, renderHook } = await import("@testing-library/react");
  const hook = renderHook(useFilePicker);
  const calls = [];
  const open = (options = { multiple: true }) =>
    act(() => hook.result.current(options, (files) => calls.push(files)));
  return { act, hook, calls, open };
}
for (const cancellation of ["cancel", "empty change", "no event"]) {
  test(`${cancellation} then immediate reopen reuses one mounted input`, async () => {
    const s = await picker();
    s.open();
    const node = input();
    assert.ok(node.isConnected);
    assert.equal(node.hidden, true);
    if (cancellation === "cancel")
      node.dispatchEvent(new dom.window.Event("cancel"));
    if (cancellation === "empty change") select(node, []);
    s.open();
    assert.equal(input(), node);
    assert.equal(document.querySelectorAll('input[type="file"]').length, 1);
    const chosen = file();
    select(node, [chosen]);
    assert.deepEqual(s.calls, [[chosen]]);
    assert.equal(node.value, "");
    select(node, [chosen]);
    assert.equal(s.calls.length, 1);
  });
}
test("same-file reselection and multi-select reset the value and reconfigure options", async () => {
  const s = await picker();
  const chosen = file();
  s.open({ accept: "video/*", multiple: false });
  const node = input();
  assert.equal(node.accept, "video/*");
  select(node, [chosen]);
  s.open();
  assert.equal(node.accept, "");
  assert.equal(node.multiple, true);
  assert.equal(node.value, "");
  const second = file("two.mp4");
  select(node, [chosen, second]);
  assert.deepEqual(s.calls, [[chosen], [chosen, second]]);
});
test("active reentry retains the particular open callback and ignores obsolete handlers", async () => {
  const s = await picker();
  const calls = [];
  s.act(() => s.hook.result.current({}, () => calls.push("first")));
  const node = input();
  const oldChange = node.onchange;
  s.act(() => s.hook.result.current({}, () => calls.push("second")));
  select(node, [file()]);
  assert.deepEqual(calls, ["first"]);
  s.act(() => s.hook.result.current({}, () => calls.push("third")));
  oldChange();
  assert.deepEqual(calls, ["first"]);
  select(node, [file()]);
  assert.deepEqual(calls, ["first", "third"]);
});
test("reusing a stable callback does not revive an earlier open handler", async () => {
  const s = await picker();
  let count = 0;
  const onFiles = () => count++;
  s.act(() => s.hook.result.current({}, onFiles));
  const node = input();
  const oldChange = node.onchange;
  node.dispatchEvent(new dom.window.Event("cancel"));
  s.act(() => s.hook.result.current({}, onFiles));
  oldChange();
  assert.equal(count, 0);
  select(node, [file()]);
  assert.equal(count, 1);
});
for (const settled of [false, true]) {
  test(`new ownership epoch retires the old node, settled=${settled}`, async () => {
    const s = await picker();
    const calls = [];
    s.act(() =>
      s.hook.result.current({ ownershipEpoch: 0 }, () => calls.push("old")),
    );
    const oldNode = input();
    const oldChange = oldNode.onchange;
    const oldCancel = oldNode.oncancel;
    if (settled) oldNode.dispatchEvent(new dom.window.Event("cancel"));
    s.act(() =>
      s.hook.result.current(
        { ownershipEpoch: 1, accept: "video/*", multiple: true },
        () => calls.push("fresh"),
      ),
    );
    const freshNode = input();
    assert.notEqual(freshNode, oldNode);
    assert.equal(oldNode.isConnected, false);
    assert.equal(oldNode.onchange, null);
    assert.equal(oldNode.oncancel, null);
    assert.equal(document.querySelectorAll('input[type="file"]').length, 1);
    assert.equal(freshNode.accept, "video/*");
    assert.equal(freshNode.multiple, true);
    select(oldNode, [file()]);
    oldChange();
    oldCancel();
    assert.deepEqual(calls, []);
    select(freshNode, [file()]);
    assert.deepEqual(calls, ["fresh"]);
    s.act(() =>
      s.hook.result.current({ ownershipEpoch: 1 }, () => calls.push("next")),
    );
    assert.equal(input(), freshNode);
    oldChange();
    oldCancel();
    select(freshNode, [file()]);
    assert.deepEqual(calls, ["fresh", "next"]);
  });
}
test("unmount removes the input and revokes retained handlers and open functions", async () => {
  const s = await picker();
  s.open();
  const node = input();
  const oldChange = node.onchange;
  const open = s.hook.result.current;
  s.hook.unmount();
  assert.equal(node.isConnected, false);
  assert.equal(node.onchange, null);
  assert.equal(node.oncancel, null);
  oldChange();
  open({}, () => assert.fail("unmounted callback"));
  assert.equal(input(), null);
  assert.deepEqual(s.calls, []);
});

async function media() {
  const { act, renderHook } = await import("@testing-library/react");
  const uploads = [];
  const source = readFileSync(
    new URL("./useMediaUpload.ts", import.meta.url),
    "utf8",
  );
  const js = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const dependencies = {
    react: React,
    "@/shared/api/tauri": {},
    "@/shared/api/tauriMedia": {
      uploadMediaFile: (selected) =>
        new Promise((resolve) => uploads.push({ selected, resolve })),
    },
    "./videoPosterFrame": { captureVideoPosterFrame: async () => null },
  };
  for (const [, name] of js.matchAll(/require\("([^"]+)"\)/g)) {
    if (!dependencies[name])
      dependencies[name] = await import(
        name.startsWith(".") ? new URL(`${name}.ts`, import.meta.url) : name
      );
  }
  const exports = {};
  runInNewContext(js, {
    exports,
    window,
    document,
    URL,
    AbortController,
    Set,
    Map,
    require: (name) => dependencies[name],
  });
  const hook = renderHook(() =>
    exports.useMediaUpload({ deferUploadsUntilSend: true }),
  );
  return {
    act,
    hook,
    uploads,
    get media() {
      return hook.result.current;
    },
  };
}
test("mounted media picker marks open synchronously and routes multi-select to queued and immediate uploads", async () => {
  const s = await media();
  const before = s.media.getIntentRevision();
  s.act(() => {
    void s.media.handlePaperclip();
    assert.ok(s.media.getIntentRevision() > before);
  });
  const video = file();
  const photo = file("photo.png", "image/png");
  s.act(() => select(input(), [video, photo]));
  assert.equal(s.media.queuedAttachments.length, 1);
  assert.equal(s.media.queuedAttachments[0].file, video);
  assert.equal(s.uploads.length, 1);
  assert.equal(s.uploads[0].selected, photo);
  const descriptor = {
    url: "https://media.example/photo.png",
    sha256: "1234",
    type: "image/png",
    size: 1,
  };
  await s.act(async () => s.uploads[0].resolve(descriptor));
  assert.equal(s.media.pendingImeta[0], descriptor);
});
for (const [boundary, staleFirst] of [
  ["reset", true],
  ["reset", false],
  ["scope restore", true],
  ["scope restore", false],
  ["unmount", true],
]) {
  test(`picker selection after ${boundary} rejects old events, stale first=${staleFirst}`, async () => {
    const s = await media();
    s.act(() => {
      void s.media.handlePaperclip();
    });
    const node = input();
    const staleChange = node.onchange;
    const restored = {
      url: "https://media.example/restored.png",
      sha256: "abcd",
    };
    if (boundary === "unmount") s.hook.unmount();
    else
      s.act(() => {
        s.media.setPendingImeta(boundary === "reset" ? [] : [restored]);
        // A deliberate fresh open must work even if cancellation had no event.
        void s.media.handlePaperclip();
      });
    const deliverStale = () => {
      s.act(() => select(node, [file(), file("photo.png", "image/png")]));
      s.act(() => staleChange());
    };
    if (staleFirst) deliverStale();
    assert.equal(s.uploads.length, 0);
    if (boundary !== "unmount") {
      assert.equal(s.media.queuedAttachments.length, 0);
      assert.equal(s.media.pendingImeta.length, boundary === "reset" ? 0 : 1);
      const freshNode = input();
      const chosen = file();
      const photo = file("fresh.png", "image/png");
      const revision = s.media.getIntentRevision();
      s.act(() => {
        select(freshNode, [chosen, photo]);
        assert.ok(s.media.getIntentRevision() > revision);
      });
      assert.equal(s.media.queuedAttachments.length, 1);
      assert.equal(s.media.queuedAttachments[0].file, chosen);
      assert.equal(s.uploads.length, 1);
      assert.equal(s.uploads[0].selected, photo);
      if (!staleFirst) {
        deliverStale();
        assert.equal(s.media.queuedAttachments.length, 1);
        assert.equal(s.uploads.length, 1);
      }
      assert.notEqual(freshNode, node);
      assert.equal(node.isConnected, false);
      const descriptor = {
        url: "https://media.example/fresh.png",
        sha256: "1234",
        type: "image/png",
        size: 1,
      };
      await s.act(async () => s.uploads[0].resolve(descriptor));
      assert.equal(s.media.pendingImeta.at(-1), descriptor);
      if (boundary === "scope restore")
        assert.equal(s.media.pendingImeta[0], restored);
    }
  });
}
test("a picker upload finishing after reset cannot revive the obsolete attachment", async () => {
  const s = await media();
  s.act(() => {
    void s.media.handlePaperclip();
  });
  s.act(() => select(input(), [file("photo.png", "image/png")]));
  assert.equal(s.uploads.length, 1);
  s.act(() => s.media.setPendingImeta([]));
  await s.act(async () =>
    s.uploads[0].resolve({
      url: "https://media.example/stale.png",
      sha256: "1234",
    }),
  );
  assert.equal(s.media.pendingImeta.length, 0);
  assert.equal(s.media.isUploading, false);
});
