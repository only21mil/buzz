import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { JSDOM } from "jsdom";
import ts from "typescript";
import * as scopes from "../../../shared/api/publicationScope.ts";
import * as React from "react";
import { useDraftPersistLifecycle } from "./useDraftPersistSnapshot.ts";

// Execute the real composer callback, edit helper, and ownership/lifecycle hooks.
// Only native preparation, recipient lookup, editor UI, and save are controlled.
const sourceRoot = process.env.EDIT_SUBMISSION_SOURCE_ROOT
  ? pathToFileURL(`${process.env.EDIT_SUBMISSION_SOURCE_ROOT}/`)
  : new URL("./", import.meta.url);
const source = readFileSync(new URL("MessageComposer.tsx", sourceRoot), "utf8");
const parsed = ts.createSourceFile(
  "MessageComposer.tsx",
  source,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.TSX,
);
let callback;
function visit(node) {
  if (
    ts.isVariableDeclaration(node) &&
    node.name.getText(parsed) === "submitMessage"
  ) {
    callback = node.initializer.arguments[0].getText(parsed);
  }
  ts.forEachChild(node, visit);
}
visit(parsed);
assert.ok(callback);
const compile = (source) =>
  ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.ReactJSX,
    },
  }).outputText;
const helper = compile(
  readFileSync(new URL("submitMessageEdit.ts", sourceRoot), "utf8"),
);
const modules = {};
for (const [, key] of helper.matchAll(/require\("([^"]+)"\)/g)) {
  modules[key] = await import(key);
}
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
const noop = () => {};
async function loadHook(filename, overrides = {}) {
  const js = compile(readFileSync(new URL(filename, sourceRoot), "utf8"));
  const dependencies = { react: React, ...overrides };
  for (const [, name] of js.matchAll(/require\("([^"]+)"\)/g)) {
    if (!(name in dependencies)) {
      dependencies[name] = await import(
        name.startsWith(".")
          ? new URL(`${name}.ts`, new URL(filename, import.meta.url))
          : name
      );
    }
  }
  const exports = {};
  runInNewContext(js, {
    exports,
    window,
    document,
    URL,
    Set,
    Map,
    require: (name) => dependencies[name],
  });
  return exports;
}
function deferred() {
  let resolve;
  const promise = new Promise((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
let serial = 0;
async function setup(
  stage,
  { rejectRecipients = false, rejectSave = false, initial = "none" } = {},
) {
  const { act, renderHook } = await import("@testing-library/react");
  scopes.setPublicationScope("author", "wss://relay.example", true);
  const gate = deferred();
  const entered = deferred();
  const wait = async (name) => {
    if (name === stage) {
      entered.resolve();
      await gate.promise;
    }
  };
  const calls = [];
  const uploadGate = deferred();
  const uploadEntered = deferred();
  const descriptor = {
    url: "https://media.example/new.png",
    sha256: "1234",
    type: "image/png",
    size: 1,
    filename: "new.png",
  };
  const upload = async () => {
    uploadEntered.resolve();
    await uploadGate.promise;
    return descriptor;
  };
  const { useMediaUpload } = await loadHook("../lib/useMediaUpload.ts", {
    "@/shared/api/tauri": {
      uploadMediaBytes: upload,
      pickAndUploadMedia: async () => [await upload()],
    },
    "@/shared/api/tauriMedia": { uploadMediaFile: upload },
    "./videoPosterFrame": { captureVideoPosterFrame: async () => null },
  });
  const { useEditSubmissionOwnership } = await loadHook(
    "useEditSubmissionOwnership.ts",
  );
  const { useComposerAttachmentSpoilers } = await loadHook(
    "useComposerAttachmentSpoilers.ts",
  );
  const { useComposerVoiceNote } = await loadHook("useComposerVoiceNote.tsx", {
    "@tauri-apps/api/core": { isTauri: () => true },
    "./VoiceNoteRecorder": { VoiceNoteRecorder: noop },
    "@/features/messages/lib/useVoiceNoteRecorder": {
      useVoiceNoteRecorder: () => ({
        status: "idle",
        cancel: noop,
        start: noop,
      }),
    },
  });
  const background = [];
  const media = new Proxy(
    {},
    { get: (_, name) => hook.result.current.media[name] },
  );
  const spoilers = new Proxy(
    {},
    { get: (_, name) => hook.result.current.spoilers[name] },
  );
  const target = {
    current: { id: "message-A", body: "original A", mentionRefs: [] },
  };
  let content = "edited A text";
  let lifecycle;
  const setContent = (text) => {
    content = text;
    lifecycle?.trackAuthoredContent(text);
  };
  const key = `edit-test-${++serial}`;
  const hook = renderHook(
    ({ id, draftKey }) => {
      const media = useMediaUpload({ deferUploadsUntilSend: true });
      const spoilers = useComposerAttachmentSpoilers(media);
      const voice = useComposerVoiceNote({
        draftKey,
        editTargetId: id,
        media,
        setEmojiPickerOpen: noop,
        setFormattingOpen: noop,
      });
      const draft = useDraftPersistLifecycle({
        effectiveDraftKey: draftKey,
        channelId: "channel",
        loadDraft: noop,
        persistDraft: noop,
        getMentionRefs: () => [],
        restoreMentionRefs: noop,
        livePendingImeta: [],
        setPendingImeta: noop,
        setContent,
        clearContent: noop,
        setSpoileredAttachmentUrls: noop,
        spoileredAttachmentUrlsRef: { current: new Set() },
        syncComposerContentFromEditor: () => content,
      });
      return {
        ...draft,
        voice,
        media,
        spoilers,
        capture: useEditSubmissionOwnership(
          id,
          draft.getComposerRevision,
          media.getIntentRevision,
          spoilers.getSpoilerRevision,
          draft.runComposerUpdate,
        ),
      };
    },
    { initialProps: { id: target.current.id, draftKey: key } },
  );
  lifecycle = hook.result.current;
  await act(async () => {
    if (initial === "uploaded")
      media.setPendingImeta([
        { ...descriptor, url: "https://media.example/old.png" },
      ]);
    if (initial === "queued")
      await media.uploadFile(
        new File(["video"], "old.mp4", { type: "video/mp4" }),
      );
  });
  const preparePublicationScope = async (scope) => {
    await wait("native");
    return scope;
  };
  const helperExports = {};
  runInNewContext(helper, {
    exports: helperExports,
    Set,
    Error,
    require: (key) =>
      key === "@/shared/api/preparePublicationScope"
        ? { preparePublicationScope }
        : key === "@/features/messages/lib/backgroundMediaUploadStore"
          ? {
              enqueueBackgroundMediaUpload: (job) => {
                background.push(job);
                calls.push(["enqueue"]);
              },
            }
          : modules[key],
  });
  const mentions = {
    settlePendingMentionBindings: async () => wait("bindings"),
    getDraftMentionRefs: () => [],
    restoreDraftMentionRefs: noop,
    clearMentions: noop,
    revalidateMentionPubkeys: async (keys) => {
      await wait("recipients");
      if (rejectRecipients) {
        throw new modules[
          "@/features/messages/lib/agentMentionRevalidation"
        ].AgentMentionAuthorizationError();
      }
      return keys;
    },
  };
  const exports = {};
  runInNewContext(compile(`exports.submit = ${callback};`), {
    exports,
    Set,
    ...scopes,
    preparePublicationScope,
    captureEditSubmission: () => hook.result.current.capture(),
    syncComposerContentFromEditor: () => content,
    runComposerUpdate: (...args) => lifecycle.runComposerUpdate(...args),
    editTargetRef: target,
    onEditSaveRef: {
      current: async (...args) => {
        calls.push(["save", ...args]);
        await wait("save");
        if (rejectSave)
          throw new modules[
            "@/features/messages/lib/agentMentionRevalidation"
          ].AgentMentionAuthorizationError();
      },
    },
    isEditSubmissionLocked: false,
    voiceNote: { statusRef: { current: "idle" } },
    mentions,
    customEmoji: [],
    ownerPubkeyRef: { current: "author" },
    media,
    get spoileredAttachmentUrls() {
      return spoilers.spoileredAttachmentUrls;
    },
    extractMentionPubkeysRef: { current: () => [] },
    setDeferredEditPending: (value) => calls.push(["deferred", value]),
    submitMessageEdit: helperExports.submitMessageEdit,
    setComposerContent: setContent,
    richText: {
      clearContent: () => {
        calls.push(["clear"]);
        setContent("");
      },
      setContent,
    },
    setSpoileredAttachmentUrls: (...args) =>
      spoilers.setSpoileredAttachmentUrls(...args),
    channelLinks: { clearChannels: noop },
    emojiAutocomplete: { clearEmojis: noop },
    setIsEmojiPickerOpen: noop,
    canRestoreEditDraftRef: { current: true },
  });
  const change = (id, text, draftKey = key) =>
    act(() => {
      target.current = id
        ? { id, body: `original ${id}`, mentionRefs: [] }
        : null;
      hook.rerender({ id, draftKey });
      lifecycle = hook.result.current;
      setContent(text);
    });
  return {
    ...exports,
    media,
    spoilers,
    background,
    uploadGate,
    uploadEntered,
    descriptor,
    gate,
    entered,
    calls,
    change,
    hook,
    act,
    getContent: () => content,
    key,
  };
}

const oldUrl = "https://media.example/old.png";
const queueVideo = (s) =>
  s.media.uploadFile(new File(["video"], "new.mp4", { type: "video/mp4" }));
const mutations = {
  add: { initial: "none", change: queueVideo },
  remove: {
    initial: "uploaded",
    change: (s) => s.spoilers.handleRemoveAttachment(oldUrl),
  },
  replace: {
    initial: "uploaded",
    change: (s) => s.media.setPendingImeta([s.descriptor]),
  },
  spoiler: {
    initial: "uploaded",
    change: (s) => s.spoilers.handleToggleAttachmentSpoiler(oldUrl),
  },
  queued_remove: {
    initial: "queued",
    change: (s) =>
      s.media.removeQueuedAttachment(s.media.queuedAttachments[0].id),
  },
  queued_spoiler: {
    initial: "queued",
    change: (s) =>
      s.media.toggleQueuedAttachmentSpoiler(s.media.queuedAttachments[0].id),
  },
  media_aba: {
    initial: "none",
    change: async (s) => {
      await queueVideo(s);
      s.media.clearQueuedAttachments();
    },
  },
  spoiler_aba: {
    initial: "uploaded",
    change: (s) => {
      s.spoilers.handleToggleAttachmentSpoiler(oldUrl);
      s.spoilers.handleToggleAttachmentSpoiler(oldUrl);
    },
  },
};
const snapshot = (s) => ({
  pending: s.media.pendingImeta,
  queued: s.media.queuedAttachments,
  spoilers: [...s.spoilers.spoileredAttachmentUrls],
  content: s.getContent(),
});
async function start(s) {
  let pending;
  await s.act(async () => {
    pending = s.submit();
    await s.entered.promise;
  });
  return { pending };
}
async function release(s, pending) {
  await s.act(async () => {
    s.gate.resolve();
    await pending;
  });
}
for (const stage of ["native", "bindings"]) {
  for (const [name, mutation] of Object.entries(mutations)) {
    test(`${name} during ${stage} preserves newer media and revokes save`, async () => {
      const s = await setup(stage, mutation);
      const { pending } = await start(s);
      const revision = s.hook.result.current.getComposerRevision();
      await s.act(async () => mutation.change(s));
      assert.equal(
        s.hook.result.current.getComposerRevision(),
        revision,
        "media-only authorship has no text revision",
      );
      const expected = snapshot(s);
      await release(s, pending);
      assert.deepEqual(snapshot(s), expected);
      assert.deepEqual(s.calls, []);
    });
  }
}
for (const stage of ["native", "bindings", "recipients"]) {
  for (const name of stage === "recipients"
    ? ["upload"]
    : ["upload", "replacement"]) {
    test(`${name} start during ${stage} revokes before its descriptor exists`, async () => {
      const s = await setup(stage, {
        initial: name === "replacement" ? "uploaded" : "none",
      });
      const { pending } = await start(s);
      let uploading;
      await s.act(async () => {
        uploading =
          name === "replacement"
            ? s.spoilers.handleAttachmentEditSave(oldUrl, new Uint8Array([1]))
            : s.media.uploadFile(
                new File(["image"], "new.png", { type: "image/png" }),
              );
        await s.uploadEntered.promise;
      });
      await release(s, pending);
      assert.equal(s.calls.filter(([name]) => name === "save").length, 0);
      await s.act(async () => {
        s.uploadGate.resolve();
        await uploading;
      });
      assert.equal(s.media.pendingImeta[0].url, s.descriptor.url);
    });
  }
}
for (const stage of ["recipients", "save"]) {
  test(`new media during failed ${stage} is never cleared or overwritten by recovery`, async () => {
    const s = await setup(stage, {
      rejectRecipients: stage === "recipients",
      rejectSave: stage === "save",
    });
    const { pending } = await start(s);
    await s.act(async () => queueVideo(s));
    const expected = snapshot(s);
    await release(s, pending);
    assert.deepEqual(snapshot(s), expected);
    assert.equal(
      s.calls.filter(([name]) => name === "save").length,
      stage === "save" ? 1 : 0,
    );
    assert.equal(s.media.uploadState.status, "idle");
  });
}
for (const action of ["complete", "error", "cancel"]) {
  test(`background ${action} cannot save or recover over newer media`, async () => {
    const s = await setup("native", { initial: "queued" });
    const { pending } = await start(s);
    await release(s, pending);
    assert.equal(s.background.length, 1);
    await s.act(async () => queueVideo(s));
    const expected = snapshot(s);
    await s.act(async () => {
      const job = s.background[0];
      if (action === "complete") await job.onComplete([s.descriptor]);
      if (action === "error") job.onError(new Error("upload failed"));
      if (action === "cancel") job.onCancel();
    });
    assert.deepEqual(snapshot(s), expected);
    assert.equal(s.calls.filter(([name]) => name === "save").length, 0);
    assert.equal(s.media.uploadState.status, "idle");
  });
}
for (const initial of ["none", "uploaded", "queued"]) {
  test(`unchanged ${initial} media saves across native preparation and its own clear`, async () => {
    const s = await setup("native", { initial });
    const { pending } = await start(s);
    s.act(() => s.hook.rerender({ id: "message-A", draftKey: s.key }));
    scopes.setPublicationScope("author", "wss://relay.example");
    await release(s, pending);
    if (initial === "queued")
      await s.act(async () => s.background[0].onComplete([s.descriptor]));
    const saves = s.calls.filter(([name]) => name === "save");
    assert.equal(saves.length, 1);
    assert.equal(saves[0][4], "message-A");
    if (initial !== "none")
      assert.ok(saves[0][2].some((tag) => tag[0] === "imeta"));
    assert.equal(s.getContent(), "");
    assert.equal(s.media.pendingImeta.length, 0);
    assert.equal(s.media.queuedAttachments.length, 0);
  });
}

test("media authorship revokes synchronously before a React render", async () => {
  const s = await setup("native");
  const { pending } = await start(s);
  await s.act(async () => {
    void queueVideo(s);
    s.gate.resolve();
    await pending;
  });
  assert.equal(s.media.queuedAttachments.length, 1);
  assert.deepEqual(s.calls, []);
});
for (const stage of ["native", "bindings"]) {
  test(`reverting an annotated image during ${stage} revokes the old snapshot`, async () => {
    const s = await setup(stage, { initial: "uploaded" });
    await s.act(async () => {
      s.uploadGate.resolve();
      await s.spoilers.handleAttachmentEditSave(oldUrl, new Uint8Array([1]));
    });
    const { pending } = await start(s);
    s.act(() => s.spoilers.handleAttachmentRevert(s.descriptor.url));
    await release(s, pending);
    assert.equal(s.media.pendingImeta[0]?.url, oldUrl);
    assert.deepEqual(s.calls, []);
  });
}
for (const initial of ["uploaded", "queued"]) {
  test(`owned failed save restores ${initial} attachments and spoiler metadata`, async () => {
    const s = await setup("save", { initial, rejectSave: true });
    s.act(() => {
      if (initial === "uploaded")
        s.spoilers.handleToggleAttachmentSpoiler(oldUrl);
      else
        s.media.toggleQueuedAttachmentSpoiler(s.media.queuedAttachments[0].id);
    });
    const expected = snapshot(s);
    let saving;
    await s.act(async () => {
      saving = s.submit();
      if (initial === "queued") {
        await saving;
        saving = s.background[0].onComplete([s.descriptor]);
      }
      await s.entered.promise;
    });
    await release(s, saving);
    assert.equal(s.getContent(), expected.content);
    assert.deepEqual([...s.media.pendingImeta], [...expected.pending]);
    assert.deepEqual(
      [...s.spoilers.spoileredAttachmentUrls],
      expected.spoilers,
    );
    if (initial === "queued") {
      assert.equal(s.media.queuedAttachments[0].file, expected.queued[0].file);
      assert.equal(s.media.queuedAttachments[0].spoilered, true);
    }
    assert.equal(s.media.uploadState.status, "error");
  });
}
for (const change of ["cancel", "aba", "unmount"]) {
  test(`background handoff remains revoked after ${change}`, async () => {
    const s = await setup("native", { initial: "queued" });
    const { pending } = await start(s);
    await release(s, pending);
    if (change === "unmount") s.hook.unmount();
    else if (change === "cancel") s.change(null, "new draft");
    else {
      s.change("message-B", "B draft");
      s.change("message-A", "new A draft");
    }
    await s.act(async () => s.background[0].onComplete([s.descriptor]));
    assert.equal(s.calls.filter(([name]) => name === "save").length, 0);
  });
}

test("starting a voice note during preparation revokes the captured edit", async () => {
  const s = await setup("native");
  const { pending } = await start(s);
  s.act(() => s.hook.result.current.voice.toggle());
  await release(s, pending);
  assert.deepEqual(s.calls, []);
  assert.equal(s.getContent(), "edited A text");
});
for (const replacement of [false, true]) {
  test(`completed media handoff during preparation preserves its descriptor (replacement: ${replacement})`, async () => {
    const s = await setup("native", {
      initial: replacement ? "uploaded" : "none",
    });
    const { pending } = await start(s);
    await s.act(async () => {
      s.uploadGate.resolve();
      if (replacement)
        await s.spoilers.handleAttachmentEditSave(oldUrl, new Uint8Array([1]));
      else
        await s.media.uploadFile(
          new File(["image"], "new.png", { type: "image/png" }),
        );
    });
    await release(s, pending);
    assert.equal(s.media.pendingImeta[0]?.url, s.descriptor.url);
    assert.deepEqual(s.calls, []);
  });
}
