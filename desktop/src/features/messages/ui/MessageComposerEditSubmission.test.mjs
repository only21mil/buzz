import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { JSDOM } from "jsdom";
import ts from "typescript";
import * as scopes from "../../../shared/api/publicationScope.ts";
import { useEditSubmissionOwnership } from "./useEditSubmissionOwnership.ts";
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
function deferred() {
  let resolve;
  const promise = new Promise((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
let serial = 0;
async function setup(stage, { rejectRecipients = false } = {}) {
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
        capture: useEditSubmissionOwnership(
          id,
          draft.getComposerRevision,
          undefined,
          undefined,
          draft.runComposerUpdate,
        ),
      };
    },
    { initialProps: { id: target.current.id, draftKey: key } },
  );
  lifecycle = hook.result.current;
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
      current: async (...args) => calls.push(["save", ...args]),
    },
    isEditSubmissionLocked: false,
    voiceNote: { statusRef: { current: "idle" } },
    mentions,
    customEmoji: [],
    ownerPubkeyRef: { current: "author" },
    media: {
      pendingImetaRef: { current: [] },
      queuedAttachmentsRef: { current: [] },
      setPendingImeta: noop,
      clearQueuedAttachments: noop,
      restoreQueuedAttachments: noop,
      setUploadState: (state) => calls.push(["error", state]),
    },
    spoileredAttachmentUrls: new Set(),
    extractMentionPubkeysRef: { current: () => [] },
    setDeferredEditPending: noop,
    submitMessageEdit: helperExports.submitMessageEdit,
    setComposerContent: setContent,
    richText: {
      clearContent: () => {
        calls.push(["clear"]);
        setContent("");
      },
      setContent,
    },
    setSpoileredAttachmentUrls: noop,
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

for (const stage of ["native", "bindings", "recipients"]) {
  for (const change of [
    "replace",
    "cancel",
    "revision",
    "empty",
    "aba",
    "visit",
  ]) {
    test(`${change} during ${stage} revokes the old edit and preserves the current composer`, async () => {
      const s = await setup(stage);
      const pending = s.submit();
      await s.entered.promise;
      if (change === "aba") s.change("message-B", "intermediate B");
      const id =
        change === "cancel"
          ? null
          : change === "replace"
            ? "message-B"
            : "message-A";
      const text = change === "empty" ? "" : "new authored text";
      s.change(id, text, change === "visit" ? `${s.key}-new-visit` : s.key);
      s.gate.resolve();
      await pending;
      assert.equal(s.calls.filter(([name]) => name === "save").length, 0);
      assert.equal(s.getContent(), text);
      assert.equal(s.calls.filter(([name]) => name === "error").length, 0);
      assert.equal(
        s.calls.filter(([name]) => name === "clear").length,
        stage === "recipients" ? 1 : 0,
      );
    });
  }
}

test("ordinary save survives same-target rerenders and its own optimistic clear", async () => {
  const s = await setup("native");
  const pending = s.submit();
  await s.entered.promise;
  s.act(() => s.hook.rerender({ id: "message-A", draftKey: s.key }));
  scopes.setPublicationScope("author", "wss://relay.example");
  s.gate.resolve();
  await pending;
  assert.deepEqual(s.calls, [
    ["clear"],
    [
      "save",
      "edited A text",
      undefined,
      [],
      "message-A",
      scopes.capturePublicationScope(),
    ],
  ]);
  assert.equal(s.getContent(), "");
});

test("unmount during native preparation revokes the old edit", async () => {
  const s = await setup("native");
  const pending = s.submit();
  await s.entered.promise;
  s.hook.unmount();
  s.gate.resolve();
  await pending;
  assert.deepEqual(s.calls, []);
});

for (const replaced of [false, true]) {
  test(`failed recipient validation restores only the owned draft (replaced: ${replaced})`, async () => {
    const s = await setup("recipients", { rejectRecipients: true });
    const pending = s.submit();
    await s.entered.promise;
    if (replaced) s.change("message-B", "new B text");
    s.gate.resolve();
    await pending;
    assert.equal(s.getContent(), replaced ? "new B text" : "edited A text");
    assert.equal(s.calls.filter(([name]) => name === "save").length, 0);
    assert.equal(
      s.calls.filter(([name]) => name === "error").length,
      replaced ? 0 : 1,
    );
  });
}

for (const sequence of [
  ["message-B", "message-A"],
  [null, "message-A"],
]) {
  test(`edit visit ${sequence.join(" → ")} cannot revive a submission even without an authored update`, async () => {
    const s = await setup("native");
    const pending = s.submit();
    await s.entered.promise;
    for (const id of sequence)
      s.act(() => s.hook.rerender({ id, draftKey: s.key }));
    s.gate.resolve();
    await pending;
    assert.deepEqual(s.calls, []);
  });
}
