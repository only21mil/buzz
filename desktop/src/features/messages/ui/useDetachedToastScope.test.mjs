import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { after, afterEach, before, test } from "node:test";
import { JSDOM } from "jsdom";
import * as React from "react";
import ts from "typescript";

const dom = new JSDOM("<!doctype html><html><body></body></html>");
before(() =>
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  }),
);
afterEach(async () => (await import("@testing-library/react")).cleanup());
after(() => dom.window.close());

function load(relativePath, dependencies) {
  const exports = {};
  vm.runInNewContext(
    ts.transpileModule(
      fs.readFileSync(new URL(relativePath, import.meta.url), "utf8"),
      {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
        },
      },
    ).outputText,
    {
      exports,
      console: { warn() {} },
      require(name) {
        assert.ok(name in dependencies, `unexpected dependency ${name}`);
        return dependencies[name];
      },
    },
  );
  return exports;
}

function harness() {
  const scope = load("../lib/detachedToastScope.ts", {
    "@/shared/lib/pubkey": {
      normalizePubkey: (key) => key.trim().toLowerCase(),
    },
  });
  const { useDetachedToastScope } = load("./useDetachedToastScope.ts", {
    react: React,
    "@/features/messages/lib/detachedToastScope": scope,
  });
  const errors = [];
  const pending = [];
  let current;
  const { useDetachedAgentStart } = load("./useDetachedAgentStart.ts", {
    react: React,
    sonner: { toast: { error: (message) => errors.push(message) } },
    "@/features/agents/hooks": {
      useStartManagedAgentMutation: () => ({
        mutateAsync: () =>
          new Promise((resolve, reject) => pending.push({ resolve, reject })),
      }),
    },
    "@/features/communities/useCommunities": {
      useCommunities: () => ({ activeCommunity: { relayUrl: current.relay } }),
    },
    "@/shared/api/hooks": {
      useIdentityQuery: () => ({ data: { pubkey: current.signer } }),
    },
    "@/features/messages/lib/detachedToastScope": scope,
    "@/shared/lib/pubkey": {
      normalizePubkey: (key) => key.trim().toLowerCase(),
    },
    "./useMentionSendFlow.helpers": {
      getErrorMessage: (error) => error.message,
    },
  });
  let start;
  function Shell(props) {
    current = props;
    useDetachedToastScope(props.relay, props.signer);
    start = useDetachedAgentStart();
    return null;
  }
  return {
    Shell,
    scope,
    errors,
    pending,
    start: () => start({ pubkey: "b".repeat(64), name: "Fizz" }),
  };
}
const A = { relay: "wss://Relay.A", signer: "a".repeat(64) };

test("same-scope startup failure warns after shell mount and a later start can succeed", async () => {
  const { act, render } = await import("@testing-library/react");
  const h = harness();
  render(React.createElement(h.Shell, A));
  assert.equal(h.start(), true);
  await act(async () => h.pending[0].reject(new Error("startup failed")));
  assert.equal(h.errors.length, 1);
  assert.match(h.errors[0], /your message was sent.*startup failed/);
  assert.equal(h.start(), true);
  await act(async () => h.pending[1].resolve({}));
  assert.equal(h.errors.length, 1);
});

for (const [name, next] of [
  ["community", { ...A, relay: "wss://Relay.B" }],
  ["identity", { ...A, signer: "c".repeat(64) }],
  ["unresolved identity", { ...A, signer: undefined }],
]) {
  test(`late startup failure is suppressed after ${name} changes`, async () => {
    const { act, render } = await import("@testing-library/react");
    const h = harness();
    const view = render(React.createElement(h.Shell, A));
    h.start();
    view.rerender(React.createElement(h.Shell, next));
    await act(async () =>
      h.pending[0].reject(new Error("private old failure")),
    );
    assert.deepEqual(h.errors, []);
  });
}

test("shell unmount clears immediately and returning to the original scope permits its late warning", async () => {
  const { act, render } = await import("@testing-library/react");
  const h = harness();
  const first = render(React.createElement(h.Shell, A));
  h.start();
  first.unmount();
  assert.equal(h.scope.matchesDetachedToastScope(A.relay, A.signer), false);
  render(React.createElement(h.Shell, A));
  await act(async () => h.pending[0].reject(new Error("original failure")));
  assert.equal(h.errors.length, 1);
});

test("old cleanup cannot erase a newer registration and explicit reset fails closed", () => {
  const { scope } = harness();
  const cleanup = scope.setDetachedToastScope({
    relayUrl: A.relay,
    signerPubkey: A.signer,
  });
  scope.setDetachedToastScope({
    relayUrl: A.relay,
    signerPubkey: "c".repeat(64),
  });
  cleanup();
  assert.equal(scope.matchesDetachedToastScope(A.relay, "c".repeat(64)), true);
  assert.equal(
    scope.matchesDetachedToastScope(A.relay.toLowerCase(), "c".repeat(64)),
    false,
  );
  scope.resetDetachedToastScope();
  assert.equal(scope.matchesDetachedToastScope(A.relay, "c".repeat(64)), false);
});

test("late startup failure after shell unmount cannot surface a warning", async () => {
  const { act, render } = await import("@testing-library/react");
  const h = harness();
  const view = render(React.createElement(h.Shell, A));
  h.start();
  view.unmount();
  await act(async () => h.pending[0].reject(new Error("private old failure")));
  assert.deepEqual(h.errors, []);
});
