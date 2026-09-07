import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

test("editing an unrelated author retains Advanced predicates and requires explicit Basic replacement", async (t) => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "http://localhost",
  });
  const keys = [
    "window",
    "localStorage",
    "self",
    "document",
    "Element",
    "HTMLElement",
    "HTMLInputElement",
    "Node",
    "NodeFilter",
    "MutationObserver",
    "Event",
    "CustomEvent",
    "getComputedStyle",
    "IS_REACT_ACT_ENVIRONMENT",
  ];
  const originals = keys.map((key) =>
    Object.getOwnPropertyDescriptor(globalThis, key),
  );
  for (const key of keys)
    Object.defineProperty(globalThis, key, {
      configurable: true,
      writable: true,
      value:
        key === "IS_REACT_ACT_ENVIRONMENT"
          ? true
          : key === "getComputedStyle"
            ? dom.window.getComputedStyle.bind(dom.window)
            : dom.window[key],
    });
  const { createElement: h, useState } = await import("react");
  const { render, fireEvent, cleanup } = await import("@testing-library/react");
  const { QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  );
  const { CommunitiesProvider } = await import(
    "@/features/communities/useCommunities"
  );
  const { WorkflowTriggerConditions } = await import(
    "./WorkflowTriggerConditions.tsx"
  );
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  client.setQueryData(["identity"], { pubkey: "a".repeat(64) });
  const author = `trigger_author == "${"a".repeat(64)}"`;
  const edits = [];
  function Editor({ initialValue }) {
    const [value, setValue] = useState(initialValue);
    const [conditionDrafts, setConditionDrafts] = useState(null);
    return h(WorkflowTriggerConditions, {
      value,
      conditionDrafts,
      onConditionDraftsChange: setConditionDrafts,
      onChange: (next) => {
        edits.push(next);
        setValue(next);
      },
      triggerType: "message_posted",
    });
  }
  try {
    for (const initialValue of [
      '!str_starts_with(trigger_text, "deploy")',
      '!str_ends_with(trigger_text, "deploy")',
      'trigger_text == " deploy "',
      'trigger_text == ""',
      'str_contains(trigger_text, " ")',
    ]) {
      await t.test(initialValue, () => {
        edits.length = 0;
        const view = render(
          h(
            CommunitiesProvider,
            null,
            h(QueryClientProvider, { client }, h(Editor, { initialValue })),
          ),
        );
        try {
          const input = view.getByRole("textbox", {
            name: "Advanced expression",
          });
          assert.equal(input.value, initialValue);
          assert.equal(
            view
              .getByRole("tab", { name: "Advanced" })
              .getAttribute("aria-selected"),
            "true",
          );
          // An author edit in the actual controlled editor must preserve the
          // original text predicate, including its empty or spaced literal.
          const expected = `${initialValue} && ${author}`;
          fireEvent.change(input, { target: { value: expected } });
          assert.deepEqual(edits, [expected]);
          assert.equal(input.value, expected);
          fireEvent.mouseDown(view.getByRole("tab", { name: "Basic" }), {
            button: 0,
            ctrlKey: false,
          });
          assert.ok(
            view.getByRole("button", { name: "Replace with basic filters" }),
          );
          assert.equal(
            view.queryByRole("button", { name: /Author Any/ }),
            null,
          );
          assert.deepEqual(edits, [expected]);
          fireEvent.mouseDown(view.getByRole("tab", { name: "Advanced" }), {
            button: 0,
            ctrlKey: false,
          });
          assert.equal(
            view.getByRole("textbox", { name: "Advanced expression" }).value,
            expected,
          );
        } finally {
          view.unmount();
        }
      });
    }
  } finally {
    cleanup();
    client.clear();
    // Radix restores focus in a deferred task when its portals unmount.
    await new Promise((resolve) => setTimeout(resolve, 20));
    dom.window.close();
    keys.forEach((key, index) => {
      if (originals[index])
        Object.defineProperty(globalThis, key, originals[index]);
      else delete globalThis[key];
    });
  }
});
