import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

// Mount the real dialog, popover, detail panel and trace. Only relay data is
// supplied locally through React Query; a source-text check cannot catch a
// missing or inert entry point.
test("clicking Run history opens the existing run panel and approval trace", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "http://localhost",
  });
  const keys = [
    "window",
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
  const { createElement: h } = await import("react");
  const { render, fireEvent, cleanup } = await import("@testing-library/react");
  const { QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  );
  const {
    createRouter,
    createRootRoute,
    createMemoryHistory,
    RouterContextProvider,
  } = await import("@tanstack/react-router");
  dom.window.matchMedia = () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  });
  const { ThemeProvider } = await import("@/shared/theme/ThemeProvider");
  const { WorkflowDialog } = await import("./WorkflowDialog.tsx");
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const workflow = {
    id: "workflow",
    name: "History fixture",
    channelId: "channel",
    revision: "revision",
    definition: {
      name: "History fixture",
      trigger: { on: "manual" },
      steps: [{ id: "pause", action: "wait", seconds: 1 }],
    },
  };
  const run = {
    id: "run",
    workflowId: "workflow",
    status: "completed",
    currentStep: 0,
    executionTrace: [],
    startedAt: 1,
    completedAt: 2,
    errorMessage: null,
    createdAt: 1,
  };
  client.setQueryData(["workflow", "workflow"], workflow);
  client.setQueryData(["workflow-runs", "workflow"], {
    pages: [{ runs: [run], next: { createdAt: 1, id: "run" } }],
    pageParams: [null],
  });
  client.setQueryData(
    ["run-approvals", "workflow", "run"],
    [
      {
        approvalRef: "fixture",
        workflowId: "workflow",
        runId: "run",
        stepId: "gate",
        stepIndex: 0,
        approverSpec: "owner",
        status: "granted",
        approverPubkey: null,
        note: "Approved fixture",
        expiresAt: null,
        createdAt: 1,
      },
    ],
  );
  const router = createRouter({
    routeTree: createRootRoute(),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const noop = () => {};
  try {
    const view = render(
      h(
        ThemeProvider,
        { defaultTheme: "buzz" },
        h(
          QueryClientProvider,
          { client },
          h(
            RouterContextProvider,
            { router },
            h(WorkflowDialog, {
              channels: [],
              mode: "edit",
              onDeleteWorkflow: noop,
              onDuplicateWorkflow: noop,
              onEditWorkflow: noop,
              onEditorPaneChange: noop,
              onOpenChange: noop,
              onTriggerWorkflow: noop,
              open: true,
              pane: null,
              workflow,
            }),
          ),
        ),
      ),
    );
    assert.equal(view.queryByTestId("workflow-detail-panel"), null);
    fireEvent.click(view.getByRole("button", { name: "Run history" }));
    const panel = await view.findByTestId("workflow-detail-panel");
    assert.ok(view.getByTestId("workflow-history-dropdown"));
    assert.match(panel.textContent, /Load (more|older)/i);
    fireEvent.click(panel.querySelector("button[aria-expanded]"));
    assert.match(panel.textContent, /Approval: granted/);
    assert.match(panel.textContent, /Approved fixture/);
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
