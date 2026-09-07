import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

// Mount the real dialog, popover, detail panel and trace. Only relay data is
// supplied locally through React Query; a source-text check cannot catch a
// missing or inert entry point.
test("activation confirmation Back preserves the draft; Keep off and Turn on save their chosen state", async () => {
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
  const { createElement: h } = await import("react");
  const { render, fireEvent, cleanup, waitFor } = await import(
    "@testing-library/react"
  );
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
  const { CommunitiesProvider } = await import(
    "@/features/communities/useCommunities"
  );
  const { ThemeProvider } = await import("@/shared/theme/ThemeProvider");
  const { WorkflowDialog } = await import("./WorkflowDialog.tsx");
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { gcTime: 0 },
    },
  });
  const { mockIPC, clearMocks } = await import("@tauri-apps/api/mocks");
  const { parse } = await import("yaml");
  const writes = [];
  mockIPC((command, args) => {
    if (command === "create_workflow") {
      writes.push(args);
      return {
        id: "saved",
        revision: "saved-revision",
        name: "Activation",
        owner_pubkey: "a".repeat(64),
        channel_id: "channel",
        definition: parse(args.yamlDefinition),
        status: "active",
        created_at: 1,
        updated_at: 1,
      };
    }
    if (command === "get_current_user_pubkey") return "a".repeat(64);
    return [];
  });
  client.setQueryData(["identity"], { pubkey: "a".repeat(64) });
  const workflow = {
    id: "workflow",
    name: "History fixture",
    channelId: "channel",
    revision: "revision",
    definition: {
      name: "History fixture",
      trigger: { on: "message_posted" },
      steps: [
        {
          id: "pause",
          action: "extract",
          source: "{{trigger.text}}",
          matchers: { name: "(.*)" },
        },
      ],
    },
  };
  const router = createRouter({
    routeTree: createRootRoute(),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const noop = () => {};
  try {
    const view = render(
      h(
        CommunitiesProvider,
        null,
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
                channels: [{ id: "channel", name: "Channel", kind: "public" }],
                initialChannelId: "channel",
                mode: "create",
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
      ),
    );
    const submit = () =>
      fireEvent.click(view.getByTestId("workflow-dialog-primary-action"));
    submit();
    assert.ok(await view.findByTestId("workflow-activation-confirmation"));
    fireEvent.click(view.getByRole("button", { name: "Back" }));
    await waitFor(() =>
      assert.equal(
        view.queryByTestId("workflow-activation-confirmation"),
        null,
      ),
    );
    assert.equal(writes.length, 0);
    assert.match(
      view.getByRole("textbox", { name: "Workflow YAML" }).value,
      /action: extract/,
    );
    submit();
    fireEvent.click(await view.findByRole("button", { name: "Keep off" }));
    await waitFor(() => assert.equal(writes.length, 1));
    assert.equal(parse(writes[0].yamlDefinition).enabled, false);
    submit();
    fireEvent.click(await view.findByRole("button", { name: "Turn on" }));
    await waitFor(() => assert.equal(writes.length, 2));
    assert.notEqual(parse(writes[1].yamlDefinition).enabled, false);
    await waitFor(() => assert.equal(client.isMutating(), 0));
  } finally {
    clearMocks();
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
