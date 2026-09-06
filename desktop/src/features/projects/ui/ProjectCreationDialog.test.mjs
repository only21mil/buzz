import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

test("empty Projects uses the shared creation flow and preserves desktop capability", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "http://localhost",
  });
  const keys = [
    "ResizeObserver",
    "navigator",
    "isTauri",
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
  dom.window.HTMLElement.prototype.scrollIntoView = () => {};
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  dom.window.navigator.mediaDevices = {
    enumerateDevices: async () => [],
    addEventListener() {},
    removeEventListener() {},
  };
  dom.window.matchMedia = () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  });
  const { createElement: h } = await import("react");
  const { render, fireEvent, cleanup, waitFor, act } = await import(
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
  const { CommunitiesProvider } = await import(
    "@/features/communities/useCommunities"
  );
  const { ThemeProvider } = await import("@/shared/theme/ThemeProvider");
  const { TooltipProvider } = await import("@/shared/ui/tooltip");
  const { HuddleProvider } = await import("@/features/huddle/HuddleContext");
  const { ProjectsView } = await import("./ProjectsView.tsx");
  const { ProjectCreationDialog } = await import("./ProjectCreationDialog.tsx");
  const { relayClient } = await import("@/shared/api/relayClient");
  const { beginRelayOriginFetch, resetMediaCaches } = await import(
    "@/shared/lib/mediaUrl"
  );
  const { projectCollectionQueryKey } = await import(
    "../projectCollectionQuery.ts"
  );
  const { mockIPC, mockWindows, clearMocks } = await import(
    "@tauri-apps/api/mocks"
  );
  const pubkey = "a".repeat(64);
  const scope = { pubkey, relayOrigin: "https://relay.example" };
  beginRelayOriginFetch()(scope.relayOrigin);
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: Infinity },
      mutations: { gcTime: 0 },
    },
  });
  client.setQueryData(["identity"], { pubkey });
  client.setQueryData(
    ["channels"],
    [
      {
        id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        name: "General",
        isMember: true,
      },
      { id: "private", name: "Private", isMember: false },
      { id: "dm", name: "Direct", isMember: true, channelType: "dm" },
    ],
  );
  const collectionKey = projectCollectionQueryKey(scope);
  client.setQueryData(collectionKey, []);
  const fetchEvents = relayClient.fetchEvents;
  const publishEvent = relayClient.publishEvent;
  const writes = [];
  let failure = false;
  let holdPublish;
  relayClient.fetchEvents = async () => [];
  relayClient.publishEvent = async (event) => {
    writes.push(event);
    if (holdPublish) await holdPublish;
    if (failure) throw new Error("Fixture relay rejected creation");
  };
  mockIPC((command, args) => {
    if (command === "get_identity") return { pubkey, display_name: "Fixture" };
    if (command === "sign_event")
      return JSON.stringify({
        ...args,
        pubkey,
        created_at: 1,
        id: String(writes.length),
        sig: "fixture",
      });
    if (command === "get_channels") return client.getQueryData(["channels"]);
    return [];
  });
  mockWindows("main");
  dom.window.__TAURI__ = {};
  const router = createRouter({
    routeTree: createRootRoute(),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const wrap = (child) =>
    h(
      CommunitiesProvider,
      null,
      h(
        QueryClientProvider,
        { client },
        h(
          RouterContextProvider,
          { router },
          h(
            ThemeProvider,
            { defaultTheme: "buzz" },
            h(TooltipProvider, null, h(HuddleProvider, null, child)),
          ),
        ),
      ),
    );
  try {
    // Browser entry remains visible but disabled, including a forced-open dialog.
    globalThis.isTauri = false;
    let view = render(wrap(h(ProjectsView)));
    await waitFor(() => assert.ok(view.getByText("No projects yet")));
    assert.equal(
      view.getByRole("button", { name: "Create project" }).disabled,
      true,
    );
    fireEvent.click(view.getByRole("button", { name: "Create project" }));
    assert.equal(view.queryByTestId("create-project-dialog"), null);
    await act(async () => {
      client
        .getQueryCache()
        .find({ queryKey: collectionKey })
        .setState({
          status: "error",
          error: new Error("Fixture refresh failed"),
        });
    });
    await waitFor(() => assert.ok(view.getByText(/Project refresh failed/)));
    assert.ok(view.getByRole("button", { name: "Retry" }));
    await act(async () => {
      client
        .getQueryCache()
        .find({ queryKey: collectionKey })
        .setState({ data: undefined });
    });
    await waitFor(() => assert.ok(view.getByText("Failed to load projects")));
    assert.equal(view.queryByRole("button", { name: "Create project" }), null);
    await act(async () => {
      client.setQueryData(collectionKey, []);
    });
    view.unmount();
    view = render(
      wrap(
        h(ProjectCreationDialog, {
          open: true,
          onOpenChange() {},
          onCreated() {},
        }),
      ),
    );
    assert.equal(view.queryByTestId("create-project-dialog"), null);
    view.unmount();
    globalThis.isTauri = true;
    view = render(wrap(h(ProjectsView)));
    const open = async () => {
      fireEvent.click(view.getByRole("button", { name: "Create project" }));
      await waitFor(() => assert.ok(view.getByTestId("create-project-dialog")));
    };
    await open();
    assert.equal(view.getByTestId("create-project-submit").disabled, true);
    assert.deepEqual(
      [...view.getByTestId("create-project-access-channel").options].map(
        (option) => option.value,
      ),
      ["", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
    );
    fireEvent.change(view.getByTestId("create-project-name"), {
      target: { value: "Discard me" },
    });
    fireEvent.click(view.getByRole("button", { name: "Close" }));
    await waitFor(() =>
      assert.equal(view.queryByTestId("create-project-dialog"), null),
    );
    assert.equal(writes.length, 0);
    await open();
    assert.equal(view.getByTestId("create-project-name").value, "");
    fireEvent.change(view.getByTestId("create-project-name"), {
      target: { value: "First project" },
    });
    failure = true;
    fireEvent.click(view.getByTestId("create-project-submit"));
    await waitFor(() =>
      assert.match(
        view.baseElement.textContent,
        /Fixture relay rejected creation/,
      ),
    );
    assert.equal(
      view.getByTestId("create-project-name").value,
      "First project",
    );
    assert.deepEqual(client.getQueryData(collectionKey), []);
    assert.ok(view.getByText("No projects yet"));
    failure = false;
    let release;
    holdPublish = new Promise((resolve) => {
      release = resolve;
    });
    fireEvent.click(view.getByTestId("create-project-submit"));
    await waitFor(() =>
      assert.equal(
        view.getByTestId("create-project-submit").textContent,
        "Creating...",
      ),
    );
    fireEvent.click(view.getByRole("button", { name: "Close" }));
    assert.ok(view.getByTestId("create-project-dialog"));
    // Return the newly published rows when the existing mutation invalidates.
    relayClient.fetchEvents = async (filter) =>
      writes.filter((event) => filter.kinds.includes(event.kind));
    await act(async () => {
      release();
    });
    await waitFor(() =>
      assert.equal(view.queryByTestId("create-project-dialog"), null),
    );
    await waitFor(() => assert.ok(view.getByText("First project")));
    assert.equal(view.queryByText("No projects yet"), null);
    assert.equal(client.getQueryData(collectionKey).length, 1);
    // The populated menu opens the same form after first-run creation.
    fireEvent.click(view.getByRole("button", { name: "Create", exact: true }));
    fireEvent.click(
      view.getByRole("menuitem", { name: "Project", exact: true }),
    );
    await waitFor(() => assert.ok(view.getByTestId("create-project-dialog")));
    assert.equal(view.getByTestId("create-project-name").value, "");
  } finally {
    cleanup();
    await new Promise((resolve) => setTimeout(resolve, 100));
    client.clear();
    relayClient.fetchEvents = fetchEvents;
    relayClient.publishEvent = publishEvent;
    clearMocks();
    resetMediaCaches();
    dom.window.close();
    for (let index = 0; index < keys.length; index++) {
      if (originals[index])
        Object.defineProperty(globalThis, keys[index], originals[index]);
      else delete globalThis[keys[index]];
    }
  }
});
