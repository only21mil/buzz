import assert from "node:assert/strict";
import { register } from "node:module";
import { after, afterEach, before, test } from "node:test";
import { JSDOM } from "jsdom";

// Hold only this component's deferred query. The mounted input, keyboard
// handler, channel filtering, create form, and React state remain real.
const reactUrl = import.meta.resolve("react");
const heldReactUrl = `data:text/javascript,${encodeURIComponent(`
  export * from ${JSON.stringify(reactUrl)};
  export function useDeferredValue() {
    return globalThis.__channelBrowserHeldQuery;
  }
`)}`;
register(
  `data:text/javascript,${encodeURIComponent(`
    export function resolve(specifier, context, nextResolve) {
      if (specifier === "react" && context.parentURL?.endsWith("/ChannelBrowserDialog.tsx")) {
        return { url: ${JSON.stringify(heldReactUrl)}, shortCircuit: true };
      }
      if (specifier === "@/shared/theme/ThemeProvider") {
        return { url: "data:text/javascript,export function useTheme() { return { isDark: false }; }", shortCircuit: true };
      }
      return nextResolve(specifier, context);
    }
  `)}`,
  import.meta.url,
);

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost/",
  pretendToBeVisual: true,
});
before(() => {
  for (const name of [
    "window",
    "document",
    "HTMLElement",
    "HTMLInputElement",
    "Element",
    "Node",
    "NodeFilter",
    "MutationObserver",
    "CustomEvent",
    "getComputedStyle",
    "localStorage",
  ]) {
    Object.defineProperty(globalThis, name, {
      configurable: true,
      value: name === "window" ? dom.window : dom.window[name],
    });
  }
  globalThis.ResizeObserver = class {
    observe() {}
    disconnect() {}
    unobserve() {}
  };
  document.fonts = { ready: Promise.resolve() };
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(async () => {
  (await import("@testing-library/react")).cleanup();
  delete globalThis.__channelBrowserHeldQuery;
});
after(() => dom.window.close());

function channel(id, overrides = {}) {
  return {
    id,
    name: id,
    description: "",
    channelType: "stream",
    visibility: "open",
    isMember: true,
    archivedAt: null,
    memberCount: 2,
    ...overrides,
  };
}

async function setup({ heldQuery = "", channels, ...props } = {}) {
  globalThis.__channelBrowserHeldQuery = heldQuery;
  const React = await import("react");
  const { act, render, fireEvent } = await import("@testing-library/react");
  const { QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  );
  const { ChannelBrowserDialog } = await import("./ChannelBrowserDialog.tsx");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { enabled: false, gcTime: Infinity } },
  });
  queryClient.setQueryData(["channel-templates"], []);
  const selected = [];
  const openChanges = [];
  let view;
  await act(async () => {
    view = render(
      React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(ChannelBrowserDialog, {
          channels: channels ?? [
            channel("agents"),
            channel("design"),
            channel("general"),
          ],
          open: true,
          onOpenChange: (open) => openChanges.push(open),
          onSelectChannel: (id) => selected.push(id),
          onJoinChannel: async () => {},
          onCreateChannel: async () => {},
          ...props,
        }),
      ),
    );
  });
  return {
    view,
    fireEvent,
    selected,
    openChanges,
    input: view.getByTestId("channel-browser-search"),
  };
}

test("immediate Enter creates the live query while the empty-query results stay deferred", async () => {
  const { view, fireEvent, input, selected, openChanges } = await setup();
  fireEvent.change(input, { target: { value: "brand-new-channel" } });
  // This is the exact race from CI: old agents row is still rendered.
  assert.ok(view.getByTestId("browse-channel-agents"));
  fireEvent.keyDown(input, { key: "Enter" });
  assert.deepEqual(selected, []);
  assert.deepEqual(openChanges, []);
  assert.equal(
    view.getByTestId("create-channel-name").value,
    "brand-new-channel",
  );
});

test("immediate Enter selects the current exact match instead of the stale first row", async () => {
  const { view, fireEvent, input, selected } = await setup();
  fireEvent.change(input, { target: { value: "#GENERAL" } });
  assert.ok(view.getByTestId("browse-channel-agents"));
  fireEvent.keyDown(input, { key: "Enter" });
  assert.deepEqual(selected, ["general"]);
});

test("current matches remain actionable when the deferred query had no results", async () => {
  const { view, fireEvent, input, selected } = await setup({
    heldQuery: "no-such-channel",
  });
  fireEvent.change(input, { target: { value: "desig" } });
  assert.equal(view.queryByTestId("browse-channel-design"), null);
  fireEvent.keyDown(input, { key: "Enter" });
  assert.deepEqual(selected, ["design"]);
});

test("arrow navigation and Enter use the same current result list", async () => {
  const { fireEvent, input, selected } = await setup();
  fireEvent.change(input, { target: { value: "desig" } });
  fireEvent.keyDown(input, { key: "ArrowDown" }); // Create row.
  fireEvent.keyDown(input, { key: "ArrowDown" }); // Current design match.
  fireEvent.keyDown(input, { key: "Enter" });
  assert.deepEqual(selected, ["design"]);
});

test("live keyboard resolution preserves privacy, type, and tab filtering", async () => {
  const { view, fireEvent, input, selected } = await setup({
    channelTypeFilter: "stream",
    channels: [
      channel("design-private", { visibility: "private", isMember: false }),
      channel("design-dm", { channelType: "dm" }),
      channel("design-forum", { channelType: "forum" }),
      channel("design-archived", { archivedAt: 123 }),
      channel("design-open", { isMember: false }),
      channel("design-joined"),
    ],
  });
  fireEvent.mouseDown(view.getByRole("tab", { name: /Joined/ }), {
    button: 0,
    ctrlKey: false,
  });
  fireEvent.change(input, { target: { value: "design" } });
  fireEvent.keyDown(input, { key: "Enter" });
  assert.deepEqual(selected, ["design-joined"]);
});
