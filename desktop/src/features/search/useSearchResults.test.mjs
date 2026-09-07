import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

test("scoped one-character search requests all 40 results and keyboard navigation reaches the last hit", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "http://localhost",
  });
  const keys = [
    "window",
    "localStorage",
    "document",
    "HTMLElement",
    "Node",
    "Event",
    "IS_REACT_ACT_ENVIRONMENT",
  ];
  const originals = keys.map((key) =>
    Object.getOwnPropertyDescriptor(globalThis, key),
  );
  for (const key of keys)
    Object.defineProperty(globalThis, key, {
      configurable: true,
      writable: true,
      value: key === "IS_REACT_ACT_ENVIRONMENT" ? true : dom.window[key],
    });
  const { createElement: h, useState, act } = await import("react");
  const { render, cleanup, fireEvent, waitFor } = await import(
    "@testing-library/react"
  );
  const { QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  );
  const { mockIPC, clearMocks } = await import("@tauri-apps/api/mocks");
  const { useSearchResults } = await import("./useSearchResults.ts");
  const { useSearchMenuKeyboardNavigation } = await import(
    "./ui/useSearchMenuKeyboardNavigation.ts"
  );
  const { CommunitiesProvider } = await import(
    "@/features/communities/useCommunities"
  );
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: Infinity },
    },
  });
  client.setQueryData(["identity"], { pubkey: "a".repeat(64) });
  client.setQueryData(["archivedIdentities"], { archived: [] });
  client.setQueryData(["users-batch", "a".repeat(64)], { profiles: {} });
  const calls = [];
  const opened = [];
  const scrolled = [];
  dom.window.HTMLElement.prototype.scrollIntoView = function () {
    scrolled.push(this.dataset.searchResultIndex);
  };
  mockIPC((command, args) => {
    if (command !== "search_messages")
      throw new Error(`Unexpected relay call: ${command}`);
    calls.push(args);
    if (args.q === "z") return { hits: [], found: 0 };
    const hits = Array.from({ length: 40 }, (_, index) => ({
      event_id: `hit-${index}`,
      kind: 9,
      content: "a match",
      pubkey: "a".repeat(64),
      channel_id: args.channelId,
      channel_name: "General",
      created_at: 1,
      score: 1,
    }));
    return { hits, found: 40 };
  });
  const channels = [
    {
      id: "channel",
      name: "General",
      description: "",
      visibility: "open",
      isMember: true,
    },
  ];
  function Harness({ scopeChannelId }) {
    const search = useSearchResults({
      channels,
      enabled: true,
      limit: 40,
      scopeChannelId,
    });
    const [selectedMenuIndex, setSelectedMenuIndex] = useState(0);
    const onKeyDown = useSearchMenuKeyboardNavigation({
      activeResults: search.results,
      hasLeadingAction: false,
      onActivateLeadingAction() {},
      onOpenResult: (result) => opened.push(result.hit.eventId),
      onRemoveScope() {},
      query: search.query,
      scopeActive: Boolean(scopeChannelId),
      selectedMenuIndex,
      setSelectedMenuIndex,
    });
    return h(
      "div",
      null,
      h("input", {
        "aria-label": "Search",
        value: search.query,
        onChange: (event) => search.setQuery(event.target.value),
        onKeyDown,
      }),
      ...search.results.map((result, index) =>
        h(
          "div",
          { key: result.hit.eventId, "data-search-result-index": index },
          result.hit.eventId,
        ),
      ),
    );
  }
  const tree = (scopeChannelId) =>
    h(
      CommunitiesProvider,
      null,
      h(QueryClientProvider, { client }, h(Harness, { scopeChannelId })),
    );
  try {
    const view = render(tree(null));
    fireEvent.change(view.getByLabelText("Search"), { target: { value: "a" } });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 330));
    });
    assert.equal(
      calls.length,
      0,
      "unscoped one-character input must not query messages",
    );
    view.rerender(tree("channel"));
    await waitFor(() =>
      assert.equal(
        view.container.querySelectorAll("[data-search-result-index]").length,
        40,
      ),
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].q, "a");
    assert.equal(calls[0].channelId, "channel");
    assert.equal(calls[0].limit, 40);
    for (let index = 0; index < 40; index++)
      fireEvent.keyDown(view.getByLabelText("Search"), { key: "ArrowDown" });
    fireEvent.keyDown(view.getByLabelText("Search"), { key: "Enter" });
    assert.deepEqual(opened, ["hit-39"]);
    assert.equal(scrolled.at(-1), "39");
    fireEvent.change(view.getByLabelText("Search"), { target: { value: "z" } });
    await waitFor(() => assert.equal(calls.length, 2));
    await waitFor(() =>
      assert.equal(
        view.container.querySelectorAll("[data-search-result-index]").length,
        0,
      ),
    );
    view.rerender(tree(null));
    await waitFor(() =>
      assert.equal(
        view.container.querySelectorAll("[data-search-result-index]").length,
        0,
      ),
    );
    assert.equal(
      calls.length,
      2,
      "removing scope must restore the global two-character threshold",
    );
  } finally {
    cleanup();
    client.clear();
    clearMocks();
    dom.window.close();
    keys.forEach((key, index) => {
      if (originals[index])
        Object.defineProperty(globalThis, key, originals[index]);
      else delete globalThis[key];
    });
  }
});
