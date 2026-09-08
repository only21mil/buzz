import assert from "node:assert/strict";
import { after, test } from "node:test";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "https://desktop.example",
});
Object.assign(globalThis, {
  window: dom.window,
  document: dom.window.document,
  localStorage: dom.window.localStorage,
  IS_REACT_ACT_ENVIRONMENT: true,
  isTauri: false,
});
for (const key of [
  "HTMLElement",
  "HTMLInputElement",
  "Node",
  "NodeFilter",
  "Event",
  "CustomEvent",
  "MutationObserver",
  "getComputedStyle",
])
  globalThis[key] = dom.window[key];
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: dom.window.navigator,
});

dom.window.matchMedia = (query) => ({
  matches: false,
  media: query,
  addEventListener() {},
  removeEventListener() {},
});
globalThis.matchMedia = dom.window.matchMedia;

const { default: React, act } = await import("react");
const { createRoot } = await import("react-dom/client");
const { QueryClient, QueryClientProvider } = await import(
  "@tanstack/react-query"
);
const { CommunitiesProvider } = await import(
  "@/features/communities/useCommunities.tsx"
);
const { ThemeProvider } = await import("@/shared/theme/ThemeProvider.tsx");
const { durableDraftStore } = await import("../durableDraftQueue.ts");
const { DurableDraftReviewDialog } = await import(
  "./DurableDraftReviewDialog.tsx"
);
after(() => dom.window.close());

const scope = { owner: "a".repeat(64), relayUrl: "wss://community.example" };
const event = {
  id: "1".repeat(64),
  pubkey: "b".repeat(64),
  kind: 14201,
  created_at: 99,
  tags: [
    ["r", "request-id"],
    ["h", "channel"],
    ["agent", "b".repeat(64)],
    ["p", scope.owner],
    ["v", "1"],
  ],
  content: "ciphertext",
  sig: "verified-by-native-fixture",
};
const settle = () => new Promise((resolve) => setImmediate(resolve));
const button = (label) =>
  [...document.querySelectorAll("button")].find(
    (element) => element.textContent === label,
  );
const click = async (element) => {
  assert.ok(element, "expected a rendered button");
  await act(async () => {
    element.click();
    await settle();
  });
};

async function mount({
  undecryptable = false,
  connected = true,
  operations = [],
} = {}) {
  localStorage.setItem(
    "buzz-communities",
    JSON.stringify([
      { id: "community", name: "Community", relayUrl: scope.relayUrl },
    ]),
  );
  localStorage.setItem("buzz-active-community-id", "community");
  const calls = [];
  let prepareGate = null;
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      if (["list_personas", "list_managed_agents"].includes(command)) return [];
      if (command === "get_relay_http_url") return "https://community.example";
      if (command === "get_media_proxy_port") return null;
      calls.push([command, args]);
      if (command === "agent_draft_prepare") {
        await prepareGate;
        return {
          requestEventId: event.id,
          action: "reject",
          state: "prepared",
        };
      }
      if (command === "agent_draft_apply")
        return {
          requestEventId: event.id,
          action: "reject",
          state: "rejected",
        };
      throw new Error(`Unexpected IPC: ${command}`);
    },
  };
  let connection;
  const dependencies = {
    queue: async () => ({ events: [event], operations }),
    receive: async () => {},
    backfill: async () => [],
    decrypt: async () => {
      if (undecryptable) throw new Error("Cannot decrypt");
      return { payload: { type: "malformed" } };
    },
    subscribe: () => () => {},
    connection: (listener) => {
      connection = listener;
      listener(connected);
      return () => {};
    },
  };
  let stop = durableDraftStore.start(scope, dependencies);
  await settle();
  durableDraftStore.select(scope, event.id);
  assert.equal(durableDraftStore.getSnapshot().items[0].request, null);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  client.setQueryData(["identity"], { pubkey: scope.owner });
  for (const key of ["personas", "managed-agents", "channels", "acp-runtimes"])
    client.setQueryData([key], []);
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      React.createElement(
        QueryClientProvider,
        { client },
        React.createElement(
          CommunitiesProvider,
          null,
          React.createElement(
            ThemeProvider,
            null,
            React.createElement(DurableDraftReviewDialog),
          ),
        ),
      ),
    );
    await settle();
  });
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  return {
    calls,
    client,
    connection: (value) => connection(value),
    pausePrepare: () => {
      let release;
      prepareGate = new Promise((resolve) => {
        release = resolve;
      });
      return release;
    },
    restart: async () => {
      stop();
      stop = durableDraftStore.start(scope, dependencies);
      await settle();
      durableDraftStore.select(scope, event.id);
    },
    close: async () => {
      await act(async () => {
        root.unmount();
        stop();
      });
      client.clear();
      container.remove();
      localStorage.clear();
    },
  };
}

for (const undecryptable of [false, true]) {
  test(`rendered ${undecryptable ? "undecryptable" : "malformed"} draft rejects through the exact transaction`, async () => {
    const f = await mount({ undecryptable });
    try {
      assert.equal(button("Review and save").disabled, true);
      assert.equal(button("Review and create"), undefined);
      assert.equal(button("Review and start"), undefined);
      assert.equal(button("Reject").disabled, false);
      assert.deepEqual(f.calls, [], "opening must not decide the draft");
      await click(button("Reject"));
      assert.deepEqual(f.calls, [
        [
          "agent_draft_prepare",
          {
            ...scope,
            requestEventId: event.id,
            action: "reject",
            input: null,
            expectedContent: null,
            instanceInput: null,
            publishShared: false,
          },
        ],
        ["agent_draft_apply", { ...scope, requestEventId: event.id }],
      ]);
    } finally {
      await f.close();
    }
  });
}

test("rendered Reject stays disabled offline and during a retained operation", async () => {
  for (const options of [
    { connected: false },
    {
      operations: [
        { requestEventId: event.id, action: "reject", state: "rejected" },
      ],
    },
  ]) {
    const f = await mount(options);
    try {
      assert.equal(button("Reject").disabled, true);
      await click(button("Reject"));
      assert.deepEqual(f.calls, []);
    } finally {
      await f.close();
    }
  }
});

test("rendered Reject blocks duplicate clicks while preparation is pending", async () => {
  const f = await mount();
  const release = f.pausePrepare();
  try {
    await act(async () => {
      button("Reject").click();
      button("Reject").click();
      await settle();
    });
    assert.equal(button("Reject").disabled, true);
    assert.equal(button("Close").disabled, true);
    await click(button("Reject"));
    assert.equal(f.calls.length, 1);
    await act(async () => {
      release();
      await settle();
    });
    assert.deepEqual(
      f.calls.map(([command]) => command),
      ["agent_draft_prepare", "agent_draft_apply"],
    );
  } finally {
    release();
    await f.close();
  }
});

for (const change of ["identity", "epoch", "offline"]) {
  test(`pending rendered rejection cannot apply after ${change} revocation`, async () => {
    const f = await mount();
    const release = f.pausePrepare();
    try {
      await click(button("Reject"));
      await act(async () => {
        if (change === "identity") {
          f.client.setQueryData(["identity"], { pubkey: "c".repeat(64) });
          await new Promise((resolve) => setTimeout(resolve, 0));
        } else if (change === "epoch") await f.restart();
        else f.connection(false);
        await settle();
      });
      if (change === "identity") assert.equal(button("Reject"), undefined);
      await act(async () => {
        release();
        await settle();
      });
      assert.deepEqual(
        f.calls.map(([command]) => command),
        ["agent_draft_prepare"],
      );
    } finally {
      release();
      await f.close();
    }
  });
}
