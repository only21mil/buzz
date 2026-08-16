import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, mock, test } from "node:test";

import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

let React;
let act;
let createRoot;
let QueryClient;
let QueryClientProvider;
let relayClient;
let useChannelMessagesQuery;
let useChannelSubscription;

before(async () => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    HTMLIFrameElement: dom.window.HTMLIFrameElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });

  React = await import("react");
  ({ act } = React);
  ({ createRoot } = await import("react-dom/client"));
  ({ QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  ));
  ({ relayClient } = await import("@/shared/api/relayClient.ts"));
  ({ useChannelMessagesQuery, useChannelSubscription } = await import(
    "./hooks.ts"
  ));
});

afterEach(() => {
  mock.restoreAll();
  document.body.replaceChildren();
});

after(() => dom.window.close());

function channel(id) {
  return {
    id,
    name: id,
    channelType: "stream",
    visibility: "open",
    description: "",
    topic: null,
    purpose: null,
    memberCount: 1,
    memberPubkeys: [],
    lastMessageAt: null,
    archivedAt: null,
    participants: [],
    participantPubkeys: [],
    isMember: true,
    ttlSeconds: null,
    ttlDeadline: null,
  };
}

async function flushMicrotasks() {
  await act(async () => {
    for (let index = 0; index < 6; index += 1) {
      await Promise.resolve();
    }
  });
}

function installRelayStub() {
  const pendingSubscriptions = new Map();
  const reconnectListeners = new Set();

  mock.method(relayClient, "subscribeToChannelLive", (channelId) => {
    return new Promise((resolve) => {
      pendingSubscriptions.set(channelId, resolve);
    });
  });
  mock.method(relayClient, "subscribeToReconnects", (listener) => {
    reconnectListeners.add(listener);
    return () => reconnectListeners.delete(listener);
  });

  return {
    async markReady(channelId) {
      const resolve = pendingSubscriptions.get(channelId);
      assert.ok(resolve, `missing subscription for ${channelId}`);
      pendingSubscriptions.delete(channelId);
      resolve(async () => {});
      await flushMicrotasks();
    },
    async reconnect() {
      for (const listener of [...reconnectListeners]) listener();
      await flushMicrotasks();
    },
  };
}

function mountHarness(initialChannel) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  function Harness({ activeChannel }) {
    const isSubscriptionReady = useChannelSubscription(activeChannel);
    useChannelMessagesQuery(activeChannel, isSubscriptionReady);
    return null;
  }

  async function render(activeChannel) {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client: queryClient },
          React.createElement(Harness, { activeChannel }),
        ),
      );
    });
  }

  return {
    async mount() {
      await render(initialChannel);
    },
    render,
    async unmount() {
      await act(async () => root.unmount());
      queryClient.clear();
    },
  };
}

beforeEach(() => {
  dom.window.__TAURI_INTERNALS__ = {
    invoke: async () => {
      throw new Error("Tauri invoke stub was not installed by the test");
    },
    transformCallback: () => 1,
  };
});

test("channel windows wait for subscription readiness and reconnect once", async () => {
  const windowCalls = [];
  dom.window.__TAURI_INTERNALS__.invoke = async (command, args) => {
    if (command !== "get_channel_window") {
      throw new Error(`unexpected Tauri command: ${command}`);
    }
    windowCalls.push(args.channelId);
    return [];
  };

  const relay = installRelayStub();
  const firstChannel = channel("channel-a");
  const secondChannel = channel("channel-b");
  const harness = mountHarness(firstChannel);

  await harness.mount();
  assert.deepEqual(
    windowCalls,
    [],
    "snapshot must wait for channel A readiness",
  );

  await relay.markReady(firstChannel.id);
  assert.deepEqual(windowCalls, [firstChannel.id]);

  await harness.render(secondChannel);
  assert.deepEqual(
    windowCalls,
    [firstChannel.id],
    "switching channels must synchronously close the snapshot gate",
  );

  await relay.markReady(secondChannel.id);
  assert.deepEqual(windowCalls, [firstChannel.id, secondChannel.id]);

  await relay.reconnect();
  assert.deepEqual(windowCalls, [
    firstChannel.id,
    secondChannel.id,
    secondChannel.id,
  ]);

  await harness.unmount();
});
