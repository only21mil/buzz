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
let captureMessageSnapshotScope;
let readMessageSnapshot;
let removeAllMessageSnapshots;
let writeMessageSnapshot;
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
  ({
    captureMessageSnapshotScope,
    readMessageSnapshot,
    removeAllMessageSnapshots,
    writeMessageSnapshot,
  } = await import("./lib/messageSnapshot.ts"));
  ({ useChannelMessagesQuery, useChannelSubscription } = await import(
    "./hooks.ts"
  ));
});

afterEach(() => {
  mock.restoreAll();
  removeAllMessageSnapshots();
  window.localStorage.clear();
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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function relayEvent(channelId, id, kind = 9, overrides = {}) {
  return {
    id: id.repeat(64),
    pubkey: "c".repeat(64),
    created_at: 1_700_000_000,
    kind,
    tags: [["h", channelId]],
    content: "hello",
    sig: "d".repeat(128),
    ...overrides,
  };
}

function channelWindowResponse(channelId, events = []) {
  return [
    ...events,
    relayEvent(channelId, "f", 39006, {
      content: JSON.stringify({ has_more: false, next_cursor: null }),
      tags: [
        ["h", channelId],
        ["d", `${channelId}:head`],
      ],
    }),
  ];
}

function installRelayStub({ fetchAux, fetchAuxDeletions } = {}) {
  const subscriptions = [];
  const reconnectListeners = new Set();

  mock.method(relayClient, "subscribeToChannelLive", (channelId, onEvent) => {
    return new Promise((resolve) => {
      subscriptions.push({
        channelId,
        disposed: false,
        onEvent,
        ready: false,
        resolve,
      });
    });
  });
  mock.method(relayClient, "subscribeToReconnects", (listener) => {
    reconnectListeners.add(listener);
    return () => reconnectListeners.delete(listener);
  });
  mock.method(
    relayClient,
    "fetchAuxEventsByReference",
    fetchAux ?? (async () => []),
  );
  mock.method(
    relayClient,
    "fetchAuxDeletionEventsForAuxEvents",
    fetchAuxDeletions ?? (async () => []),
  );

  return {
    async markReady(channelId) {
      const subscription = [...subscriptions].reverse().find((candidate) => {
        return candidate.channelId === channelId && !candidate.ready;
      });
      assert.ok(subscription, `missing subscription for ${channelId}`);
      subscription.ready = true;
      subscription.resolve(async () => {
        subscription.disposed = true;
      });
      await flushMicrotasks();
    },
    emit(channelId, event) {
      const subscription = [...subscriptions]
        .reverse()
        .find(
          (candidate) =>
            candidate.channelId === channelId &&
            candidate.ready &&
            !candidate.disposed,
        );
      assert.ok(subscription, `missing ready subscription for ${channelId}`);
      subscription.onEvent(event);
    },
    async reconnect() {
      for (const listener of [...reconnectListeners]) listener();
      await flushMicrotasks();
    },
  };
}

function mountHarness(initialChannel, initialSnapshotContext = null) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  function Harness({ activeChannel, snapshotContext }) {
    const isSubscriptionReady = useChannelSubscription(activeChannel);
    const query = useChannelMessagesQuery(
      activeChannel,
      isSubscriptionReady,
      snapshotContext,
    );
    return React.createElement(
      "output",
      null,
      `${isSubscriptionReady ? "ready" : "waiting"}:${(query.data ?? [])
        .map((event) => event.id)
        .join(",")}`,
    );
  }

  async function render(
    activeChannel,
    snapshotContext = initialSnapshotContext,
  ) {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client: queryClient },
          React.createElement(Harness, { activeChannel, snapshotContext }),
        ),
      );
    });
  }

  return {
    container,
    queryClient,
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
    return channelWindowResponse(args.channelId);
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

test("rapid A to B to A does not reuse the old A subscription readiness", async () => {
  dom.window.__TAURI_INTERNALS__.invoke = async (_command, args) =>
    channelWindowResponse(args.channelId);
  const relay = installRelayStub();
  const firstChannel = channel("channel-a");
  const secondChannel = channel("channel-b");
  const harness = mountHarness(firstChannel);

  await harness.mount();
  await relay.markReady(firstChannel.id);
  assert.match(harness.container.textContent, /^ready:/);

  await harness.render(secondChannel);
  assert.match(harness.container.textContent, /^waiting:/);
  await harness.render(firstChannel);
  assert.match(
    harness.container.textContent,
    /^waiting:/,
    "the new A render must not inherit the first A generation",
  );

  await relay.markReady(firstChannel.id);
  assert.match(harness.container.textContent, /^ready:/);
  await harness.unmount();
});

test("a warm scoped snapshot paints synchronously while readiness is pending", async () => {
  const selected = channel("channel-a");
  const snapshotContext = {
    relayUrl: "wss://relay.example.com",
    signerPubkey: "a".repeat(64),
  };
  const scope = captureMessageSnapshotScope(
    snapshotContext.relayUrl,
    snapshotContext.signerPubkey,
    selected.id,
  );
  assert.ok(scope);
  const snapshotEvent = relayEvent(selected.id, "1");
  assert.equal(writeMessageSnapshot(scope, [snapshotEvent]), true);
  const windowCalls = [];
  dom.window.__TAURI_INTERNALS__.invoke = async (_command, args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  };
  installRelayStub();
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  assert.equal(harness.container.textContent, `waiting:${snapshotEvent.id}`);
  assert.deepEqual(windowCalls, []);
  await harness.unmount();
});

for (const responseContainsLiveEvent of [false, true]) {
  test(`a live event during the window await is preserved once when the response ${
    responseContainsLiveEvent ? "contains" : "omits"
  } it`, async () => {
    const selected = channel("channel-a");
    const liveEvent = relayEvent(selected.id, "2");
    const freshEvent = relayEvent(selected.id, "3", 9, {
      created_at: liveEvent.created_at - 1,
    });
    const windowRequest = deferred();
    const windowCalls = [];
    dom.window.__TAURI_INTERNALS__.invoke = async (_command, args) => {
      windowCalls.push(args.channelId);
      return windowRequest.promise;
    };
    const relay = installRelayStub();
    const harness = mountHarness(selected);

    await harness.mount();
    assert.deepEqual(windowCalls, []);
    await relay.markReady(selected.id);
    assert.deepEqual(windowCalls, [selected.id]);
    relay.emit(selected.id, liveEvent);
    windowRequest.resolve(
      channelWindowResponse(
        selected.id,
        responseContainsLiveEvent ? [liveEvent, freshEvent] : [freshEvent],
      ),
    );
    await flushMicrotasks();

    const messages = harness.queryClient.getQueryData([
      "channel-messages",
      selected.id,
    ]);
    assert.equal(
      messages.filter((event) => event.id === liveEvent.id).length,
      1,
    );
    await harness.unmount();
  });
}

test("auxiliary closure lands before durable snapshot persistence", async () => {
  const selected = channel("channel-a");
  const snapshotContext = {
    relayUrl: "wss://relay.example.com",
    signerPubkey: "a".repeat(64),
  };
  const message = relayEvent(selected.id, "1");
  const reaction = relayEvent(selected.id, "2", 7, {
    tags: [
      ["h", selected.id],
      ["e", message.id],
    ],
  });
  const tombstone = relayEvent(selected.id, "3", 5, {
    tags: [
      ["h", selected.id],
      ["e", message.id],
    ],
  });
  const reactionDeletion = relayEvent(selected.id, "4", 5, {
    tags: [
      ["h", selected.id],
      ["e", reaction.id],
    ],
  });
  dom.window.__TAURI_INTERNALS__.invoke = async () =>
    channelWindowResponse(selected.id, [message]);
  const relay = installRelayStub({
    fetchAux: async () => [reaction, tombstone],
    fetchAuxDeletions: async () => [reactionDeletion],
  });
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  await relay.markReady(selected.id);
  await flushMicrotasks();

  const scope = captureMessageSnapshotScope(
    snapshotContext.relayUrl,
    snapshotContext.signerPubkey,
    selected.id,
  );
  assert.ok(scope);
  const persisted = readMessageSnapshot(scope);
  await harness.unmount();
  assert.ok(persisted);
  assert.deepEqual(
    new Set(persisted.map((event) => event.id)),
    new Set([message.id, reaction.id, tombstone.id, reactionDeletion.id]),
  );
});

test("auxiliary failure keeps the fresh page but skips durable rewrite", async () => {
  const selected = channel("channel-a");
  const snapshotContext = {
    relayUrl: "wss://relay.example.com",
    signerPubkey: "a".repeat(64),
  };
  const scope = captureMessageSnapshotScope(
    snapshotContext.relayUrl,
    snapshotContext.signerPubkey,
    selected.id,
  );
  assert.ok(scope);
  const snapshotEvent = relayEvent(selected.id, "1");
  const freshEvent = relayEvent(selected.id, "2");
  assert.equal(writeMessageSnapshot(scope, [snapshotEvent]), true);
  dom.window.__TAURI_INTERNALS__.invoke = async () =>
    channelWindowResponse(selected.id, [freshEvent]);
  const relay = installRelayStub({
    fetchAux: async () => {
      throw new Error("aux unavailable");
    },
  });
  const consoleError = mock.method(console, "error", () => {});
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  await relay.markReady(selected.id);
  await flushMicrotasks();

  const messages = harness.queryClient.getQueryData([
    "channel-messages",
    selected.id,
  ]);
  assert.ok(messages.some((event) => event.id === freshEvent.id));
  assert.deepEqual(
    readMessageSnapshot(scope).map((event) => event.id),
    [snapshotEvent.id],
  );
  assert.equal(consoleError.mock.callCount(), 1);
  await harness.unmount();
});

test("an invalidated snapshot scope no-ops after the window await", async () => {
  const selected = channel("channel-a");
  const snapshotContext = {
    relayUrl: "wss://relay.example.com",
    signerPubkey: "a".repeat(64),
  };
  const scope = captureMessageSnapshotScope(
    snapshotContext.relayUrl,
    snapshotContext.signerPubkey,
    selected.id,
  );
  assert.ok(scope);
  const snapshotEvent = relayEvent(selected.id, "1");
  const staleFreshEvent = relayEvent(selected.id, "2");
  assert.equal(writeMessageSnapshot(scope, [snapshotEvent]), true);
  const windowRequest = deferred();
  dom.window.__TAURI_INTERNALS__.invoke = async () => windowRequest.promise;
  const relay = installRelayStub();
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  await relay.markReady(selected.id);
  removeAllMessageSnapshots();
  windowRequest.resolve(channelWindowResponse(selected.id, [staleFreshEvent]));
  await flushMicrotasks();

  const messages = harness.queryClient.getQueryData([
    "channel-messages",
    selected.id,
  ]);
  assert.equal(
    messages.some((event) => event.id === staleFreshEvent.id),
    false,
  );
  assert.equal(readMessageSnapshot(scope), null);
  await harness.unmount();
});
