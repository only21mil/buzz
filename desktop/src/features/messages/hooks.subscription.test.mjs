import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, mock, test } from "node:test";

import { JSDOM } from "jsdom";
import { finalizeEvent } from "nostr-tools/pure";

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
let flattenChannelWindowEvents;
let useChannelMessagesQuery;
let useChannelSubscription;
const EVENT_SECRET = new Uint8Array(32).fill(11);
const NEVER_SETTLES = new Promise(() => {});
let eventSequence = 0;

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
  ({ flattenChannelWindowEvents } = await import(
    "./lib/channelWindowStore.ts"
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

async function waitForCondition(condition, message) {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() >= deadline) assert.fail(message);
    await act(async () => {
      await new Promise((resolve) => setImmediate(resolve));
    });
  }
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

async function resolveDeferred(request, value) {
  await act(async () => request.resolve(value));
}

async function rejectDeferred(request, error) {
  await act(async () => request.reject(error));
}

function relayEvent(channelId, id, kind = 9, overrides = {}) {
  eventSequence += 1;
  return finalizeEvent(
    {
      created_at: 1_700_000_000 + eventSequence,
      kind,
      tags: [["h", channelId]],
      content: `hello-${id}`,
      ...overrides,
    },
    EVENT_SECRET,
  );
}

function channelWindowResponse(
  channelId,
  events = [],
  { hasMore = false } = {},
) {
  const oldest = events.at(-1);
  return [
    ...events,
    relayEvent(channelId, "f", 39006, {
      content: JSON.stringify({
        has_more: hasMore,
        next_cursor:
          hasMore && oldest
            ? { created_at: oldest.created_at, id: oldest.id }
            : null,
      }),
      tags: [
        ["h", channelId],
        ["d", `${channelId}:head`],
      ],
    }),
  ];
}

function installChannelWindowInvoke(handler) {
  dom.window.__TAURI_INTERNALS__.invoke = async (command, args) => {
    if (command !== "get_channel_window") return undefined;
    assert.ok(args, "channel-window invoke args are required");
    return handler(args);
  };
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
      await act(async () => {
        subscription.resolve(async () => {
          subscription.disposed = true;
        });
      });
    },
    async emit(channelId, event) {
      const subscription = [...subscriptions]
        .reverse()
        .find(
          (candidate) =>
            candidate.channelId === channelId &&
            candidate.ready &&
            !candidate.disposed,
        );
      assert.ok(subscription, `missing ready subscription for ${channelId}`);
      await act(async () => subscription.onEvent(event));
    },
    async reconnect() {
      await act(async () => {
        for (const listener of [...reconnectListeners]) listener();
      });
    },
  };
}

function mountHarness(
  initialChannel,
  initialSnapshotContext = null,
  { strictMode = false, suspendedChannelId = null } = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  function Harness({ activeChannel, snapshotContext }) {
    const subscriptionGeneration = useChannelSubscription(activeChannel);
    const query = useChannelMessagesQuery(
      activeChannel,
      subscriptionGeneration,
      snapshotContext,
    );
    if (activeChannel?.id === suspendedChannelId) throw NEVER_SETTLES;
    return React.createElement(
      "output",
      null,
      `${subscriptionGeneration ? "ready" : "waiting"}:${(query.data ?? [])
        .map((event) => event.id)
        .join(",")}`,
    );
  }

  async function render(
    activeChannel,
    snapshotContext = initialSnapshotContext,
    transition = false,
  ) {
    await act(async () => {
      const harness = React.createElement(Harness, {
        activeChannel,
        snapshotContext,
      });
      const tree = React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(
          React.Suspense,
          { fallback: React.createElement("output", null, "suspended") },
          strictMode
            ? React.createElement(React.StrictMode, null, harness)
            : harness,
        ),
      );
      if (transition) React.startTransition(() => root.render(tree));
      else root.render(tree);
    });
  }

  return {
    container,
    queryClient,
    async mount() {
      await render(initialChannel);
    },
    render,
    renderTransition(activeChannel) {
      return render(activeChannel, initialSnapshotContext, true);
    },
    async unmount({ waitForIdle = true } = {}) {
      if (waitForIdle) {
        await waitForCondition(
          () => queryClient.isFetching() === 0,
          "channel query did not settle before unmount",
        );
      }
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
  installChannelWindowInvoke(async (args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  });

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
  await waitForCondition(
    () => windowCalls.length === 1,
    "channel A head query did not start",
  );
  assert.deepEqual(windowCalls, [firstChannel.id]);

  await harness.render(secondChannel);
  assert.deepEqual(
    windowCalls,
    [firstChannel.id],
    "switching channels must synchronously close the snapshot gate",
  );

  await relay.markReady(secondChannel.id);
  await waitForCondition(
    () => windowCalls.length === 2,
    "channel B head query did not start",
  );
  assert.deepEqual(windowCalls, [firstChannel.id, secondChannel.id]);

  await relay.reconnect();
  await waitForCondition(
    () => windowCalls.length === 3,
    "reconnect head query did not start",
  );
  assert.deepEqual(windowCalls, [
    firstChannel.id,
    secondChannel.id,
    secondChannel.id,
  ]);

  await harness.unmount();
});

test("StrictMode effect replay keeps only the current subscription generation", async () => {
  const windowCalls = [];
  installChannelWindowInvoke(async (args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  });
  const relay = installRelayStub();
  const selected = channel("channel-a");
  const harness = mountHarness(selected, null, { strictMode: true });

  await harness.mount();
  assert.deepEqual(windowCalls, []);
  await relay.markReady(selected.id);
  await waitForCondition(
    () => windowCalls.length === 1,
    "StrictMode head query did not start",
  );
  assert.deepEqual(windowCalls, [selected.id]);
  assert.match(harness.container.textContent, /^ready:/);
  await harness.unmount();
});

test("an abandoned B render cannot poison the committed A generation", async () => {
  const windowCalls = [];
  installChannelWindowInvoke(async (args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  });
  const relay = installRelayStub();
  const firstChannel = channel("channel-a");
  const suspendedChannel = channel("channel-b");
  const harness = mountHarness(firstChannel, null, {
    suspendedChannelId: suspendedChannel.id,
  });

  await harness.mount();
  await relay.markReady(firstChannel.id);
  await waitForCondition(
    () => windowCalls.length === 1,
    "initial A head query did not start",
  );
  assert.deepEqual(windowCalls, [firstChannel.id]);

  await harness.renderTransition(suspendedChannel);
  assert.match(
    harness.container.textContent,
    /^ready:/,
    "the committed A tree must remain visible while B is abandoned",
  );
  await relay.reconnect();
  await waitForCondition(
    () => windowCalls.length === 2,
    "committed A reconnect query did not start",
  );
  assert.deepEqual(
    windowCalls,
    [firstChannel.id, firstChannel.id],
    "committed A must retain its live generation after abandoned B render",
  );
  await harness.unmount();
});

test("rapid A to B to A does not reuse the old A subscription readiness", async () => {
  const windowCalls = [];
  installChannelWindowInvoke(async (args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  });
  const relay = installRelayStub();
  const firstChannel = channel("channel-a");
  const secondChannel = channel("channel-b");
  const harness = mountHarness(firstChannel);

  await harness.mount();
  assert.deepEqual(windowCalls, []);
  await relay.markReady(firstChannel.id);
  await waitForCondition(
    () => windowCalls.length === 1,
    "first A head query did not start",
  );
  assert.match(harness.container.textContent, /^ready:/);
  assert.deepEqual(windowCalls, [firstChannel.id]);

  await harness.render(secondChannel);
  assert.match(harness.container.textContent, /^waiting:/);
  assert.deepEqual(windowCalls, [firstChannel.id]);
  await harness.render(firstChannel);
  assert.match(
    harness.container.textContent,
    /^waiting:/,
    "the new A render must not inherit the first A generation",
  );
  assert.deepEqual(
    windowCalls,
    [firstChannel.id],
    "the reopened A generation must not fetch before its own readiness",
  );

  await relay.markReady(firstChannel.id);
  await waitForCondition(
    () => windowCalls.length === 2,
    "reopened A head query did not start",
  );
  assert.match(harness.container.textContent, /^ready:/);
  assert.deepEqual(
    windowCalls,
    [firstChannel.id, firstChannel.id],
    "a fresh cached A query must fetch exactly once for the new generation",
  );
  await harness.unmount();
});

test("a pending earlier A generation cannot mutate reopened A caches", async () => {
  const firstChannel = channel("channel-a");
  const secondChannel = channel("channel-b");
  const staleEvent = relayEvent(firstChannel.id, "1");
  const currentEvent = relayEvent(firstChannel.id, "2");
  const firstRequest = deferred();
  const secondRequest = deferred();
  let firstChannelCalls = 0;
  installChannelWindowInvoke(async (args) => {
    if (args.channelId !== firstChannel.id) {
      return channelWindowResponse(args.channelId);
    }
    firstChannelCalls += 1;
    return firstChannelCalls === 1
      ? firstRequest.promise
      : secondRequest.promise;
  });
  const relay = installRelayStub();
  const harness = mountHarness(firstChannel);

  await harness.mount();
  await relay.markReady(firstChannel.id);
  await waitForCondition(
    () => firstChannelCalls === 1,
    "stale A request did not start",
  );
  assert.equal(firstChannelCalls, 1);
  await harness.render(secondChannel);
  await harness.render(firstChannel);
  assert.equal(firstChannelCalls, 1);
  await relay.markReady(firstChannel.id);
  await waitForCondition(
    () => firstChannelCalls === 2,
    "current A request did not start",
  );
  assert.equal(firstChannelCalls, 2);

  await resolveDeferred(
    firstRequest,
    channelWindowResponse(firstChannel.id, [staleEvent]),
  );
  const messagesAfterStale =
    harness.queryClient.getQueryData(["channel-messages", firstChannel.id]) ??
    [];
  const windowAfterStale = harness.queryClient.getQueryData([
    "channel-window",
    firstChannel.id,
  ]);
  assert.equal(
    messagesAfterStale.some((event) => event.id === staleEvent.id),
    false,
  );
  assert.equal(
    windowAfterStale
      ? flattenChannelWindowEvents(windowAfterStale).some(
          (event) => event.id === staleEvent.id,
        )
      : false,
    false,
  );

  await resolveDeferred(
    secondRequest,
    channelWindowResponse(firstChannel.id, [currentEvent]),
  );
  await waitForCondition(
    () => harness.queryClient.isFetching() === 0,
    "current A request did not settle",
  );
  const settledMessages = harness.queryClient.getQueryData([
    "channel-messages",
    firstChannel.id,
  ]);
  const settledWindow = harness.queryClient.getQueryData([
    "channel-window",
    firstChannel.id,
  ]);
  assert.equal(
    settledMessages.filter((event) => event.id === currentEvent.id).length,
    1,
  );
  assert.equal(
    settledMessages.some((event) => event.id === staleEvent.id),
    false,
  );
  assert.equal(
    flattenChannelWindowEvents(settledWindow).filter(
      (event) => event.id === currentEvent.id,
    ).length,
    1,
  );
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
  installChannelWindowInvoke(async (args) => {
    windowCalls.push(args.channelId);
    return channelWindowResponse(args.channelId);
  });
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
    installChannelWindowInvoke(async (args) => {
      windowCalls.push(args.channelId);
      return windowRequest.promise;
    });
    const relay = installRelayStub();
    const harness = mountHarness(selected);

    await harness.mount();
    assert.deepEqual(windowCalls, []);
    await relay.markReady(selected.id);
    await waitForCondition(
      () => windowCalls.length === 1,
      "live-race head query did not start",
    );
    assert.deepEqual(windowCalls, [selected.id]);
    await relay.emit(selected.id, liveEvent);
    await resolveDeferred(
      windowRequest,
      channelWindowResponse(
        selected.id,
        responseContainsLiveEvent ? [liveEvent, freshEvent] : [freshEvent],
      ),
    );
    await waitForCondition(
      () => harness.queryClient.isFetching() === 0,
      "live-race head query did not settle",
    );

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

for (const responseContainsLiveEvent of [false, true]) {
  test(`a backdated live event during auxiliary closure is retained once when the response ${
    responseContainsLiveEvent ? "contains" : "omits"
  } it`, async () => {
    const selected = channel("channel-a");
    const historyEvent = relayEvent(selected.id, "1");
    const liveEvent = relayEvent(selected.id, "2", 9, {
      created_at: historyEvent.created_at - 100,
    });
    const auxiliaryRequest = deferred();
    let auxStarted = false;
    installChannelWindowInvoke(async () =>
      channelWindowResponse(
        selected.id,
        responseContainsLiveEvent ? [historyEvent, liveEvent] : [historyEvent],
        { hasMore: true },
      ),
    );
    const relay = installRelayStub({
      fetchAux: async () => {
        auxStarted = true;
        return auxiliaryRequest.promise;
      },
    });
    const harness = mountHarness(selected);

    await harness.mount();
    await relay.markReady(selected.id);
    await waitForCondition(() => auxStarted, "auxiliary closure did not start");
    await relay.emit(selected.id, liveEvent);
    await resolveDeferred(auxiliaryRequest, []);
    await waitForCondition(
      () => harness.queryClient.isFetching() === 0,
      "buffered backdated event query did not settle",
    );

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
    tags: [["e", message.id]],
  });
  const tombstone = relayEvent(selected.id, "3", 5, {
    tags: [["e", message.id]],
  });
  const reactionDeletion = relayEvent(selected.id, "4", 5, {
    tags: [["e", reaction.id]],
  });
  installChannelWindowInvoke(async () =>
    channelWindowResponse(selected.id, [message]),
  );
  const relay = installRelayStub({
    fetchAux: async () => [reaction, tombstone],
    fetchAuxDeletions: async () => [reactionDeletion],
  });
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  await relay.markReady(selected.id);
  await waitForCondition(
    () => harness.queryClient.isFetching() === 0,
    "auxiliary snapshot query did not settle",
  );

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
  const backdatedLiveEvent = relayEvent(selected.id, "3", 9, {
    created_at: freshEvent.created_at - 100,
  });
  const auxiliaryRequest = deferred();
  let auxStarted = false;
  assert.equal(writeMessageSnapshot(scope, [snapshotEvent]), true);
  installChannelWindowInvoke(async () =>
    channelWindowResponse(selected.id, [freshEvent], { hasMore: true }),
  );
  const relay = installRelayStub({
    fetchAux: async () => {
      auxStarted = true;
      return auxiliaryRequest.promise;
    },
  });
  const consoleError = mock.method(console, "error", () => {});
  const harness = mountHarness(selected, snapshotContext);

  await harness.mount();
  await relay.markReady(selected.id);
  await waitForCondition(
    () => auxStarted,
    "failing auxiliary closure did not start",
  );
  await relay.emit(selected.id, backdatedLiveEvent);
  await rejectDeferred(auxiliaryRequest, new Error("aux unavailable"));
  await waitForCondition(
    () => harness.queryClient.isFetching() === 0,
    "failing auxiliary closure did not settle",
  );

  const messages = harness.queryClient.getQueryData([
    "channel-messages",
    selected.id,
  ]);
  assert.ok(messages.some((event) => event.id === freshEvent.id));
  assert.equal(
    messages.filter((event) => event.id === backdatedLiveEvent.id).length,
    1,
  );
  assert.deepEqual(
    readMessageSnapshot(scope).map((event) => event.id),
    [snapshotEvent.id],
  );
  assert.equal(consoleError.mock.callCount(), 1);
  await harness.unmount();
});

test("an invalidated snapshot scope no-ops after the window await", async (t) => {
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
  let windowStarted = false;
  installChannelWindowInvoke(async () => {
    windowStarted = true;
    return windowRequest.promise;
  });
  const relay = installRelayStub();
  const harness = mountHarness(selected, snapshotContext);
  t.after(() => harness.unmount({ waitForIdle: false }));

  await harness.mount();
  await relay.markReady(selected.id);
  await waitForCondition(
    () => windowStarted,
    "snapshot-scoped head query did not start",
  );
  removeAllMessageSnapshots();
  await resolveDeferred(
    windowRequest,
    channelWindowResponse(selected.id, [staleFreshEvent]),
  );

  const messages = harness.queryClient.getQueryData([
    "channel-messages",
    selected.id,
  ]);
  assert.equal(
    messages.some((event) => event.id === staleFreshEvent.id),
    false,
  );
  assert.equal(readMessageSnapshot(scope), null);
});
