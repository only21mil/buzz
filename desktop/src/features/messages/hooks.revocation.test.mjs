import assert from "node:assert/strict";
import { after, afterEach, before, mock, test } from "node:test";
import { JSDOM } from "jsdom";
import { finalizeEvent } from "nostr-tools/pure";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
const CHANNEL = "11111111-1111-4111-8111-111111111111";
const CONTEXT = {
  relayUrl: "wss://relay.example.com",
  signerPubkey: "a".repeat(64),
};
let React, act, createRoot, QueryClient, QueryClientProvider, useQuery;
let RelayClient, relayClient, subscribeLiveQueryCache;
let useChannelMessagesQuery, useFetchOlderMessages;
let captureMessageSnapshotScope, readMessageSnapshot;
let removeAllMessageSnapshots, isMessageSnapshotScopeCurrent;
let sequence = 0;

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
  ({ QueryClient, QueryClientProvider, useQuery } = await import(
    "@tanstack/react-query"
  ));
  const { timeoutManager } = await import("@tanstack/react-query");
  // Removed queries can schedule GC after their delayed transport settles.
  // Their hour-long retention timers must not keep this test process alive.
  timeoutManager.setTimeoutProvider({
    setTimeout: (callback, delay) => setTimeout(callback, delay).unref(),
    clearTimeout,
    setInterval: (callback, delay) => setInterval(callback, delay).unref(),
    clearInterval,
  });
  ({ RelayClient } = await import("@/shared/api/relayClientSession.ts"));
  ({ relayClient } = await import("@/shared/api/relayClient.ts"));
  ({ subscribeLiveQueryCache } = await import(
    "@/shared/api/liveQueryCacheSubscriptions.ts"
  ));
  ({ useChannelMessagesQuery } = await import("./hooks.ts"));
  ({ useFetchOlderMessages } = await import("./useFetchOlderMessages.ts"));
  ({
    captureMessageSnapshotScope,
    isMessageSnapshotScopeCurrent,
    readMessageSnapshot,
    removeAllMessageSnapshots,
  } = await import("./lib/messageSnapshot.ts"));
});
afterEach(() => {
  mock.restoreAll();
  removeAllMessageSnapshots();
  window.localStorage.clear();
});
after(() => dom.window.close());

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}
async function waitFor(check) {
  const deadline = Date.now() + 5000;
  while (!check()) {
    assert.ok(Date.now() < deadline, "condition timed out");
    await flush();
  }
}
function event(
  content,
  kind = 9,
  tags = [["h", CHANNEL]],
  createdAt = 1_700_000_000 + ++sequence,
) {
  return finalizeEvent(
    { kind, created_at: createdAt, tags, content },
    new Uint8Array(32).fill(11),
  );
}
function response(message, hasMore = false, cursor = null) {
  return [
    message,
    event(
      JSON.stringify({
        has_more: hasMore,
        next_cursor: hasMore
          ? { created_at: message.created_at, id: message.id }
          : null,
      }),
      39006,
      [
        ["h", CHANNEL],
        [
          "d",
          cursor
            ? `${CHANNEL}:${cursor.created_at}:${cursor.event_id}`
            : `${CHANNEL}:head`,
        ],
      ],
    ),
  ];
}

async function harness(t, { visibility = "private", isMember = true } = {}) {
  const selected = {
    id: CHANNEL,
    name: "Private history",
    channelType: "stream",
    visibility,
    isMember,
    memberPubkeys: [CONTEXT.signerPubkey],
    memberCount: 1,
    lastMessageAt: null,
  };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  client.setQueryData(["channels"], [selected]);
  const requests = [],
    aux = [],
    writes = [];
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1,
    invoke: async (command, args) => {
      assert.equal(command, "get_channel_window");
      const pending = deferred();
      requests.push({ ...pending, args });
      return pending.promise;
    },
  };
  mock.method(relayClient, "fetchAuxEventsByReference", () => {
    const pending = deferred();
    aux.push(pending);
    return pending.promise;
  });
  mock.method(
    relayClient,
    "fetchAuxDeletionEventsForAuxEvents",
    async () => [],
  );
  const setItem = dom.window.Storage.prototype.setItem;
  mock.method(dom.window.Storage.prototype, "setItem", function (key, value) {
    if (key.startsWith("buzz-channel-messages.")) writes.push(value);
    return setItem.call(this, key, value);
  });
  const relay = new RelayClient();
  const frames = [];
  const receive = (frame) =>
    relay.handleWsMessage(JSON.stringify(frame), relay.connectionGeneration);
  relay.ensureConnected = async () => {};
  relay.sendRawWithReconnectRetry = async (frame) => {
    frames.push(frame);
    if (frame[0] === "REQ") await receive(["EOSE", frame[1]]);
  };
  relay.closeSubscription = async () => {};
  const stop = subscribeLiveQueryCache(
    client,
    relay,
    CONTEXT.signerPubkey,
    () => true,
  );
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  let older;
  function Harness() {
    const { data: channels = [] } = useQuery({
      queryKey: ["channels"],
      enabled: false,
      queryFn: () => [],
    });
    // HomeView derives the selected channel from discovery and starts history
    // immediately, without a subscription-generation guard.
    const channel = channels.find((item) => item.id === CHANNEL) ?? null;
    const query = useChannelMessagesQuery(channel, true, CONTEXT);
    older = useFetchOlderMessages(channel);
    return React.createElement(
      "output",
      null,
      channel?.id ?? "none",
      ...(query.data ?? []).map((item) => item.content),
    );
  }
  await act(async () =>
    root.render(
      React.createElement(
        QueryClientProvider,
        { client },
        React.createElement(Harness),
      ),
    ),
  );
  t.after(async () => {
    stop();
    await act(async () => root.unmount());
    clearTimeout(relay.flushTimeout);
    client.clear();
    container.remove();
  });
  const scope = captureMessageSnapshotScope(
    CONTEXT.relayUrl,
    CONTEXT.signerPubkey,
    CHANNEL,
  );
  return {
    client,
    requests,
    aux,
    writes,
    scope,
    container,
    fetchOlder: () => older.fetchOlder(),
    rejoin: async () => {
      await act(async () => client.setQueryData(["channels"], [selected]));
    },
    close: async () => {
      const frame = frames.find((item) => item[2]?.["#h"]?.[0] === CHANNEL);
      assert.ok(frame, "actual channel metadata subscription registered");
      await act(async () =>
        receive(["CLOSED", frame[1], "restricted: channel access revoked"]),
      );
      await waitFor(() => container.textContent === "none");
      assert.deepEqual(client.getQueryData(["channels"]), []);
      assert.equal(
        isMessageSnapshotScopeCurrent(scope),
        true,
        "channel revocation must be tested without an identity epoch change",
      );
    },
    assertEmpty: () => {
      assert.deepEqual(
        {
          messages: client.getQueryData(["channel-messages", CHANNEL]),
          window: client.getQueryData(["channel-window", CHANNEL]),
          snapshot: readMessageSnapshot(scope),
          writes,
        },
        { messages: undefined, window: undefined, snapshot: null, writes: [] },
      );
    },
  };
}

for (const visibility of ["private", "open"]) {
  test(`CLOSED fences pending immediate ${visibility} history after selection clears`, async (t) => {
    const h = await harness(t, { visibility });
    await waitFor(() => h.requests.length === 1);
    await h.close();
    h.assertEmpty();
    await act(async () =>
      h.requests[0].resolve(response(event("late private"))),
    );
    await flush();
    // Settle any auxiliary work started by an unfenced baseline head too, so
    // this regression observes both cache recreation and the disk write.
    if (h.aux[0]) await act(async () => h.aux[0].resolve([]));
    h.assertEmpty();
    assert.equal(
      h.aux.length,
      0,
      "cancelled head must not begin auxiliary work",
    );
  });
}

for (const outcome of ["resolve", "reject"]) {
  test(`CLOSED fences late auxiliary ${outcome} and snapshot writes`, async (t) => {
    const h = await harness(t);
    await waitFor(() => h.requests.length === 1);
    const message = event("head before revocation");
    await act(async () => h.requests[0].resolve(response(message)));
    await waitFor(() => h.aux.length === 1);
    assert.equal(
      h.client.getQueryData(["channel-messages", CHANNEL])[0].id,
      message.id,
    );
    await h.close();
    h.assertEmpty();
    await act(async () =>
      h.aux[0][outcome](outcome === "resolve" ? [] : new Error("late aux")),
    );
    await flush();
    h.assertEmpty();
  });
}

test("a rejoined channel accepts fresh history and cannot revive the cancelled head", async (t) => {
  const h = await harness(t);
  await waitFor(() => h.requests.length === 1);
  await h.close();
  await h.rejoin();
  await waitFor(() => h.requests.length === 2);
  const fresh = event("authorized rejoin");
  await act(async () => h.requests[1].resolve(response(fresh)));
  await waitFor(() => h.aux.length === 1);
  await act(async () => h.aux[0].resolve([]));
  await waitFor(() => h.client.isFetching() === 0);
  const writes = [...h.writes];
  await act(async () => h.requests[0].resolve(response(event("old private"))));
  await flush();
  assert.deepEqual(
    h.client.getQueryData(["channel-messages", CHANNEL]).map((item) => item.id),
    [fresh.id],
  );
  assert.deepEqual(
    readMessageSnapshot(h.scope).map((item) => item.id),
    [fresh.id],
  );
  assert.deepEqual(h.writes, writes);
});

test("open nonmember history remains readable and persists after auxiliary closure", async (t) => {
  const h = await harness(t, { visibility: "open", isMember: false });
  await waitFor(() => h.requests.length === 1);
  const message = event("public history");
  await act(async () => h.requests[0].resolve(response(message)));
  await waitFor(() => h.aux.length === 1);
  await act(async () => h.aux[0].resolve([]));
  await waitFor(() => h.client.isFetching() === 0);
  assert.deepEqual(
    readMessageSnapshot(h.scope).map((item) => item.id),
    [message.id],
  );
  assert.equal(h.writes.length, 1);
});

test("identity invalidation still fences a pending immediate-history response", async (t) => {
  const h = await harness(t);
  await waitFor(() => h.requests.length === 1);
  removeAllMessageSnapshots();
  await act(async () => {
    h.client.setQueryData(["channels"], []);
    h.client.removeQueries({ queryKey: ["channel-window", CHANNEL] });
    h.client.removeQueries({ queryKey: ["channel-messages", CHANNEL] });
  });
  await act(async () =>
    h.requests[0].resolve(response(event("previous identity"))),
  );
  await waitFor(() => h.client.isFetching() === 0);
  h.assertEmpty();
});

test("a revoked older page cannot append to a rejoined channel window", async (t) => {
  const h = await harness(t);
  await waitFor(() => h.requests.length === 1);
  const oldHead = event("old head");
  await act(async () => h.requests[0].resolve(response(oldHead, true)));
  await waitFor(() => h.aux.length === 1);
  await flush();
  let oldPage;
  await act(async () => {
    oldPage = h.fetchOlder();
  });
  await waitFor(() => h.requests.length === 2);
  assert.deepEqual(h.requests[1].args.cursor, {
    created_at: oldHead.created_at,
    event_id: oldHead.id,
  });
  await h.close();
  await act(async () => h.aux[0].resolve([]));
  await h.rejoin();
  await waitFor(() => h.requests.length === 3);
  // Rejoining may return the same head and cursor. Matching cursor values do
  // not authorize a page requested before revocation.
  const fresh = oldHead;
  await act(async () => h.requests[2].resolve(response(fresh, true)));
  await waitFor(() => h.aux.length === 2);
  await act(async () => h.aux[1].resolve([]));
  await waitFor(() => h.client.isFetching() === 0);
  await act(async () => {
    h.requests[1].resolve(
      response(
        event(
          "revoked older response",
          9,
          [["h", CHANNEL]],
          oldHead.created_at - 1,
        ),
        false,
        h.requests[1].args.cursor,
      ),
    );
    await oldPage;
  });
  assert.deepEqual(
    h.client.getQueryData(["channel-messages", CHANNEL]).map((item) => item.id),
    [fresh.id],
  );
  let freshPage;
  await act(async () => {
    freshPage = h.fetchOlder();
  });
  await waitFor(() => h.requests.length === 4);
  assert.deepEqual(h.requests[3].args.cursor, {
    created_at: fresh.created_at,
    event_id: fresh.id,
  });
  const authorizedOlder = event(
    "authorized older history",
    9,
    [["h", CHANNEL]],
    fresh.created_at - 2,
  );
  await act(async () => {
    h.requests[3].resolve(
      response(authorizedOlder, false, h.requests[3].args.cursor),
    );
    await freshPage;
  });
  assert.deepEqual(
    new Set(
      h.client
        .getQueryData(["channel-messages", CHANNEL])
        .map((item) => item.id),
    ),
    new Set([fresh.id, authorizedOlder.id]),
  );
});
