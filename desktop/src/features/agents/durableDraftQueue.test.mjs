import assert from "node:assert/strict";
import test from "node:test";
import { DurableDraftStore } from "./durableDraftQueue.ts";
import {
  draftCanResume,
  draftStatusLabel,
  draftUnavailableReason,
} from "./durableDraftReview.ts";

const owner = "a".repeat(64);
const agent = "b".repeat(64);
const scope = { owner, relayUrl: "wss://community.example" };
const settle = () => new Promise((resolve) => setImmediate(resolve));
const request = (id, createdAt = 12) => ({
  id: String(id).padStart(64, "0"),
  pubkey: agent,
  created_at: createdAt,
  kind: 14201,
  tags: [
    ["r", `request-${id}`],
    ["h", "channel"],
    ["p", owner],
    ["agent", agent],
    ["v", "1"],
  ],
  content: "ciphertext",
  sig: "verified-by-native-fixture",
});
const payload = (event) => ({
  payload: {
    type: "agent_management_request",
    action: "create",
    requestId: event.tags.find(([key]) => key === "r")[1],
    request: {
      channelId: "channel",
      displayName: "Draft agent",
      systemPrompt: "Reviewed prompt",
    },
  },
});
const decision = (event, state = "rejected", generation = 1) => ({
  ...event,
  id: `f${event.id.slice(1)}`,
  pubkey: owner,
  kind: 14202,
  tags: [
    ["p", owner],
    ["v", "1"],
    ["e", event.id],
    ["state", state],
    ["generation", String(generation)],
  ],
});

function fixture({
  events = [],
  operations = [],
  history = [],
  connected = true,
  decrypt = payload,
} = {}) {
  const retained = new Map(events.map((event) => [event.id, event]));
  const calls = [];
  let receive;
  let connection;
  const store = new DurableDraftStore();
  const dependencies = {
    queue: async (bound) => {
      calls.push(["queue", bound]);
      return { events: [...retained.values()], operations };
    },
    receive: async (bound, event) => {
      calls.push(["receive", bound, event.id]);
      retained.set(event.id, event);
    },
    decrypt: async (event) => {
      calls.push(["decrypt", event.id]);
      return decrypt(event);
    },
    backfill: async (bound, cursor) => {
      calls.push(["backfill", bound, cursor]);
      return history
        .filter(
          (event) =>
            cursor.until === undefined ||
            event.created_at < cursor.until ||
            (event.created_at === cursor.until && event.id > cursor.beforeId),
        )
        .slice(0, cursor.limit);
    },
    subscribe: (_filter, listener) => {
      receive = listener;
      calls.push(["subscribe"]);
      return () => calls.push(["unsubscribe"]);
    },
    connection: (listener) => {
      connection = listener;
      listener(connected);
      return () => {};
    },
  };
  const stop = store.start(scope, dependencies);
  return {
    store,
    stop,
    dependencies,
    calls,
    retained,
    receive: (event) => receive(event),
    connection: (state) => connection(state),
  };
}

test("offline retained queue and restart preserve a terminal result without replaying effects", async () => {
  const event = request(1);
  const f = fixture({ events: [event, decision(event)], connected: false });
  await settle();
  assert.equal(f.store.getSnapshot().items.length, 1);
  assert.equal(f.store.getSnapshot().items[0].decision, "rejected");
  assert.equal(f.store.getSnapshot().ready, false);
  assert.equal(
    f.calls.some(([call]) => call === "backfill"),
    false,
  );
  f.store.select(scope, event.id);
  assert.throws(() => f.store.assertCurrent(scope, event.id), /offline/);
  f.store.select(scope, null);
  f.stop();
  const restart = fixture({
    events: [...f.retained.values()],
    connected: false,
  });
  await settle();
  assert.equal(
    draftStatusLabel(restart.store.getSnapshot().items[0]),
    "Rejected",
  );
  assert.ok(
    [...f.calls, ...restart.calls].every(([call]) =>
      ["queue", "decrypt", "subscribe", "unsubscribe"].includes(call),
    ),
  );
  restart.stop();
});

test("keyset backfill crosses multiple pages in the same second without eviction or duplicates", async () => {
  const history = Array.from({ length: 451 }, (_, index) => request(index));
  const f = fixture({ history });
  await settle();
  assert.equal(f.store.getSnapshot().ready, true);
  assert.equal(f.store.getSnapshot().items.length, 451);
  assert.equal(f.calls.filter(([call]) => call === "backfill").length, 3);
  f.receive(history[0]);
  f.receive(history[200]);
  await settle();
  assert.equal(f.store.getSnapshot().items.length, 451);
  assert.equal(f.calls.filter(([call]) => call === "decrypt").length, 451);
  f.stop();
});

test("outcome-before-request and reconnect replay never expose an actionable request", async () => {
  const event = request(1);
  const f = fixture();
  await settle();
  f.receive(decision(event, "applied", 2));
  f.receive(event);
  await settle();
  assert.equal(f.store.getSnapshot().items[0].decision, "applied");
  f.connection(false);
  f.connection(true);
  await settle();
  assert.equal(f.store.getSnapshot().items[0].decision, "applied");
  f.stop();
});

test("registered managed-agent policy remains unavailable until current shared membership exists", async () => {
  const f = fixture({ history: [request(1)] });
  await settle();
  const item = f.store.getSnapshot().items[0];
  const channels = [{ id: "channel", isMember: true, memberPubkeys: [agent] }];
  assert.match(
    draftUnavailableReason(item, [], channels),
    /registered managed agent/,
  );
  assert.equal(
    draftUnavailableReason(item, [{ pubkey: agent }], channels),
    null,
  );
  assert.match(
    draftUnavailableReason(
      item,
      [{ pubkey: agent }],
      [{ ...channels[0], isMember: false }],
    ),
    /Unavailable/,
  );
  assert.match(
    draftUnavailableReason(
      item,
      [{ pubkey: agent }],
      [{ ...channels[0], memberPubkeys: [] }],
    ),
    /Unavailable/,
  );
  f.stop();
});

test("switch owner or community during decrypt fences old plaintext, callbacks and selections", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const event = request(1);
  const f = fixture({
    events: [event],
    decrypt: async () => {
      await gate;
      return payload(event);
    },
  });
  await settle();
  f.stop();
  const changed = { owner: "c".repeat(64), relayUrl: "wss://other.example" };
  const nextStop = f.store.start(changed, {
    ...f.dependencies,
    queue: async () => ({ events: [], operations: [] }),
  });
  release();
  await settle();
  assert.equal(f.store.getSnapshot().items.length, 0);
  assert.deepEqual(f.store.getSnapshot().scope, changed);
  f.store.select(scope, event.id);
  assert.equal(f.store.getSnapshot().selectedId, null);
  assert.throws(
    () => f.store.assertCurrent(scope, event.id),
    /no longer active/,
  );
  nextStop();
});

test("mismatched encrypted request UUID or channel is retained unavailable", async () => {
  const event = request(1);
  for (const mutate of [
    (value) => {
      value.payload.requestId = "another-request";
    },
    (value) => {
      value.payload.request.channelId = "another-channel";
    },
  ]) {
    const f = fixture({
      events: [event],
      decrypt: (row) => {
        const value = payload(row);
        mutate(value);
        return value;
      },
    });
    await settle();
    assert.equal(f.store.getSnapshot().items[0].request, null);
    assert.match(f.store.getSnapshot().items[0].unavailable, /does not match/);
    f.stop();
  }
});

test("prepared, partial saved and uncertain operations survive restart without automatic retry", async () => {
  for (const state of ["prepared", "saved", "uncertain", "applied"]) {
    const event = request(1);
    const operation = {
      requestEventId: event.id,
      targetId: "stable-persona",
      state,
      action: "start",
    };
    const f = fixture({ events: [event], operations: [operation] });
    await settle();
    assert.deepEqual(f.store.getSnapshot().items[0].operation, operation);
    assert.ok(
      f.calls.every(([call]) =>
        ["queue", "decrypt", "subscribe", "backfill"].includes(call),
      ),
    );
    f.stop();
  }
});

test("read/retain failure keeps review disabled and explicit refresh recovers", async () => {
  const f = fixture({ history: [request(1)] });
  await settle();
  const original = f.dependencies.queue;
  f.dependencies.queue = async () => {
    throw new Error("local store unavailable");
  };
  await f.store.refresh();
  assert.equal(f.store.getSnapshot().ready, false);
  assert.match(f.store.getSnapshot().error, /local store unavailable/);
  f.dependencies.queue = original;
  await f.store.refresh();
  assert.equal(f.store.getSnapshot().ready, true);
  f.stop();
});

test("ordinary closing invalidates retained review callbacks", async () => {
  const event = request(1);
  const f = fixture({ history: [event] });
  await settle();
  f.store.select(scope, event.id);
  assert.equal(f.store.assertCurrent(scope, event.id).event.id, event.id);
  f.store.select(scope, null);
  assert.throws(
    () => f.store.assertCurrent(scope, event.id),
    /no longer active/,
  );
  f.stop();
});

test("returning to the same owner/community cannot revive a previous review epoch", async () => {
  const event = request(1);
  const f = fixture({ history: [event] });
  await settle();
  const oldEpoch = f.store.getEpoch();
  f.stop();
  const stop = f.store.start(scope, f.dependencies);
  await settle();
  f.store.select(scope, event.id);
  assert.throws(
    () => f.store.assertCurrent(scope, event.id, true, oldEpoch),
    /no longer active/,
  );
  assert.equal(f.store.assertCurrent(scope, event.id).event.id, event.id);
  stop();
});

test("a competing terminal decision closes locally prepared approval retry", () => {
  for (const state of ["prepared", "claimed"]) {
    for (const decision of ["applied", "rejected"]) {
      const item = { decision, operation: { state, action: "start" } };
      assert.equal(draftCanResume(item), false);
      assert.match(
        draftStatusLabel(item),
        /Applied on an owner device|Rejected/,
      );
    }
  }
  assert.equal(
    draftCanResume({ decision: "applied", operation: { state: "saved" } }),
    true,
  );
  assert.equal(
    draftCanResume({ decision: "applying", operation: { state: "uncertain" } }),
    false,
  );
});
