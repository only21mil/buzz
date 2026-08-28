import assert from "node:assert/strict";
import test from "node:test";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { messageDeliveryLabel } from "@/features/messages/lib/messageDeliveryStatus";

import {
  OFFLINE_MESSAGE_MAX_ATTEMPTS,
  OFFLINE_MESSAGE_MAX_COUNT,
  OFFLINE_MESSAGE_TTL_MS,
  OfflineMessageOutbox,
  OfflineMessageRetryDriver,
  createOfflineMessagePublisher,
} from "./offlineMessageOutbox.ts";

const SECRET = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const OTHER_SECRET = Uint8Array.from({ length: 32 }, (_, index) => index + 33);
const PUBKEY = getPublicKey(SECRET);
const OTHER_PUBKEY = getPublicKey(OTHER_SECRET);
const RELAY = "wss://relay.example";
const OTHER_RELAY = "wss://other-relay.example";
const CHANNEL = "12345678-1234-4234-8234-123456789abc";
const OTHER_CHANNEL = "22345678-1234-4234-8234-123456789abc";

test("message delivery labels distinguish queued and terminal failures", () => {
  assert.equal(messageDeliveryLabel("queued", true), "Queued offline");
  assert.equal(messageDeliveryLabel("failed", false), "Delivery failed");
  assert.equal(messageDeliveryLabel("expired", false), "Delivery expired");
  assert.equal(messageDeliveryLabel(undefined, true), "Sending…");
  assert.equal(messageDeliveryLabel(undefined, false), null);
});

class MemoryStore {
  records = new Map();

  async list() {
    return [...this.records.values()];
  }

  async put(record) {
    this.records.set(record.key, structuredClone(record));
  }

  async delete(key) {
    this.records.delete(key);
  }
}

function event(index, secret = SECRET, channel = CHANNEL) {
  return finalizeEvent(
    {
      created_at: 1_700_000_000 + index,
      kind: 9,
      tags: [["h", channel]],
      content: `message ${index}`,
    },
    secret,
  );
}

test("outbox is idempotent and bounded within its owning scope", async () => {
  const store = new MemoryStore();
  const statuses = [];
  const outbox = new OfflineMessageOutbox(store, (status) =>
    statuses.push(status),
  );
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };

  await outbox.enqueue(scope, event(0), 1_000);
  await outbox.enqueue(scope, event(0), 1_001);
  assert.equal(store.records.size, 1);

  for (let index = 1; index <= OFFLINE_MESSAGE_MAX_COUNT; index += 1) {
    await outbox.enqueue(scope, event(index), 1_001 + index);
  }
  assert.equal(store.records.size, OFFLINE_MESSAGE_MAX_COUNT);
  assert.equal(
    [...store.records.values()].some(
      (record) => record.event.id === event(0).id,
    ),
    false,
  );
  assert.equal(
    statuses.some(
      (status) => status.eventId === event(0).id && status.state === "failed",
    ),
    true,
  );
});

test("max-count eviction never crosses relay or account scope", async () => {
  const foreignScopes = [
    {
      scope: { relayUrl: OTHER_RELAY, pubkey: PUBKEY },
      eventSecret: SECRET,
    },
    {
      scope: { relayUrl: RELAY, pubkey: OTHER_PUBKEY },
      eventSecret: OTHER_SECRET,
    },
  ];

  for (const { scope: foreignScope, eventSecret } of foreignScopes) {
    const store = new MemoryStore();
    const statuses = [];
    const outbox = new OfflineMessageOutbox(store, (status) =>
      statuses.push(status),
    );
    for (let index = 0; index < OFFLINE_MESSAGE_MAX_COUNT; index += 1) {
      await outbox.enqueue(
        foreignScope,
        event(100 + index, eventSecret),
        1_000,
      );
    }
    statuses.length = 0;
    await outbox.enqueue(
      { relayUrl: RELAY, pubkey: PUBKEY },
      event(999),
      2_000,
    );

    assert.equal(store.records.size, OFFLINE_MESSAGE_MAX_COUNT + 1);
    assert.equal(
      [...store.records.values()].filter(
        (record) =>
          record.relayUrl === foreignScope.relayUrl &&
          record.pubkey === foreignScope.pubkey,
      ).length,
      OFFLINE_MESSAGE_MAX_COUNT,
    );
    assert.equal(
      statuses.some((status) => status.state === "failed"),
      false,
    );
  }
});

test("flush publishes only the active relay and signer scope in FIFO order", async () => {
  const store = new MemoryStore();
  const outbox = new OfflineMessageOutbox(store);
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  await outbox.enqueue(scope, event(2), 2_000);
  await outbox.enqueue(scope, event(1), 1_000);
  await outbox.enqueue(
    { relayUrl: RELAY, pubkey: OTHER_PUBKEY },
    event(3, OTHER_SECRET),
    3_000,
  );

  const published = [];
  const result = await outbox.flush(
    scope,
    async (queuedEvent) => published.push(queuedEvent.id),
    4_000,
  );

  assert.deepEqual(published, [event(1).id, event(2).id]);
  assert.deepEqual(result, {
    published: 2,
    remaining: 0,
    nextAttemptAt: null,
  });
  assert.equal(store.records.size, 1);
});

test("expired messages are discarded without publishing", async () => {
  const store = new MemoryStore();
  const statuses = [];
  const outbox = new OfflineMessageOutbox(store, (status) =>
    statuses.push(status),
  );
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  await outbox.enqueue(scope, event(1), 1_000);
  let calls = 0;

  const result = await outbox.flush(
    scope,
    async () => {
      calls += 1;
    },
    1_000 + OFFLINE_MESSAGE_TTL_MS,
  );

  assert.equal(calls, 0);
  assert.deepEqual(result, {
    published: 0,
    remaining: 0,
    nextAttemptAt: null,
  });
  assert.equal(statuses.at(-1).state, "expired");
  assert.equal(statuses.at(-1).eventId, event(1).id);
});

test("expiry and max-attempt sweep reports only the active relay and account", async () => {
  const store = new MemoryStore();
  const statuses = [];
  const outbox = new OfflineMessageOutbox(store, (status) =>
    statuses.push(status),
  );
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  const otherAccountScope = { relayUrl: RELAY, pubkey: OTHER_PUBKEY };
  const otherRelayScope = { relayUrl: OTHER_RELAY, pubkey: PUBKEY };
  await outbox.enqueue(scope, event(1), 1_000);
  await outbox.enqueue(otherAccountScope, event(2, OTHER_SECRET), 1_000);
  await outbox.enqueue(otherRelayScope, event(3), 1_000);
  const otherRelayRecord = [...store.records.values()].find(
    (record) => record.relayUrl === OTHER_RELAY,
  );
  store.records.set(otherRelayRecord.key, {
    ...otherRelayRecord,
    attempts: OFFLINE_MESSAGE_MAX_ATTEMPTS,
    expiresAt: 1_000 + OFFLINE_MESSAGE_TTL_MS + 1,
  });
  statuses.length = 0;

  const result = await outbox.flush(
    scope,
    async () => {
      throw new Error("expired active record must not publish");
    },
    1_000 + OFFLINE_MESSAGE_TTL_MS,
  );

  assert.deepEqual(result, {
    published: 0,
    remaining: 0,
    nextAttemptAt: null,
  });
  assert.equal(store.records.size, 2);
  assert.deepEqual(
    [...store.records.values()].map((record) => [
      record.relayUrl,
      record.pubkey,
    ]),
    [
      [RELAY, OTHER_PUBKEY],
      [OTHER_RELAY, PUBKEY],
    ],
  );
  assert.deepEqual(
    statuses.map((status) => [status.eventId, status.state]),
    [[event(1).id, "expired"]],
  );
});

test("retry is bounded before a later same-channel message can publish", async () => {
  const store = new MemoryStore();
  const statuses = [];
  const outbox = new OfflineMessageOutbox(store, (status) =>
    statuses.push(status),
  );
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  await outbox.enqueue(scope, event(1), 1_000);
  await outbox.enqueue(scope, event(2), 2_000);
  const calls = [];
  const firstEventId = event(1).id;

  for (let attempt = 0; attempt < OFFLINE_MESSAGE_MAX_ATTEMPTS; attempt += 1) {
    await outbox.flush(
      scope,
      async (queuedEvent) => {
        calls.push(queuedEvent.id);
        if (queuedEvent.id === firstEventId) throw new Error("offline");
      },
      1_000 + attempt * 10 * 60 * 1_000,
    );
  }

  assert.deepEqual(calls, [
    firstEventId,
    firstEventId,
    firstEventId,
    firstEventId,
    firstEventId,
    event(2).id,
  ]);
  assert.equal(store.records.size, 0);
  assert.deepEqual(
    statuses.findLast((status) => status.eventId === firstEventId),
    {
      eventId: event(1).id,
      channelId: CHANNEL,
      relayUrl: RELAY,
      pubkey: PUBKEY,
      state: "failed",
      attempts: OFFLINE_MESSAGE_MAX_ATTEMPTS,
    },
  );
});

test("a retrying channel does not starve an eligible different channel", async () => {
  const store = new MemoryStore();
  const outbox = new OfflineMessageOutbox(store, () => {});
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  const first = event(20);
  const laterSameChannel = event(21);
  const otherChannel = event(22, SECRET, OTHER_CHANNEL);
  await outbox.enqueue(scope, first, 1_000);
  await outbox.enqueue(scope, otherChannel, 1_500);
  await outbox.enqueue(scope, laterSameChannel, 2_000);
  const calls = [];

  const result = await outbox.flush(
    scope,
    async (queuedEvent) => {
      calls.push(queuedEvent.id);
      if (queuedEvent.id === first.id) throw new Error("connection closed");
    },
    3_000,
  );

  assert.deepEqual(calls, [first.id, otherChannel.id]);
  assert.deepEqual(result, {
    published: 1,
    remaining: 2,
    nextAttemptAt: 8_000,
  });
  assert.deepEqual(
    [...store.records.values()].map((record) => record.event.id).sort(),
    [first.id, laterSameChannel.id].sort(),
  );
});

class FakeRetryClock {
  now = 1_000;
  online = true;
  nextTimerId = 1;
  timers = new Map();

  setTimer = (callback, delayMs) => {
    const id = this.nextTimerId;
    this.nextTimerId += 1;
    this.timers.set(id, { at: this.now + delayMs, callback });
    return id;
  };

  clearTimer = (id) => {
    this.timers.delete(id);
  };

  fireNext() {
    const next = [...this.timers.entries()].sort(
      ([leftId, left], [rightId, right]) =>
        left.at - right.at || leftId - rightId,
    )[0];
    assert.ok(next, "expected a pending retry timer");
    const [id, timer] = next;
    this.timers.delete(id);
    this.now = timer.at;
    timer.callback();
  }
}

test("retry driver wakes exactly at nextAttemptAt and waits while offline", async () => {
  const clock = new FakeRetryClock();
  const flushTimes = [];
  const driver = new OfflineMessageRetryDriver(
    async () => {
      flushTimes.push(clock.now);
      return {
        published: 0,
        remaining: flushTimes.length === 1 ? 1 : 0,
        nextAttemptAt: flushTimes.length === 1 ? 6_000 : null,
      };
    },
    {
      now: () => clock.now,
      isOnline: () => clock.online,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    },
  );

  clock.online = false;
  await driver.flushNow();
  assert.deepEqual(flushTimes, []);
  assert.equal(clock.timers.size, 0);

  clock.online = true;
  await driver.flushNow();
  assert.deepEqual(flushTimes, [1_000]);
  assert.deepEqual(
    [...clock.timers.values()].map((timer) => timer.at),
    [6_000],
  );

  clock.fireNext();
  await driver.settled();
  assert.deepEqual(flushTimes, [1_000, 6_000]);
  assert.equal(clock.timers.size, 0);
});

test("retry driver coalesces signals without concurrent flushes", async () => {
  const clock = new FakeRetryClock();
  let releaseFirst;
  let calls = 0;
  let active = 0;
  let maxActive = 0;
  const driver = new OfflineMessageRetryDriver(
    async () => {
      calls += 1;
      active += 1;
      maxActive = Math.max(maxActive, active);
      if (calls === 1) {
        await new Promise((resolve) => {
          releaseFirst = resolve;
        });
      }
      active -= 1;
      return { published: 0, remaining: 0, nextAttemptAt: null };
    },
    {
      now: () => clock.now,
      isOnline: () => true,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    },
  );

  driver.wake();
  driver.wake();
  driver.wake();
  await Promise.resolve();
  assert.equal(calls, 1);
  releaseFirst();
  await driver.settled();

  assert.equal(calls, 2);
  assert.equal(maxActive, 1);
});

test("offline publish returns an explicit queued outcome", async () => {
  const store = new MemoryStore();
  const outbox = new OfflineMessageOutbox(store, () => {});
  const publisher = createOfflineMessagePublisher(
    () => ({ relayUrl: RELAY, pubkey: PUBKEY }),
    {
      publishEvent: async () => {
        throw new Error("offline publish must not reach the relay");
      },
    },
    outbox,
  );
  const descriptor = Object.getOwnPropertyDescriptor(navigator, "onLine");
  Object.defineProperty(navigator, "onLine", {
    configurable: true,
    value: false,
  });
  try {
    const queued = await publisher.publishOrQueue(event(9));
    assert.equal(queued.deliveryStatus, "queued");
    assert.equal(queued.event.id, event(9).id);
    assert.equal(store.records.size, 1);
  } finally {
    if (descriptor) Object.defineProperty(navigator, "onLine", descriptor);
    else delete navigator.onLine;
  }
});

test("online transport failure queues without trusting navigator status", async () => {
  const store = new MemoryStore();
  const publisher = createOfflineMessagePublisher(
    () => ({ relayUrl: RELAY, pubkey: PUBKEY }),
    {
      publishEvent: async () => {
        throw new Error("Relay connection closed.");
      },
    },
    new OfflineMessageOutbox(store, () => {}),
  );
  const descriptor = Object.getOwnPropertyDescriptor(navigator, "onLine");
  Object.defineProperty(navigator, "onLine", {
    configurable: true,
    value: true,
  });
  try {
    const queued = await publisher.publishOrQueue(event(10));
    assert.equal(queued.deliveryStatus, "queued");
    assert.equal(store.records.size, 1);
  } finally {
    if (descriptor) Object.defineProperty(navigator, "onLine", descriptor);
    else delete navigator.onLine;
  }
});

test("auth, validation, and permanent publish failures never enter the outbox", async () => {
  for (const message of [
    "Relay authentication rejected.",
    "invalid: malformed event",
    "blocked: publishing is permanently denied by policy",
  ]) {
    const store = new MemoryStore();
    const publisher = createOfflineMessagePublisher(
      () => ({ relayUrl: RELAY, pubkey: PUBKEY }),
      {
        publishEvent: async () => {
          throw new Error(message);
        },
      },
      new OfflineMessageOutbox(store, () => {}),
    );
    await assert.rejects(
      publisher.publishOrQueue(event(11)),
      (error) => error instanceof Error && error.message === message,
    );
    assert.equal(store.records.size, 0);
  }
});

test("outbox rejects unsigned and cross-signer records", async () => {
  const outbox = new OfflineMessageOutbox(new MemoryStore());
  const scope = { relayUrl: RELAY, pubkey: PUBKEY };
  await assert.rejects(
    outbox.enqueue(scope, { ...event(1), sig: "" }),
    /complete signed channel messages/,
  );
  await assert.rejects(
    outbox.enqueue(scope, event(2, OTHER_SECRET)),
    /scope does not match/,
  );
});
