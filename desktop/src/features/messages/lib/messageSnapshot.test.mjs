import assert from "node:assert/strict";
import test from "node:test";
import { finalizeEvent } from "nostr-tools/pure";

import {
  canonicalSnapshotRelayUrl,
  captureMessageSnapshotScope,
  mergeHistoryOverSnapshot,
  messageSnapshotKey,
  readMessageSnapshot,
  removeAllMessageSnapshots,
  removeMessageSnapshotsForCommunities,
  removeMessageSnapshotsForIdentity,
  writeMessageSnapshot,
} from "./messageSnapshot.ts";
import {
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
  KIND_CHANNEL_THREAD_SUMMARY,
  KIND_CHANNEL_WINDOW_BOUNDS,
} from "@/shared/constants/kinds";

const storage = new Map();
globalThis.window = {
  localStorage: {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
    key: (index) => [...storage.keys()][index] ?? null,
    get length() {
      return storage.size;
    },
  },
};

const RELAY = "wss://relay.example.com";
const SIGNER_A = "a".repeat(64);
const SIGNER_B = "b".repeat(64);
const EVENT_SECRET = new Uint8Array(32).fill(7);
let eventSequence = 1;

function makeEvent({
  channelId = "chan-1",
  content = "hello",
  created_at,
  kind = 9,
  tags,
  ...overrides
} = {}) {
  const sequence = eventSequence++;
  const eventTags = tags ?? [["h", channelId]];
  const tagsAreCanonical = eventTags.every(
    (tag) =>
      Array.isArray(tag) && tag.every((part) => typeof part === "string"),
  );
  return {
    ...finalizeEvent(
      {
        created_at: created_at ?? 1_700_000_000 + sequence,
        kind,
        tags: tagsAreCanonical ? eventTags : [["h", channelId]],
        content,
      },
      EVENT_SECRET,
    ),
    ...(tagsAreCanonical ? {} : { tags: eventTags }),
    ...overrides,
  };
}

function scope(
  signerPubkey = SIGNER_A,
  channelId = "chan-1",
  relayUrl = RELAY,
) {
  const captured = captureMessageSnapshotScope(
    relayUrl,
    signerPubkey,
    channelId,
  );
  assert.ok(captured);
  return captured;
}

function resetStorage() {
  removeAllMessageSnapshots();
  storage.clear();
}

test("scope and key canonicalize relay and signer while preserving channel", () => {
  resetStorage();
  const captured = scope(
    SIGNER_A.toUpperCase(),
    "channel:private",
    " WSS://Relay.Example.com/ ",
  );
  assert.equal(captured.relayUrl, RELAY);
  assert.equal(captured.signerPubkey, SIGNER_A);
  assert.equal(captured.channelId, "channel:private");
  assert.equal(
    messageSnapshotKey(captured),
    `buzz-channel-messages.v3:${encodeURIComponent(RELAY)}:${SIGNER_A}:channel%3Aprivate`,
  );
});

test("relay canonicalization normalizes authority but preserves path and query case", () => {
  assert.equal(
    canonicalSnapshotRelayUrl(" WSS://Relay.Example.com:443/ "),
    RELAY,
  );
  assert.equal(
    canonicalSnapshotRelayUrl("WS://Relay.Example.com:80/Path?Token=ABC"),
    "ws://relay.example.com/Path?Token=ABC",
  );
  assert.notEqual(
    canonicalSnapshotRelayUrl("wss://relay.example.com/Path?Token=ABC"),
    canonicalSnapshotRelayUrl("wss://relay.example.com/path?Token=ABC"),
  );
  assert.notEqual(
    canonicalSnapshotRelayUrl("wss://relay.example.com/Path?Token=ABC"),
    canonicalSnapshotRelayUrl("wss://relay.example.com/Path?Token=abc"),
  );
});

test("scope capture rejects malformed identity or empty channel input", () => {
  assert.equal(
    captureMessageSnapshotScope(RELAY, "not-a-pubkey", "chan"),
    null,
  );
  assert.equal(captureMessageSnapshotScope(RELAY, SIGNER_A, ""), null);
  assert.equal(captureMessageSnapshotScope(" ", SIGNER_A, "chan"), null);
});

test("read after write returns the exact identity-scoped events", () => {
  resetStorage();
  const captured = scope();
  const events = [makeEvent(), makeEvent()];
  assert.equal(writeMessageSnapshot(captured, events), true);
  assert.deepEqual(
    readMessageSnapshot(captured),
    JSON.parse(JSON.stringify(events)),
  );
});

test("all existing timeline and auxiliary kinds remain persistable", () => {
  resetStorage();
  const captured = scope();
  const kinds = [
    ...new Set([...CHANNEL_TIMELINE_CONTENT_KINDS, ...CHANNEL_AUX_EVENT_KINDS]),
  ];
  const events = kinds.map((kind) => makeEvent({ kind }));
  assert.equal(writeMessageSnapshot(captured, events), true);
  assert.deepEqual(
    readMessageSnapshot(captured).map((event) => event.kind),
    kinds,
  );
});

test("write rejects pending, local, unsigned, malformed, and wrong-channel events", async (t) => {
  const cases = [
    ["pending", { pending: true }],
    ["pending false", { pending: false }],
    ["localKey", { localKey: "optimistic-1" }],
    ["optimistic id", { id: "optimistic-1" }],
    ["empty signature", { sig: "" }],
    ["malformed pubkey", { pubkey: "bad" }],
    ["malformed tags", { tags: [["h", 1]] }],
    ["unknown event field", { unexpected: true }],
    ["missing channel tag", { tags: [["p", SIGNER_A]] }],
    ["wrong channel", { tags: [["h", "chan-2"]] }],
    ["thread-summary metadata", { kind: KIND_CHANNEL_THREAD_SUMMARY }],
    ["window-bounds metadata", { kind: KIND_CHANNEL_WINDOW_BOUNDS }],
    [
      "ambiguous channel",
      {
        tags: [
          ["h", "chan-1"],
          ["h", "chan-2"],
        ],
      },
    ],
  ];

  for (const [name, overrides] of cases) {
    await t.test(name, () => {
      resetStorage();
      const captured = scope();
      assert.equal(
        writeMessageSnapshot(captured, [makeEvent(), makeEvent(overrides)]),
        false,
      );
      assert.equal(storage.get(messageSnapshotKey(captured)), undefined);
    });
  }
});

test("write rejects a valid-shape forged tombstone", () => {
  resetStorage();
  const captured = scope();
  const tombstone = makeEvent({
    kind: 5,
    tags: [
      ["h", captured.channelId],
      ["e", "1".repeat(64)],
    ],
    content: "",
  });
  const forgedTombstone = { ...tombstone, content: "forged deletion" };

  assert.equal(
    writeMessageSnapshot(captured, [makeEvent(), forgedTombstone]),
    false,
  );
  assert.equal(storage.has(messageSnapshotKey(captured)), false);
});

test("read deletes a manually inserted snapshot with a forged canonical event", () => {
  resetStorage();
  const captured = scope();
  const tombstone = makeEvent({
    kind: 5,
    tags: [
      ["h", captured.channelId],
      ["e", "2".repeat(64)],
    ],
    content: "",
  });
  assert.equal(writeMessageSnapshot(captured, [makeEvent(), tombstone]), true);
  const key = messageSnapshotKey(captured);
  const payload = JSON.parse(storage.get(key));
  payload.events[1] = { ...payload.events[1], content: "forged deletion" };
  storage.set(key, JSON.stringify(payload));

  assert.equal(readMessageSnapshot(captured), null);
  assert.equal(storage.has(key), false);
});

test("read deletes corrupt or scope-mismatched payloads", async (t) => {
  const mutations = [
    ["wrong schema", (payload) => ({ ...payload, version: 2 })],
    [
      "wrong relay",
      (payload) => ({ ...payload, relayUrl: "wss://other.test" }),
    ],
    ["wrong signer", (payload) => ({ ...payload, signerPubkey: SIGNER_B })],
    ["wrong channel", (payload) => ({ ...payload, channelId: "chan-2" })],
    ["invalid timestamp", (payload) => ({ ...payload, updatedAt: "now" })],
    ["unknown payload field", (payload) => ({ ...payload, unexpected: true })],
    ["empty events", (payload) => ({ ...payload, events: [] })],
    [
      "malformed event",
      (payload) => ({
        ...payload,
        events: [{ ...payload.events[0], sig: "" }],
      }),
    ],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      resetStorage();
      const captured = scope();
      assert.equal(writeMessageSnapshot(captured, [makeEvent()]), true);
      const key = messageSnapshotKey(captured);
      storage.set(key, JSON.stringify(mutate(JSON.parse(storage.get(key)))));
      assert.equal(readMessageSnapshot(captured), null);
      assert.equal(storage.has(key), false);
    });
  }

  await t.test("invalid JSON", () => {
    resetStorage();
    const captured = scope();
    const key = messageSnapshotKey(captured);
    storage.set(key, "not-json{{{");
    assert.equal(readMessageSnapshot(captured), null);
    assert.equal(storage.has(key), false);
  });
});

test("read purges v1 and ambiguous v2 entries without migration", () => {
  resetStorage();
  const captured = scope();
  const legacyKey = `buzz-channel-messages.v1:${RELAY}:chan-1`;
  const previousKey = `buzz-channel-messages.v2:${RELAY}:${SIGNER_A}:chan-1`;
  storage.set(
    legacyKey,
    JSON.stringify({ version: 1, updatedAt: 1, events: [makeEvent()] }),
  );
  storage.set(
    previousKey,
    JSON.stringify({ version: 2, updatedAt: 1, events: [makeEvent()] }),
  );
  const unrelatedLegacyKey =
    "buzz-channel-messages.v1:wss://other.example.com:other-channel";
  storage.set(unrelatedLegacyKey, "legacy");
  assert.equal(readMessageSnapshot(captured), null);
  assert.equal(storage.has(legacyKey), false);
  assert.equal(storage.has(previousKey), false);
  assert.equal(storage.has(unrelatedLegacyKey), false);
  assert.equal(storage.has(messageSnapshotKey(captured)), false);
});

test("write and identity lifecycle reset purge both old namespaces", () => {
  resetStorage();
  const captured = scope();
  const oldKeys = [
    `buzz-channel-messages.v1:${RELAY}:chan-1`,
    `buzz-channel-messages.v2:${RELAY}:${SIGNER_A}:chan-1`,
  ];
  for (const key of oldKeys) storage.set(key, "old");
  assert.equal(writeMessageSnapshot(captured, [makeEvent()]), true);
  assert.ok(oldKeys.every((key) => !storage.has(key)));

  for (const key of oldKeys) storage.set(key, "old-again");
  removeMessageSnapshotsForIdentity(RELAY, SIGNER_A);
  assert.ok(oldKeys.every((key) => !storage.has(key)));

  for (const key of oldKeys) storage.set(key, "old-globally");
  removeAllMessageSnapshots();
  assert.ok(oldKeys.every((key) => !storage.has(key)));
});

test("escaped keys prevent accepted-scope collisions and isolate purges", () => {
  resetStorage();
  const suffix = "room:private";
  const left = scope(
    SIGNER_A,
    suffix,
    `wss://relay.example.com/path:${SIGNER_B}`,
  );
  const right = scope(
    SIGNER_B,
    `${SIGNER_A}:${suffix}`,
    "wss://relay.example.com/path",
  );
  const leftV2Key = `buzz-channel-messages.v2:${left.relayUrl}:${left.signerPubkey}:${left.channelId}`;
  const rightV2Key = `buzz-channel-messages.v2:${right.relayUrl}:${right.signerPubkey}:${right.channelId}`;
  assert.equal(leftV2Key, rightV2Key);
  assert.notEqual(messageSnapshotKey(left), messageSnapshotKey(right));

  assert.equal(
    writeMessageSnapshot(left, [makeEvent({ channelId: left.channelId })]),
    true,
  );
  assert.equal(
    writeMessageSnapshot(right, [makeEvent({ channelId: right.channelId })]),
    true,
  );
  removeMessageSnapshotsForIdentity(left.relayUrl, left.signerPubkey);

  assert.equal(readMessageSnapshot(left), null);
  assert.notEqual(readMessageSnapshot(right), null);
});

test("snapshot keeps only the newest bounded slice", () => {
  resetStorage();
  const captured = scope();
  const events = Array.from({ length: 200 }, () => makeEvent());
  assert.equal(writeMessageSnapshot(captured, events), true);
  const persisted = readMessageSnapshot(captured);
  assert.equal(persisted.length, 80);
  assert.equal(persisted.at(-1).id, events.at(-1).id);
  assert.equal(persisted[0].id, events[120].id);
});

test("per-identity channel cap evicts only that identity's oldest snapshot", () => {
  resetStorage();
  const otherIdentity = scope(SIGNER_B, "other");
  assert.equal(
    writeMessageSnapshot(otherIdentity, [makeEvent({ channelId: "other" })]),
    true,
  );
  for (let index = 0; index < 21; index += 1) {
    const channelId = `chan-${index}`;
    assert.equal(
      writeMessageSnapshot(scope(SIGNER_A, channelId), [
        makeEvent({ channelId }),
      ]),
      true,
    );
  }
  const retained = Array.from({ length: 21 }, (_, index) =>
    readMessageSnapshot(scope(SIGNER_A, `chan-${index}`)),
  ).filter(Boolean);
  assert.equal(retained.length, 20);
  assert.notEqual(readMessageSnapshot(otherIdentity), null);
});

test("community removal purges the exact relay+identity bucket", () => {
  resetStorage();
  const a = scope(SIGNER_A);
  const b = scope(SIGNER_B);
  assert.equal(writeMessageSnapshot(a, [makeEvent()]), true);
  assert.equal(writeMessageSnapshot(b, [makeEvent()]), true);

  removeMessageSnapshotsForIdentity(RELAY, SIGNER_A);

  assert.equal(storage.has(messageSnapshotKey(a)), false);
  assert.equal(writeMessageSnapshot(a, [makeEvent()]), false);
  assert.notEqual(readMessageSnapshot(b), null);
});

test("clearCommunities purges every removed relay for the current identity", () => {
  resetStorage();
  const secondRelay = "wss://second.example.com";
  const firstA = scope(SIGNER_A, "first", RELAY);
  const secondA = scope(SIGNER_A, "second", secondRelay);
  const firstB = scope(SIGNER_B, "first", RELAY);
  assert.equal(
    writeMessageSnapshot(firstA, [makeEvent({ channelId: "first" })]),
    true,
  );
  assert.equal(
    writeMessageSnapshot(secondA, [makeEvent({ channelId: "second" })]),
    true,
  );
  assert.equal(
    writeMessageSnapshot(firstB, [makeEvent({ channelId: "first" })]),
    true,
  );

  removeMessageSnapshotsForCommunities([RELAY, secondRelay], SIGNER_A);

  assert.equal(readMessageSnapshot(firstA), null);
  assert.equal(readMessageSnapshot(secondA), null);
  assert.notEqual(readMessageSnapshot(firstB), null);
});

test("clear or removal without a valid signer fails safe with a broad purge", () => {
  for (const signerPubkey of [null, "not-a-pubkey"]) {
    resetStorage();
    const a = scope(SIGNER_A);
    const b = scope(SIGNER_B);
    assert.equal(writeMessageSnapshot(a, [makeEvent()]), true);
    assert.equal(writeMessageSnapshot(b, [makeEvent()]), true);

    if (signerPubkey === null) {
      removeMessageSnapshotsForCommunities([RELAY], signerPubkey);
    } else {
      removeMessageSnapshotsForIdentity(RELAY, signerPubkey);
    }

    assert.equal(readMessageSnapshot(a), null);
    assert.equal(readMessageSnapshot(b), null);
  }
});

test("two identities on one origin cannot cross-read or resurrect stale data", () => {
  resetStorage();
  const privateA = scope(SIGNER_A, "private");
  assert.equal(
    writeMessageSnapshot(privateA, [makeEvent({ channelId: "private" })]),
    true,
  );
  const aKey = messageSnapshotKey(privateA);

  // Successful identity import/replacement uses this same invalidate+purge.
  removeAllMessageSnapshots();
  const privateB = scope(SIGNER_B, "private");

  assert.equal(readMessageSnapshot(privateB), null);
  assert.equal(storage.has(aKey), false);
  assert.equal(
    writeMessageSnapshot(privateA, [makeEvent({ channelId: "private" })]),
    false,
  );
  assert.equal(storage.has(aKey), false);
});

test("generation is rechecked immediately before storage commit", () => {
  resetStorage();
  const captured = scope();
  const event = makeEvent();
  let contentReads = 0;
  Object.defineProperty(event, "content", {
    enumerable: true,
    get() {
      contentReads += 1;
      if (contentReads === 2) removeAllMessageSnapshots();
      return "hello";
    },
  });
  assert.equal(writeMessageSnapshot(captured, [event]), false);
  assert.equal(storage.has(messageSnapshotKey(captured)), false);
});

test("write is tolerant of storage failures", () => {
  resetStorage();
  const original = window.localStorage.setItem;
  window.localStorage.setItem = () => {
    throw new Error("quota exceeded");
  };
  try {
    assert.equal(writeMessageSnapshot(scope(), [makeEvent()]), false);
  } finally {
    window.localStorage.setItem = original;
  }
});

test("cold snapshot load keeps snapshot rows and widens aux backfill", () => {
  const snapshotOnly = makeEvent({ created_at: 1_700_000_000 });
  const fresh = makeEvent({ created_at: 1_700_000_100 });
  const { merged, auxBackfillWindow } = mergeHistoryOverSnapshot({
    cached: undefined,
    snapshot: [snapshotOnly],
    history: [fresh],
  });
  assert.deepEqual(
    merged.map((event) => event.id),
    [snapshotOnly.id, fresh.id],
  );
  assert.deepEqual(auxBackfillWindow, merged);
});

test("warm load keeps aux backfill scoped to fresh history", () => {
  const cached = makeEvent({ created_at: 1_700_000_000 });
  const fresh = makeEvent({ created_at: 1_700_000_100 });
  const { merged, auxBackfillWindow } = mergeHistoryOverSnapshot({
    cached: [cached],
    snapshot: [makeEvent()],
    history: [fresh],
  });
  assert.ok(merged.some((event) => event.id === cached.id));
  assert.deepEqual(auxBackfillWindow, [fresh]);
});

test("cold load without a snapshot backfills fresh history only", () => {
  const fresh = makeEvent();
  const { merged, auxBackfillWindow } = mergeHistoryOverSnapshot({
    cached: undefined,
    snapshot: null,
    history: [fresh],
  });
  assert.deepEqual(merged, [fresh]);
  assert.deepEqual(auxBackfillWindow, [fresh]);
});
