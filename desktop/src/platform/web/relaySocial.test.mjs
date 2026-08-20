import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { dispatch, resetRegistryForTests } from "./registry.ts";
import { registerRelaySocialCommands } from "./relaySocial.ts";

const PUBKEY = "a".repeat(64);
const NOTE_ID = "b".repeat(64);
const OTHER_PUBKEY = "c".repeat(64);

const identity = {
  pubkey: () => PUBKEY,
  sign(request) {
    return JSON.stringify({
      ...request,
      id: "signed-note",
      pubkey: PUBKEY,
      created_at: 100,
      sig: "f".repeat(128),
    });
  },
};

function event({
  id = NOTE_ID,
  pubkey = OTHER_PUBKEY,
  createdAt = 10,
  kind = 1,
  content = "hello",
  tags = [],
} = {}) {
  return {
    id,
    pubkey,
    created_at: createdAt,
    kind,
    content,
    tags,
    sig: "f".repeat(128),
  };
}

afterEach(() => resetRegistryForTests());

test("publish_note signs kind 1 with native reply, mention, and imeta tags", async () => {
  const published = [];
  const client = {
    async fetchEvents() {
      return [];
    },
    async publishEvent(signed, timeoutMessage, sendErrorMessage) {
      published.push({ signed, timeoutMessage, sendErrorMessage });
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  assert.deepEqual(
    await dispatch("publish_note", {
      content: "hello",
      replyTo: NOTE_ID.toUpperCase(),
      mentionPubkeys: [OTHER_PUBKEY.toUpperCase(), OTHER_PUBKEY],
      mediaTags: [["imeta", "url https://example.test/image.png"]],
    }),
    { event_id: "signed-note", accepted: true, message: "" },
  );
  assert.deepEqual(published[0].signed, {
    id: "signed-note",
    pubkey: PUBKEY,
    created_at: 100,
    sig: "f".repeat(128),
    kind: 1,
    content: "hello",
    tags: [
      ["e", NOTE_ID, "", "reply"],
      ["p", OTHER_PUBKEY],
      ["imeta", "url https://example.test/image.png"],
    ],
  });
  assert.equal(
    published[0].timeoutMessage,
    "Timed out while publishing the note.",
  );
});

test("get_user_notes applies native limits/cursor and preserves relay order", async () => {
  const calls = [];
  const events = [
    event({ id: "1".repeat(64), createdAt: 30 }),
    event({ id: "2".repeat(64), createdAt: 20 }),
  ];
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      return events;
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  const response = await dispatch("get_user_notes", {
    pubkey: OTHER_PUBKEY,
    limit: 500,
    before: 40,
    beforeId: "ignored",
  });
  assert.deepEqual(calls, [
    { kinds: [1], authors: [OTHER_PUBKEY], limit: 100, until: 40 },
  ]);
  assert.deepEqual(response.next_cursor, {
    before: 20,
    before_id: "2".repeat(64),
  });
  assert.deepEqual(
    response.notes.map((note) => note.id),
    ["1".repeat(64), "2".repeat(64)],
  );
});

test("get_note validates ids and maps the first kind-1 event", async () => {
  const calls = [];
  const note = event({ tags: [["p", PUBKEY]] });
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      return [note];
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  assert.deepEqual(await dispatch("get_note", { noteId: NOTE_ID }), {
    id: NOTE_ID,
    pubkey: OTHER_PUBKEY,
    created_at: 10,
    content: "hello",
    tags: [["p", PUBKEY]],
  });
  assert.deepEqual(calls, [{ kinds: [1], ids: [NOTE_ID], limit: 1 }]);
  await assert.rejects(
    dispatch("get_note", { noteId: "bad" }),
    /invalid note id/,
  );
});

test("get_notes_timeline caps the multi-author query and sorts newest first", async () => {
  const calls = [];
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      return [
        event({ id: "1".repeat(64), createdAt: 10 }),
        event({ id: "2".repeat(64), createdAt: 30 }),
      ];
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  const response = await dispatch("get_notes_timeline", {
    pubkeys: [PUBKEY, OTHER_PUBKEY],
    limitPerUser: 99,
  });
  assert.deepEqual(calls, [
    { kinds: [1], authors: [PUBKEY, OTHER_PUBKEY], limit: 100 },
  ]);
  assert.deepEqual(
    response.notes.map((note) => note.created_at),
    [30, 10],
  );
  assert.equal(response.next_cursor, null);
});

test("get_feed mirrors native filters, sections, shapes, and type selection", async () => {
  const calls = [];
  const client = {
    async fetchEvents(filter) {
      calls.push(filter);
      if (filter.kinds[0] === 9) {
        return [event({ kind: 9, tags: [["h", "channel-id"]] })];
      }
      if (filter.kinds[0] === 40003) return [];
      return [event({ id: "d".repeat(64), kind: 46010 })];
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  const originalNow = Date.now;
  Date.now = () => 123_000;
  try {
    const response = await dispatch("get_feed", { since: 5, limit: 999 });
    assert.equal(calls.length, 3);
    assert.deepEqual(calls[0], {
      kinds: [
        9, 40002, 1, 45001, 45003, 1618, 1619, 1621, 1630, 1631, 1632, 1633,
      ],
      "#p": [PUBKEY],
      limit: 100,
      since: 5,
    });
    assert.deepEqual(calls[1], {
      kinds: [46010, 46011, 46012],
      "#p": [PUBKEY],
      limit: 20,
      since: 5,
    });
    assert.deepEqual(calls[2], {
      kinds: [40003],
      "#e": [NOTE_ID],
    });
    assert.deepEqual(response.feed.mentions[0], {
      id: NOTE_ID,
      kind: 9,
      pubkey: OTHER_PUBKEY,
      content: "hello",
      created_at: 10,
      channel_id: "channel-id",
      channel_name: "",
      channel_type: null,
      tags: [["h", "channel-id"]],
      category: "mentions",
    });
    assert.equal(response.feed.needs_action[0].category, "needs_action");
    assert.deepEqual(response.feed.activity, []);
    assert.deepEqual(response.feed.agent_activity, []);
    assert.deepEqual(response.meta, { since: 5, total: 2, generated_at: 123 });
  } finally {
    Date.now = originalNow;
  }

  calls.length = 0;
  await dispatch("get_feed", { types: "needs_action" });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].kinds, [46010, 46011, 46012]);
});

test("get_feed accepts same-author link-preview suppression edits", async () => {
  const client = {
    async fetchEvents(filter) {
      if (filter.kinds[0] === 9) return [event({ kind: 9 })];
      if (filter.kinds[0] === 40003) {
        return [
          event({
            id: "e".repeat(64),
            kind: 40003,
            tags: [
              ["e", NOTE_ID],
              ["link-preview", "none"],
            ],
          }),
        ];
      }
      return [];
    },
    async publishEvent(signed) {
      return signed;
    },
  };
  registerRelaySocialCommands(identity, client);

  const response = await dispatch("get_feed", { types: "mentions" });
  assert.deepEqual(response.feed.mentions[0].tags, [["link-preview", "none"]]);
});
