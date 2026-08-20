import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerMessageMutationCommands } from "./messageMutations.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const PUBKEY = "a".repeat(64);
const EVENT_ID = "b".repeat(64);
const REACTION_ID = "c".repeat(64);
const CHANNEL_ID = "123e4567-e89b-12d3-a456-426614174000";

function harness(events = []) {
  const signed = [];
  const published = [];
  const filters = [];
  const identity = {
    pubkey: () => PUBKEY,
    sign(request) {
      signed.push(request);
      return JSON.stringify({
        ...request,
        id: "d".repeat(64),
        pubkey: PUBKEY,
        created_at: 100,
        sig: "e".repeat(128),
      });
    },
  };
  const client = {
    async queryEvents(queryFilters) {
      filters.push(queryFilters);
      return events;
    },
    async publishEvent(event, timeoutMessage, sendErrorMessage) {
      published.push({ event, timeoutMessage, sendErrorMessage });
      return event;
    },
  };
  registerMessageMutationCommands(identity, client);
  return { filters, published, signed };
}

afterEach(() => resetRegistryForTests());

test("edit_message trims content and emits the complete kind-40003 tag shape", async () => {
  const { published, signed } = harness();
  await dispatch("edit_message", {
    input: {
      channelId: CHANNEL_ID.toUpperCase(),
      eventId: EVENT_ID.toUpperCase(),
      content: "  updated body  ",
      mediaTags: [["imeta", "url https://example.test/image.png"]],
      emojiTags: [["emoji", "party", "https://example.test/party.png"]],
      mentionPubkeys: [PUBKEY.toUpperCase(), PUBKEY],
      suppressLinkPreviews: true,
    },
  });

  assert.deepEqual(signed, [
    {
      kind: 40003,
      content: "updated body",
      tags: [
        ["h", CHANNEL_ID],
        ["e", EVENT_ID],
        ["p", PUBKEY],
        ["imeta", "url https://example.test/image.png"],
        ["emoji", "party", "https://example.test/party.png"],
        ["link-preview", "none"],
      ],
    },
  ]);
  assert.deepEqual(published[0], {
    event: {
      ...signed[0],
      id: "d".repeat(64),
      pubkey: PUBKEY,
      created_at: 100,
      sig: "e".repeat(128),
    },
    timeoutMessage: "Timed out while editing the message.",
    sendErrorMessage: "Failed while editing the message.",
  });
});

test("edit_message permits a media-only edit and rejects an empty edit", async () => {
  const { signed } = harness();
  await dispatch("edit_message", {
    input: {
      channelId: CHANNEL_ID,
      eventId: EVENT_ID,
      content: "  ",
      mediaTags: [["imeta", "url https://example.test/image.png"]],
    },
  });
  assert.equal(signed[0].content, "");

  await assert.rejects(
    dispatch("edit_message", {
      input: {
        channelId: CHANNEL_ID,
        eventId: EVENT_ID,
        content: "  ",
      },
    }),
    /edit must have content or attachments/,
  );
});

test("delete_message emits a channel-scoped NIP-09 event", async () => {
  const { signed } = harness();
  await dispatch("delete_message", {
    channelId: CHANNEL_ID,
    eventId: EVENT_ID,
  });
  assert.deepEqual(signed[0], {
    kind: 5,
    content: "",
    tags: [
      ["h", CHANNEL_ID],
      ["e", EVENT_ID],
    ],
  });
});

test("add_reaction emits standard and normalized NIP-30 reactions", async () => {
  const { signed } = harness();
  await dispatch("add_reaction", { eventId: EVENT_ID, emoji: " 👍 " });
  await dispatch("add_reaction", {
    eventId: EVENT_ID,
    emoji: ":Party_Parrot:",
    emojiUrl: "https://example.test/parrot.png",
  });

  assert.deepEqual(signed, [
    { kind: 7, content: "👍", tags: [["e", EVENT_ID]] },
    {
      kind: 7,
      content: ":party_parrot:",
      tags: [
        ["e", EVENT_ID],
        ["emoji", "party_parrot", "https://example.test/parrot.png"],
      ],
    },
  ]);
});

test("add_reaction rejects invalid custom emoji without signing", async () => {
  const { signed } = harness();
  await assert.rejects(
    dispatch("add_reaction", {
      eventId: EVENT_ID,
      emoji: "not valid",
      emojiUrl: "file:///tmp/emoji.png",
    }),
    /invalid custom emoji reaction: emoji shortcode may only contain ASCII/,
  );
  assert.deepEqual(signed, []);
});

test("remove_reaction queries the caller's reaction and deletes its event", async () => {
  const { filters, signed } = harness([
    {
      id: REACTION_ID,
      pubkey: PUBKEY,
      created_at: 90,
      kind: 7,
      tags: [["e", EVENT_ID]],
      content: " 👍 ",
      sig: "f".repeat(128),
    },
    {
      id: "1".repeat(64),
      pubkey: PUBKEY,
      created_at: 80,
      kind: 7,
      tags: [["e", EVENT_ID]],
      content: "👍",
      sig: "f".repeat(128),
    },
  ]);
  await dispatch("remove_reaction", { eventId: ` ${EVENT_ID} `, emoji: "👍" });

  assert.deepEqual(filters, [
    [
      {
        kinds: [7],
        "#e": [EVENT_ID],
        authors: [PUBKEY],
      },
    ],
  ]);
  assert.deepEqual(signed[0], {
    kind: 5,
    content: "",
    tags: [["e", REACTION_ID]],
  });
});

test("remove_reaction fails without publishing when no own match exists", async () => {
  const { published, signed } = harness([]);
  await assert.rejects(
    dispatch("remove_reaction", { eventId: EVENT_ID, emoji: "👍" }),
    /could not find your reaction event for this emoji/,
  );
  assert.deepEqual(signed, []);
  assert.deepEqual(published, []);
});
