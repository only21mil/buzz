import assert from "node:assert/strict";
import { test } from "node:test";

import { nip44 } from "nostr-tools";
import { nsecEncode } from "nostr-tools/nip19";
import { finalizeEvent, getPublicKey, verifyEvent } from "nostr-tools/pure";

import { registerRelayCryptoSocialCommands } from "./relayCryptoSocial.ts";
import {
  dispatch,
  getUnregisteredCommandMissCount,
  register,
  resetRegistryForTests,
} from "../registry.ts";

const OWNER_SECRET = Uint8Array.from({ length: 32 }, (_, index) =>
  index === 31 ? 1 : 0,
);
const AGENT_SECRET = Uint8Array.from({ length: 32 }, (_, index) =>
  index === 31 ? 2 : 0,
);
const RELAY_SECRET = Uint8Array.from({ length: 32 }, (_, index) =>
  index === 31 ? 3 : 0,
);
const OWNER = getPublicKey(OWNER_SECRET);
const AGENT = getPublicKey(AGENT_SECRET);
const RELAY = getPublicKey(RELAY_SECRET);
const NOTE_A = "a".repeat(64);
const CHANNEL = "123e4567-e89b-42d3-a456-426614174000";
const RELAY_HTTP = "https://relay.example.test";

function signedEvent(
  secret,
  { kind, content = "", tags = [], createdAt = 100 },
) {
  return finalizeEvent(
    { kind, content, tags, created_at: createdAt },
    Uint8Array.from(secret),
  );
}

function identity(secret = OWNER_SECRET) {
  return {
    pubkey: () => getPublicKey(secret),
    getNsec: () => nsecEncode(secret),
    sign(request) {
      return JSON.stringify(
        signedEvent(secret, {
          kind: request.kind,
          content: request.content,
          tags: request.tags,
          createdAt: request.createdAt ?? 100,
        }),
      );
    },
  };
}

function fakeClient(overrides = {}) {
  return {
    async fetchEvents() {
      return [];
    },
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(event) {
      return event;
    },
    ...overrides,
  };
}

const cases = [
  {
    command: "archive_identity",
    async run() {
      const published = [];
      const client = fakeClient({
        async publishEvent(event) {
          published.push(event);
          return event;
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      const result = await dispatch("archive_identity", {
        req: {
          targetPubkey: OWNER,
          content: "retired identity",
          reason: "retired",
          replacedBy: AGENT,
        },
      });
      assert.equal(result.accepted, true);
      assert.equal(published[0].kind, 9035);
      assert.deepEqual(published[0].tags, [
        ["-"],
        ["p", OWNER],
        ["reason", "retired"],
        ["replaced-by", AGENT],
      ]);
    },
  },
  {
    command: "build_observer_control_event",
    async run() {
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      const eventJson = await dispatch("build_observer_control_event", {
        agentPubkey: AGENT,
        payload: { type: "cancel", turnId: "turn-1" },
      });
      const event = JSON.parse(eventJson);
      assert.equal(verifyEvent(event), true);
      assert.equal(event.kind, 24200);
      assert.deepEqual(event.tags, [
        ["p", AGENT],
        ["agent", AGENT],
        ["frame", "control"],
      ]);
      const key = nip44.v2.utils.getConversationKey(AGENT_SECRET, OWNER);
      assert.deepEqual(JSON.parse(nip44.v2.decrypt(event.content, key)), {
        type: "cancel",
        turnId: "turn-1",
      });
      key.fill(0);
    },
  },
  {
    command: "decrypt_observer_event",
    async run() {
      const key = nip44.v2.utils.getConversationKey(AGENT_SECRET, OWNER);
      const content = nip44.v2.encrypt(
        JSON.stringify({ type: "turn_started", turnId: "turn-2" }),
        key,
      );
      key.fill(0);
      const event = signedEvent(AGENT_SECRET, {
        kind: 24200,
        content,
        tags: [
          ["p", OWNER],
          ["agent", AGENT],
          ["frame", "telemetry"],
        ],
      });
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      assert.deepEqual(
        await dispatch("decrypt_observer_event", {
          eventJson: JSON.stringify(event),
        }),
        { type: "turn_started", turnId: "turn-2" },
      );
    },
  },
  {
    command: "fetch_snapshot_bytes",
    async run() {
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      await assert.rejects(
        dispatch("fetch_snapshot_bytes", {
          url: `${RELAY_HTTP}/media/${"c".repeat(64)}.json`,
          filename: "eva.agent.json",
          expectedSha256: "c".repeat(64),
          expectedSize: 1,
        }),
        (error) => error.name === "BrowserUnavailableError",
      );
    },
  },
  {
    command: "fetch_workspace_icon",
    async run() {
      globalThis.fetch = async (url, options) => {
        assert.equal(String(url), RELAY_HTTP);
        assert.equal(options.headers.Accept, "application/nostr+json");
        return new Response(
          JSON.stringify({ icon: "https://cdn.example/icon.png" }),
          {
            status: 200,
          },
        );
      };
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      assert.equal(
        await dispatch("fetch_workspace_icon", {
          relayUrl: "wss://relay.example.test",
        }),
        "https://cdn.example/icon.png",
      );
    },
  },
  {
    command: "get_global_notes",
    async run() {
      const note = signedEvent(AGENT_SECRET, {
        kind: 1,
        content: "hello pulse",
        createdAt: 90,
      });
      const client = fakeClient({
        async fetchEvents(filter) {
          assert.deepEqual(filter, { kinds: [1], limit: 25, until: 91 });
          return [note];
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      assert.deepEqual(
        await dispatch("get_global_notes", { limit: 25, before: 91 }),
        {
          notes: [
            {
              id: note.id,
              pubkey: AGENT,
              created_at: 90,
              content: "hello pulse",
              tags: [],
            },
          ],
          next_cursor: { before: 90, before_id: note.id },
        },
      );
    },
  },
  {
    command: "get_liked_notes",
    async run() {
      const reaction = signedEvent(OWNER_SECRET, {
        kind: 7,
        content: "+",
        tags: [["e", NOTE_A]],
        createdAt: 200,
      });
      const note = {
        ...signedEvent(AGENT_SECRET, {
          kind: 1,
          content: "liked",
          createdAt: 100,
        }),
        id: NOTE_A,
      };
      const client = fakeClient({
        async fetchEvents(filter) {
          if (filter.kinds[0] === 7) {
            assert.deepEqual(filter, {
              kinds: [7],
              authors: [OWNER],
              limit: 20,
            });
            return [reaction];
          }
          if (filter.kinds[0] === 5) return [];
          assert.deepEqual(filter, { kinds: [1], ids: [NOTE_A], limit: 5 });
          return [note];
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      const result = await dispatch("get_liked_notes", {
        authorPubkey: OWNER,
        limit: 5,
      });
      assert.equal(result.notes[0].id, NOTE_A);
      assert.equal(result.notes[0].content, "liked");
    },
  },
  {
    command: "get_note_reactions",
    async run() {
      const reaction = signedEvent(AGENT_SECRET, {
        kind: 7,
        content: "🔥",
        tags: [["e", NOTE_A]],
      });
      const client = fakeClient({
        async fetchEvents(filter) {
          if (filter.kinds[0] === 7) {
            assert.deepEqual(filter, {
              kinds: [7],
              "#e": [NOTE_A],
              limit: 500,
            });
            return [reaction, reaction];
          }
          return [];
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      assert.deepEqual(
        await dispatch("get_note_reactions", { noteIds: [NOTE_A] }),
        [{ note_id: NOTE_A, emoji: "🔥", count: 1, pubkeys: [AGENT] }],
      );
    },
  },
  {
    command: "has_managed_agent_channel_message_marker",
    async run() {
      const marked = signedEvent(AGENT_SECRET, {
        kind: 9,
        tags: [
          ["h", CHANNEL],
          ["client", "managed:welcome"],
        ],
      });
      const client = fakeClient({
        async fetchEvents(filter) {
          assert.deepEqual(filter, {
            kinds: [9],
            "#h": [CHANNEL],
            limit: 500,
            authors: [AGENT],
          });
          return [marked];
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      assert.equal(
        await dispatch("has_managed_agent_channel_message_marker", {
          channelId: CHANNEL,
          marker: "managed:welcome",
          agentPubkey: AGENT,
          markerScope: "agent",
        }),
        true,
      );
    },
  },
  {
    command: "get_relay_self",
    async run() {
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      globalThis.fetch = async (url, options) => {
        assert.equal(String(url), RELAY_HTTP);
        assert.equal(options.headers.Accept, "application/nostr+json");
        return new Response(JSON.stringify({ self: RELAY.toUpperCase() }), {
          status: 200,
        });
      };
      assert.equal(await dispatch("get_relay_self"), RELAY);
      globalThis.fetch = async () => new Response("nope", { status: 404 });
      assert.equal(await dispatch("get_relay_self"), null);
      globalThis.fetch = async () =>
        new Response(JSON.stringify({ self: "not-hex" }), { status: 200 });
      assert.equal(await dispatch("get_relay_self"), null);
      globalThis.fetch = async () => new Response("{", { status: 200 });
      await assert.rejects(dispatch("get_relay_self"), /malformed NIP-11/);
    },
  },
  {
    command: "list_archived_identities",
    async run() {
      const snapshot = signedEvent(RELAY_SECRET, {
        kind: 13535,
        tags: [
          ["p", AGENT.toUpperCase()],
          ["p", "not-a-pubkey"],
        ],
      });
      globalThis.fetch = async (url, options) => {
        assert.equal(String(url), RELAY_HTTP);
        assert.equal(options.headers.Accept, "application/nostr+json");
        return new Response(JSON.stringify({ self: RELAY }), { status: 200 });
      };
      const client = fakeClient({
        async fetchFirstEvent(filter) {
          assert.deepEqual(filter, {
            authors: [RELAY],
            kinds: [13535],
            limit: 1,
          });
          return snapshot;
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      assert.deepEqual(await dispatch("list_archived_identities"), {
        archived: [AGENT],
      });
    },
  },
  {
    command: "save_agent_card",
    async run() {
      const png = Uint8Array.from([
        ...new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
        1,
        2,
        3,
      ]);
      let clicked;
      globalThis.document = {
        createElement(name) {
          assert.equal(name, "a");
          return {
            href: "",
            download: "",
            click() {
              clicked = { href: this.href, download: this.download };
            },
          };
        },
      };
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      assert.equal(
        await dispatch("save_agent_card", {
          cardPngBase64: Buffer.from(png).toString("base64"),
          fileName: "eva.agent.png",
        }),
        true,
      );
      assert.equal(clicked.download, "eva.agent.png");
      assert.match(clicked.href, /^blob:nodedata:/);
    },
  },
  {
    command: "sign_nostr_identity_binding",
    async run() {
      registerRelayCryptoSocialCommands(identity(), fakeClient());
      const event = JSON.parse(
        await dispatch("sign_nostr_identity_binding", {
          challengeId: CHANNEL,
          nonce: "A".repeat(43),
          verificationCode: "123456",
          origin: "https://app.example.test",
          expiresAt: "2999-01-01T00:00:00Z",
        }),
      );
      assert.equal(verifyEvent(event), true);
      assert.equal(event.kind, 24243);
      assert.deepEqual(event.tags, [
        ["challenge_id", CHANNEL],
        ["nonce", "A".repeat(43)],
        ["verification_code", "123456"],
        ["audience", "buzz:nostr-identity"],
        ["action", "bind_nostr_identity"],
        ["protocol", "buzz-nostr-identity"],
        ["version", "1"],
        ["origin", "https://app.example.test"],
        ["expires_at", "2999-01-01T00:00:00Z"],
      ]);
    },
  },
  {
    command: "unarchive_identity",
    async run() {
      const published = [];
      const client = fakeClient({
        async publishEvent(event) {
          published.push(event);
          return event;
        },
      });
      registerRelayCryptoSocialCommands(identity(), client);
      await dispatch("unarchive_identity", {
        req: { targetPubkey: OWNER, content: "restored", reason: "restored" },
      });
      assert.equal(published[0].kind, 9036);
      assert.deepEqual(published[0].tags, [
        ["-"],
        ["p", OWNER],
        ["reason", "restored"],
      ]);
    },
  },
];

test("relay crypto/social PAL handlers mirror browser-capable desktop semantics", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalDocument = globalThis.document;
  for (const entry of cases) {
    await t.test(entry.command, async () => {
      resetRegistryForTests();
      register("get_relay_http_url", () => RELAY_HTTP);
      try {
        await entry.run();
        assert.equal(
          getUnregisteredCommandMissCount(),
          0,
          `${entry.command} must be registered`,
        );
      } finally {
        globalThis.fetch = originalFetch;
        if (originalDocument === undefined) delete globalThis.document;
        else globalThis.document = originalDocument;
      }
    });
  }
});
