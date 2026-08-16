import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";

import { listen } from "./shims/event.ts";
import {
  getMyRelayMembership,
  relayRequiresMembership,
  resolveOaOwner,
  showNativeNotification,
} from "./relayMembershipStatus.ts";

const PUBKEY = "a".repeat(64);
const workspace = {
  httpUrl: () => "https://relay.example.test",
};

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const originalNotification = globalThis.Notification;
const originalWindow = globalThis.window;

afterEach(() => {
  globalThis.Notification = originalNotification;
  globalThis.window = originalWindow;
});

test("relay membership discovery reads NIP-11 /info with an optional relay override", async () => {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url: String(url), init });
    return response({ supported_nips: [1, 43] });
  };

  assert.equal(await relayRequiresMembership({}, workspace, fetchImpl), true);
  assert.equal(
    await relayRequiresMembership(
      { relayUrl: "ws://other.example.test/" },
      workspace,
      fetchImpl,
    ),
    true,
  );
  assert.deepEqual(
    requests.map((request) => request.url),
    ["https://relay.example.test/info", "http://other.example.test/info"],
  );
  assert.equal(requests[0].init.headers.Accept, "application/nostr+json");
});

test("relay membership discovery distinguishes relay failures from a parsed false", async () => {
  assert.equal(
    await relayRequiresMembership({}, workspace, async () =>
      response({ supported_nips: [1] }),
    ),
    false,
  );
  await assert.rejects(
    relayRequiresMembership({}, workspace, async () => {
      throw new Error("network down");
    }),
    /relay information request failed/i,
  );
  await assert.rejects(
    relayRequiresMembership({}, workspace, async () => response({}, 503)),
    /relay information request failed.*503/i,
  );
  await assert.rejects(
    relayRequiresMembership(
      {},
      workspace,
      async () => new Response("{", { status: 200 }),
    ),
    /malformed NIP-11 document/i,
  );
  await assert.rejects(
    relayRequiresMembership({}, workspace, async () => response([])),
    /malformed NIP-11 document/i,
  );
  await assert.rejects(
    relayRequiresMembership({}, workspace, async () =>
      response({ supported_nips: "43" }),
    ),
    /malformed NIP-11 document/i,
  );
});

test("get_my_relay_membership mirrors current member and legacy p-tag shapes", async () => {
  const event = {
    id: "membership",
    pubkey: "b".repeat(64),
    created_at: 1,
    kind: 13534,
    content: "",
    sig: "f".repeat(128),
    tags: [
      ["member", "c".repeat(64), "admin"],
      ["p", PUBKEY, "wss://relay.example.test", "owner"],
    ],
  };
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, { kinds: [13534], limit: 1 });
      return event;
    },
  };
  assert.deepEqual(
    await getMyRelayMembership({ pubkey: () => PUBKEY }, client),
    { member: { pubkey: PUBKEY, role: "owner" } },
  );
  assert.deepEqual(
    await getMyRelayMembership({ pubkey: () => "d".repeat(64) }, client),
    { member: null },
  );
});

test("resolve_oa_owner verifies the NIP-OA attestation before naming the owner", async () => {
  const targetSecret = new Uint8Array(32);
  targetSecret[31] = 2;
  const targetPubkey = getPublicKey(targetSecret);
  const ownerSecret = new Uint8Array(32);
  ownerSecret[31] = 1;
  const owner = bytesToHex(schnorr.getPublicKey(ownerSecret));
  const conditions = "created_at<4294967295";
  const message = sha256(
    utf8ToBytes(`nostr:agent-auth:${targetPubkey}:${conditions}`),
  );
  const signature = bytesToHex(schnorr.sign(message, ownerSecret));
  const validAuthTag = ["auth", owner, conditions, signature];
  const signedProfile = (tags) =>
    finalizeEvent(
      { created_at: 1, kind: 0, content: "{}", tags },
      targetSecret,
    );
  let event = signedProfile([
    ["auth", owner, conditions, "0".repeat(128)],
    validAuthTag,
  ]);
  const client = {
    async fetchFirstEvent(filter) {
      assert.deepEqual(filter, {
        authors: [targetPubkey],
        kinds: [0],
        limit: 1,
      });
      return event;
    },
  };

  assert.deepEqual(
    await resolveOaOwner({ targetPubkey }, { pubkey: () => owner }, client),
    { owner, is_me: true },
  );
  event = signedProfile([
    ["auth", owner, conditions, "0".repeat(128)],
    ["auth", owner, conditions, "0".repeat(128)],
  ]);
  assert.equal(
    await resolveOaOwner({ targetPubkey }, { pubkey: () => owner }, client),
    null,
  );
  event = signedProfile([validAuthTag]);
  event = {
    id: event.id,
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: "tampered",
    sig: event.sig,
  };
  assert.equal(
    await resolveOaOwner({ targetPubkey }, { pubkey: () => owner }, client),
    null,
  );
});

test("show_native_notification uses the browser API and forwards click targets", async () => {
  const notifications = [];
  let focused = 0;
  class FakeNotification {
    static permission = "granted";

    constructor(title, options) {
      this.title = title;
      this.options = options;
      notifications.push(this);
    }

    close() {
      this.closed = true;
    }
  }
  globalThis.Notification = FakeNotification;
  globalThis.window = { focus: () => (focused += 1) };
  const targets = [];
  const unlisten = await listen("native-notification-activated", (event) =>
    targets.push(event.payload),
  );

  await showNativeNotification({
    title: "New message",
    body: "hello",
    target: { channelId: "general" },
  });
  assert.equal(notifications.length, 1);
  assert.deepEqual(notifications[0].options, { body: "hello", silent: true });
  notifications[0].onclick();
  await Promise.resolve();
  assert.deepEqual(targets, [{ channelId: "general" }]);
  assert.equal(focused, 1);
  assert.equal(notifications[0].closed, true);
  unlisten();
});
