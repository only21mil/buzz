import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { RelayClient } from "./relayClientSession.ts";
import { subscribeLiveQueryCache } from "./liveQueryCacheSubscriptions.ts";
import { replayLiveSubscriptions } from "./relayReconnectReplay.ts";

const A = "11111111-1111-4111-8111-111111111111",
  B = "22222222-2222-4222-8222-222222222222",
  C = "33333333-3333-4333-8333-333333333333";
const self = "a".repeat(64),
  peer = "b".repeat(64);
globalThis.window = { setTimeout, clearTimeout };
const tick = () => new Promise((resolve) => setImmediate(resolve));
const channel = (id, visibility = "open", isMember = true) => ({
  id,
  visibility,
  isMember,
  name: id,
  channelType: "stream",
  memberPubkeys: [self],
  memberCount: 1,
  lastMessageAt: null,
});
const snapshot = (id, kind, tags, created_at = 1000) => ({
  id,
  kind,
  tags,
  created_at,
  pubkey: peer,
  content: "",
  sig: "f".repeat(128),
});

// Deterministic transport fixture for the Rust relay contract, not a running
// relay. Registration, frame handling, cache lifecycle and replay use the real
// client. Source anchors below bind the fixture's scope/access rules to Rust.
function scopeOf(filter) {
  const ids = new Set(
    (filter["#h"] ?? []).filter((id) => /^[0-9a-f-]{36}$/.test(id)),
  );
  return ids.size === 1 ? [...ids][0] : null;
}
function matches(filter, event, storedChannel) {
  if (!filter.kinds.includes(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since)
    return false;
  if (filter.until !== undefined && event.created_at > filter.until)
    return false;
  return Object.entries(filter)
    .filter(([key]) => key.startsWith("#"))
    .every(([key, values]) => {
      const tags = event.tags.filter(([name]) => name === key.slice(1));
      if (key === "#h" && tags.length === 0)
        return values.includes(storedChannel);
      return tags.some((tag) => values.includes(tag[1]));
    });
}
function harness(
  t,
  initial,
  {
    accessible = initial.map((item) => item.id),
    tokenChannels = null,
    eose = true,
  } = {},
) {
  const client = new QueryClient({
    defaultOptions: { queries: { gcTime: Infinity } },
  });
  client.setQueryData(["channels"], initial);
  const relay = new RelayClient(),
    registry = new Map(),
    frames = [],
    heads = [];
  const allowed = new Set(accessible);
  let attached = true;
  const receive = (frame) =>
    relay.handleWsMessage(JSON.stringify(frame), relay.connectionGeneration);
  const admit = (id) =>
    id === null ||
    (allowed.has(id) && (tokenChannels === null || tokenChannels.includes(id)));
  const send = async (frame) => {
    frames.push(frame);
    const [type, subId, filter] = frame;
    if (type === "CLOSE") {
      registry.delete(subId);
      return;
    }
    assert.equal(type, "REQ");
    const scope = scopeOf(filter);
    if (!admit(scope)) {
      await receive(["CLOSED", subId, "restricted: not a channel member"]);
      return;
    }
    registry.set(subId, { scope, filter });
    // Historical discovery may cross global/channel scopes, subject to access
    // and filter predicates. Live delivery below requires exact scope equality.
    for (const stored of heads
      .filter(
        ({ event, channelId }) =>
          admit(channelId) && matches(filter, event, channelId),
      )
      .slice(0, filter.limit))
      await receive(["EVENT", subId, stored.event]);
    if (eose) await receive(["EOSE", subId]);
  };
  relay.ensureConnected = async () => {};
  relay.sendRawWithReconnectRetry = send;
  relay.closeSubscription = (id) => send(["CLOSE", id]);
  const flush = () => {
    clearTimeout(relay.flushTimeout);
    relay.flushEventBuffer();
  };
  const publish = async (event, channelId = null) => {
    let delivered = 0;
    for (const [id, entry] of [...registry]) {
      // subscription.rs scope equality, core/filter.rs stored-channel fallback,
      // and event.rs delivery-time access check. Limit applies only to history.
      if (
        entry.scope === channelId &&
        admit(channelId) &&
        matches(entry.filter, event, channelId)
      ) {
        await receive(["EVENT", id, event]);
        delivered++;
      }
    }
    flush();
    return delivered;
  };
  const stop = subscribeLiveQueryCache(client, relay, self, () => attached);
  t.after(async () => {
    stop();
    await tick();
    clearTimeout(relay.flushTimeout);
    client.clear();
  });
  return {
    client,
    relay,
    registry,
    frames,
    heads,
    allowed,
    receive,
    send,
    publish,
    flush,
    stop,
    detach: () => {
      attached = false;
    },
    reconnect: async () => {
      registry.clear();
      await replayLiveSubscriptions({
        subscriptions: relay.subscriptions,
        sendRaw: send,
        requestHistoryPage: async () =>
          assert.fail("Discovery heads do not use timeline paging"),
        now: 1100,
      });
      flush();
    },
  };
}

test("fixture anchors match relay admission, scope isolation and d-only fallback", () => {
  const read = (path) =>
    readFileSync(new URL(`../../../../${path}`, import.meta.url), "utf8");
  const req = read("crates/buzz-relay/src/handlers/req.rs");
  assert.match(
    req,
    /let channel_id = extract_channel_id_from_filters\(&filters\)/,
  );
  assert.match(req, /if !resolve_request_local_access\(/);
  assert.match(req, /allowed\.contains\(&ch_id\)/);
  assert.match(req, /Some\(existing\) if existing != id =>/);
  assert.match(
    read("crates/buzz-relay/src/subscription.rs"),
    /\*sub_channel_id == event\.channel_id\s*&& filters_match/,
  );
  const filter = read("crates/buzz-core/src/filter.rs");
  assert.match(filter, /if !has_match && tag_key_str == "h"/);
  assert.match(
    filter,
    /if !event_has_h_tags \{\s*if let Some\(ch_id\) = ev.channel_id/,
  );
  const effects = read("crates/buzz-relay/src/handlers/side_effects.rs");
  assert.match(
    effects,
    /replace_addressable_event\(tenant.community\(\), &event, Some\(channel_id\)\)/,
  );
  const removal = effects.slice(effects.indexOf("async fn handle_remove_user"));
  assert.ok(
    removal.indexOf("evict_live_channel_subscriptions(") <
      removal.indexOf("emit_group_discovery_events("),
  );
  assert.match(
    read("crates/buzz-relay/src/handlers/event.rs"),
    /is_member_cached\(community_id, channel_id, &pubkey\)/,
  );
  assert.match(
    read("desktop/src/app/App.tsx"),
    /return subscribeLiveQueryCache\(queryClient, relayClient, pubkey/,
  );
});

test("actual subscriptions deliver d-only metadata and rosters after EOSE with profiles global", async (t) => {
  const h = harness(t, [channel(A), channel(B, "private")]);
  await tick();
  assert.equal(h.registry.size, 3);
  for (const { scope, filter } of h.registry.values()) {
    assert.deepEqual(filter.kinds, scope === null ? [0] : [39000, 39002]);
    if (scope !== null) assert.deepEqual(filter["#h"], [scope]);
  }
  assert.equal(
    await h.publish(
      snapshot("name", 39000, [
        ["d", A],
        ["name", "Renamed"],
      ]),
      A,
    ),
    1,
  );
  assert.equal(h.client.getQueryData(["channels"])[0].name, "Renamed");
  assert.equal(
    await h.publish(
      snapshot("members", 39002, [
        ["d", B],
        ["p", self],
        ["p", peer],
      ]),
      B,
    ),
    1,
  );
  assert.deepEqual(h.client.getQueryData(["channels"])[1].memberPubkeys, [
    self,
    peer,
  ]);
  const profile = {
    ...snapshot("profile", 0, [], Math.floor(Date.now() / 1000)),
    content: JSON.stringify({ display_name: "Peer" }),
  };
  assert.equal(await h.publish(profile), 1);
  assert.equal(
    h.client.getQueryData(["user-profile", peer]).displayName,
    "Peer",
  );
  assert.equal(
    await h.publish(
      snapshot("wrong-h", 39000, [
        ["d", A],
        ["h", B],
        ["name", "Wrong"],
      ]),
      A,
    ),
    0,
  );
  assert.equal(await h.publish(snapshot("foreign", 39000, [["d", C]]), C), 0);
  assert.equal(h.client.getQueryData(["channels"])[0].name, "Renamed");
});

test("old global and multi-channel filters cannot deliver live channel discovery", async (t) => {
  const h = harness(t, [channel(A), channel(B)]);
  await tick();
  h.stop();
  await tick();
  const seen = [],
    disposers = [];
  disposers.push(
    await h.relay.subscribeLive(
      { kinds: [0, 39000, 39002], limit: 1000 },
      (event) => seen.push(event),
    ),
  );
  disposers.push(
    await h.relay.subscribeLive(
      { kinds: [39000, 39002], "#h": [A, B], limit: 2 },
      (event) => seen.push(event),
    ),
  );
  assert.equal(await h.publish(snapshot("name", 39000, [["d", A]]), A), 0);
  assert.deepEqual(seen, []);
  await Promise.all(disposers.map((dispose) => dispose()));
});

test("channels discovered after startup subscribe and receive both current discovery heads", async (t) => {
  const h = harness(t, [], { accessible: [A] });
  await tick();
  assert.equal(h.registry.size, 1);
  h.heads.push(
    {
      channelId: A,
      event: snapshot("initial-name", 39000, [
        ["d", A],
        ["name", "Current name"],
      ]),
    },
    {
      channelId: A,
      event: snapshot("initial-roster", 39002, [
        ["d", A],
        ["p", self],
        ["p", peer],
      ]),
    },
  );
  h.client.setQueryData(["channels"], [channel(A)]);
  await tick();
  h.flush();
  assert.equal(h.registry.size, 2);
  assert.equal(h.client.getQueryData(["channels"])[0].name, "Current name");
  assert.deepEqual(h.client.getQueryData(["channels"])[0].memberPubkeys, [
    self,
    peer,
  ]);
});

test("channel-set changes close removed scopes, retain unchanged scopes and restore heads on reconnect", async (t) => {
  const h = harness(t, [channel(A), channel(B, "private")], {
    accessible: [A, B, C],
  });
  await tick();
  const aSub = [...h.registry].find(([, sub]) => sub.scope === A)[0];
  h.client.setQueryData(["channels"], [channel(A), channel(C)]);
  await tick();
  assert.ok(h.registry.has(aSub));
  assert.deepEqual(
    [...h.registry.values()].map((sub) => sub.scope).sort(),
    [null, A, C].sort(),
  );
  assert.equal(await h.publish(snapshot("removed", 39000, [["d", B]]), B), 0);
  await h.publish(
    snapshot("prior", 39000, [
      ["d", A],
      ["name", "Before"],
    ]),
    A,
  );
  h.heads.push({
    channelId: A,
    event: snapshot(
      "offline",
      39000,
      [
        ["d", A],
        ["name", "Offline edit"],
      ],
      1050,
    ),
  });
  await h.reconnect();
  assert.equal(h.client.getQueryData(["channels"])[0].name, "Offline edit");
  assert.ok(
    [...h.registry.values()].every(
      ({ scope }) => scope === null || scope === A || scope === C,
    ),
  );
  assert.equal(
    await h.publish(
      snapshot(
        "live-after-reconnect",
        39002,
        [
          ["d", C],
          ["p", peer],
        ],
        1101,
      ),
      C,
    ),
    1,
  );
  assert.equal(h.client.getQueryData(["channels"])[1].isMember, false);
});

test("admission rejects cached unauthorized and token-excluded channels without cache delivery", async (t) => {
  const h = harness(t, [channel(A), channel(B, "private"), channel(C)], {
    accessible: [A, C],
    tokenChannels: [A],
  });
  await tick();
  assert.deepEqual(
    [...h.registry.values()].map(({ scope }) => scope).sort(),
    [null, A].sort(),
  );
  assert.deepEqual(
    h.client.getQueryData(["channels"]).map(({ id }) => id),
    [A],
  );
  assert.equal(
    await h.publish(
      snapshot("denied", 39002, [
        ["d", B],
        ["p", peer],
      ]),
      B,
    ),
    0,
  );
  assert.equal(
    await h.publish(snapshot("token-denied", 39000, [["d", C]]), C),
    0,
  );
});

test("CLOSED clears revoked cache before forbidden roster, including changed visibility and reconnect denial", async (t) => {
  for (const [reconnect, visibility] of [
    [false, "private"],
    [true, "private"],
    [false, "open"],
  ]) {
    const h = harness(t, [channel(A), channel(B, visibility)]);
    for (const key of [
      ["channel-messages", B],
      ["channel-window", B],
      ["thread-replies", B, "root"],
      ["channels", B, "detail"],
      ["channels", B, "members"],
    ])
      h.client.setQueryData(key, ["private"]);
    let resolveStaleChannels;
    const staleChannels = h.client
      .fetchQuery({
        queryKey: ["channels"],
        queryFn: () =>
          new Promise((resolve) => {
            resolveStaleChannels = resolve;
          }),
      })
      .catch(() => {});
    await tick();
    h.allowed.delete(B);
    if (reconnect) await h.reconnect();
    else
      for (const [id, sub] of [...h.registry])
        if (sub.scope === B) {
          h.registry.delete(id);
          await h.receive(["CLOSED", id, "restricted: channel access revoked"]);
        }
    resolveStaleChannels([channel(A), channel(B, visibility)]);
    await staleChannels;
    await tick();
    assert.deepEqual(
      h.client.getQueryData(["channels"]).map(({ id }) => id),
      [A],
    );
    for (const root of [
      "channels",
      "channel-messages",
      "channel-window",
      "thread-replies",
    ])
      assert.equal(
        h.client.getQueryCache().findAll({ queryKey: [root, B] }).length,
        0,
      );
    assert.equal(
      await h.publish(
        snapshot("revoked-roster", 39002, [
          ["d", B],
          ["p", peer],
        ]),
        B,
      ),
      0,
    );
    assert.equal(
      await h.publish(
        snapshot("allowed", 39000, [
          ["d", A],
          ["name", "Still live"],
        ]),
        A,
      ),
      1,
    );
    assert.equal(h.client.getQueryData(["channels"])[0].name, "Still live");
  }
});

test("open nonmember roster keeps history and transient CLOSED does not revoke cache", async (t) => {
  const h = harness(t, [channel(A, "open", false)]);
  h.client.setQueryData(["channel-messages", A], ["public"]);
  await tick();
  const [id] = [...h.registry].find(([, sub]) => sub.scope === A);
  await h.receive(["CLOSED", id, "error: database error"]);
  assert.deepEqual(h.client.getQueryData(["channel-messages", A]), ["public"]);
  await h.publish(
    snapshot("nonmember", 39002, [
      ["d", A],
      ["p", peer],
    ]),
    A,
  );
  assert.deepEqual(h.client.getQueryData(["channel-messages", A]), ["public"]);
});

test("pending completion cannot survive channel removal or provider cleanup", async (t) => {
  const h = harness(t, [channel(A), channel(B)], { eose: false });
  await tick();
  const pending = [...h.registry.keys()];
  h.client.setQueryData(["channels"], [channel(A)]);
  const [removedId] = [...h.registry].find(([, sub]) => sub.scope === B);
  await h.receive(["EOSE", removedId]);
  await tick();
  assert.equal(h.registry.has(removedId), false);
  assert.equal(h.registry.size, 2);
  h.stop();
  for (const id of pending) await h.receive(["EOSE", id]);
  await tick();
  assert.equal(h.registry.size, 0);
  assert.equal(h.relay.subscriptions.size, 0);
});

test("detached identity fences EVENT and CLOSED writes before effect cleanup", async (t) => {
  const h = harness(t, [channel(A)]);
  await tick();
  h.detach();
  await h.publish(
    snapshot("stale", 39000, [
      ["d", A],
      ["name", "Wrong identity"],
    ]),
    A,
  );
  const [id] = [...h.registry].find(([, sub]) => sub.scope === A);
  await h.receive(["CLOSED", id, "restricted: channel access revoked"]);
  assert.equal(h.client.getQueryData(["channels"])[0].name, A);
});
