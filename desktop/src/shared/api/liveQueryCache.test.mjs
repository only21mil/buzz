import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { applyLiveQueryCache } from "./liveQueryCache.ts";
import { RelayClient } from "./relayClientSession.ts";
import { CHANNEL_EVENT_KINDS } from "../constants/kinds.ts";
import { replayLiveSubscriptions } from "./relayReconnectReplay.ts";
import {
  emptyChannelWindowStore,
  flattenChannelWindowEvents,
} from "../../features/messages/lib/channelWindowStore.ts";

const self = "a".repeat(64),
  peer = "b".repeat(64);
const event = (
  id,
  kind = 9,
  tags = [["h", "channel"]],
  content = "",
  created_at = 1000,
) => ({
  id,
  kind,
  tags,
  content,
  pubkey: peer,
  created_at,
  sig: "f".repeat(128),
});
const cache = () =>
  new QueryClient({ defaultOptions: { queries: { gcTime: Infinity } } });
const channel = {
  id: "channel",
  name: "General",
  channelType: "stream",
  visibility: "open",
  memberPubkeys: [self, peer],
  memberCount: 2,
  isMember: true,
  lastMessageAt: null,
};
function seed(client) {
  client.setQueryData(["channels"], [channel]);
  client.setQueryData(["channel-messages", "channel"], [event("old")]);
  client.setQueryData(["channel-window", "channel"], emptyChannelWindowStore());
}

test("two synthetic clients receive messages, edits, reactions and deletes before UI with no query refetch", async () => {
  globalThis.window = { setTimeout, clearTimeout };
  const clients = [cache(), cache()];
  const relays = [new RelayClient(), new RelayClient()];
  let networkQueries = 0;
  for (let i = 0; i < clients.length; i++) {
    const client = clients[i],
      relay = relays[i];
    seed(client);
    client.setDefaultOptions({
      queries: {
        queryFn: () => {
          networkQueries++;
          return [];
        },
      },
    });
    relay.ensureConnected = async () => {};
    relay.sendRawWithReconnectRetry = async (frame) => {
      if (frame[0] === "REQ") relay.handleEose(frame[1]);
    };
    relay.liveEvents.observe((incoming) =>
      applyLiveQueryCache(client, incoming, self),
    );
    await relay.subscribeLive(
      { kinds: [9, 7, 5, 40003], "#h": ["channel"], since: 1000, limit: 1000 },
      (incoming) => {
        assert.ok(
          client
            .getQueryData(["channel-messages", "channel"])
            .some((item) => item.id === incoming.id),
        );
      },
    );
  }
  for (const incoming of [
    event("new"),
    event(
      "edit",
      40003,
      [
        ["h", "channel"],
        ["e", "old"],
      ],
      "edited",
    ),
    event(
      "reaction",
      7,
      [
        ["h", "channel"],
        ["e", "old"],
      ],
      "+",
    ),
    event("delete", 5, [["e", "old"]]),
  ]) {
    for (const relay of relays) {
      const subId = [...relay.subscriptions.keys()][0];
      relay.handleEvent(subId, incoming);
      clearTimeout(relay.flushTimeout);
      relay.flushEventBuffer();
    }
  }
  for (const client of clients) {
    assert.deepEqual(
      client
        .getQueryData(["channel-messages", "channel"])
        .map((item) => item.id)
        .sort(),
      ["old", "new", "edit", "reaction", "delete"].sort(),
    );
    assert.equal(
      flattenChannelWindowEvents(
        client.getQueryData(["channel-window", "channel"]),
      ).length,
      4,
    );
  }
  assert.equal(networkQueries, 0);
});

test("profile and membership snapshots update hot data without HTTP and older events cannot undo them", () => {
  const client = cache();
  seed(client);
  client.setQueryData(["users-batch", peer], { profiles: {}, missing: [peer] });
  client.setQueryData(
    ["channels", "channel", "members"],
    [{ pubkey: peer, role: "member", displayName: "Old" }],
  );
  applyLiveQueryCache(
    client,
    event(
      "profile-new",
      0,
      [],
      JSON.stringify({ display_name: "New", picture: "avatar" }),
      1002,
    ),
    self,
  );
  applyLiveQueryCache(
    client,
    event("profile-old", 0, [], JSON.stringify({ display_name: "Old" }), 1001),
    self,
  );
  assert.equal(client.getQueryData(["user-profile", peer]).displayName, "New");
  assert.equal(
    client.getQueryData(["users-batch", peer]).profiles[peer].displayName,
    "New",
  );
  assert.equal(
    client.getQueryData(["channels", "channel", "members"])[0].displayName,
    "New",
  );
  applyLiveQueryCache(
    client,
    event("roster", 39002, [
      ["d", "channel"],
      ["p", peer, "", "admin"],
    ]),
    self,
  );
  assert.equal(client.getQueryData(["channels"])[0].isMember, false);
  assert.equal(
    client.getQueryData(["channels", "channel", "members"])[0].role,
    "admin",
  );
  assert.equal(client.getQueryData(["channel-messages", "channel"]), undefined);
});

test("a thread reply only updates its own cached thread", () => {
  const client = cache();
  seed(client);
  client.setQueryData(["thread-replies", "channel", "root-a"], []);
  client.setQueryData(["thread-replies", "channel", "root-b"], []);
  applyLiveQueryCache(
    client,
    event("reply", 9, [
      ["h", "channel"],
      ["e", "root-a", "", "reply"],
    ]),
    self,
  );
  assert.equal(
    client.getQueryData(["thread-replies", "channel", "root-a"]).length,
    1,
  );
  assert.equal(
    client.getQueryData(["thread-replies", "channel", "root-b"]).length,
    0,
  );
  assert.equal(
    flattenChannelWindowEvents(
      client.getQueryData(["channel-window", "channel"]),
    ).length,
    0,
  );
});

test("thread-only and window-only caches receive live events without a timeline query", () => {
  const client = cache();
  client.setQueryData(
    ["thread-replies", "channel", "root-a"],
    [event("reply-a")],
  );
  client.setQueryData(
    ["thread-replies", "channel", "root-b"],
    [event("reply-b")],
  );
  applyLiveQueryCache(
    client,
    event("reply-new", 9, [
      ["h", "channel"],
      ["e", "root-a", "", "reply"],
    ]),
    self,
  );
  applyLiveQueryCache(client, event("delete-a", 5, [["e", "reply-a"]]), self);
  assert.deepEqual(
    client
      .getQueryData(["thread-replies", "channel", "root-a"])
      .map((item) => item.id)
      .sort(),
    ["delete-a", "reply-a", "reply-new"],
  );
  assert.deepEqual(
    client
      .getQueryData(["thread-replies", "channel", "root-b"])
      .map((item) => item.id),
    ["reply-b"],
  );
  client.setQueryData(["channel-window", "other"], emptyChannelWindowStore());
  applyLiveQueryCache(client, event("new-window", 9, [["h", "other"]]), self);
  assert.equal(
    flattenChannelWindowEvents(
      client.getQueryData(["channel-window", "other"]),
    )[0].id,
    "new-window",
  );
});

test("unrelated live events never enter persisted message caches", () => {
  const client = cache();
  seed(client);
  applyLiveQueryCache(client, event("typing", 20002), self);
  applyLiveQueryCache(client, event("summary", 39005), self);
  assert.deepEqual(
    client.getQueryData(["channel-messages", "channel"]).map((item) => item.id),
    ["old"],
  );
  assert.deepEqual(
    flattenChannelWindowEvents(
      client.getQueryData(["channel-window", "channel"]),
    ),
    [],
  );
});

test("60-second reconnect restores live delivery and fetches only the missed gap into cache", async () => {
  const client = cache();
  seed(client);
  const requests = [],
    pages = [];
  const subscriptions = new Map([
    [
      "live",
      {
        mode: "live",
        filter: {
          kinds: [...CHANNEL_EVENT_KINDS],
          "#h": ["channel"],
          limit: 1000,
        },
        lastSeenCreatedAt: 1000,
        onEvent: (incoming) => applyLiveQueryCache(client, incoming, self),
      },
    ],
  ]);
  await replayLiveSubscriptions({
    subscriptions,
    now: 1060,
    sendRaw: async (frame) => {
      requests.push(frame);
    },
    requestHistoryPage: async (request) => {
      pages.push(request);
      return {
        events: [event("offline", 9, [["h", "channel"]], "", 1030)],
        nextCursor: null,
      };
    },
  });
  assert.equal(requests[0][2].limit, 0);
  assert.equal(requests[0][2].since, 1060);
  assert.equal(pages[0].since, 995);
  assert.equal(pages[0].until, 1060);
  assert.ok(
    client
      .getQueryData(["channel-messages", "channel"])
      .some((item) => item.id === "offline"),
  );
});
