import type { QueryClient } from "@tanstack/react-query";
import type { RelayClient } from "./relayClientSession";
import type { RelaySubscriptionFilter } from "./relayClientShared";
import type { Channel } from "./types";
import { applyLiveQueryCache } from "./liveQueryCache";

/** Keep cache delivery subscribed in the relay's authorized channel scopes. */
export function subscribeLiveQueryCache(
  client: QueryClient,
  relay: Pick<RelayClient, "subscribeLive" | "liveEvents">,
  pubkey: string,
  isCurrent: () => boolean,
): () => void {
  let active = true;
  const subscriptions = new Map<string, { dispose?: () => Promise<void> }>();
  const current = () => active && isCurrent();
  const remove = (id: string) => {
    const subscription = subscriptions.get(id);
    subscriptions.delete(id);
    void subscription?.dispose?.().catch(() => {});
  };
  const add = (id: string, filter: RelaySubscriptionFilter) => {
    if (subscriptions.has(id)) return;
    const subscription: { dispose?: () => Promise<void> } = {};
    subscriptions.set(id, subscription);
    void relay
      .subscribeLive(filter, () => {})
      .then((dispose) => {
        if (current() && subscriptions.get(id) === subscription) {
          subscription.dispose = dispose;
        } else void dispose().catch(() => {});
      })
      .catch((error: unknown) => {
        if (subscriptions.get(id) === subscription) subscriptions.delete(id);
        console.warn("Live cache metadata unavailable", error);
      });
  };
  const syncChannels = () => {
    if (!current()) return;
    const ids = new Set(
      (client.getQueryData<Channel[]>(["channels"]) ?? [])
        .filter((channel) => channel.visibility === "open" || channel.isMember)
        .map((channel) => channel.id),
    );
    for (const id of subscriptions.keys()) {
      if (id !== "profiles" && !ids.has(id)) remove(id);
    }
    for (const id of ids) {
      // One #h per REQ is required by the registry. The relay matches d-only
      // discovery events through their stored channel_id fallback for #h.
      // Fetch both current addressable heads, including edits made offline.
      add(id, { kinds: [39000, 39002], "#h": [id], limit: 2 });
    }
  };
  const stopEvents = relay.liveEvents.observe((event) => {
    if (current()) applyLiveQueryCache(client, event, pubkey);
  });
  const stopClosed = relay.liveEvents.observeChannelClosed((id, reason) => {
    if (
      !current() ||
      ![
        "restricted: channel access revoked",
        "restricted: not a channel member",
      ].includes(reason.trim().toLowerCase())
    )
      return;
    // Revocation precedes roster fan-out. Cached visibility may itself be
    // stale after an open→private change, so discard and rediscover access.
    void client.cancelQueries({ queryKey: ["channels"] });
    client.removeQueries({
      predicate: (query) =>
        ([
          "channels",
          "channel-messages",
          "channel-window",
          "thread-replies",
        ].includes(String(query.queryKey[0])) &&
          query.queryKey[1] === id) ||
        (query.queryKey[0] === "cache-event" && query.queryKey[3] === id),
    });
    remove(id);
    client.setQueryData<Channel[]>(["channels"], (channels) =>
      channels?.filter((channel) => channel.id !== id),
    );
    void client.invalidateQueries({ queryKey: ["channels"], exact: true });
  });
  const stopCache = client.getQueryCache().subscribe(({ query }) => {
    if (query.queryKey.length === 1 && query.queryKey[0] === "channels")
      syncChannels();
  });
  if (current()) {
    add("profiles", {
      kinds: [0],
      limit: 1000,
      since: Math.floor(Date.now() / 1000),
    });
    syncChannels();
  }
  return () => {
    active = false;
    stopCache();
    stopClosed();
    stopEvents();
    for (const id of subscriptions.keys()) remove(id);
  };
}
