import * as React from "react";
import { useCommunities } from "@/features/communities/useCommunities";
import { useIdentityQuery } from "@/shared/api/hooks";
import { isTauri } from "@tauri-apps/api/core";
import { relayClient } from "@/shared/api/relayClient";
import { decryptObserverEvent } from "@/shared/api/tauriObserver";
import {
  agentDraftBackfill,
  agentDraftQueue,
  agentDraftReceive,
} from "@/shared/api/tauriAgentDrafts";
import {
  durableDraftStore,
  EMPTY_DRAFT_SNAPSHOT,
  sameDraftScope,
} from "./durableDraftQueue";

/** Starts independently of the managed-agent count; unavailable senders stay visible. */
export function useDurableDraftBridge(
  owner: string | undefined,
  relayUrl: string | undefined,
) {
  React.useEffect(() => {
    if (!owner || !relayUrl || !isTauri()) return;
    return durableDraftStore.start(
      { owner, relayUrl },
      {
        queue: agentDraftQueue,
        receive: agentDraftReceive,
        decrypt: decryptObserverEvent,
        backfill: agentDraftBackfill,
        subscribe: (filter, receive) =>
          relayClient.subscribeLive(filter, receive),
        connection: (changed) => {
          const unsubscribe = relayClient.subscribeToConnectionState((state) =>
            changed(state === "connected"),
          );
          changed(relayClient.getConnectionState() === "connected");
          return unsubscribe;
        },
      },
    );
  }, [owner, relayUrl]);
}

/** Hide old scope data during render, before the previous bridge's cleanup runs. */
export function useDurableDraftQueue() {
  const identity = useIdentityQuery();
  const { activeCommunity } = useCommunities();
  const snapshot = React.useSyncExternalStore(
    durableDraftStore.subscribe,
    durableDraftStore.getSnapshot,
  );
  const scope =
    identity.data?.pubkey && activeCommunity?.relayUrl
      ? { owner: identity.data.pubkey, relayUrl: activeCommunity.relayUrl }
      : null;
  return sameDraftScope(scope, snapshot.scope)
    ? snapshot
    : EMPTY_DRAFT_SNAPSHOT;
}
