import type { QueryClient } from "@tanstack/react-query";

import {
  mapChannelWindowEvents,
  type ChannelWindowStore,
} from "@/features/messages/lib/channelWindowStore";
import { channelWindowKey } from "@/features/messages/lib/messageQueryKeys";
import { projectChannelWindowMessages } from "@/features/messages/lib/projectChannelWindow";
import {
  OFFLINE_MESSAGE_STATUS_EVENT,
  type OfflineMessageDeliveryStatus,
} from "@/platform/web/offlineMessageOutbox";

const DELIVERY_STATES = new Set(["queued", "delivered", "failed", "expired"]);

export function subscribeOfflineMessageDeliveryStatuses(
  queryClient: QueryClient,
  pubkey: string,
): () => void {
  const handleDeliveryStatus = (rawEvent: Event) => {
    const detail = (rawEvent as CustomEvent<OfflineMessageDeliveryStatus>)
      .detail;
    if (
      !detail ||
      detail.pubkey !== pubkey ||
      !detail.channelId ||
      !DELIVERY_STATES.has(detail.state)
    ) {
      return;
    }
    const windowKey = channelWindowKey(detail.channelId);
    const current = queryClient.getQueryData<ChannelWindowStore>(windowKey);
    if (!current) return;
    const next = mapChannelWindowEvents(current, (event) => {
      if (event.id !== detail.eventId) return event;
      if (detail.state === "delivered") {
        const { deliveryStatus: _deliveryStatus, ...delivered } = event;
        return { ...delivered, pending: false };
      }
      return {
        ...event,
        pending: detail.state === "queued",
        deliveryStatus: detail.state,
      };
    });
    if (next === current) return;
    queryClient.setQueryData(windowKey, next);
    projectChannelWindowMessages(queryClient, detail.channelId);
  };
  window.addEventListener(OFFLINE_MESSAGE_STATUS_EVENT, handleDeliveryStatus);
  return () =>
    window.removeEventListener(
      OFFLINE_MESSAGE_STATUS_EVENT,
      handleDeliveryStatus,
    );
}
