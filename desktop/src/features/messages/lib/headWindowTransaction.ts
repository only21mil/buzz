import { mergeHeadTransactionChannelWindowEvents } from "@/features/messages/lib/projectChannelWindow";
import type { ChannelWindowStore } from "@/features/messages/lib/channelWindowStore";
import type { Channel, RelayEvent } from "@/shared/api/types";
import { CancelledError } from "@tanstack/react-query";

type SubscriptionGenerationGuard = { current: boolean };
type HeadWindowTransaction = {
  version: number;
  active: boolean;
  events: RelayEvent[];
};

export type ChannelSubscriptionGeneration = Readonly<{
  channelId: string;
  channelType: Channel["channelType"];
  generation: number;
  guard: SubscriptionGenerationGuard;
  headTransaction: HeadWindowTransaction;
}>;

// Match the durable snapshot/window scale while preventing a noisy live stream
// from growing a subscribe/reconnect head transaction without bound.
const MAX_HEAD_TRANSACTION_EVENTS = 80;

export function beginHeadTransaction(
  token: ChannelSubscriptionGeneration,
): number {
  token.headTransaction.version += 1;
  token.headTransaction.active = true;
  token.headTransaction.events.length = 0;
  return token.headTransaction.version;
}

export function finishHeadTransaction(
  token: ChannelSubscriptionGeneration,
  version: number,
): void {
  if (token.headTransaction.version !== version) return;
  token.headTransaction.active = false;
  token.headTransaction.events.length = 0;
}

export function clearHeadTransaction(
  token: ChannelSubscriptionGeneration,
): void {
  token.headTransaction.version += 1;
  token.headTransaction.active = false;
  token.headTransaction.events.length = 0;
}

export function bufferHeadTransactionEvent(
  token: ChannelSubscriptionGeneration,
  event: RelayEvent,
): void {
  const transaction = token.headTransaction;
  if (
    !transaction.active ||
    transaction.events.some((candidate) => candidate.id === event.id)
  ) {
    return;
  }
  if (transaction.events.length === MAX_HEAD_TRANSACTION_EVENTS) {
    transaction.events.shift();
  }
  transaction.events.push(event);
}

function mergeBufferedHeadTransactionEvents(
  token: ChannelSubscriptionGeneration | null,
  version: number | null,
  store: ChannelWindowStore,
): ChannelWindowStore {
  if (
    !token ||
    version === null ||
    !token.guard.current ||
    !token.headTransaction.active ||
    token.headTransaction.version !== version
  ) {
    return store;
  }
  return mergeHeadTransactionChannelWindowEvents(
    store,
    token.headTransaction.events.splice(0),
  );
}

export function createHeadTransactionAccess(
  token: ChannelSubscriptionGeneration | null,
  requireCurrentRequest: () => void,
) {
  const version = token?.headTransaction.version ?? null;
  const requireCurrent = () => {
    requireCurrentRequest();
    if (token && token.headTransaction.version !== version) {
      throw new CancelledError({ silent: true });
    }
  };
  return {
    requireCurrent,
    merge(store: ChannelWindowStore) {
      requireCurrent();
      return mergeBufferedHeadTransactionEvents(token, version, store);
    },
    finish() {
      if (token && version !== null) finishHeadTransaction(token, version);
    },
  };
}
