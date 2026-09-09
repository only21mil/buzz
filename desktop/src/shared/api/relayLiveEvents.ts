import type { RelayEvent } from "./types";
import { handleRelayClosed } from "./relayClosedRecovery";

/** Session-local cache observers run before each live subscription consumer. */
export class RelayLiveEvents {
  private observers = new Set<(event: RelayEvent) => void>();
  private channelClosedObservers = new Set<
    (channelId: string, reason: string) => void
  >();

  /** Observe channel subscription closure after the session handles recovery. */
  observeChannelClosed(
    observer: (channelId: string, reason: string) => void,
  ): () => void {
    this.channelClosedObservers.add(observer);
    return () => {
      this.channelClosedObservers.delete(observer);
    };
  }

  /** Handle subscription recovery, then notify observers of channel closure. */
  handleClosed(args: Parameters<typeof handleRelayClosed>[0]): void {
    const subscription = args.subscriptions.get(args.subId);
    const channelIds =
      subscription?.mode === "live" ? subscription.filter["#h"] : undefined;
    handleRelayClosed(args);
    if (channelIds?.length !== 1) return;
    for (const observer of this.channelClosedObservers) {
      try {
        observer(channelIds[0], args.message);
      } catch (error) {
        console.error("Failed to update closed channel cache", error);
      }
    }
  }

  observe(observer: (event: RelayEvent) => void): () => void {
    this.observers.add(observer);
    return () => {
      this.observers.delete(observer);
    };
  }

  forward(consumer: (event: RelayEvent) => void): (event: RelayEvent) => void {
    return (event) => {
      for (const observer of this.observers) {
        try {
          observer(event);
        } catch (error) {
          console.error("Failed to update live query cache", error);
        }
      }
      consumer(event);
    };
  }
}
