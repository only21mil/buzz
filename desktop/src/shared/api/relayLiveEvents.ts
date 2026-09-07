import type { RelayEvent } from "./types";

/** Session-local cache observers run before each live subscription consumer. */
export class RelayLiveEvents {
  private observers = new Set<(event: RelayEvent) => void>();

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
