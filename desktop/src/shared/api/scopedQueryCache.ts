import {
  dehydrate,
  hydrate,
  type DehydratedState,
  type QueryClient,
} from "@tanstack/react-query";
import {
  IndexedDbQueryCacheStorage,
  type QueryCacheStorage,
} from "./queryCacheStorage";

const ROOTS = new Set([
  "channels",
  "channel-messages",
  "channel-window",
  "thread-replies",
  "cache-event",
  "profile",
  "user-profile",
  "users-batch",
  "users-batch-entry",
  "relayMembers",
]);
const MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024;
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_MEMORY_SCOPES = 8;

export function queryCacheScopeKey(relay: string, pubkey: string): string {
  const url = new URL(relay);
  if (
    !["ws:", "wss:", "http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  ) {
    throw new Error("Invalid cache relay");
  }
  url.protocol =
    url.protocol === "ws:"
      ? "http:"
      : url.protocol === "wss:"
        ? "https:"
        : url.protocol;
  url.hash = "";
  if (!/^[0-9a-f]{64}$/i.test(pubkey))
    throw new Error("Invalid cache identity");
  return JSON.stringify([url.href.replace(/\/$/, ""), pubkey.toLowerCase()]);
}

function persistedQuery(key: readonly unknown[]): boolean {
  return typeof key[0] === "string" && ROOTS.has(key[0]);
}

type Snapshot = {
  version: 1;
  scope: string;
  savedAt: number;
  state: DehydratedState;
};

/** React Query remains the hot store. Persistence only snapshots its selected data. */
export class ScopedQueryCache {
  private generation = 0;
  private memory = new Map<string, string>();
  private clients = new Set<{ client: QueryClient; stop: () => void }>();
  private writes: Promise<void> = Promise.resolve();

  private readonly storage: QueryCacheStorage;

  constructor(storage: QueryCacheStorage) {
    this.storage = storage;
  }

  private enqueue(write: () => Promise<void>): Promise<void> {
    const result = this.writes.then(write);
    this.writes = result.catch(() => {});
    return result;
  }

  attach(
    client: QueryClient,
    scope: string,
  ): { ready: Promise<void>; stop: () => void } {
    const generation = this.generation;
    let active = true;
    let restored = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const current = () => active && generation === this.generation;
    const save = () => {
      if (!current() || !restored) return;
      const state = dehydrate(client, {
        shouldDehydrateMutation: () => false,
        shouldDehydrateQuery: (query) =>
          persistedQuery(query.queryKey) && query.state.status === "success",
      });
      const snapshot: Snapshot = {
        version: 1,
        scope,
        savedAt: Date.now(),
        state,
      };
      const serialized = JSON.stringify(snapshot);
      if (serialized.length > MAX_SNAPSHOT_BYTES) return;
      this.memory.delete(scope);
      this.memory.set(scope, serialized);
      const oldest = this.memory.keys().next().value;
      if (this.memory.size > MAX_MEMORY_SCOPES && oldest !== undefined)
        this.memory.delete(oldest);
      void this.enqueue(async () => {
        if (generation === this.generation)
          await this.storage.write(scope, serialized);
      }).catch(() => {});
    };
    const unsubscribe = client.getQueryCache().subscribe((event) => {
      if (!current() || !restored || !persistedQuery(event.query.queryKey))
        return;
      if (event.type !== "updated" && event.type !== "removed") return;
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(save, 100);
    });
    const entry = {
      client,
      stop: () => {
        if (!active) return;
        if (timer !== undefined) clearTimeout(timer);
        save();
        active = false;
        unsubscribe();
        this.clients.delete(entry);
        void client.cancelQueries();
      },
    };
    this.clients.add(entry);
    const restore = (raw: string | null) => {
      if (!current()) return;
      if (raw) {
        try {
          const snapshot = JSON.parse(raw) as Snapshot;
          if (
            snapshot.version === 1 &&
            snapshot.scope === scope &&
            Date.now() - snapshot.savedAt < MAX_AGE_MS &&
            snapshot.state?.queries?.every((query) =>
              persistedQuery(query.queryKey),
            )
          ) {
            // Hydrated entries render immediately, then revalidate on first use.
            hydrate(client, {
              mutations: [],
              queries: snapshot.state.queries.map((query) => ({
                ...query,
                state: {
                  ...query.state,
                  isInvalidated: true,
                  fetchStatus: "idle" as const,
                },
              })),
            });
          }
        } catch {
          /* Corrupt cache is a miss. */
        }
      }
      restored = true;
    };
    const hot = this.memory.get(scope);
    if (hot) restore(hot);
    const ready = hot
      ? Promise.resolve()
      : this.storage.read(scope).then(restore, () => restore(null));
    return { ready, stop: entry.stop };
  }

  isAttached(client: QueryClient): boolean {
    return [...this.clients].some((entry) => entry.client === client);
  }

  invalidate(): void {
    // Invalidate first: no late hydrate, response or queued save can recreate
    // plaintext data after logout, including an already-running disk write.
    this.generation += 1;
    for (const { client, stop } of [...this.clients]) {
      stop();
      client.clear();
    }
    this.memory.clear();
  }

  async clear(): Promise<void> {
    this.invalidate();
    cacheClearChannel?.postMessage("clear");
    await this.enqueue(() => this.storage.clear());
  }
}

const cacheClearChannel =
  typeof window !== "undefined" && typeof window.BroadcastChannel === "function"
    ? new window.BroadcastChannel("buzz-query-cache")
    : null;

export const scopedQueryCache = new ScopedQueryCache(
  new IndexedDbQueryCacheStorage(),
);

cacheClearChannel?.addEventListener("message", (event) => {
  if (event.data === "clear") scopedQueryCache.invalidate();
});
