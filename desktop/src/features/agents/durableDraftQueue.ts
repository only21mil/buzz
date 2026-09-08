import type { RelayEvent } from "@/shared/api/types";
import type { RelaySubscriptionFilter } from "@/shared/api/relayClientShared";
import type {
  DraftOperation,
  DraftQueue,
  DraftScope,
} from "@/shared/api/tauriAgentDrafts";
import {
  parseAgentManagementRequest,
  type AgentManagementRequest,
} from "./agentManagement";

export const DRAFT_REQUEST_KIND = 14201;
export const DRAFT_DECISION_KIND = 14202;
const PAGE_SIZE = 200;
export type DurableDraftItem = {
  event: RelayEvent;
  request: AgentManagementRequest | null;
  unavailable: string | null;
  decision: "applying" | "applied" | "rejected" | null;
  operation: DraftOperation | null;
};
export type DurableDraftSnapshot = {
  scope: DraftScope | null;
  items: readonly DurableDraftItem[];
  ready: boolean;
  error: string | null;
  selectedId: string | null;
};
export const EMPTY_DRAFT_SNAPSHOT: DurableDraftSnapshot = {
  scope: null,
  items: [],
  ready: false,
  error: null,
  selectedId: null,
};
export function sameDraftScope(
  a: DraftScope | null,
  b: DraftScope | null,
): boolean {
  return (
    a !== null && b !== null && a.owner === b.owner && a.relayUrl === b.relayUrl
  );
}

function tag(event: RelayEvent, key: string): string | null {
  const matches = event.tags.filter((entry) => entry[0] === key);
  return matches.length === 1 && matches[0].length === 2 ? matches[0][1] : null;
}

export type DraftBridgeDependencies = {
  queue: (scope: DraftScope) => Promise<DraftQueue>;
  receive: (scope: DraftScope, event: RelayEvent) => Promise<void>;
  decrypt: (event: RelayEvent) => Promise<unknown>;
  backfill: (
    scope: DraftScope,
    cursor: { until?: number; beforeId?: string; limit: number },
  ) => Promise<RelayEvent[]>;
  subscribe: (
    filter: RelaySubscriptionFilter,
    receive: (event: RelayEvent) => void,
  ) => (() => void | Promise<void>) | Promise<() => void | Promise<void>>;
  connection: (changed: (connected: boolean) => void) => () => void;
};

/** One shared projection for queue and detail. No lifecycle path applies an operation. */
export class DurableDraftStore {
  private snapshot: DurableDraftSnapshot = EMPTY_DRAFT_SNAPSHOT;
  private listeners = new Set<() => void>();
  private epoch = 0;
  private refreshCurrent: (() => Promise<void>) | null = null;
  readonly subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  readonly getSnapshot = () => this.snapshot;
  readonly getEpoch = () => this.epoch;
  private emit(patch: Partial<DurableDraftSnapshot>) {
    this.snapshot = { ...this.snapshot, ...patch };
    for (const listener of this.listeners) listener();
  }
  select(scope: DraftScope, id: string | null) {
    if (!sameDraftScope(scope, this.snapshot.scope)) return;
    this.emit({ selectedId: id });
  }
  assertCurrent(
    scope: DraftScope,
    id: string,
    requireSelected = true,
    expectedEpoch = this.epoch,
  ) {
    if (
      !sameDraftScope(scope, this.snapshot.scope) ||
      expectedEpoch !== this.epoch ||
      !this.snapshot.ready ||
      (requireSelected && this.snapshot.selectedId !== id)
    ) {
      throw new Error(
        "This draft review is no longer active or the queue is offline. Reconnect and open it again.",
      );
    }
    const item = this.snapshot.items.find(
      (candidate) => candidate.event.id === id,
    );
    if (!item) throw new Error("This draft is no longer available.");
    return item;
  }
  async refresh() {
    await this.refreshCurrent?.();
  }

  start(scope: DraftScope, dependencies: DraftBridgeDependencies): () => void {
    const epoch = ++this.epoch;
    const active = () => epoch === this.epoch;
    const requests = new Map<string, DurableDraftItem>();
    const decisions = new Map<
      string,
      { generation: number; state: DurableDraftItem["decision"] }
    >();
    const operations = new Map<string, DraftOperation>();
    const processed = new Set<string>();
    let serial = Promise.resolve();
    let connected = false;
    let liveReady = false;
    let loading: Promise<void> | null = null;
    this.emit({ ...EMPTY_DRAFT_SNAPSHOT, scope });
    const publish = () => {
      if (!active()) return;
      this.emit({
        items: [...requests.values()]
          .map((item) => ({
            ...item,
            decision: decisions.get(item.event.id)?.state ?? null,
            operation: operations.get(item.event.id) ?? null,
          }))
          .sort(
            (a, b) =>
              b.event.created_at - a.event.created_at ||
              a.event.id.localeCompare(b.event.id),
          ),
      });
    };
    const ingest = async (event: RelayEvent, retained = false) => {
      if (!active() || processed.has(event.id)) return;
      if (tag(event, "p") !== scope.owner || tag(event, "v") !== "1") return;
      if (
        event.kind !== DRAFT_REQUEST_KIND &&
        event.kind !== DRAFT_DECISION_KIND
      )
        return;
      if (!retained) await dependencies.receive(scope, event);
      if (!active()) return;
      if (event.kind === DRAFT_DECISION_KIND) {
        const requestId = tag(event, "e");
        const state = tag(event, "state");
        const generation = Number(tag(event, "generation"));
        if (
          event.pubkey !== scope.owner ||
          !requestId ||
          ![1, 2].includes(generation) ||
          (state !== "applying" && state !== "applied" && state !== "rejected")
        )
          return;
        if (generation > (decisions.get(requestId)?.generation ?? 0)) {
          decisions.set(requestId, { generation, state });
        }
      } else {
        if (tag(event, "agent") !== event.pubkey) return;
        let request: AgentManagementRequest | null = null;
        let unavailable: string | null = null;
        try {
          const envelope = await dependencies.decrypt(event);
          if (!active()) return;
          request = parseAgentManagementRequest(
            typeof envelope === "object" &&
              envelope !== null &&
              "payload" in envelope
              ? envelope.payload
              : null,
          );
          if (
            !request ||
            request.requestId !== tag(event, "r") ||
            request.request.channelId !== tag(event, "h")
          ) {
            request = null;
            unavailable =
              "Draft content does not match its signed request and channel.";
          }
        } catch {
          if (!active()) return;
          unavailable = "Draft content could not be decrypted.";
        }
        requests.set(event.id, {
          event,
          request,
          unavailable,
          decision: null,
          operation: null,
        });
      }
      processed.add(event.id);
      publish();
    };
    const enqueue = (event: RelayEvent, retained = false) => {
      const work = serial.then(() => ingest(event, retained));
      serial = work.catch(() => {});
      return work;
    };
    const fail = (error: unknown) => {
      if (active())
        this.emit({
          ready: false,
          error:
            error instanceof Error
              ? error.message
              : "Draft queue could not sync. Reconnect to retry.",
        });
    };
    const load = async () => {
      const local = await dependencies.queue(scope);
      if (!active()) return;
      for (const operation of local.operations)
        operations.set(operation.requestEventId, operation);
      // Decisions first means a retained terminal request is never transiently actionable.
      for (const event of [...local.events].sort((a, b) => b.kind - a.kind))
        await enqueue(event, true);
      publish();
      if (!connected || !active()) return;
      let until: number | undefined;
      let beforeId: string | undefined;
      for (;;) {
        if (!active()) return;
        const page = await dependencies.backfill(scope, {
          limit: PAGE_SIZE,
          until,
          beforeId,
        });
        if (!active()) return;
        for (const event of page) await enqueue(event);
        if (page.length < PAGE_SIZE) break;
        const last = page[page.length - 1];
        if (
          until !== undefined &&
          (last.created_at > until ||
            (last.created_at === until &&
              beforeId !== undefined &&
              last.id <= beforeId))
        ) {
          throw new Error(
            "Draft history cursor did not advance. Queue sync is incomplete; reconnect to retry.",
          );
        }
        until = last.created_at;
        beforeId = last.id;
      }
      if (active()) this.emit({ ready: connected && liveReady, error: null });
    };
    const refresh = () => {
      if (!active()) return Promise.resolve();
      if (loading) return loading;
      this.emit({ ready: false });
      loading = load()
        .catch(fail)
        .finally(() => {
          loading = null;
        });
      return loading;
    };
    this.refreshCurrent = refresh;
    const unsubscribe = Promise.resolve(
      dependencies.subscribe(
        {
          kinds: [DRAFT_REQUEST_KIND, DRAFT_DECISION_KIND],
          "#p": [scope.owner],
          limit: 0,
        },
        (event) => {
          void enqueue(event).catch(fail);
        },
      ),
    );
    void unsubscribe
      .then(() => {
        if (!active()) return;
        liveReady = true;
        void refresh();
      })
      .catch(fail);
    const disconnect = dependencies.connection((next) => {
      connected = next;
      if (!active()) return;
      if (!next) this.emit({ ready: false });
      else void refresh();
    });
    void refresh();
    return () => {
      void unsubscribe.then((dispose) => dispose()).catch(() => {});
      disconnect();
      if (!active()) return;
      ++this.epoch;
      this.refreshCurrent = null;
      this.emit(EMPTY_DRAFT_SNAPSHOT);
    };
  }
}

export const durableDraftStore = new DurableDraftStore();
