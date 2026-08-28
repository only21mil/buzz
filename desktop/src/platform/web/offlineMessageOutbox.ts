import type { RelayEvent } from "@/shared/api/types";
import { verifyEvent } from "nostr-tools/pure";

export const OFFLINE_MESSAGE_MAX_COUNT = 50;
export const OFFLINE_MESSAGE_MAX_ATTEMPTS = 5;
export const OFFLINE_MESSAGE_TTL_MS = 24 * 60 * 60 * 1_000;
export const OFFLINE_MESSAGE_STATUS_EVENT = "buzz:offline-message-status";

const RETRY_BASE_MS = 5_000;
const RETRY_MAX_MS = 5 * 60 * 1_000;
const DB_NAME = "buzz-browser-message-outbox";
const STORE_NAME = "messages";
const RETRYABLE_PUBLISH_FAILURE =
  /(?:timed? out|timeout|network|offline|socket|websocket|connection|connect failed|disconnected|closed|unreachable|failed to fetch|failed while sending)/i;
const TERMINAL_PUBLISH_FAILURE =
  /(?:auth|unauthori[sz]ed|forbidden|permission|denied|invalid|malformed|validation|signature|blocked|duplicate|rate.?limit|too many requests|policy|rejected|permanent)/i;

export type OfflineMessageScope = Readonly<{
  relayUrl: string;
  pubkey: string;
}>;

export type OfflineMessageRecord = Readonly<{
  key: string;
  relayUrl: string;
  pubkey: string;
  event: RelayEvent;
  enqueuedAt: number;
  expiresAt: number;
  attempts: number;
  nextAttemptAt: number;
}>;

export type OfflineMessageDeliveryState =
  | "queued"
  | "delivered"
  | "failed"
  | "expired";

export type OfflineMessageDeliveryStatus = Readonly<{
  eventId: string;
  channelId: string;
  relayUrl: string;
  pubkey: string;
  state: OfflineMessageDeliveryState;
  attempts: number;
}>;

export type OfflineMessageStore = {
  list(): Promise<OfflineMessageRecord[]>;
  put(record: OfflineMessageRecord): Promise<void>;
  delete(key: string): Promise<void>;
};

export type OfflineMessageFlushResult = Readonly<{
  published: number;
  remaining: number;
  nextAttemptAt: number | null;
}>;

export type OfflineMessageRetryDriverOptions = Readonly<{
  now?: () => number;
  isOnline?: () => boolean;
  setTimer?: (callback: () => void, delayMs: number) => unknown;
  clearTimer?: (timer: unknown) => void;
  onError?: (error: unknown) => void;
}>;

/** Coalesces retry signals and schedules the next persisted outbox attempt. */
export class OfflineMessageRetryDriver {
  private readonly flushOnce: () => Promise<OfflineMessageFlushResult>;
  private readonly now: () => number;
  private readonly isOnline: () => boolean;
  private readonly setTimer: (callback: () => void, delayMs: number) => unknown;
  private readonly clearTimer: (timer: unknown) => void;
  private readonly onError: (error: unknown) => void;
  private timer: unknown = null;
  private inFlight: Promise<void> | null = null;
  private wakeRequested = false;

  constructor(
    flushOnce: () => Promise<OfflineMessageFlushResult>,
    options: OfflineMessageRetryDriverOptions = {},
  ) {
    this.flushOnce = flushOnce;
    this.now = options.now ?? Date.now;
    this.isOnline = options.isOnline ?? (() => navigator.onLine !== false);
    this.setTimer =
      options.setTimer ??
      ((callback, delayMs) => window.setTimeout(callback, delayMs));
    this.clearTimer =
      options.clearTimer ?? ((timer) => window.clearTimeout(timer as number));
    this.onError = options.onError ?? (() => {});
  }

  /** Wake the driver now; concurrent signals collapse into one follow-up pass. */
  wake(): void {
    this.wakeRequested = true;
    this.cancelTimer();
    if (this.inFlight) return;

    this.inFlight = this.drain().finally(() => {
      this.inFlight = null;
      if (this.wakeRequested) this.wake();
    });
  }

  /** Wake the driver and wait until all currently coalesced work settles. */
  async flushNow(): Promise<void> {
    this.wake();
    await this.inFlight;
  }

  /** Wait for an already-running pass without requesting another one. */
  async settled(): Promise<void> {
    await this.inFlight;
  }

  /** Stop a pending retry timer. */
  dispose(): void {
    this.wakeRequested = false;
    this.cancelTimer();
  }

  private async drain(): Promise<void> {
    while (this.wakeRequested) {
      this.wakeRequested = false;
      if (!this.isOnline()) continue;

      try {
        const result = await this.flushOnce();
        if (result.nextAttemptAt !== null) {
          this.schedule(result.nextAttemptAt);
        }
      } catch (error) {
        this.onError(error);
        this.schedule(this.now() + RETRY_BASE_MS);
      }
    }
  }

  private schedule(at: number): void {
    this.cancelTimer();
    this.timer = this.setTimer(
      () => {
        this.timer = null;
        this.wake();
      },
      Math.max(0, at - this.now()),
    );
  }

  private cancelTimer(): void {
    if (this.timer === null) return;
    this.clearTimer(this.timer);
    this.timer = null;
  }
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed"));
  });
}

export class IndexedDbOfflineMessageStore implements OfflineMessageStore {
  private readonly database: Promise<IDBDatabase>;

  constructor(factory: IDBFactory = indexedDB) {
    this.database = new Promise((resolve, reject) => {
      const request = factory.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: "key" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Unable to open message outbox"));
      request.onblocked = () =>
        reject(new Error("Message outbox database upgrade is blocked"));
    });
  }

  async list(): Promise<OfflineMessageRecord[]> {
    const database = await this.database;
    const transaction = database.transaction(STORE_NAME, "readonly");
    const records = await requestResult<OfflineMessageRecord[]>(
      transaction.objectStore(STORE_NAME).getAll(),
    );
    await transactionDone(transaction);
    return records;
  }

  async put(record: OfflineMessageRecord): Promise<void> {
    const database = await this.database;
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(record);
    await transactionDone(transaction);
  }

  async delete(key: string): Promise<void> {
    const database = await this.database;
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).delete(key);
    await transactionDone(transaction);
  }
}

function recordKey(scope: OfflineMessageScope, eventId: string): string {
  return `${scope.relayUrl}\u0000${scope.pubkey}\u0000${eventId}`;
}

function recordMatchesScope(
  record: OfflineMessageRecord,
  scope: OfflineMessageScope,
): boolean {
  return record.relayUrl === scope.relayUrl && record.pubkey === scope.pubkey;
}

function assertMessageEvent(
  scope: OfflineMessageScope,
  event: RelayEvent,
): void {
  if (!/^wss?:\/\/[^\s]+$/.test(scope.relayUrl)) {
    throw new Error("Offline message scope has an invalid relay URL");
  }
  if (!/^[0-9a-f]{64}$/i.test(scope.pubkey) || event.pubkey !== scope.pubkey) {
    throw new Error("Offline message scope does not match the signer");
  }
  if (
    !/^[0-9a-f]{64}$/i.test(event.id) ||
    !/^[0-9a-f]{128}$/i.test(event.sig) ||
    !verifyEvent(event) ||
    ![9, 45001, 45003].includes(event.kind) ||
    !event.tags.some(
      (tag) =>
        tag[0] === "h" &&
        typeof tag[1] === "string" &&
        /^[0-9a-f-]{36}$/i.test(tag[1]),
    )
  ) {
    throw new Error("Only complete signed channel messages may be queued");
  }
}

function retryDelay(attempts: number): number {
  return Math.min(RETRY_BASE_MS * 2 ** Math.max(0, attempts - 1), RETRY_MAX_MS);
}

function channelId(event: RelayEvent): string {
  return event.tags.find((tag) => tag[0] === "h")?.[1] ?? "";
}

function dispatchDeliveryStatus(status: OfflineMessageDeliveryStatus): void {
  if (typeof window === "undefined" || typeof CustomEvent === "undefined") {
    return;
  }
  window.dispatchEvent(
    new CustomEvent<OfflineMessageDeliveryStatus>(
      OFFLINE_MESSAGE_STATUS_EVENT,
      { detail: status },
    ),
  );
}

export class OfflineMessageOutbox {
  private readonly store: OfflineMessageStore;
  private readonly reportStatus: (status: OfflineMessageDeliveryStatus) => void;

  constructor(
    store: OfflineMessageStore = new IndexedDbOfflineMessageStore(),
    reportStatus: (
      status: OfflineMessageDeliveryStatus,
    ) => void = dispatchDeliveryStatus,
  ) {
    this.store = store;
    this.reportStatus = reportStatus;
  }

  private report(
    record: OfflineMessageRecord,
    state: OfflineMessageDeliveryState,
    attempts = record.attempts,
  ): void {
    this.reportStatus({
      eventId: record.event.id,
      channelId: channelId(record.event),
      relayUrl: record.relayUrl,
      pubkey: record.pubkey,
      state,
      attempts,
    });
  }

  async enqueue(
    scope: OfflineMessageScope,
    event: RelayEvent,
    now = Date.now(),
  ): Promise<void> {
    assertMessageEvent(scope, event);
    const key = recordKey(scope, event.id);
    const records = await this.store.list();
    const scopedRecords = records.filter((record) =>
      recordMatchesScope(record, scope),
    );

    for (const record of scopedRecords) {
      if (record.expiresAt <= now) {
        await this.store.delete(record.key);
        this.report(record, "expired");
      }
    }
    const existing = scopedRecords.find(
      (record) => record.key === key && record.expiresAt > now,
    );
    if (existing) {
      this.report(existing, "queued");
      return;
    }

    const liveRecords = scopedRecords
      .filter((record) => record.expiresAt > now && record.key !== key)
      .sort((left, right) => left.enqueuedAt - right.enqueuedAt);
    while (liveRecords.length >= OFFLINE_MESSAGE_MAX_COUNT) {
      const oldest = liveRecords.shift();
      if (oldest) {
        await this.store.delete(oldest.key);
        this.report(oldest, "failed");
      }
    }

    const record: OfflineMessageRecord = {
      key,
      relayUrl: scope.relayUrl,
      pubkey: scope.pubkey,
      event,
      enqueuedAt: now,
      expiresAt: now + OFFLINE_MESSAGE_TTL_MS,
      attempts: 0,
      nextAttemptAt: now,
    };
    await this.store.put(record);
    this.report(record, "queued");
  }

  async flush(
    scope: OfflineMessageScope,
    publish: (event: RelayEvent) => Promise<unknown>,
    now = Date.now(),
    isRetryableFailure: (error: unknown) => boolean = () => true,
  ): Promise<OfflineMessageFlushResult> {
    const records = (await this.store.list())
      .filter((record) => recordMatchesScope(record, scope))
      .sort(
        (left, right) =>
          left.enqueuedAt - right.enqueuedAt ||
          left.key.localeCompare(right.key),
      );
    let published = 0;

    for (const record of records) {
      if (
        record.expiresAt <= now ||
        record.attempts >= OFFLINE_MESSAGE_MAX_ATTEMPTS
      ) {
        await this.store.delete(record.key);
        this.report(record, record.expiresAt <= now ? "expired" : "failed");
      }
    }

    const liveRecords = (await this.store.list())
      .filter((record) => recordMatchesScope(record, scope))
      .sort(
        (left, right) =>
          left.enqueuedAt - right.enqueuedAt ||
          left.key.localeCompare(right.key),
      );
    const blockedChannels = new Set<string>();

    for (const record of liveRecords) {
      const recordChannelId = channelId(record.event);
      if (blockedChannels.has(recordChannelId)) continue;
      if (record.nextAttemptAt > now) {
        blockedChannels.add(recordChannelId);
        continue;
      }
      try {
        assertMessageEvent(scope, record.event);
        await publish(record.event);
        await this.store.delete(record.key);
        this.report(record, "delivered");
        published += 1;
      } catch (error) {
        if (!isRetryableFailure(error)) {
          await this.store.delete(record.key);
          this.report(record, "failed", record.attempts + 1);
          continue;
        }
        const attempts = record.attempts + 1;
        if (attempts >= OFFLINE_MESSAGE_MAX_ATTEMPTS) {
          await this.store.delete(record.key);
          this.report(record, "failed", attempts);
        } else {
          const retryRecord = {
            ...record,
            attempts,
            nextAttemptAt: now + retryDelay(attempts),
          };
          await this.store.put(retryRecord);
          this.report(retryRecord, "queued");
          blockedChannels.add(recordChannelId);
        }
      }
    }

    const remainingRecords = (await this.store.list())
      .filter((record) => recordMatchesScope(record, scope))
      .sort(
        (left, right) =>
          left.enqueuedAt - right.enqueuedAt ||
          left.key.localeCompare(right.key),
      );
    const firstAttemptByChannel = new Map<string, number>();
    for (const record of remainingRecords) {
      const recordChannelId = channelId(record.event);
      if (!firstAttemptByChannel.has(recordChannelId)) {
        firstAttemptByChannel.set(recordChannelId, record.nextAttemptAt);
      }
    }
    const nextAttemptAt =
      firstAttemptByChannel.size === 0
        ? null
        : Math.min(...firstAttemptByChannel.values());
    return {
      published,
      remaining: remainingRecords.length,
      nextAttemptAt,
    };
  }
}

export type OfflineMessagePublisher = {
  publishOrQueue(event: RelayEvent): Promise<{
    event: RelayEvent;
    deliveryStatus: "delivered" | "queued";
  }>;
  flush(): Promise<OfflineMessageFlushResult>;
};

type RelayPublisher = {
  publishEvent(
    event: RelayEvent,
    timeoutMessage?: string,
    errorMessage?: string,
  ): Promise<RelayEvent>;
};

function isRetryableTransportPublishFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (TERMINAL_PUBLISH_FAILURE.test(error.message)) return false;
  return RETRYABLE_PUBLISH_FAILURE.test(error.message);
}

export function createOfflineMessagePublisher(
  scope: () => OfflineMessageScope,
  client: RelayPublisher,
  outbox = new OfflineMessageOutbox(),
  onQueued: () => void = () => {},
): OfflineMessagePublisher {
  const publish = (event: RelayEvent) =>
    client.publishEvent(
      event,
      "Timed out while sending the queued message.",
      "Failed while sending the queued message.",
    );
  return {
    async publishOrQueue(event) {
      if (navigator.onLine !== false) {
        try {
          return { event: await publish(event), deliveryStatus: "delivered" };
        } catch (error) {
          if (!isRetryableTransportPublishFailure(error)) throw error;
        }
      }
      await outbox.enqueue(scope(), event);
      onQueued();
      return { event, deliveryStatus: "queued" };
    },
    async flush() {
      if (navigator.onLine === false) {
        return { published: 0, remaining: 0, nextAttemptAt: null };
      }
      return outbox.flush(
        scope(),
        publish,
        Date.now(),
        isRetryableTransportPublishFailure,
      );
    },
  };
}
