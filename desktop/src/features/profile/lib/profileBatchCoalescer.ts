import { getUsersBatch } from "@/shared/api/tauriProfiles";
import type {
  UserProfileSummary,
  UsersBatchResponse,
} from "@/shared/api/types";

type InFlightEntry = {
  promise: Promise<UserProfileSummary | null>;
  reject: (error: unknown) => void;
  resolve: (profile: UserProfileSummary | null) => void;
};

type PendingBatch = {
  entries: Map<string, InFlightEntry>;
};

const pendingBatches = new Map<string, PendingBatch>();
const inFlightByScope = new Map<string, Map<string, InFlightEntry>>();

function normalizePubkeys(pubkeys: string[]): string[] {
  return [...new Set(pubkeys.map((pubkey) => pubkey.toLowerCase()))]
    .filter((pubkey) => pubkey.length > 0)
    .sort();
}

function createInFlightEntry(): InFlightEntry {
  let resolve!: InFlightEntry["resolve"];
  let reject!: InFlightEntry["reject"];
  const promise = new Promise<UserProfileSummary | null>(
    (resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    },
  );
  return { promise, reject, resolve };
}

async function flushBatch(scope: string, batch: PendingBatch): Promise<void> {
  if (pendingBatches.get(scope) !== batch) return;
  pendingBatches.delete(scope);
  const scopedEntries = inFlightByScope.get(scope);
  try {
    const response = await getUsersBatch([...batch.entries.keys()].sort());
    for (const [pubkey, entry] of batch.entries) {
      entry.resolve(response.profiles[pubkey] ?? null);
    }
  } catch (error) {
    for (const entry of batch.entries.values()) entry.reject(error);
  } finally {
    for (const [pubkey, entry] of batch.entries) {
      if (scopedEntries?.get(pubkey) === entry) scopedEntries.delete(pubkey);
    }
    if (scopedEntries?.size === 0) inFlightByScope.delete(scope);
  }
}

/** Coalesce same-turn misses and reuse unresolved per-pubkey relay work. */
export function getUsersBatchCoalesced(
  relayScope: string,
  pubkeys: string[],
): Promise<UsersBatchResponse> {
  const normalizedPubkeys = normalizePubkeys(pubkeys);
  if (normalizedPubkeys.length === 0) {
    return Promise.resolve({ profiles: {}, missing: [] });
  }

  let scopedEntries = inFlightByScope.get(relayScope);
  if (!scopedEntries) {
    scopedEntries = new Map();
    inFlightByScope.set(relayScope, scopedEntries);
  }

  const requestedEntries = normalizedPubkeys.map((pubkey) => {
    let entry = scopedEntries.get(pubkey);
    if (entry) return entry;

    let batch = pendingBatches.get(relayScope);
    if (!batch) {
      batch = { entries: new Map() };
      pendingBatches.set(relayScope, batch);
      const scheduledBatch = batch;
      queueMicrotask(() => {
        void flushBatch(relayScope, scheduledBatch);
      });
    }
    entry = createInFlightEntry();
    batch.entries.set(pubkey, entry);
    scopedEntries.set(pubkey, entry);
    return entry;
  });

  return Promise.all(requestedEntries.map((entry) => entry.promise)).then(
    (results) => {
      const profiles: UsersBatchResponse["profiles"] = {};
      const missing: string[] = [];
      for (const [index, pubkey] of normalizedPubkeys.entries()) {
        const profile = results[index];
        if (profile) profiles[pubkey] = profile;
        else missing.push(pubkey);
      }
      return { profiles, missing };
    },
  );
}
