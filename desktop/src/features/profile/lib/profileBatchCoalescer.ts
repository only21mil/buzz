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
let identityEpoch = 0;

function batchScopeKey(relayScope: string, identityScope: string): string {
  return `${identityEpoch}\0${relayScope}\0${identityScope.toLowerCase()}`;
}

function normalizePubkeys(pubkeys: string[]): string[] {
  return [...new Set(pubkeys.map((pubkey) => pubkey.toLowerCase()))]
    .filter((pubkey) => pubkey.length > 0)
    .sort();
}

function createInFlightEntry(): InFlightEntry {
  let settled = false;
  let resolvePromise!: InFlightEntry["resolve"];
  let rejectPromise!: InFlightEntry["reject"];
  const promise = new Promise<UserProfileSummary | null>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const resolve: InFlightEntry["resolve"] = (profile) => {
    if (settled) return;
    settled = true;
    resolvePromise(profile);
  };
  const reject: InFlightEntry["reject"] = (error) => {
    if (settled) return;
    settled = true;
    rejectPromise(error);
  };
  return { promise, reject, resolve };
}

/** Fence pending profile work before the active signer can be replaced. */
export function invalidateProfileBatchCoalescer(): void {
  identityEpoch += 1;
  const error = new Error("Profile batch scope invalidated by identity change");
  for (const scopedEntries of inFlightByScope.values()) {
    for (const entry of scopedEntries.values()) entry.reject(error);
  }
  pendingBatches.clear();
  inFlightByScope.clear();
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
    if (
      scopedEntries?.size === 0 &&
      inFlightByScope.get(scope) === scopedEntries
    ) {
      inFlightByScope.delete(scope);
    }
  }
}

/** Coalesce same-turn misses within one relay and active identity scope. */
export function getUsersBatchCoalesced(
  relayScope: string,
  identityScope: string,
  pubkeys: string[],
): Promise<UsersBatchResponse> {
  const normalizedPubkeys = normalizePubkeys(pubkeys);
  if (normalizedPubkeys.length === 0) {
    return Promise.resolve({ profiles: {}, missing: [] });
  }
  const scope = batchScopeKey(relayScope, identityScope);

  let scopedEntries = inFlightByScope.get(scope);
  if (!scopedEntries) {
    scopedEntries = new Map();
    inFlightByScope.set(scope, scopedEntries);
  }

  const requestedEntries = normalizedPubkeys.map((pubkey) => {
    let entry = scopedEntries.get(pubkey);
    if (entry) return entry;

    let batch = pendingBatches.get(scope);
    if (!batch) {
      batch = { entries: new Map() };
      pendingBatches.set(scope, batch);
      const scheduledBatch = batch;
      queueMicrotask(() => {
        void flushBatch(scope, scheduledBatch);
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
