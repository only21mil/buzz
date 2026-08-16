import { getUsersBatch } from "@/shared/api/tauriProfiles";
import type { UsersBatchResponse } from "@/shared/api/types";

type BatchCaller = {
  pubkeys: string[];
  resolve: (response: UsersBatchResponse) => void;
  reject: (error: unknown) => void;
};

type PendingBatch = {
  pubkeys: Set<string>;
  callers: BatchCaller[];
};

const pendingBatches = new Map<string, PendingBatch>();

function normalizePubkeys(pubkeys: string[]): string[] {
  return [...new Set(pubkeys.map((pubkey) => pubkey.toLowerCase()))]
    .filter((pubkey) => pubkey.length > 0)
    .sort();
}

function selectBatchResponse(
  response: UsersBatchResponse,
  pubkeys: string[],
): UsersBatchResponse {
  const profiles: UsersBatchResponse["profiles"] = {};
  const missing: string[] = [];
  for (const pubkey of pubkeys) {
    const profile = response.profiles[pubkey];
    if (profile) profiles[pubkey] = profile;
    else missing.push(pubkey);
  }
  return { profiles, missing };
}

async function flushBatch(scope: string, batch: PendingBatch): Promise<void> {
  if (pendingBatches.get(scope) !== batch) return;
  pendingBatches.delete(scope);
  try {
    const response = await getUsersBatch([...batch.pubkeys].sort());
    for (const caller of batch.callers) {
      caller.resolve(selectBatchResponse(response, caller.pubkeys));
    }
  } catch (error) {
    for (const caller of batch.callers) caller.reject(error);
  }
}

/** Coalesce same-turn aggregate profile misses into one relay transport batch. */
export function getUsersBatchCoalesced(
  relayScope: string,
  pubkeys: string[],
): Promise<UsersBatchResponse> {
  const normalizedPubkeys = normalizePubkeys(pubkeys);
  if (normalizedPubkeys.length === 0) {
    return Promise.resolve({ profiles: {}, missing: [] });
  }

  let batch = pendingBatches.get(relayScope);
  if (!batch) {
    batch = { pubkeys: new Set(), callers: [] };
    pendingBatches.set(relayScope, batch);
    const scheduledBatch = batch;
    queueMicrotask(() => {
      void flushBatch(relayScope, scheduledBatch);
    });
  }
  for (const pubkey of normalizedPubkeys) batch.pubkeys.add(pubkey);

  return new Promise<UsersBatchResponse>((resolve, reject) => {
    batch.callers.push({ pubkeys: normalizedPubkeys, resolve, reject });
  });
}
