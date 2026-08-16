/**
 * Bounded, disposable per-channel message snapshots.
 *
 * Snapshots are scoped to the exact relay, signer, and channel that produced
 * them. Callers capture that scope before starting work; lifecycle resets bump
 * the generation so a delayed write from the previous identity cannot recreate
 * data after it has been purged.
 */

import { mergeTimelineHistoryMessages } from "@/features/messages/lib/messageQueryKeys";
import { normalizeRelayUrl } from "@/features/profile/lib/selfProfileStorage";
import type { RelayEvent } from "@/shared/api/types";
import { setLocalStorageItemWithRecovery } from "@/shared/lib/localStorageQuota";
import { normalizePubkey } from "@/shared/lib/pubkey";

const STORAGE_KEY_PREFIX = "buzz-channel-messages.v2";
const LEGACY_STORAGE_KEY_PREFIX = "buzz-channel-messages.v1";
const HEX_64_RE = /^[0-9a-f]{64}$/;
const HEX_128_RE = /^[0-9a-f]{128}$/;
const EVENT_KEYS = new Set([
  "id",
  "pubkey",
  "created_at",
  "kind",
  "tags",
  "content",
  "sig",
  "pending",
]);
const PAYLOAD_KEYS = new Set([
  "version",
  "relayUrl",
  "signerPubkey",
  "channelId",
  "updatedAt",
  "events",
]);

const MAX_EVENTS_PER_SNAPSHOT = 80;
const MAX_CHANNELS_PER_IDENTITY = 20;

let generationSequence = 0;
let globalScopeGeneration = 0;
const identityScopeGenerations = new Map<string, number>();

export type MessageSnapshotScope = Readonly<{
  relayUrl: string;
  signerPubkey: string;
  channelId: string;
  generation: number;
}>;

type SnapshotPayload = {
  version: 2;
  relayUrl: string;
  signerPubkey: string;
  channelId: string;
  updatedAt: number;
  events: RelayEvent[];
};

function canonicalScope(
  relayUrl: string,
  signerPubkey: string,
  channelId: string,
): Omit<MessageSnapshotScope, "generation"> | null {
  const canonicalRelay = normalizeRelayUrl(relayUrl);
  const canonicalSigner = normalizePubkey(signerPubkey);
  if (
    canonicalRelay.length === 0 ||
    !HEX_64_RE.test(canonicalSigner) ||
    channelId.length === 0 ||
    channelId !== channelId.trim()
  ) {
    return null;
  }
  return {
    relayUrl: canonicalRelay,
    signerPubkey: canonicalSigner,
    channelId,
  };
}

/** Capture the exact identity-bound scope used by a later snapshot read/write. */
export function captureMessageSnapshotScope(
  relayUrl: string,
  signerPubkey: string,
  channelId: string,
): MessageSnapshotScope | null {
  const scope = canonicalScope(relayUrl, signerPubkey, channelId);
  return scope
    ? Object.freeze({
        ...scope,
        generation: currentScopeGeneration(scope.relayUrl, scope.signerPubkey),
      })
    : null;
}

function identityGenerationKey(relayUrl: string, signerPubkey: string): string {
  return `${relayUrl}\n${signerPubkey}`;
}

function currentScopeGeneration(
  relayUrl: string,
  signerPubkey: string,
): number {
  return (
    identityScopeGenerations.get(
      identityGenerationKey(relayUrl, signerPubkey),
    ) ?? globalScopeGeneration
  );
}

export function isMessageSnapshotScopeCurrent(
  scope: MessageSnapshotScope,
): boolean {
  const canonical = canonicalScope(
    scope.relayUrl,
    scope.signerPubkey,
    scope.channelId,
  );
  return (
    canonical !== null &&
    canonical.relayUrl === scope.relayUrl &&
    canonical.signerPubkey === scope.signerPubkey &&
    canonical.channelId === scope.channelId &&
    scope.generation ===
      currentScopeGeneration(scope.relayUrl, scope.signerPubkey)
  );
}

export function messageSnapshotKey(scope: MessageSnapshotScope): string {
  return `${STORAGE_KEY_PREFIX}:${scope.relayUrl}:${scope.signerPubkey}:${scope.channelId}`;
}

function identityPrefix(relayUrl: string, signerPubkey: string): string {
  return `${STORAGE_KEY_PREFIX}:${normalizeRelayUrl(relayUrl)}:${normalizePubkey(signerPubkey)}:`;
}

function collectKeysWithPrefix(prefix: string): string[] {
  const keys: string[] = [];
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    if (key?.startsWith(prefix)) keys.push(key);
  }
  return keys;
}

function removeKeysWithPrefix(prefix: string): void {
  for (const key of collectKeysWithPrefix(prefix)) {
    window.localStorage.removeItem(key);
  }
}

function removeStoredKey(key: string): null {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Storage access failures are non-fatal.
  }
  return null;
}

function isPersistableEvent(
  value: unknown,
  channelId: string,
): value is RelayEvent {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const event = value as Record<string, unknown>;
  if (
    !HEX_64_RE.test(typeof event.id === "string" ? event.id : "") ||
    !HEX_64_RE.test(typeof event.pubkey === "string" ? event.pubkey : "") ||
    !HEX_128_RE.test(typeof event.sig === "string" ? event.sig : "") ||
    typeof event.content !== "string" ||
    typeof event.created_at !== "number" ||
    !Number.isSafeInteger(event.created_at) ||
    event.created_at < 0 ||
    typeof event.kind !== "number" ||
    !Number.isSafeInteger(event.kind) ||
    event.kind < 0 ||
    !Array.isArray(event.tags) ||
    "localKey" in event ||
    (event.pending !== undefined && event.pending !== false) ||
    !Object.keys(event).every((key) => EVENT_KEYS.has(key))
  ) {
    return false;
  }

  const tags = event.tags as unknown[];
  if (
    !tags.every(
      (tag) =>
        Array.isArray(tag) && tag.every((part) => typeof part === "string"),
    )
  ) {
    return false;
  }
  const channelTags = (tags as string[][]).filter((tag) => tag[0] === "h");
  return (
    channelTags.length === 1 &&
    channelTags[0]?.length === 2 &&
    channelTags[0][1] === channelId
  );
}

function parseSnapshotPayload(
  value: unknown,
  scope: MessageSnapshotScope,
): SnapshotPayload | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const payload = value as Record<string, unknown>;
  if (
    !Object.keys(payload).every((key) => PAYLOAD_KEYS.has(key)) ||
    Object.keys(payload).length !== PAYLOAD_KEYS.size ||
    payload.version !== 2 ||
    payload.relayUrl !== scope.relayUrl ||
    payload.signerPubkey !== scope.signerPubkey ||
    payload.channelId !== scope.channelId ||
    typeof payload.updatedAt !== "number" ||
    !Number.isSafeInteger(payload.updatedAt) ||
    payload.updatedAt < 0 ||
    !Array.isArray(payload.events) ||
    payload.events.length === 0 ||
    payload.events.length > MAX_EVENTS_PER_SNAPSHOT ||
    !payload.events.every((event) => isPersistableEvent(event, scope.channelId))
  ) {
    return null;
  }
  return payload as SnapshotPayload;
}

/** Read and strictly validate a snapshot; corrupt or mismatched data is deleted. */
export function readMessageSnapshot(
  scope: MessageSnapshotScope,
): RelayEvent[] | null {
  if (!isMessageSnapshotScopeCurrent(scope)) return null;
  const key = messageSnapshotKey(scope);
  try {
    // V1 had no identity dimension, so none of it can be attributed safely.
    removeKeysWithPrefix(`${LEGACY_STORAGE_KEY_PREFIX}:`);
    const raw = window.localStorage.getItem(key);
    if (raw === null) return null;
    const parsed = parseSnapshotPayload(JSON.parse(raw), scope);
    return parsed ? parsed.events : removeStoredKey(key);
  } catch {
    return removeStoredKey(key);
  }
}

function evictOldestSnapshots(prefix: string, keepingKey: string): void {
  const others = collectKeysWithPrefix(prefix).filter(
    (key) => key !== keepingKey,
  );
  if (others.length < MAX_CHANNELS_PER_IDENTITY) return;

  const byAge = others
    .map((key) => {
      let updatedAt = 0;
      try {
        const value = JSON.parse(window.localStorage.getItem(key) ?? "") as {
          updatedAt?: unknown;
        };
        if (
          typeof value.updatedAt === "number" &&
          Number.isFinite(value.updatedAt)
        ) {
          updatedAt = value.updatedAt;
        }
      } catch {
        // Corrupt entries sort oldest and are evicted first.
      }
      return { key, updatedAt };
    })
    .sort((left, right) => left.updatedAt - right.updatedAt);

  for (const { key } of byAge.slice(
    0,
    others.length - (MAX_CHANNELS_PER_IDENTITY - 1),
  )) {
    window.localStorage.removeItem(key);
  }
}

/**
 * Persist a bounded snapshot only when every event is relay-authored and bound
 * to this channel. The generation is rechecked immediately before commit.
 */
export function writeMessageSnapshot(
  scope: MessageSnapshotScope,
  events: RelayEvent[],
): boolean {
  try {
    if (!isMessageSnapshotScopeCurrent(scope)) return false;
    removeKeysWithPrefix(`${LEGACY_STORAGE_KEY_PREFIX}:`);
    if (
      events.length === 0 ||
      !events.every((event) => isPersistableEvent(event, scope.channelId))
    ) {
      return false;
    }

    const persistable = events.slice(-MAX_EVENTS_PER_SNAPSHOT);
    const key = messageSnapshotKey(scope);
    const previous = window.localStorage.getItem(key);
    if (previous !== null) {
      const parsed = parseSnapshotPayload(JSON.parse(previous), scope);
      if (
        parsed &&
        JSON.stringify(parsed.events) === JSON.stringify(persistable)
      ) {
        return true;
      }
    }

    evictOldestSnapshots(
      identityPrefix(scope.relayUrl, scope.signerPubkey),
      key,
    );
    const serialized = JSON.stringify({
      version: 2,
      relayUrl: scope.relayUrl,
      signerPubkey: scope.signerPubkey,
      channelId: scope.channelId,
      updatedAt: Date.now(),
      events: persistable,
    } satisfies SnapshotPayload);

    if (!isMessageSnapshotScopeCurrent(scope)) return false;
    return setLocalStorageItemWithRecovery(key, serialized);
  } catch {
    return false;
  }
}

/** Invalidate captured scopes and remove one relay+identity snapshot bucket. */
export function removeMessageSnapshotsForIdentity(
  relayUrl: string,
  signerPubkey: string,
): void {
  try {
    const canonical = canonicalScope(relayUrl, signerPubkey, "purge");
    if (!canonical) {
      removeAllMessageSnapshots();
      return;
    }
    generationSequence += 1;
    identityScopeGenerations.set(
      identityGenerationKey(canonical.relayUrl, canonical.signerPubkey),
      generationSequence,
    );
    removeKeysWithPrefix(
      identityPrefix(canonical.relayUrl, canonical.signerPubkey),
    );
    removeKeysWithPrefix(
      `${LEGACY_STORAGE_KEY_PREFIX}:${normalizeRelayUrl(relayUrl)}:`,
    );
  } catch {
    // Storage access failures are non-fatal.
  }
}

/** Purge every removed community exactly when possible, otherwise fail safe. */
export function removeMessageSnapshotsForCommunities(
  relayUrls: string[],
  signerPubkey?: string | null,
): void {
  if (!signerPubkey || relayUrls.length === 0) {
    removeAllMessageSnapshots();
    return;
  }
  for (const relayUrl of relayUrls) {
    removeMessageSnapshotsForIdentity(relayUrl, signerPubkey);
  }
}

/** Invalidate every captured scope and remove all v1/v2 message snapshots. */
export function removeAllMessageSnapshots(): void {
  generationSequence += 1;
  globalScopeGeneration = generationSequence;
  identityScopeGenerations.clear();
  try {
    removeKeysWithPrefix(`${STORAGE_KEY_PREFIX}:`);
    removeKeysWithPrefix(`${LEGACY_STORAGE_KEY_PREFIX}:`);
  } catch {
    // Storage access failures are non-fatal.
  }
}

/**
 * Merge fresh history over cached/snapshot rows without changing the existing
 * cold-load aux-backfill behavior.
 */
export function mergeHistoryOverSnapshot(input: {
  cached: RelayEvent[] | undefined;
  snapshot: RelayEvent[] | null;
  history: RelayEvent[];
}): { merged: RelayEvent[]; auxBackfillWindow: RelayEvent[] } {
  const usedSnapshot = !input.cached && input.snapshot !== null;
  const merged = mergeTimelineHistoryMessages(
    input.cached ?? input.snapshot ?? [],
    input.history,
  );
  return { merged, auxBackfillWindow: usedSnapshot ? merged : input.history };
}
