/**
 * Bounded, disposable per-channel message snapshots.
 *
 * Snapshots are scoped to the exact relay, signer, and channel that produced
 * them. Callers capture that scope before starting work; lifecycle resets bump
 * the generation so a delayed write from the previous identity cannot recreate
 * data after it has been purged.
 */

import { mergeTimelineHistoryMessages } from "@/features/messages/lib/messageQueryKeys";
import type { RelayEvent } from "@/shared/api/types";
import {
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
} from "@/shared/constants/kinds";
import { setLocalStorageItemWithRecovery } from "@/shared/lib/localStorageQuota";
import { normalizePubkey } from "@/shared/lib/pubkey";
import { verifyEvent } from "nostr-tools/pure";

const STORAGE_KEY_PREFIX = "buzz-channel-messages.v3";
const PREVIOUS_STORAGE_KEY_PREFIX = "buzz-channel-messages.v2";
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
const PERSISTABLE_EVENT_KINDS: ReadonlySet<number> = new Set([
  ...CHANNEL_TIMELINE_CONTENT_KINDS,
  ...CHANNEL_AUX_EVENT_KINDS,
]);
const TIMELINE_EVENT_KINDS: ReadonlySet<number> = new Set(
  CHANNEL_TIMELINE_CONTENT_KINDS,
);

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
  version: 3;
  relayUrl: string;
  signerPubkey: string;
  channelId: string;
  updatedAt: number;
  events: RelayEvent[];
};

/** Canonical relay identity for snapshots without lowercasing path/query data. */
export function canonicalSnapshotRelayUrl(relayUrl: string): string {
  const trimmed = relayUrl.trim();
  if (trimmed.length === 0) return "";
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `wss://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") return "";
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    const credentials = parsed.username
      ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ""}@`
      : "";
    const authority = `${parsed.protocol}//${credentials}${parsed.host}`;
    const path = parsed.pathname === "/" ? "" : parsed.pathname;
    return `${authority}${path}${parsed.search}${parsed.hash}`;
  } catch {
    return "";
  }
}

function canonicalScope(
  relayUrl: string,
  signerPubkey: string,
  channelId: string,
): Omit<MessageSnapshotScope, "generation"> | null {
  const canonicalRelay = canonicalSnapshotRelayUrl(relayUrl);
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
  return `${STORAGE_KEY_PREFIX}:${encodeURIComponent(scope.relayUrl)}:${encodeURIComponent(scope.signerPubkey)}:${encodeURIComponent(scope.channelId)}`;
}

function identityPrefix(relayUrl: string, signerPubkey: string): string {
  return `${STORAGE_KEY_PREFIX}:${encodeURIComponent(relayUrl)}:${encodeURIComponent(signerPubkey)}:`;
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

function removeObsoleteSnapshotNamespaces(): void {
  removeKeysWithPrefix(`${LEGACY_STORAGE_KEY_PREFIX}:`);
  removeKeysWithPrefix(`${PREVIOUS_STORAGE_KEY_PREFIX}:`);
}

function removeStoredKey(key: string): null {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Storage access failures are non-fatal.
  }
  return null;
}

type ValidatedPersistableEvent = {
  event: RelayEvent;
  isTimeline: boolean;
  hasScopedChannelTag: boolean;
  referencedEventIds: string[];
};

function validatePersistableEvent(
  value: unknown,
  channelId: string,
): ValidatedPersistableEvent | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
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
    !PERSISTABLE_EVENT_KINDS.has(event.kind) ||
    !Array.isArray(event.tags) ||
    "localKey" in event ||
    "pending" in event ||
    Object.keys(event).length !== EVENT_KEYS.size ||
    !Object.keys(event).every((key) => EVENT_KEYS.has(key))
  ) {
    return null;
  }

  const tags = event.tags as unknown[];
  if (
    !tags.every(
      (tag) =>
        Array.isArray(tag) && tag.every((part) => typeof part === "string"),
    )
  ) {
    return null;
  }
  const channelTags = (tags as string[][]).filter((tag) => tag[0] === "h");
  const hasScopedChannelTag =
    channelTags.length === 1 &&
    channelTags[0]?.length === 2 &&
    channelTags[0][1] === channelId;
  const isTimeline = TIMELINE_EVENT_KINDS.has(event.kind as number);
  if (
    isTimeline
      ? !hasScopedChannelTag
      : channelTags.length > 0 && !hasScopedChannelTag
  ) {
    return null;
  }
  try {
    // Reconstruct the canonical event so verifier cache metadata attached to a
    // previously finalized object cannot survive a post-signature mutation.
    if (
      !verifyEvent({
        id: event.id as string,
        pubkey: event.pubkey as string,
        created_at: event.created_at as number,
        kind: event.kind as number,
        tags: event.tags as string[][],
        content: event.content as string,
        sig: event.sig as string,
      })
    ) {
      return null;
    }
  } catch {
    return null;
  }
  return {
    event: event as RelayEvent,
    isTimeline,
    hasScopedChannelTag,
    referencedEventIds: (tags as string[][])
      .filter((tag) => tag[0] === "e" && typeof tag[1] === "string")
      .map((tag) => tag[1]),
  };
}

function isPersistableEventBatch(
  events: unknown[],
  channelId: string,
): events is RelayEvent[] {
  const validated = events.map((event) =>
    validatePersistableEvent(event, channelId),
  );
  if (validated.some((event) => event === null)) return false;

  const acceptedIds = new Set(
    validated.flatMap((event) => (event?.isTimeline ? [event.event.id] : [])),
  );
  let unresolved = validated.filter(
    (event): event is ValidatedPersistableEvent =>
      event !== null && !event.isTimeline,
  );

  while (unresolved.length > 0) {
    const next = unresolved.filter((event) => {
      if (
        event.hasScopedChannelTag ||
        event.referencedEventIds.some((id) => acceptedIds.has(id))
      ) {
        acceptedIds.add(event.event.id);
        return false;
      }
      return true;
    });
    if (next.length === unresolved.length) return false;
    unresolved = next;
  }
  return true;
}

function parseSnapshotPayload(
  value: unknown,
  scope: MessageSnapshotScope,
  validateEvents = true,
): SnapshotPayload | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const payload = value as Record<string, unknown>;
  if (
    !Object.keys(payload).every((key) => PAYLOAD_KEYS.has(key)) ||
    Object.keys(payload).length !== PAYLOAD_KEYS.size ||
    payload.version !== 3 ||
    payload.relayUrl !== scope.relayUrl ||
    payload.signerPubkey !== scope.signerPubkey ||
    payload.channelId !== scope.channelId ||
    typeof payload.updatedAt !== "number" ||
    !Number.isSafeInteger(payload.updatedAt) ||
    payload.updatedAt < 0 ||
    !Array.isArray(payload.events) ||
    payload.events.length === 0 ||
    payload.events.length > MAX_EVENTS_PER_SNAPSHOT ||
    (validateEvents &&
      !isPersistableEventBatch(payload.events, scope.channelId))
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
    // V1 had no identity dimension and branch-local V2 used ambiguous keys.
    removeObsoleteSnapshotNamespaces();
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
    removeObsoleteSnapshotNamespaces();
    if (
      events.length === 0 ||
      !isPersistableEventBatch(events, scope.channelId)
    ) {
      return false;
    }

    const persistable = events.slice(-MAX_EVENTS_PER_SNAPSHOT);
    if (!isPersistableEventBatch(persistable, scope.channelId)) return false;
    const key = messageSnapshotKey(scope);
    const previous = window.localStorage.getItem(key);
    if (previous !== null) {
      // Incoming events were verified above. A byte-equivalent previous event
      // array is therefore canonical without repeating signature verification.
      const parsed = parseSnapshotPayload(JSON.parse(previous), scope, false);
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
      version: 3,
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
    removeObsoleteSnapshotNamespaces();
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

/** Invalidate every captured scope and remove all message snapshot namespaces. */
export function removeAllMessageSnapshots(): void {
  generationSequence += 1;
  globalScopeGeneration = generationSequence;
  identityScopeGenerations.clear();
  try {
    removeKeysWithPrefix(`${STORAGE_KEY_PREFIX}:`);
    removeObsoleteSnapshotNamespaces();
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
