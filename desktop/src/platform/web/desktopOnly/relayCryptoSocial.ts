import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import { nip44 } from "nostr-tools";
import { decode } from "nostr-tools/nip19";
import { verifyEvent } from "nostr-tools/pure";

import type { BrowserIdentityManager } from "../identity";
import { dispatch, register, type InvokeBody } from "../registry";
import { registerOffMutation } from "./capabilityOff";

type RelayCryptoSocialClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent" | "publishEvent"
>;

type ObjectBody = Record<string, unknown>;
type Point = { x: bigint; y: bigint } | null;

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;
const MAX_NOTE_IDS = 200;
const OBSERVER_MAX_PLAINTEXT_BYTES = 65_535;
const NIP44_MIN_CONTENT_LENGTH = 132;
const NIP44_MAX_CONTENT_LENGTH = 87_472;
const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47] as const;

const CURVE_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const CURVE_G: Exclude<Point, null> = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

function objectBody(body: InvokeBody, command: string): ObjectBody {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body;
}

function optionalString(body: ObjectBody, field: string): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string")
    throw new TypeError(`${field} must be a string`);
  return value;
}

function requiredString(body: ObjectBody, field: string): string {
  const value = optionalString(body, field);
  if (value === undefined) throw new TypeError(`${field} must be a string`);
  return value;
}

const RFC3339_WITH_OFFSET =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

function optionalInteger(body: ObjectBody, field: string): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${field} must be a non-negative integer`);
  }
  return value;
}

function requiredStringArray(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function normalizedPubkey(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!HEX_64.test(normalized)) {
    throw new Error(`${field} must be a 64-character hexadecimal pubkey`);
  }
  return normalized;
}

function validateNoteId(value: string): void {
  if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error("invalid note id");
}

function parseSignedEvent(value: string): RelayEvent {
  const parsed: unknown = JSON.parse(value);
  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof (parsed as RelayEvent).id !== "string" ||
    typeof (parsed as RelayEvent).pubkey !== "string" ||
    typeof (parsed as RelayEvent).sig !== "string"
  ) {
    throw new Error("Browser identity returned an invalid signed event");
  }
  return parsed as RelayEvent;
}

async function publishRequest(
  identity: BrowserIdentityManager,
  client: RelayCryptoSocialClient,
  request: { kind: number; content: string; tags: string[][] },
  operation: string,
) {
  const event = parseSignedEvent(identity.sign(request));
  await client.publishEvent(
    event,
    `Timed out while ${operation}.`,
    `Failed while ${operation}.`,
  );
  return { event_id: event.id, accepted: true, message: "accepted" };
}

function eventTagValues(event: RelayEvent, name: string): string[] {
  return event.tags
    .filter((tag) => tag[0] === name && typeof tag[1] === "string")
    .map((tag) => tag[1]);
}

function lastEventTag(event: RelayEvent, name: string): string | undefined {
  for (let index = event.tags.length - 1; index >= 0; index -= 1) {
    const tag = event.tags[index];
    if (tag?.[0] === name && tag[1]) return tag[1];
  }
  return undefined;
}

function notesResponse(events: RelayEvent[]) {
  const notes = events.map((event) => ({
    id: event.id,
    pubkey: event.pubkey,
    created_at: event.created_at,
    content: event.content,
    tags: event.tags,
  }));
  const last = notes.at(-1);
  return {
    notes,
    next_cursor: last ? { before: last.created_at, before_id: last.id } : null,
  };
}

function deletedEventIds(events: RelayEvent[]): Set<string> {
  return new Set(events.flatMap((event) => eventTagValues(event, "e")));
}

function identitySecret(identity: BrowserIdentityManager): Uint8Array {
  const decoded = decode(identity.getNsec());
  if (decoded.type !== "nsec")
    throw new Error("Identity did not provide an nsec");
  return Uint8Array.from(decoded.data);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function hexToBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    throw new Error("invalid hexadecimal value");
  }
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function concatBytes(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    values.reduce((total, value) => total + value.length, 0),
  );
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)),
  );
}

function mod(value: bigint, modulus = CURVE_P): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }
  return result;
}

function pointAdd(left: Point, right: Point): Point {
  if (!left) return right;
  if (!right) return left;
  if (left.x === right.x && left.y !== right.y) return null;
  if (left.y === 0n && left.x === right.x) return null;
  const slope =
    left.x === right.x
      ? mod(3n * left.x * left.x * modPow(2n * left.y, CURVE_P - 2n, CURVE_P))
      : mod(
          (right.y - left.y) * modPow(right.x - left.x, CURVE_P - 2n, CURVE_P),
        );
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
}

function pointMultiply(scalar: bigint, point: Point): Point {
  let result: Point = null;
  let addend = point;
  let value = scalar;
  while (value > 0n) {
    if ((value & 1n) === 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    value >>= 1n;
  }
  return result;
}

function liftX(x: bigint): Point {
  if (x >= CURVE_P) return null;
  const ySquared = mod(x * x * x + 7n);
  let y = modPow(ySquared, (CURVE_P + 1n) / 4n, CURVE_P);
  if (mod(y * y) !== ySquared) return null;
  if ((y & 1n) === 1n) y = CURVE_P - y;
  return { x, y };
}

async function taggedHash(
  tag: string,
  payload: Uint8Array,
): Promise<Uint8Array> {
  const tagHash = await sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, payload));
}

async function verifySchnorr(
  signatureHex: string,
  message: Uint8Array,
  pubkeyHex: string,
): Promise<boolean> {
  try {
    if (!HEX_128.test(signatureHex) || !HEX_64.test(pubkeyHex)) return false;
    const signature = hexToBytes(signatureHex);
    const r = BigInt(`0x${signatureHex.slice(0, 64)}`);
    const s = BigInt(`0x${signatureHex.slice(64)}`);
    if (r >= CURVE_P || s >= CURVE_N) return false;
    const publicPoint = liftX(BigInt(`0x${pubkeyHex}`));
    if (!publicPoint) return false;
    const challenge = await taggedHash(
      "BIP0340/challenge",
      concatBytes(signature.slice(0, 32), hexToBytes(pubkeyHex), message),
    );
    const e = BigInt(`0x${bytesToHex(challenge)}`) % CURVE_N;
    const point = pointAdd(
      pointMultiply(s, CURVE_G),
      pointMultiply(CURVE_N - e, publicPoint),
    );
    return Boolean(point && (point.y & 1n) === 0n && point.x === r);
  } catch {
    return false;
  }
}

function validConditions(value: string): boolean {
  if (value === "") return true;
  if (/\s/.test(value)) return false;
  return value.split("&").every((clause) => {
    const match = /^(kind=|created_at<|created_at>)(0|[1-9][0-9]*)$/.exec(
      clause,
    );
    if (!match) return false;
    const parsed = Number(match[2]);
    return (
      Number.isSafeInteger(parsed) &&
      parsed <= (match[1] === "kind=" ? 65_535 : 4_294_967_295)
    );
  });
}

async function verifiedOwnerAuthTag(
  target: string,
  event: RelayEvent,
): Promise<string[] | undefined> {
  if (event.pubkey.toLowerCase() !== target || !verifyEvent(event))
    return undefined;
  for (const tag of event.tags) {
    if (tag.length !== 4 || tag[0] !== "auth") continue;
    const owner = tag[1]?.toLowerCase() ?? "";
    const conditions = tag[2] ?? "";
    const signature = tag[3]?.toLowerCase() ?? "";
    if (
      !HEX_64.test(owner) ||
      owner === target ||
      !validConditions(conditions) ||
      !HEX_128.test(signature)
    ) {
      continue;
    }
    const message = await sha256(
      new TextEncoder().encode(`nostr:agent-auth:${target}:${conditions}`),
    );
    if (await verifySchnorr(signature, message, owner)) {
      return ["auth", owner, conditions, signature];
    }
  }
  return undefined;
}

async function archiveTags(
  identity: BrowserIdentityManager,
  client: RelayCryptoSocialClient,
  target: string,
  reason?: string,
  replacedBy?: string,
): Promise<string[][]> {
  if (reason !== undefined) {
    if (utf8Length(reason) > 64)
      throw new Error("reason code exceeds maximum length of 64 UTF-8 bytes");
    if (/\p{Cc}/u.test(reason))
      throw new Error("reason code must not contain control characters");
  }
  const tags: string[][] = [["-"], ["p", target]];
  if (reason !== undefined) tags.push(["reason", reason]);
  if (replacedBy !== undefined) {
    const replacement = normalizedPubkey(replacedBy, "replaced_by");
    if (replacement === target)
      throw new Error("replaced-by must differ from the target");
    tags.push(["replaced-by", replacement]);
  }
  if (identity.pubkey().toLowerCase() !== target) {
    const profile = await client.fetchFirstEvent({
      kinds: [0],
      authors: [target],
      limit: 1,
    });
    if (profile) {
      const auth = await verifiedOwnerAuthTag(target, profile);
      if (auth?.[1] === identity.pubkey().toLowerCase()) tags.push(auth);
    }
  }
  return tags;
}

function relayHttpUrl(value: string): string {
  const url = new URL(value.trim());
  if (url.protocol === "wss:") url.protocol = "https:";
  else if (url.protocol === "ws:") url.protocol = "http:";
  else if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Relay URL must use ws://, wss://, http://, or https://");
  }
  return url.toString().replace(/\/$/, "");
}

async function activeRelayHttpUrl(): Promise<string> {
  return relayHttpUrl(await dispatch<string>("get_relay_http_url"));
}

function validateBindingRequest(body: ObjectBody) {
  const challengeId = requiredString(body, "challengeId");
  const nonce = requiredString(body, "nonce");
  const verificationCode = requiredString(body, "verificationCode");
  const origin = requiredString(body, "origin");
  const expiresAt = requiredString(body, "expiresAt");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      challengeId,
    )
  ) {
    throw new Error("invalid challenge_id");
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) throw new Error("invalid nonce");
  if (!/^\d{6}$/.test(verificationCode))
    throw new Error("verification_code must be exactly 6 digits");
  const parsedOrigin = new URL(origin);
  if (
    parsedOrigin.protocol !== "https:" ||
    !parsedOrigin.hostname ||
    parsedOrigin.username ||
    parsedOrigin.password ||
    parsedOrigin.pathname !== "/" ||
    parsedOrigin.search ||
    parsedOrigin.hash
  ) {
    throw new Error("invalid origin");
  }
  // Rust parses RFC3339 strictly (date, time, and offset all required).
  if (!RFC3339_WITH_OFFSET.test(expiresAt))
    throw new Error("invalid expires_at");
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry)) throw new Error("invalid expires_at");
  if (expiry <= Date.now()) throw new Error("expires_at is expired");
  return { challengeId, nonce, verificationCode, origin, expiresAt };
}

export function registerRelayCryptoSocialCommands(
  identity: BrowserIdentityManager,
  client: RelayCryptoSocialClient = relayClient,
): void {
  register("archive_identity", async (rawBody) => {
    const body = objectBody(rawBody, "archive_identity");
    const req = objectBody(body.req as InvokeBody, "archive_identity.req");
    const target = normalizedPubkey(
      requiredString(req, "targetPubkey"),
      "target_pubkey",
    );
    const content = optionalString(req, "content") ?? "";
    if (utf8Length(content) > 65_536)
      throw new Error("content exceeds maximum length of 65536 UTF-8 bytes");
    const tags = await archiveTags(
      identity,
      client,
      target,
      optionalString(req, "reason"),
      optionalString(req, "replacedBy"),
    );
    return publishRequest(
      identity,
      client,
      { kind: 9035, content, tags },
      "archiving identity",
    );
  });

  register("unarchive_identity", async (rawBody) => {
    const body = objectBody(rawBody, "unarchive_identity");
    const req = objectBody(body.req as InvokeBody, "unarchive_identity.req");
    const target = normalizedPubkey(
      requiredString(req, "targetPubkey"),
      "target_pubkey",
    );
    const content = optionalString(req, "content") ?? "";
    if (utf8Length(content) > 65_536)
      throw new Error("content exceeds maximum length of 65536 UTF-8 bytes");
    const tags = await archiveTags(
      identity,
      client,
      target,
      optionalString(req, "reason"),
    );
    return publishRequest(
      identity,
      client,
      { kind: 9036, content, tags },
      "unarchiving identity",
    );
  });

  register("build_observer_control_event", (rawBody) => {
    const body = objectBody(rawBody, "build_observer_control_event");
    const agentPubkey = normalizedPubkey(
      requiredString(body, "agentPubkey"),
      "agent_pubkey",
    );
    const plaintext = JSON.stringify(body.payload);
    if (plaintext === undefined)
      throw new Error("observer payload is not JSON serializable");
    if (utf8Length(plaintext) > OBSERVER_MAX_PLAINTEXT_BYTES)
      throw new Error("observer plaintext exceeds 65535 bytes");
    const secret = identitySecret(identity);
    try {
      const key = nip44.v2.utils.getConversationKey(secret, agentPubkey);
      try {
        const content = nip44.v2.encrypt(plaintext, key);
        return identity.sign({
          kind: 24200,
          content,
          tags: [
            ["p", agentPubkey],
            ["agent", agentPubkey],
            ["frame", "control"],
          ],
        });
      } finally {
        key.fill(0);
      }
    } finally {
      secret.fill(0);
    }
  });

  register("decrypt_observer_event", (rawBody) => {
    const body = objectBody(rawBody, "decrypt_observer_event");
    const parsed: unknown = JSON.parse(requiredString(body, "eventJson"));
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !verifyEvent(parsed as RelayEvent)
    ) {
      throw new Error("observer event has invalid ID or signature");
    }
    const event = parsed as RelayEvent;
    if (
      event.content.length < NIP44_MIN_CONTENT_LENGTH ||
      event.content.length > NIP44_MAX_CONTENT_LENGTH
    ) {
      throw new Error(
        `invalid NIP-44 ciphertext length: ${event.content.length}`,
      );
    }
    const secret = identitySecret(identity);
    try {
      const key = nip44.v2.utils.getConversationKey(secret, event.pubkey);
      try {
        const plaintext = nip44.v2.decrypt(event.content, key);
        if (utf8Length(plaintext) > OBSERVER_MAX_PLAINTEXT_BYTES)
          throw new Error("observer plaintext exceeds 65535 bytes");
        return JSON.parse(plaintext) as unknown;
      } finally {
        key.fill(0);
      }
    } finally {
      secret.fill(0);
    }
  });

  // Snapshot import (preview/confirm) is desktop-only, so the fetched bytes
  // would have no truthful consumer in the browser; fail clearly at the Import
  // button instead of returning bytes we cannot validate like Rust does.
  registerOffMutation(
    "fetch_snapshot_bytes",
    "importing agent/team snapshots needs the desktop app",
  );
  register("fetch_workspace_icon", async (rawBody) => {
    const body = objectBody(rawBody, "fetch_workspace_icon");
    try {
      const response = await fetch(
        relayHttpUrl(requiredString(body, "relayUrl")),
        {
          headers: { Accept: "application/nostr+json" },
        },
      );
      if (!response.ok) return null;
      const value: unknown = await response.json();
      if (!value || typeof value !== "object") return null;
      const icon = (value as { icon?: unknown }).icon;
      return typeof icon === "string" && icon.length > 0 ? icon : null;
    } catch {
      return null;
    }
  });

  register("get_global_notes", async (rawBody) => {
    const body = objectBody(rawBody, "get_global_notes");
    const filter: { kinds: number[]; limit: number; until?: number } = {
      kinds: [1],
      limit: Math.min(optionalInteger(body, "limit") ?? 50, 200),
    };
    const before = optionalInteger(body, "before");
    if (before !== undefined) filter.until = before;
    return notesResponse(await client.fetchEvents(filter));
  });

  register("get_liked_notes", async (rawBody) => {
    const body = objectBody(rawBody, "get_liked_notes");
    const author = normalizedPubkey(
      requiredString(body, "authorPubkey"),
      "author_pubkey",
    );
    const cap = Math.min(optionalInteger(body, "limit") ?? 50, MAX_NOTE_IDS);
    const reactions = await client.fetchEvents({
      kinds: [7],
      authors: [author],
      limit: Math.min(cap * 4, 1_000),
    });
    reactions.sort((left, right) => right.created_at - left.created_at);
    const reactionIds = reactions.map((event) => event.id);
    const deletions = reactionIds.length
      ? await client.fetchEvents({
          kinds: [5],
          authors: [author],
          "#e": reactionIds,
          limit: 500,
        })
      : [];
    const deleted = deletedEventIds(deletions);
    const targetIds: string[] = [];
    const likedAt = new Map<string, number>();
    const seen = new Set<string>();
    for (const reaction of reactions) {
      if (targetIds.length >= cap) break;
      if (deleted.has(reaction.id)) continue;
      const target = lastEventTag(reaction, "e");
      if (target && !seen.has(target)) {
        seen.add(target);
        targetIds.push(target);
        likedAt.set(target, reaction.created_at);
      }
    }
    if (!targetIds.length) return { notes: [], next_cursor: null };
    const response = notesResponse(
      await client.fetchEvents({ kinds: [1], ids: targetIds, limit: cap }),
    );
    response.notes.sort(
      (left, right) =>
        (likedAt.get(right.id) ?? 0) - (likedAt.get(left.id) ?? 0),
    );
    response.notes.splice(cap);
    return response;
  });

  register("get_note_reactions", async (rawBody) => {
    const body = objectBody(rawBody, "get_note_reactions");
    const noteIds = requiredStringArray(body, "noteIds");
    if (!noteIds.length) return [];
    if (noteIds.length > MAX_NOTE_IDS)
      throw new Error(
        `too many note ids (max ${MAX_NOTE_IDS}, got ${noteIds.length})`,
      );
    noteIds.forEach(validateNoteId);
    const reactions = await client.fetchEvents({
      kinds: [7],
      "#e": noteIds,
      limit: 500,
    });
    const reactionIds = reactions.map((event) => event.id);
    const deletions = reactionIds.length
      ? await client.fetchEvents({ kinds: [5], "#e": reactionIds, limit: 500 })
      : [];
    const deleted = deletedEventIds(deletions);
    const targets = new Set(noteIds);
    const folded = new Map<string, Set<string>>();
    for (const reaction of reactions) {
      if (deleted.has(reaction.id)) continue;
      const target = [...reaction.tags]
        .reverse()
        .find((tag) => tag[0] === "e" && tag[1] && targets.has(tag[1]))?.[1];
      if (!target) continue;
      const emoji = reaction.content || "+";
      const key = `${target}\0${emoji}`;
      const pubkeys = folded.get(key) ?? new Set<string>();
      pubkeys.add(reaction.pubkey);
      folded.set(key, pubkeys);
    }
    return Array.from(folded, ([key, values]) => {
      const [note_id, emoji] = key.split("\0");
      const pubkeys = [...values].sort();
      return { note_id, emoji, count: pubkeys.length, pubkeys };
    }).sort(
      (left, right) =>
        left.note_id.localeCompare(right.note_id) ||
        left.emoji.localeCompare(right.emoji),
    );
  });

  register("has_managed_agent_channel_message_marker", async (rawBody) => {
    const body = objectBody(
      rawBody,
      "has_managed_agent_channel_message_marker",
    );
    const channelId = requiredString(body, "channelId");
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        channelId,
      )
    ) {
      throw new Error(`invalid channel UUID: ${channelId}`);
    }
    const marker = requiredString(body, "marker").trim();
    if (!marker) throw new Error("message marker is required");
    const scope = optionalString(body, "markerScope");
    const rawAgent = optionalString(body, "agentPubkey")?.trim();
    if (scope !== undefined && scope !== "agent" && scope !== "channel")
      throw new Error(`unsupported marker scope: ${scope}`);
    if ((scope === undefined || scope === "agent") && !rawAgent)
      throw new Error("agent pubkey is required for agent-scoped markers");
    const author =
      scope === "channel"
        ? undefined
        : normalizedPubkey(rawAgent ?? "", "agent_pubkey");
    let until: number | undefined;
    for (let page = 0; page < 10; page += 1) {
      const filter: {
        kinds: number[];
        "#h": string[];
        limit: number;
        authors?: string[];
        until?: number;
      } = {
        kinds: [9],
        "#h": [channelId],
        limit: 500,
      };
      if (author) filter.authors = [author];
      if (until !== undefined) filter.until = until;
      const events = await client.fetchEvents(filter);
      if (
        events.some((event) =>
          event.tags.some((tag) => tag[0] === "client" && tag[1] === marker),
        )
      )
        return true;
      if (events.length < 500) break;
      until = Math.min(...events.map((event) => event.created_at)) - 1;
    }
    return false;
  });

  register("list_archived_identities", async () => {
    let relaySelf: string | undefined;
    try {
      const response = await fetch(await activeRelayHttpUrl(), {
        headers: { Accept: "application/nostr+json" },
      });
      if (!response.ok) return { archived: [] };
      const document: unknown = await response.json();
      const value =
        document && typeof document === "object"
          ? (document as { self?: unknown }).self
          : undefined;
      if (typeof value === "string" && HEX_64.test(value.toLowerCase()))
        relaySelf = value.toLowerCase();
    } catch {
      return { archived: [] };
    }
    if (!relaySelf) return { archived: [] };
    const snapshot = await client.fetchFirstEvent({
      authors: [relaySelf],
      kinds: [13535],
      limit: 1,
    });
    if (
      !snapshot ||
      snapshot.pubkey.toLowerCase() !== relaySelf ||
      !verifyEvent(snapshot)
    )
      return { archived: [] };
    return {
      archived: eventTagValues(snapshot, "p")
        .map((pubkey) => pubkey.toLowerCase())
        .filter((pubkey) => HEX_64.test(pubkey)),
    };
  });

  register("save_agent_card", (rawBody) => {
    const body = objectBody(rawBody, "save_agent_card");
    const base64 = requiredString(body, "cardPngBase64");
    const requestedName = requiredString(body, "fileName");
    let binary: string;
    try {
      binary = atob(base64);
    } catch (error) {
      throw new Error(`Card bytes were not valid base64: ${String(error)}`);
    }
    if (binary.length > 10 * 1024 * 1024)
      throw new Error("Snapshot PNG exceeds the 10 MiB cap");
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    if (!PNG_MAGIC.every((byte, index) => bytes[index] === byte))
      throw new Error("Refusing to save: card is not a PNG");
    const fileName =
      requestedName.endsWith(".agent.png") && !/[\\/]/.test(requestedName)
        ? requestedName
        : "card.agent.png";
    const url = URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
    try {
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = fileName;
      anchor.click();
    } finally {
      URL.revokeObjectURL(url);
    }
    return true;
  });

  register("sign_nostr_identity_binding", (rawBody) => {
    const body = objectBody(rawBody, "sign_nostr_identity_binding");
    const input = validateBindingRequest(body);
    return identity.sign({
      kind: 24243,
      content: "",
      tags: [
        ["challenge_id", input.challengeId],
        ["nonce", input.nonce],
        ["verification_code", input.verificationCode],
        ["audience", "buzz:nostr-identity"],
        ["action", "bind_nostr_identity"],
        ["protocol", "buzz-nostr-identity"],
        ["version", "1"],
        ["origin", input.origin],
        ["expires_at", input.expiresAt],
      ],
    });
  });
}
