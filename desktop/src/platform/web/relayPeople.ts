import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayPeopleClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent" | "publishEvent"
>;

type ObjectBody = Record<string, unknown>;
type RelayFilter = Parameters<RelayPeopleClient["fetchEvents"]>[0];

const MAX_SEARCH_LIMIT = 500;
const MAX_CONTACTS = 10_000;
const HEX_PUBKEY = /^[0-9a-f]{64}$/i;
const LOWER_HEX_PUBKEY = /^[0-9a-f]{64}$/;
const LOWER_HEX_SIGNATURE = /^[0-9a-f]{128}$/;

function objectBody(body: unknown, command: string): ObjectBody {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body as ObjectBody;
}

function requiredString(body: ObjectBody, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function stringArray(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value;
}

function optionalU32(body: ObjectBody, field: string): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (
    !Number.isInteger(value) ||
    (value as number) < 0 ||
    (value as number) > 0xffff_ffff
  ) {
    throw new TypeError(`${field} must be an unsigned 32-bit integer`);
  }
  return value as number;
}

function searchPage(cursor: unknown): number {
  if (typeof cursor !== "string" || !/^\d+$/.test(cursor)) return 1;
  const page = Number(cursor);
  return Number.isSafeInteger(page) && page > 0 && page <= 0xffff_ffff
    ? page
    : 1;
}

function extendedFilter(
  filter: RelayFilter & {
    page?: number;
    search?: string;
    search_mode?: "prefix";
  },
): RelayFilter {
  return filter;
}

function parseProfile(event: RelayEvent) {
  let content: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(event.content) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      content = parsed as Record<string, unknown>;
    }
  } catch {
    // Rust converters treat malformed kind:0 content as an empty profile.
  }
  const text = (field: string): string | null =>
    typeof content[field] === "string" ? (content[field] as string) : null;
  return {
    displayName: text("display_name") ?? text("name"),
    avatarUrl: text("picture"),
    nip05: text("nip05"),
  };
}

// BIP-340 verification is kept local because nostr-tools exposes event
// verification, not verification of the arbitrary NIP-OA attestation digest.
const FIELD_PRIME = (1n << 256n) - (1n << 32n) - 977n;
const GROUP_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const GENERATOR = {
  x: BigInt(
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  ),
  y: BigInt(
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  ),
};
type Point = typeof GENERATOR | null;

function mod(value: bigint, modulus = FIELD_PRIME): bigint {
  const reduced = value % modulus;
  return reduced >= 0n ? reduced : reduced + modulus;
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
}

function pointAdd(left: Point, right: Point): Point {
  if (!left) return right;
  if (!right) return left;
  if (left.x === right.x && left.y !== right.y) return null;
  const slope =
    left.x === right.x
      ? mod(3n * left.x * left.x * modPow(2n * left.y, FIELD_PRIME - 2n))
      : mod((right.y - left.y) * modPow(right.x - left.x, FIELD_PRIME - 2n));
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
}

function scalarMultiply(scalar: bigint, point: Point): Point {
  let result: Point = null;
  let addend = point;
  let value = scalar;
  while (value > 0n) {
    if (value & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    value >>= 1n;
  }
  return result;
}

function liftX(x: bigint): Point {
  if (x >= FIELD_PRIME) return null;
  const candidate = modPow(mod(x * x * x + 7n), (FIELD_PRIME + 1n) / 4n);
  if (mod(candidate * candidate - x * x * x - 7n) !== 0n) return null;
  return { x, y: candidate & 1n ? FIELD_PRIME - candidate : candidate };
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(
    chunks.reduce((sum, chunk) => sum + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function verifySchnorr(
  signature: string,
  message: Uint8Array,
  pubkey: string,
): boolean {
  try {
    const signatureBytes = hexToBytes(signature);
    const pubkeyBytes = hexToBytes(pubkey);
    const r = BigInt(`0x${bytesToHex(signatureBytes.slice(0, 32))}`);
    const s = BigInt(`0x${bytesToHex(signatureBytes.slice(32))}`);
    if (r >= FIELD_PRIME || s >= GROUP_ORDER) return false;
    const point = liftX(BigInt(`0x${pubkey}`));
    if (!point) return false;
    const tagHash = sha256(new TextEncoder().encode("BIP0340/challenge"));
    const challenge = mod(
      BigInt(
        `0x${bytesToHex(sha256(concatBytes(tagHash, tagHash, signatureBytes.slice(0, 32), pubkeyBytes, message)))}`,
      ),
      GROUP_ORDER,
    );
    const negated = { x: point.x, y: mod(-point.y) };
    const result = pointAdd(
      scalarMultiply(s, GENERATOR),
      scalarMultiply(challenge, negated),
    );
    return Boolean(result && !(result.y & 1n) && result.x === r);
  } catch {
    return false;
  }
}

function validConditions(value: string): boolean {
  if (!value) return true;
  return value.split("&").every((clause) => {
    const match = /^(kind=|created_at[<>])(0|[1-9]\d*)$/.exec(clause);
    if (!match) return false;
    const numeric = Number(match[2]);
    return (
      Number.isSafeInteger(numeric) &&
      (match[1] === "kind=" ? numeric <= 65_535 : numeric <= 0xffff_ffff)
    );
  });
}

function verifiedOwner(event: RelayEvent): string | null {
  if (!LOWER_HEX_PUBKEY.test(event.pubkey)) return null;
  for (const tag of event.tags) {
    if (tag.length !== 4 || tag[0] !== "auth") continue;
    const [, owner, conditions, signature] = tag;
    if (
      !LOWER_HEX_PUBKEY.test(owner) ||
      owner === event.pubkey ||
      !LOWER_HEX_SIGNATURE.test(signature) ||
      !validConditions(conditions)
    ) {
      continue;
    }
    const preimage = new TextEncoder().encode(
      `nostr:agent-auth:${event.pubkey}:${conditions}`,
    );
    if (verifySchnorr(signature, sha256(preimage), owner)) return owner;
  }
  return null;
}

function userResult(event: RelayEvent) {
  const profile = parseProfile(event);
  const owner = verifiedOwner(event);
  return {
    pubkey: event.pubkey,
    display_name: profile.displayName,
    avatar_url: profile.avatarUrl,
    nip05_handle: profile.nip05,
    owner_pubkey: owner,
    is_agent: owner !== null,
  };
}

function matchScore(query: string, event: RelayEvent): number {
  const profile = parseProfile(event);
  const display = profile.displayName?.toLowerCase() ?? "";
  const nip05 = profile.nip05?.toLowerCase() ?? "";
  const pubkey = event.pubkey.toLowerCase();
  const fieldScore = (
    field: string,
    exact: number,
    prefix: number,
    contains: number,
  ) =>
    !field
      ? 0
      : field === query
        ? exact
        : field.startsWith(query)
          ? prefix
          : field.includes(query)
            ? contains
            : 0;
  return Math.max(
    fieldScore(display, 1000, 900, 800),
    fieldScore(nip05, 700, 600, 500),
    pubkey.startsWith(query) ? 400 : 0,
  );
}

function emptyQueryResults(events: RelayEvent[]) {
  const latest = new Map<string, RelayEvent>();
  for (const event of events) {
    if (event.kind !== 0) continue;
    const key = event.pubkey.toLowerCase();
    const prior = latest.get(key);
    if (!prior || event.created_at > prior.created_at) latest.set(key, event);
  }
  return [...latest.values()].sort((left, right) => {
    const leftProfile = parseProfile(left);
    const rightProfile = parseProfile(right);
    const leftLabel = (
      leftProfile.displayName ??
      leftProfile.nip05 ??
      left.pubkey
    ).toLowerCase();
    const rightLabel = (
      rightProfile.displayName ??
      rightProfile.nip05 ??
      right.pubkey
    ).toLowerCase();
    if (leftLabel !== rightLabel) return leftLabel < rightLabel ? -1 : 1;
    return left.pubkey < right.pubkey ? -1 : left.pubkey > right.pubkey ? 1 : 0;
  });
}

function rankedResults(events: RelayEvent[], query: string) {
  const seen = new Set<string>();
  return events
    .map((event, index) => ({
      event,
      index,
      score: event.kind === 0 ? matchScore(query, event) : 0,
    }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .flatMap(({ event }) => {
      if (seen.has(event.pubkey)) return [];
      seen.add(event.pubkey);
      return [event];
    });
}

export async function searchUsers(body: unknown, client: RelayPeopleClient) {
  const input = objectBody(body, "search_users");
  const query = requiredString(input, "query").trim().toLowerCase();
  const limit = Math.min(optionalU32(input, "limit") ?? 8, MAX_SEARCH_LIMIT);
  const page = searchPage(input.cursor);
  if (limit === 0) return { users: [], next_cursor: null };

  const offset = (page - 1) * limit;
  if (!Number.isSafeInteger(offset) || offset >= MAX_SEARCH_LIMIT) {
    return { users: [], next_cursor: null };
  }
  const cumulativeLimit = Math.min(MAX_SEARCH_LIMIT, offset + limit);
  const filter = query
    ? extendedFilter({
        kinds: [0],
        search: query,
        search_mode: "prefix",
        limit: cumulativeLimit,
        page: 1,
      })
    : extendedFilter({ kinds: [0], limit: cumulativeLimit, page: 1 });
  const events = await client.fetchEvents(filter);
  const ordered = query
    ? rankedResults(events, query)
    : emptyQueryResults(events);
  const users = ordered.slice(offset, offset + limit).map(userResult);
  const hasNext =
    cumulativeLimit < MAX_SEARCH_LIMIT &&
    events.length >= cumulativeLimit &&
    ordered.length >= offset + limit;
  return { users, next_cursor: hasNext ? String(page + 1) : null };
}

export async function getPresence(body: unknown, client: RelayPeopleClient) {
  const pubkeys = stringArray(objectBody(body, "get_presence"), "pubkeys");
  if (pubkeys.length === 0) return {};
  let events: RelayEvent[];
  try {
    events = await client.fetchEvents({
      kinds: [20001],
      authors: pubkeys,
      limit: 1_000,
    });
  } catch {
    return {};
  }
  const latest = new Map<
    string,
    { createdAt: number; status: "online" | "away" | "offline" }
  >();
  for (const event of events) {
    const status = event.content.trim();
    if (status !== "online" && status !== "away" && status !== "offline")
      continue;
    const pubkey =
      event.tags.find((tag) => tag[0] === "p" && tag.length >= 2)?.[1] ??
      event.pubkey;
    const prior = latest.get(pubkey);
    if (!prior || event.created_at > prior.createdAt)
      latest.set(pubkey, { createdAt: event.created_at, status });
  }
  return Object.fromEntries(
    [...latest].map(([pubkey, value]) => [pubkey, value.status]),
  );
}

export async function getContactList(body: unknown, client: RelayPeopleClient) {
  const pubkey = requiredString(objectBody(body, "get_contact_list"), "pubkey");
  const event = await client.fetchFirstEvent({
    kinds: [3],
    authors: [pubkey],
    limit: 1,
  });
  return event
    ? {
        id: event.id,
        pubkey: event.pubkey,
        created_at: event.created_at,
        tags: event.tags,
        content: event.content,
      }
    : { id: "", pubkey, created_at: 0, tags: [], content: "" };
}

export async function setContactList(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayPeopleClient,
) {
  const input = objectBody(body, "set_contact_list");
  if (!Array.isArray(input.contacts))
    throw new TypeError("contacts must be an array");
  if (input.contacts.length > MAX_CONTACTS) {
    throw new Error(
      `too many contacts (max ${MAX_CONTACTS}, got ${input.contacts.length})`,
    );
  }
  const seen = new Set<string>();
  const tags: string[][] = [];
  for (const raw of input.contacts) {
    const contact = objectBody(raw, "contact");
    const pubkey = requiredString(contact, "pubkey");
    if (!HEX_PUBKEY.test(pubkey)) {
      throw new Error(
        `pubkey must be a 64-character hex string (got ${pubkey.length} chars)`,
      );
    }
    const normalized = pubkey.toLowerCase();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    const relayUrl = contact.relay_url;
    const petname = contact.petname;
    if (
      relayUrl !== undefined &&
      relayUrl !== null &&
      typeof relayUrl !== "string"
    ) {
      throw new TypeError("relay_url must be a string or null");
    }
    if (
      petname !== undefined &&
      petname !== null &&
      typeof petname !== "string"
    ) {
      throw new TypeError("petname must be a string or null");
    }
    tags.push(["p", normalized, relayUrl ?? "", petname ?? ""]);
  }
  const event = JSON.parse(
    identity.sign({ kind: 3, content: "", tags }),
  ) as RelayEvent;
  if (!event || typeof event.id !== "string" || typeof event.sig !== "string") {
    throw new Error("Browser identity returned an invalid signed event");
  }
  const published = await client.publishEvent(
    event,
    "Timed out while updating the contact list.",
    "Failed while updating the contact list.",
  );
  return { event_id: published.id, accepted: true, message: "" };
}

export function registerRelayPeopleCommands(
  identity: BrowserIdentityManager,
  client: RelayPeopleClient = relayClient,
): void {
  register("search_users", (body) => searchUsers(body, client));
  register("get_presence", (body) => getPresence(body, client));
  register("get_contact_list", (body) => getContactList(body, client));
  register("set_contact_list", (body) =>
    setContactList(body, identity, client),
  );
}
