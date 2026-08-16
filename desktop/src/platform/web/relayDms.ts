import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayDmClient = Pick<typeof relayClient, "fetchEvents" | "publishEvent">;
type ObjectBody = Record<string, unknown>;

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

function requiredPubkeys(body: ObjectBody): string[] {
  const value = body.pubkeys;
  if (!Array.isArray(value)) {
    throw new TypeError("pubkeys must be an array");
  }
  if (value.length === 0) {
    throw new Error("dm_open requires at least one pubkey");
  }
  return value.map((pubkey) => {
    if (
      typeof pubkey !== "string" ||
      pubkey.length !== 64 ||
      !/^[0-9a-f]+$/i.test(pubkey)
    ) {
      const length = typeof pubkey === "string" ? pubkey.length : 0;
      throw new Error(
        `pubkey must be a 64-character hex string (got ${length} chars)`,
      );
    }
    return pubkey.toLowerCase();
  });
}

function parseSignedEvent(value: string): RelayEvent {
  const event = JSON.parse(value) as RelayEvent;
  if (
    !event ||
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    typeof event.sig !== "string"
  ) {
    throw new Error("Browser identity returned an invalid signed event");
  }
  return event;
}

async function publishCommand(
  identity: BrowserIdentityManager,
  client: RelayDmClient,
  kind: number,
  tags: string[][],
  operation: string,
): Promise<void> {
  const event = parseSignedEvent(identity.sign({ kind, content: "", tags }));
  await client.publishEvent(
    event,
    `Timed out while ${operation}.`,
    `Failed while ${operation}.`,
  );
}

function tagValue(event: RelayEvent, name: string): string | null {
  return event.tags.find((tag) => tag[0] === name)?.[1] ?? null;
}

function tagValues(event: RelayEvent, name: string): string[] {
  return event.tags
    .filter((tag) => tag[0] === name && typeof tag[1] === "string")
    .map((tag) => tag[1]);
}

function channelType(event: RelayEvent): string {
  return (
    tagValue(event, "t") ??
    (event.tags.some((tag) => tag[0] === "hidden") ? "dm" : "stream")
  );
}

function isNewer(candidate: RelayEvent, current: RelayEvent): boolean {
  return (
    candidate.created_at > current.created_at ||
    (candidate.created_at === current.created_at && candidate.id < current.id)
  );
}

function sameParticipants(event: RelayEvent, expected: Set<string>): boolean {
  if (channelType(event) !== "dm") return false;
  const actual = new Set(
    tagValues(event, "p").map((value) => value.toLowerCase()),
  );
  return (
    actual.size === expected.size &&
    Array.from(expected).every((pubkey) => actual.has(pubkey))
  );
}

function ttlSeconds(event: RelayEvent): number | null {
  const value = tagValue(event, "ttl");
  if (value === null || !/^[+-]?\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) &&
    parsed >= -2147483648 &&
    parsed <= 2147483647
    ? parsed
    : null;
}

function channelInfo(event: RelayEvent) {
  const id = tagValue(event, "d");
  if (!id) throw new Error("kind:39000 missing required `d` tag");
  const participantPubkeys = tagValues(event, "p");
  const visibilityTag = tagValue(event, "visibility");
  const visibility =
    event.tags.some((tag) => tag[0] === "public") || visibilityTag === "open"
      ? "open"
      : event.tags.some((tag) => tag[0] === "private") ||
          visibilityTag === "private"
        ? "private"
        : "open";
  return {
    id,
    name: tagValue(event, "name") ?? "",
    channel_type: channelType(event),
    visibility,
    description: tagValue(event, "about") ?? "",
    topic: tagValue(event, "topic"),
    purpose: tagValue(event, "purpose"),
    member_count: 0,
    member_pubkeys: [],
    last_message_at: null,
    archived_at:
      tagValue(event, "archived") === "true"
        ? new Date(event.created_at * 1000).toISOString()
        : null,
    participants: participantPubkeys,
    participant_pubkeys: participantPubkeys,
    is_member: true,
    ttl_seconds: ttlSeconds(event),
    ttl_deadline: tagValue(event, "ttl_deadline"),
  };
}

async function fetchDmMetadata(
  client: RelayDmClient,
  participants: Set<string>,
  selfPubkey: string,
): Promise<RelayEvent> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const events = await client.fetchEvents({
      kinds: [39000],
      "#p": [selfPubkey],
      limit: 1000,
    });
    const match = events
      .filter((event) => sameParticipants(event, participants))
      .reduce<RelayEvent | null>(
        (latest, event) => (!latest || isNewer(event, latest) ? event : latest),
        null,
      );
    if (match) return match;
    if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("DM channel created but metadata not yet available");
}

export async function openDm(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayDmClient,
) {
  const pubkeys = requiredPubkeys(objectBody(body, "open_dm"));
  await publishCommand(
    identity,
    client,
    41010,
    pubkeys.map((pubkey) => ["p", pubkey]),
    "opening the DM",
  );
  const selfPubkey = identity.pubkey().toLowerCase();
  const participants = new Set([selfPubkey, ...pubkeys]);
  return channelInfo(await fetchDmMetadata(client, participants, selfPubkey));
}

export async function hideDm(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayDmClient,
): Promise<void> {
  const channelId = requiredString(objectBody(body, "hide_dm"), "channelId");
  await publishCommand(
    identity,
    client,
    41012,
    [["h", channelId]],
    "hiding the DM",
  );
}

export function registerRelayDmCommands(
  identity: BrowserIdentityManager,
  client: RelayDmClient = relayClient,
): void {
  register("open_dm", (body) => openDm(body, identity, client));
  register("hide_dm", (body) => hideDm(body, identity, client));
}
