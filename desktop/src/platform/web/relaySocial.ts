import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type SocialFilter = {
  ids?: string[];
  kinds: number[];
  authors?: string[];
  since?: number;
  until?: number;
  limit?: number;
} & Partial<Record<`#${string}`, string[]>>;

export type RelaySocialClient = {
  fetchEvents(filter: SocialFilter): Promise<RelayEvent[]>;
  publishEvent(
    event: RelayEvent,
    timeoutMessage: string,
    sendErrorMessage: string,
  ): Promise<RelayEvent>;
};

type ObjectBody = Record<string, unknown>;

const MAX_CONTENT_BYTES = 64 * 1024;
const MAX_MENTIONS = 50;
const MAX_TIMELINE_PUBKEYS = 100;
const HEX_64 = /^[0-9a-fA-F]{64}$/;

const MENTION_KINDS = [
  9, 40002, 1, 45001, 45003, 1618, 1619, 1621, 1630, 1631, 1632, 1633,
];
const APPROVAL_KINDS = [46010, 46011, 46012];

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

function optionalString(body: ObjectBody, field: string): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function requiredString(body: ObjectBody, field: string): string {
  const value = optionalString(body, field);
  if (value === undefined) throw new TypeError(`${field} must be a string`);
  return value;
}

function optionalInteger(body: ObjectBody, field: string): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${field} must be an integer`);
  }
  return value;
}

function optionalStringArray(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value;
}

function optionalTagArray(body: ObjectBody, field: string): string[][] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) ||
    value.some(
      (tag) =>
        !Array.isArray(tag) || tag.some((part) => typeof part !== "string"),
    )
  ) {
    throw new TypeError(`${field} must be an array of string arrays`);
  }
  return value;
}

function validateHex64(value: string, label: string): void {
  if (!HEX_64.test(value)) throw new Error(`invalid ${label}`);
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

function noteFromEvent(event: RelayEvent) {
  return {
    id: event.id,
    pubkey: event.pubkey,
    created_at: event.created_at,
    content: event.content,
    tags: event.tags,
  };
}

function notesResponse(events: RelayEvent[]) {
  const notes = events.map(noteFromEvent);
  const oldest = notes.at(-1);
  return {
    notes,
    next_cursor: oldest
      ? { before: oldest.created_at, before_id: oldest.id }
      : null,
  };
}

async function publishNote(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelaySocialClient,
) {
  const input = objectBody(body, "publish_note");
  const content = requiredString(input, "content");
  if (new TextEncoder().encode(content).byteLength > MAX_CONTENT_BYTES) {
    throw new Error(
      `content exceeds maximum size of ${MAX_CONTENT_BYTES} bytes`,
    );
  }

  const tags: string[][] = [];
  const replyTo = optionalString(input, "replyTo");
  if (replyTo !== undefined) {
    validateHex64(replyTo, "reply_to event id");
    tags.push(["e", replyTo.toLowerCase(), "", "reply"]);
  }

  const mentions = optionalStringArray(input, "mentionPubkeys");
  if (mentions.length > MAX_MENTIONS) {
    throw new Error(`too many mentions (max ${MAX_MENTIONS})`);
  }
  const seenMentions = new Set<string>();
  for (const mention of mentions) {
    validateHex64(mention, "mention pubkey");
    const normalized = mention.toLowerCase();
    if (!seenMentions.has(normalized)) {
      seenMentions.add(normalized);
      tags.push(["p", normalized]);
    }
  }

  for (const mediaTag of optionalTagArray(input, "mediaTags")) {
    if (mediaTag[0] !== "imeta") {
      throw new Error(
        `media tags must use 'imeta' prefix (got ${JSON.stringify(mediaTag[0])})`,
      );
    }
    tags.push(mediaTag);
  }

  const event = parseSignedEvent(identity.sign({ kind: 1, content, tags }));
  const published = await client.publishEvent(
    event,
    "Timed out while publishing the note.",
    "Failed while publishing the note.",
  );
  return { event_id: published.id, accepted: true, message: "" };
}

async function getUserNotes(body: unknown, client: RelaySocialClient) {
  const input = objectBody(body, "get_user_notes");
  const filter: SocialFilter = {
    kinds: [1],
    authors: [requiredString(input, "pubkey")],
    limit: Math.min(optionalInteger(input, "limit") ?? 20, 100),
  };
  const before = optionalInteger(input, "before");
  if (before !== undefined) filter.until = before;
  return notesResponse(await client.fetchEvents(filter));
}

async function getNote(body: unknown, client: RelaySocialClient) {
  const noteId = requiredString(objectBody(body, "get_note"), "noteId");
  validateHex64(noteId, "note id");
  const events = await client.fetchEvents({
    kinds: [1],
    ids: [noteId],
    limit: 1,
  });
  return events[0] ? noteFromEvent(events[0]) : null;
}

async function getNotesTimeline(body: unknown, client: RelaySocialClient) {
  const input = objectBody(body, "get_notes_timeline");
  const pubkeys = optionalStringArray(input, "pubkeys");
  if (pubkeys.length === 0) return { notes: [], next_cursor: null };
  if (pubkeys.length > MAX_TIMELINE_PUBKEYS) {
    throw new Error(
      `too many pubkeys (max ${MAX_TIMELINE_PUBKEYS}, got ${pubkeys.length})`,
    );
  }
  const perUser = Math.min(optionalInteger(input, "limitPerUser") ?? 10, 50);
  const events = await client.fetchEvents({
    kinds: [1],
    authors: pubkeys,
    limit: Math.min(perUser * pubkeys.length, 200),
  });
  const notes = events
    .map(noteFromEvent)
    .sort((left, right) => right.created_at - left.created_at)
    .slice(0, 200);
  return { notes, next_cursor: null };
}

function feedItem(event: RelayEvent, category: string) {
  const channelId = event.tags.find((tag) => tag[0] === "h")?.[1] ?? null;
  return {
    id: event.id,
    kind: event.kind,
    pubkey: event.pubkey,
    content: event.content,
    created_at: event.created_at,
    channel_id: channelId,
    channel_name: "",
    channel_type: null,
    tags: event.tags,
    category,
  };
}

async function fetchOrEmpty(
  client: RelaySocialClient,
  filter: SocialFilter,
): Promise<RelayEvent[]> {
  try {
    return await client.fetchEvents(filter);
  } catch {
    return [];
  }
}

async function getFeed(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelaySocialClient,
) {
  const input = body === undefined ? {} : objectBody(body, "get_feed");
  const since = optionalInteger(input, "since");
  const cap = Math.min(optionalInteger(input, "limit") ?? 50, 100);
  const types = optionalString(input, "types");
  const requested = types?.split(",").map((value) => value.trim());
  const wants = (type: string) => requested?.includes(type) ?? true;
  const pubkey = identity.pubkey();

  const mentionFilter: SocialFilter = {
    kinds: MENTION_KINDS,
    "#p": [pubkey],
    limit: cap,
  };
  const approvalFilter: SocialFilter = {
    kinds: APPROVAL_KINDS,
    "#p": [pubkey],
    limit: 20,
  };
  if (since !== undefined) {
    mentionFilter.since = since;
    approvalFilter.since = since;
  }

  const mentionEvents = wants("mentions")
    ? await fetchOrEmpty(client, mentionFilter)
    : [];
  const approvalEvents = wants("needs_action")
    ? await fetchOrEmpty(client, approvalFilter)
    : [];
  const mentionById = new Map(mentionEvents.map((event) => [event.id, event]));
  const mentionEdits = mentionEvents.length
    ? await fetchOrEmpty(client, {
        kinds: [40003],
        "#e": mentionEvents.map((event) => event.id),
      })
    : [];
  const suppressed = new Set<string>();
  for (const edit of mentionEdits) {
    if (
      edit.kind !== 40003 ||
      !edit.tags.some((tag) => tag[0] === "link-preview" && tag[1] === "none")
    ) {
      continue;
    }
    const targetId = edit.tags.find((tag) => tag[0] === "e")?.[1];
    const target = targetId ? mentionById.get(targetId) : undefined;
    if (target && edit.pubkey === target.pubkey) suppressed.add(target.id);
  }
  const mentions = mentionEvents.map((event) => {
    const item = feedItem(event, "mentions");
    if (
      suppressed.has(event.id) &&
      !item.tags.some((tag) => tag[0] === "link-preview" && tag[1] === "none")
    ) {
      item.tags = [...item.tags, ["link-preview", "none"]];
    }
    return item;
  });
  const needsAction = approvalEvents.map((event) =>
    feedItem(event, "needs_action"),
  );
  return {
    feed: {
      mentions,
      needs_action: needsAction,
      activity: [],
      agent_activity: [],
    },
    meta: {
      since: since ?? 0,
      total: mentions.length + needsAction.length,
      generated_at: Math.floor(Date.now() / 1000),
    },
  };
}

export function registerRelaySocialCommands(
  identity: BrowserIdentityManager,
  client: RelaySocialClient = relayClient as unknown as RelaySocialClient,
): void {
  register("get_feed", (body) => getFeed(body, identity, client));
  register("publish_note", (body) => publishNote(body, identity, client));
  register("get_note", (body) => getNote(body, client));
  register("get_notes_timeline", (body) => getNotesTimeline(body, client));
  register("get_user_notes", (body) => getUserNotes(body, client));
}
