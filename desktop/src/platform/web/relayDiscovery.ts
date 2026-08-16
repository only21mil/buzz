import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import { queryBridge, type QueryBridgeClient } from "./relayQueries";
import { register } from "./registry";

type RelayDiscoveryClient = QueryBridgeClient;
type ObjectBody = Record<string, unknown>;

function objectBody(body: unknown, command: string): ObjectBody {
  if (
    !body ||
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
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${field} must be an integer`);
  }
  return value;
}

function optionalLimit(body: ObjectBody, fallback: number): number {
  const value = optionalInteger(body, "limit");
  if (value !== undefined && value < 0) {
    throw new TypeError("limit must be a non-negative integer");
  }
  return Math.min(value ?? fallback, 100);
}

function firstTagValue(event: RelayEvent, name: string): string | null {
  return event.tags.find((tag) => tag[0] === name)?.[1] ?? null;
}

function suppressionTargets(
  originals: RelayEvent[],
  edits: RelayEvent[],
): Set<string> {
  const originalsById = new Map(originals.map((event) => [event.id, event]));
  const suppressed = new Set<string>();
  for (const edit of edits) {
    if (
      edit.kind !== 40003 ||
      !edit.tags.some((tag) => tag[0] === "link-preview" && tag[1] === "none")
    ) {
      continue;
    }
    const targetId = firstTagValue(edit, "e");
    const target = targetId ? originalsById.get(targetId) : undefined;
    // The browser can verify author-signed suppression. Unlike the Rust path,
    // it cannot also verify a NIP-OA owner without an owner key in this API.
    if (target && target.pubkey === edit.pubkey) suppressed.add(target.id);
  }
  return suppressed;
}

function tagsWithSuppression(event: RelayEvent, suppressed: Set<string>) {
  const tags = event.tags.map((tag) => [...tag]);
  if (
    suppressed.has(event.id) &&
    !tags.some((tag) => tag[0] === "link-preview" && tag[1] === "none")
  ) {
    tags.push(["link-preview", "none"]);
  }
  return tags;
}

async function fetchSuppressedTargets(
  events: RelayEvent[],
  client: RelayDiscoveryClient,
): Promise<Set<string>> {
  if (events.length === 0) return new Set();
  try {
    const edits = await queryBridge(client, [
      {
        kinds: [40003],
        "#e": events.map((event) => event.id),
      },
    ]);
    return suppressionTargets(events, edits);
  } catch {
    // Link-preview edits are optional enrichment in the desktop command.
    return new Set();
  }
}

function forumPost(
  event: RelayEvent,
  channelId: string,
  suppressed: Set<string>,
) {
  return {
    event_id: event.id,
    pubkey: event.pubkey,
    sig: event.sig,
    content: event.content,
    kind: event.kind,
    created_at: event.created_at,
    channel_id: channelId,
    tags: tagsWithSuppression(event, suppressed),
    thread_summary: {
      reply_count: 0,
      descendant_count: 0,
      last_reply_at: null,
      participants: [],
    },
    reactions: null,
  };
}

function forumReply(
  event: RelayEvent,
  channelId: string,
  rootEventId: string,
  suppressed: Set<string>,
) {
  let parentId: string | null = null;
  let explicitRoot: string | null = null;
  for (const tag of event.tags) {
    if (tag[0] !== "e" || typeof tag[1] !== "string") continue;
    if (tag[3] === "root") explicitRoot = tag[1];
    else if (tag[3] === "reply") parentId = tag[1];
    else if (parentId === null) parentId = tag[1];
  }
  const parent = parentId ?? rootEventId;
  const root = explicitRoot ?? rootEventId;
  return {
    event_id: event.id,
    pubkey: event.pubkey,
    sig: event.sig,
    content: event.content,
    kind: event.kind,
    created_at: event.created_at,
    channel_id: channelId,
    tags: tagsWithSuppression(event, suppressed),
    parent_event_id: parent,
    root_event_id: root,
    depth: parent === root ? 1 : 2,
    broadcast: false,
    reactions: null,
  };
}

export async function getForumPosts(
  body: unknown,
  client: RelayDiscoveryClient,
) {
  const input = objectBody(body, "get_forum_posts");
  const channelId = requiredString(input, "channelId");
  const filter: Record<string, unknown> = {
    kinds: [45001],
    "#h": [channelId],
    limit: optionalLimit(input, 20),
  };
  const before = optionalInteger(input, "before");
  if (before !== undefined) filter.until = before;

  const events = await queryBridge(client, [filter]);
  const suppressed = await fetchSuppressedTargets(events, client);
  const messages = events.map((event) =>
    forumPost(event, channelId, suppressed),
  );
  return {
    messages,
    next_cursor: messages.at(-1)?.created_at ?? null,
  };
}

export async function getForumThread(
  body: unknown,
  client: RelayDiscoveryClient,
) {
  const input = objectBody(body, "get_forum_thread");
  const channelId = requiredString(input, "channelId");
  const eventId = requiredString(input, "eventId");
  // The desktop command currently ignores its limit/cursor arguments.
  optionalLimit(input, 20);
  optionalString(input, "cursor");
  const events = await queryBridge(client, [
    {
      ids: [eventId],
      kinds: [9, 40002, 45001, 45003],
      limit: 1,
    },
    {
      kinds: [9, 45003],
      "#e": [eventId],
      "#h": [channelId],
    },
  ]);
  const root = events.find((event) => event.id === eventId);
  if (!root) throw new Error("forum thread root event not found");

  const replies = events.filter((event) => event.id !== eventId);
  const suppressed = await fetchSuppressedTargets(events, client);
  return {
    root: forumPost(root, channelId, suppressed),
    replies: replies.map((event) =>
      forumReply(event, channelId, eventId, suppressed),
    ),
    total_replies: replies.length,
    next_cursor: null,
  };
}

export function registerRelayDiscoveryCommands(
  client: RelayDiscoveryClient = relayClient as RelayDiscoveryClient,
): void {
  register("get_forum_posts", (body) => getForumPosts(body, client));
  register("get_forum_thread", (body) => getForumThread(body, client));
}
