import { relayClient } from "@/shared/api/relayClient";
import type { RelaySubscriptionFilter } from "@/shared/api/relayClientShared";
import type { RelayEvent } from "@/shared/api/types";
import { KIND_HUDDLE_STARTED } from "@/shared/constants/kinds";
import { register } from "./registry";

type RelayMessageReadClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent"
>;

type ObjectBody = Record<string, unknown>;

type RawCursor = {
  created_at: number;
  event_id: string;
};

type MessageReadFilter = RelaySubscriptionFilter & {
  depth_limit?: number;
  thread_cursor?: number;
  thread_cursor_id?: string;
  top_level?: boolean;
  include_summaries?: boolean;
  include_aux?: boolean;
  before_id?: string;
};

const TIMELINE_KINDS = [
  9,
  40002,
  40008,
  40099,
  43001,
  43002,
  43003,
  43004,
  43005,
  43006,
  KIND_HUDDLE_STARTED,
];

const EVENT_KINDS = [
  0,
  1,
  3,
  5,
  7,
  9,
  30078,
  40002,
  40003,
  40008,
  40099,
  40100,
  45001,
  45003,
  KIND_HUDDLE_STARTED,
];

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

function requiredString(body: ObjectBody, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function optionalUnsignedInteger(
  body: ObjectBody,
  field: string,
): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new TypeError(`${field} must be an unsigned integer`);
  }
  return value as number;
}

function optionalCursor(body: ObjectBody): RawCursor | undefined {
  const value = body.cursor;
  if (value === undefined || value === null) return undefined;
  const cursor = objectBody(value, "cursor");
  const createdAt = cursor.created_at;
  if (!Number.isInteger(createdAt)) {
    throw new TypeError("cursor.created_at must be an integer");
  }
  return {
    created_at: createdAt as number,
    event_id: requiredString(cursor, "event_id"),
  };
}

export async function getThreadReplies(
  body: unknown,
  client: RelayMessageReadClient,
) {
  const input = objectBody(body, "get_thread_replies");
  const cap = Math.min(optionalUnsignedInteger(input, "limit") ?? 200, 500);
  const cursor = optionalCursor(input);
  const channelId = input.channelId;
  if (
    channelId !== undefined &&
    channelId !== null &&
    typeof channelId !== "string"
  ) {
    throw new TypeError("channelId must be a string");
  }

  const filter: MessageReadFilter = {
    "#e": [requiredString(input, "rootEventId")],
    kinds: [...TIMELINE_KINDS],
    depth_limit: optionalUnsignedInteger(input, "depthLimit") ?? 64,
    limit: cap,
  };
  if (typeof channelId === "string") filter["#h"] = [channelId];
  if (cursor) {
    filter.thread_cursor = cursor.created_at;
    filter.thread_cursor_id = cursor.event_id;
  }

  const events = await client.fetchEvents(filter);
  const lastEvent = events.at(-1);
  return {
    events,
    next_cursor:
      events.length >= cap && lastEvent
        ? { created_at: lastEvent.created_at, event_id: lastEvent.id }
        : null,
  };
}

export async function getChannelWindow(
  body: unknown,
  client: RelayMessageReadClient,
): Promise<RelayEvent[]> {
  const input = objectBody(body, "get_channel_window");
  const cap = Math.min(optionalUnsignedInteger(input, "limitRows") ?? 50, 200);
  const cursor = optionalCursor(input);
  const filter: MessageReadFilter = {
    "#h": [requiredString(input, "channelId")],
    kinds: [...TIMELINE_KINDS],
    limit: cap,
    top_level: true,
    include_summaries: true,
    include_aux: true,
  };
  if (cursor) {
    filter.until = cursor.created_at;
    filter.before_id = cursor.event_id;
  }
  return client.fetchEvents(filter);
}

export async function getEvent(
  body: unknown,
  client: RelayMessageReadClient,
): Promise<string> {
  const input = objectBody(body, "get_event");
  const event = await client.fetchFirstEvent({
    ids: [requiredString(input, "eventId")],
    kinds: [...EVENT_KINDS],
    limit: 1,
  });
  if (!event) throw new Error("event not found");
  return JSON.stringify(event);
}

export function registerRelayMessageReadCommands(
  client: RelayMessageReadClient = relayClient,
): void {
  register("get_thread_replies", (body) => getThreadReplies(body, client));
  register("get_channel_window", (body) => getChannelWindow(body, client));
  register("get_event", (body) => getEvent(body, client));
}
