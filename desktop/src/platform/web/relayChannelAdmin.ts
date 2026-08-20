import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayChannelAdminClient = Pick<
  typeof relayClient,
  "fetchFirstEvent" | "publishEvent"
>;

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

function requiredString(body: ObjectBody, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function normalizedChannelUuid(channelId: string): string {
  let value = channelId.toLowerCase();
  if (value.startsWith("urn:uuid:")) value = value.slice("urn:uuid:".length);
  if (value.startsWith("{") && value.endsWith("}")) value = value.slice(1, -1);
  if (
    !/^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/.test(
      value,
    )
  ) {
    throw new Error(`invalid channel UUID: ${channelId}`);
  }
  const compact = value.replaceAll("-", "");
  return `${compact.slice(0, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}-${compact.slice(16, 20)}-${compact.slice(20)}`;
}

function tagValue(event: RelayEvent, name: string): string | null {
  return event.tags.find((tag) => tag[0] === name)?.[1] ?? null;
}

function hasTag(event: RelayEvent, name: string): boolean {
  return event.tags.some((tag) => tag[0] === name);
}

function isoTimestamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

function optionalI32Tag(event: RelayEvent, name: string): number | null {
  const value = tagValue(event, name);
  if (value === null || !/^[+-]?\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) &&
    parsed >= -2_147_483_648 &&
    parsed <= 2_147_483_647
    ? parsed
    : null;
}

function channelDetailFromMetadata(event: RelayEvent) {
  const id = tagValue(event, "d");
  if (!id) throw new Error("kind:39000 missing required `d` tag");

  const timestamp = isoTimestamp(event.created_at);
  const explicitVisibility = tagValue(event, "visibility");
  return {
    id,
    name: tagValue(event, "name") ?? "",
    channel_type:
      tagValue(event, "t") ?? (hasTag(event, "hidden") ? "dm" : "stream"),
    visibility:
      hasTag(event, "public") || explicitVisibility === "open"
        ? "open"
        : hasTag(event, "private") || explicitVisibility === "private"
          ? "private"
          : "open",
    description: tagValue(event, "about") ?? "",
    topic: tagValue(event, "topic"),
    topic_set_by: null,
    topic_set_at: null,
    purpose: tagValue(event, "purpose"),
    purpose_set_by: null,
    purpose_set_at: null,
    created_by: event.pubkey,
    created_at: timestamp,
    updated_at: timestamp,
    archived_at: tagValue(event, "archived") === "true" ? timestamp : null,
    member_count: 0,
    topic_required: false,
    max_members: null,
    nip29_group_id: null,
    ttl_seconds: optionalI32Tag(event, "ttl"),
    ttl_deadline: tagValue(event, "ttl_deadline"),
  };
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

async function publishChannelAdminEvent(
  identity: BrowserIdentityManager,
  client: RelayChannelAdminClient,
  kind: 9002 | 9008,
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

async function getChannelDetails(
  body: unknown,
  client: RelayChannelAdminClient,
) {
  const input = objectBody(body, "get_channel_details");
  const channelId = requiredString(input, "channelId");
  const event = await client.fetchFirstEvent({
    kinds: [39000],
    "#d": [channelId],
    limit: 1,
  });
  if (!event) throw new Error("channel not found");
  return channelDetailFromMetadata(event);
}

async function publishMetadataMutation(
  body: unknown,
  command: string,
  valueField: "topic" | "purpose" | "archived",
  operation: string,
  identity: BrowserIdentityManager,
  client: RelayChannelAdminClient,
): Promise<void> {
  const input = objectBody(body, command);
  const channelId = normalizedChannelUuid(requiredString(input, "channelId"));
  const value = requiredString(input, valueField);
  await publishChannelAdminEvent(
    identity,
    client,
    9002,
    [
      ["h", channelId],
      [valueField, value],
    ],
    operation,
  );
}

export function registerRelayChannelAdminCommands(
  identity: BrowserIdentityManager,
  client: RelayChannelAdminClient = relayClient,
): void {
  register("get_channel_details", (body) => getChannelDetails(body, client));
  register("set_channel_topic", (body) =>
    publishMetadataMutation(
      body,
      "set_channel_topic",
      "topic",
      "setting the channel topic",
      identity,
      client,
    ),
  );
  register("set_channel_purpose", (body) =>
    publishMetadataMutation(
      body,
      "set_channel_purpose",
      "purpose",
      "setting the channel purpose",
      identity,
      client,
    ),
  );
  register("archive_channel", (body) =>
    publishMetadataMutation(
      { ...objectBody(body, "archive_channel"), archived: "true" },
      "archive_channel",
      "archived",
      "archiving the channel",
      identity,
      client,
    ),
  );
  register("unarchive_channel", (body) =>
    publishMetadataMutation(
      { ...objectBody(body, "unarchive_channel"), archived: "false" },
      "unarchive_channel",
      "archived",
      "unarchiving the channel",
      identity,
      client,
    ),
  );
  register("delete_channel", async (body) => {
    const input = objectBody(body, "delete_channel");
    const channelId = normalizedChannelUuid(requiredString(input, "channelId"));
    await publishChannelAdminEvent(
      identity,
      client,
      9008,
      [["h", channelId]],
      "deleting the channel",
    );
  });
}
