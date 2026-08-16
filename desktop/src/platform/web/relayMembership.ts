import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayMembershipClient = Pick<typeof relayClient, "publishEvent">;
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

function parseChannelUuid(value: string): string {
  let candidate = value;
  if (candidate.startsWith("urn:uuid:")) candidate = candidate.slice(9);
  if (candidate.startsWith("{") && candidate.endsWith("}")) {
    candidate = candidate.slice(1, -1);
  }
  if (
    !/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/.test(
      candidate,
    )
  ) {
    throw new Error(`invalid channel UUID: ${value}`);
  }
  const hex = candidate.replaceAll("-", "");
  const canonical = hex.toLowerCase();
  return `${canonical.slice(0, 8)}-${canonical.slice(8, 12)}-${canonical.slice(12, 16)}-${canonical.slice(16, 20)}-${canonical.slice(20)}`;
}

function parsePubkey(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("pubkey must be a string");
  }
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(
      `pubkey must be a 64-character hex string (got ${new TextEncoder().encode(value).length} chars)`,
    );
  }
  return value.toLowerCase();
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

async function publishSignedEvent(
  identity: BrowserIdentityManager,
  client: RelayMembershipClient,
  request: { kind: number; content: string; tags: string[][] },
  operation: string,
): Promise<void> {
  const event = parseSignedEvent(identity.sign(request));
  await client.publishEvent(
    event,
    `Timed out while ${operation}.`,
    `Failed while ${operation}.`,
  );
}

function singleChannelBody(body: unknown, command: string): string {
  return parseChannelUuid(
    requiredString(objectBody(body, command), "channelId"),
  );
}

async function addChannelMembers(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayMembershipClient,
) {
  const input = objectBody(body, "add_channel_members");
  const channelId = parseChannelUuid(requiredString(input, "channelId"));
  if (!Array.isArray(input.pubkeys)) {
    throw new TypeError("pubkeys must be an array");
  }
  if (!input.pubkeys.every((pubkey) => typeof pubkey === "string")) {
    throw new TypeError("pubkeys must contain only strings");
  }
  const pubkeys = input.pubkeys as string[];
  const role = input.role;
  if (
    role !== undefined &&
    role !== null &&
    role !== "admin" &&
    role !== "bot" &&
    role !== "guest" &&
    role !== "member"
  ) {
    throw new Error(`invalid role: ${String(role)}`);
  }
  const roleTag = role === "member" || role == null ? undefined : role;
  const added: string[] = [];
  const errors: Array<{ pubkey: string; error: string }> = [];

  for (const pubkey of pubkeys) {
    try {
      const canonicalPubkey = parsePubkey(pubkey);
      const tags = [
        ["h", channelId],
        ["p", canonicalPubkey],
      ];
      if (roleTag !== undefined) tags.push(["role", roleTag]);
      await publishSignedEvent(
        identity,
        client,
        { kind: 9000, content: "", tags },
        "adding the channel member",
      );
      added.push(pubkey);
    } catch (error) {
      errors.push({
        pubkey,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { added, errors };
}

async function removeChannelMember(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayMembershipClient,
): Promise<void> {
  const input = objectBody(body, "remove_channel_member");
  const channelId = parseChannelUuid(requiredString(input, "channelId"));
  const pubkey = parsePubkey(input.pubkey);
  await publishSignedEvent(
    identity,
    client,
    {
      kind: 9001,
      content: "",
      tags: [
        ["h", channelId],
        ["p", pubkey],
      ],
    },
    "removing the channel member",
  );
}

async function changeChannelMemberRole(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayMembershipClient,
): Promise<void> {
  const input = objectBody(body, "change_channel_member_role");
  const channelId = parseChannelUuid(requiredString(input, "channelId"));
  const pubkey = parsePubkey(input.pubkey);
  const role = requiredString(input, "role");
  if (role === "owner") {
    throw new Error("cannot assign owner role — use transfer ownership");
  }
  if (
    role !== "admin" &&
    role !== "member" &&
    role !== "guest" &&
    role !== "bot"
  ) {
    throw new Error(`invalid role: ${role}`);
  }
  await publishSignedEvent(
    identity,
    client,
    {
      kind: 9000,
      content: "",
      tags: [
        ["h", channelId],
        ["p", pubkey],
        ["role", role],
      ],
    },
    "changing the channel member role",
  );
}

export function registerRelayMembershipCommands(
  identity: BrowserIdentityManager,
  client: RelayMembershipClient = relayClient,
): void {
  register("join_channel", (body) =>
    publishSignedEvent(
      identity,
      client,
      {
        kind: 9021,
        content: "",
        tags: [["h", singleChannelBody(body, "join_channel")]],
      },
      "joining the channel",
    ),
  );
  register("leave_channel", (body) =>
    publishSignedEvent(
      identity,
      client,
      {
        kind: 9022,
        content: "",
        tags: [["h", singleChannelBody(body, "leave_channel")]],
      },
      "leaving the channel",
    ),
  );
  register("add_channel_members", (body) =>
    addChannelMembers(body, identity, client),
  );
  register("remove_channel_member", (body) =>
    removeChannelMember(body, identity, client),
  );
  register("change_channel_member_role", (body) =>
    changeChannelMemberRole(body, identity, client),
  );
}
