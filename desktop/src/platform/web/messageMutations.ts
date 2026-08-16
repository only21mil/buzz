import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { queryBridge, type QueryBridgeClient } from "./relayQueries";
import { register, type InvokeBody } from "./registry";

type MutationRelayClient = Pick<typeof relayClient, "publishEvent"> &
  QueryBridgeClient;

type ObjectBody = Record<string, unknown>;

const MAX_CONTENT_BYTES = 64 * 1024;
const MAX_MENTIONS = 50;
const MAX_EMOJI_CHARS = 64;
const MAX_CUSTOM_EMOJI_SHORTCODE_BYTES = 64;
const MAX_CUSTOM_EMOJI_URL_BYTES = 2048;

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

function requiredObject(
  body: ObjectBody,
  field: string,
  command: string,
): ObjectBody {
  const value = body[field];
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value instanceof ArrayBuffer ||
    value instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an ${field} object`);
  }
  return value as ObjectBody;
}

function requiredString(body: ObjectBody, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function optionalString(body: ObjectBody, field: string): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function optionalBoolean(body: ObjectBody, field: string): boolean {
  const value = body[field];
  if (value === undefined || value === null) return false;
  if (typeof value !== "boolean") {
    throw new TypeError(`${field} must be a boolean`);
  }
  return value;
}

function stringArray(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value;
}

function tagArray(body: ObjectBody, field: string): string[][] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) ||
    value.some(
      (tag) =>
        !Array.isArray(tag) || tag.some((item) => typeof item !== "string"),
    )
  ) {
    throw new TypeError(`${field} must be an array of string arrays`);
  }
  return value;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function eventId(value: string): string {
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error("invalid event ID: expected 64 hexadecimal characters");
  }
  return value.toLowerCase();
}

function channelId(value: string): string {
  const compact = value
    .trim()
    .replace(/^urn:uuid:/i, "")
    .replace(/^\{(.*)\}$/, "$1")
    .replaceAll("-", "");
  if (!/^[0-9a-f]{32}$/i.test(compact)) {
    throw new Error(`invalid channel UUID: ${value}`);
  }
  const lower = compact.toLowerCase();
  return `${lower.slice(0, 8)}-${lower.slice(8, 12)}-${lower.slice(12, 16)}-${lower.slice(16, 20)}-${lower.slice(20)}`;
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

async function publish(
  identity: BrowserIdentityManager,
  client: MutationRelayClient,
  request: { kind: number; content: string; tags: string[][] },
  operation: string,
): Promise<void> {
  const signed = parseSignedEvent(identity.sign(request));
  await client.publishEvent(
    signed,
    `Timed out while ${operation}.`,
    `Failed while ${operation}.`,
  );
}

function validatedPassthroughTags(
  tags: string[][],
  expectedPrefix: "imeta" | "emoji",
): string[][] {
  return tags.map((tag) => {
    if (tag[0] !== expectedPrefix) {
      throw new Error(
        `${expectedPrefix === "imeta" ? "media" : "emoji"} tags must use '${expectedPrefix}' prefix`,
      );
    }
    return [...tag];
  });
}

function mentionTags(pubkeys: string[]): string[][] {
  if (pubkeys.length > MAX_MENTIONS) {
    throw new Error(`too many mentions (max ${MAX_MENTIONS})`);
  }
  const seen = new Set<string>();
  const tags: string[][] = [];
  for (const pubkey of pubkeys) {
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new Error(
        `pubkey must be a 64-character hex string (got ${pubkey.length} chars)`,
      );
    }
    const lower = pubkey.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      tags.push(["p", lower]);
    }
  }
  return tags;
}

async function editMessage(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: MutationRelayClient,
): Promise<void> {
  const input = requiredObject(
    objectBody(body, "edit_message"),
    "input",
    "edit_message",
  );
  const content = requiredString(input, "content").trim();
  const mediaTags = tagArray(input, "mediaTags");
  if (!content && mediaTags.length === 0) {
    throw new Error("edit must have content or attachments");
  }
  if (byteLength(content) > MAX_CONTENT_BYTES) {
    throw new Error(
      `content exceeds maximum size of ${MAX_CONTENT_BYTES} bytes (got ${byteLength(content)})`,
    );
  }
  const tags: string[][] = [
    ["h", channelId(requiredString(input, "channelId"))],
    ["e", eventId(requiredString(input, "eventId"))],
    ...mentionTags(stringArray(input, "mentionPubkeys")),
    ...validatedPassthroughTags(mediaTags, "imeta"),
    ...validatedPassthroughTags(tagArray(input, "emojiTags"), "emoji"),
  ];
  if (optionalBoolean(input, "suppressLinkPreviews")) {
    tags.push(["link-preview", "none"]);
  }
  await publish(
    identity,
    client,
    { kind: 40003, content, tags },
    "editing the message",
  );
}

async function deleteMessage(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: MutationRelayClient,
): Promise<void> {
  const input = objectBody(body, "delete_message");
  await publish(
    identity,
    client,
    {
      kind: 5,
      content: "",
      tags: [
        ["h", channelId(requiredString(input, "channelId"))],
        ["e", eventId(requiredString(input, "eventId"))],
      ],
    },
    "deleting the message",
  );
}

function customEmoji(
  emoji: string,
  url: string,
): {
  content: string;
  tag: string[];
} {
  const shortcode = emoji.trim().replace(/^:+|:+$/g, "");
  if (!shortcode) throw new Error("emoji shortcode must not be empty");
  if (byteLength(shortcode) > MAX_CUSTOM_EMOJI_SHORTCODE_BYTES) {
    throw new Error(
      `emoji shortcode exceeds ${MAX_CUSTOM_EMOJI_SHORTCODE_BYTES} bytes (got ${byteLength(shortcode)})`,
    );
  }
  if (!/^[A-Za-z0-9_-]+$/.test(shortcode)) {
    throw new Error(
      "emoji shortcode may only contain ASCII letters, digits, hyphens, and underscores",
    );
  }
  if (!url) throw new Error("emoji image URL must not be empty");
  if (byteLength(url) > MAX_CUSTOM_EMOJI_URL_BYTES) {
    throw new Error(
      `emoji image URL exceeds ${MAX_CUSTOM_EMOJI_URL_BYTES} bytes (got ${byteLength(url)})`,
    );
  }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    throw new Error("emoji image URL must start with http:// or https://");
  }
  const normalized = shortcode.toLowerCase();
  return {
    content: `:${normalized}:`,
    tag: ["emoji", normalized, url],
  };
}

async function addReaction(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: MutationRelayClient,
): Promise<void> {
  const input = objectBody(body, "add_reaction");
  const target = eventId(requiredString(input, "eventId"));
  const emoji = requiredString(input, "emoji").trim();
  const emojiUrl = optionalString(input, "emojiUrl");
  let content = emoji;
  const tags: string[][] = [["e", target]];
  if (emojiUrl !== undefined) {
    try {
      const custom = customEmoji(emoji, emojiUrl);
      content = custom.content;
      tags.push(custom.tag);
    } catch (error) {
      throw new Error(
        `invalid custom emoji reaction: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } else if ([...emoji].length > MAX_EMOJI_CHARS) {
    throw new Error(
      `emoji exceeds maximum length of ${MAX_EMOJI_CHARS} characters`,
    );
  }
  await publish(
    identity,
    client,
    { kind: 7, content, tags },
    "adding the reaction",
  );
}

async function removeReaction(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: MutationRelayClient,
): Promise<void> {
  const input = objectBody(body, "remove_reaction");
  const target = requiredString(input, "eventId").trim();
  const emoji = requiredString(input, "emoji").trim();
  const reactions = await queryBridge(client, [
    {
      kinds: [7],
      "#e": [target],
      authors: [identity.pubkey()],
    },
  ]);
  const reaction = reactions.find((event) => event.content.trim() === emoji);
  if (!reaction) {
    throw new Error("could not find your reaction event for this emoji");
  }
  await publish(
    identity,
    client,
    { kind: 5, content: "", tags: [["e", eventId(reaction.id)]] },
    "removing the reaction",
  );
}

export function registerMessageMutationCommands(
  identity: BrowserIdentityManager,
  client: MutationRelayClient = relayClient,
): void {
  register("edit_message", (body) => editMessage(body, identity, client));
  register("delete_message", (body) => deleteMessage(body, identity, client));
  register("add_reaction", (body) => addReaction(body, identity, client));
  register("remove_reaction", (body) => removeReaction(body, identity, client));
}
