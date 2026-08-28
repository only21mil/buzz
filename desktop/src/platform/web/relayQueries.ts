import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { nip98Fetch } from "./nip98";
import type { OfflineMessagePublisher } from "./offlineMessageOutbox";
import { dispatch, register } from "./registry";

export type QueryBridgeClient = {
  queryEvents?: (
    filters: Array<Record<string, unknown>>,
  ) => Promise<RelayEvent[]>;
};

type RelayQueryClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent" | "publishEvent"
> &
  QueryBridgeClient;

type ObjectBody = Record<string, unknown>;

const pendingOwnedChannelIds = new Set<string>();

const TIMELINE_KINDS = [
  9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006, 48100,
] as const;

const STARTER_CHANNELS = [
  {
    name: "general",
    description: "General conversation and community updates.",
  },
  {
    name: "welcome-everyone",
    description: "Say hi, ask a question, or share what brought you here.",
  },
] as const;

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

function optionalNumber(body: ObjectBody, field: string): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${field} must be an integer`);
  }
  return value;
}

function optionalStringArrays(body: ObjectBody, field: string): string[][] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) ||
    value.some(
      (tag) =>
        !Array.isArray(tag) ||
        tag.length === 0 ||
        tag.some((part) => typeof part !== "string"),
    )
  ) {
    throw new TypeError(`${field} must be an array of string arrays`);
  }
  return value as string[][];
}

function optionalStrings(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((part) => typeof part !== "string")) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value as string[];
}

function optionalKinds(body: ObjectBody, field: string): number[] | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some(
      (kind) =>
        !Number.isInteger(kind) || (kind as number) < 0 || kind > 65_535,
    )
  ) {
    throw new TypeError(`${field} must be non-empty valid Nostr kinds`);
  }
  return value as number[];
}

function optionalNullableNumber(
  body: ObjectBody,
  field: string,
): number | null | undefined {
  if (!(field in body) || body[field] === undefined) return undefined;
  if (body[field] === null) return null;
  return optionalNumber(body, field);
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
  client: RelayQueryClient,
  request: { kind: number; content: string; tags: string[][] },
  operation: string,
): Promise<RelayEvent> {
  const event = parseSignedEvent(identity.sign(request));
  return client.publishEvent(
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

function isNewer(candidate: RelayEvent, current: RelayEvent): boolean {
  return (
    candidate.created_at > current.created_at ||
    (candidate.created_at === current.created_at && candidate.id < current.id)
  );
}

function latestByTag(
  events: RelayEvent[],
  tagName: string,
): Map<string, RelayEvent> {
  const latest = new Map<string, RelayEvent>();
  for (const event of events) {
    const value = tagValue(event, tagName);
    if (!value) continue;
    const current = latest.get(value);
    if (!current || isNewer(event, current)) latest.set(value, event);
  }
  return latest;
}

function isoTimestamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export async function queryBridge(
  client: QueryBridgeClient,
  filters: Array<Record<string, unknown>>,
): Promise<RelayEvent[]> {
  if (client.queryEvents) return client.queryEvents(filters);
  const relayHttpUrl = await dispatch<string>("get_relay_http_url");
  const response = await nip98Fetch({
    url: `${relayHttpUrl}/query`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(filters),
  });
  if (!response.ok) {
    throw new Error(`Relay query failed (${response.status}).`);
  }
  return response.json() as Promise<RelayEvent[]>;
}

function profileFromEvent(pubkey: string, event: RelayEvent | null) {
  if (!event) {
    return {
      pubkey,
      display_name: null,
      avatar_url: null,
      about: null,
      nip05_handle: null,
      owner_pubkey: null,
      has_profile_event: false,
    };
  }
  const content = JSON.parse(event.content) as Record<string, unknown>;
  const value = (name: string): string | null =>
    typeof content[name] === "string" ? (content[name] as string) : null;
  return {
    pubkey,
    display_name: value("display_name") ?? value("name"),
    avatar_url: value("picture"),
    about: value("about"),
    nip05_handle: value("nip05"),
    // The desktop only exposes an owner after cryptographically verifying a
    // NIP-OA auth tag. The web PAL does not yet carry that verifier, so fail
    // closed instead of trusting profile JSON.
    owner_pubkey: null,
    has_profile_event: true,
  };
}

export async function getProfile(
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const pubkey = identity.pubkey();
  const event = await client.fetchFirstEvent({
    kinds: [0],
    authors: [pubkey],
    limit: 1,
  });
  return profileFromEvent(pubkey, event);
}

async function getUserProfile(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const target =
    optionalString(objectBody(body, "get_user_profile"), "pubkey") ??
    identity.pubkey();
  const event = await client.fetchFirstEvent({
    kinds: [0],
    authors: [target],
    limit: 1,
  });
  return profileFromEvent(target, event);
}

async function getUsersBatch(body: unknown, client: RelayQueryClient) {
  const pubkeys = optionalStrings(
    objectBody(body, "get_users_batch"),
    "pubkeys",
  );
  if (pubkeys.length === 0) return { profiles: {}, missing: [] };
  const events = await client.fetchEvents({
    kinds: [0],
    authors: pubkeys,
    limit: pubkeys.length,
  });
  const latest = new Map<string, RelayEvent>();
  for (const event of events) {
    const current = latest.get(event.pubkey);
    if (!current || isNewer(event, current)) latest.set(event.pubkey, event);
  }
  const profiles: Record<string, Record<string, unknown>> = {};
  const missing: string[] = [];
  for (const pubkey of pubkeys) {
    const event = latest.get(pubkey);
    if (!event) {
      missing.push(pubkey);
      continue;
    }
    let content: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(event.content) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        content = parsed as Record<string, unknown>;
      }
    } catch {
      // Batch profile conversion matches the desktop's tolerant summary path.
    }
    const value = (name: string): string | null =>
      typeof content[name] === "string" ? (content[name] as string) : null;
    profiles[pubkey] = {
      display_name: value("display_name") ?? value("name"),
      name: value("name"),
      avatar_url: value("picture"),
      nip05_handle: value("nip05"),
      owner_pubkey: null,
      is_agent: false,
    };
  }
  return { profiles, missing };
}

export async function updateProfile(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const input = objectBody(body, "update_profile");
  const pubkey = identity.pubkey();
  const prior = await client.fetchFirstEvent({
    kinds: [0],
    authors: [pubkey],
    limit: 1,
  });
  let current: Record<string, unknown> = {};
  if (prior) {
    try {
      const parsed = JSON.parse(prior.content) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        current = parsed as Record<string, unknown>;
      }
    } catch {
      // Match the desktop read-merge-write path: malformed prior content is
      // treated as an empty snapshot.
    }
  }

  const merged = {
    display_name:
      optionalString(input, "displayName") ??
      (typeof current.display_name === "string"
        ? current.display_name
        : undefined),
    name: typeof current.name === "string" ? current.name : undefined,
    picture:
      optionalString(input, "avatarUrl") ??
      (typeof current.picture === "string" ? current.picture : undefined),
    about:
      optionalString(input, "about") ??
      (typeof current.about === "string" ? current.about : undefined),
    nip05:
      optionalString(input, "nip05Handle") ??
      (typeof current.nip05 === "string" ? current.nip05 : undefined),
  };
  const content = JSON.stringify(
    Object.fromEntries(
      Object.entries(merged).filter((entry) => entry[1] !== undefined),
    ),
  );
  await publishSignedEvent(
    identity,
    client,
    { kind: 0, content, tags: [] },
    "updating the profile",
  );
  return getProfile(identity, client);
}

function channelFromMetadata(
  event: RelayEvent,
  membership: RelayEvent | undefined,
  lastMessage: RelayEvent | undefined,
) {
  const id = tagValue(event, "d");
  if (!id) throw new Error("kind:39000 missing required `d` tag");
  const type =
    tagValue(event, "t") ??
    (event.tags.some((tag) => tag[0] === "hidden") ? "dm" : "stream");
  const privateChannel =
    event.tags.some((tag) => tag[0] === "private") ||
    tagValue(event, "visibility") === "private";
  const participants = Array.from(
    new Set(membership ? tagValues(membership, "p") : tagValues(event, "p")),
  );
  return {
    id,
    name: tagValue(event, "name") ?? "",
    channel_type: type === "forum" || type === "dm" ? type : "stream",
    visibility: privateChannel ? "private" : "open",
    description: tagValue(event, "about") ?? "",
    topic: tagValue(event, "topic"),
    purpose: tagValue(event, "purpose"),
    member_count: participants.length,
    member_pubkeys: participants,
    last_message_at: lastMessage ? isoTimestamp(lastMessage.created_at) : null,
    archived_at:
      tagValue(event, "archived") === "true"
        ? isoTimestamp(event.created_at)
        : null,
    participants,
    participant_pubkeys: participants,
    is_member: Boolean(membership) || pendingOwnedChannelIds.has(id),
    ttl_seconds: tagValue(event, "ttl") ? Number(tagValue(event, "ttl")) : null,
    ttl_deadline: tagValue(event, "ttl_deadline"),
  };
}

function channelDetailFromMetadata(event: RelayEvent) {
  const channel = channelFromMetadata(event, undefined, undefined);
  const timestamp = isoTimestamp(event.created_at);
  return {
    ...channel,
    created_by: event.pubkey,
    created_at: timestamp,
    updated_at: timestamp,
    topic_set_by: null,
    topic_set_at: null,
    purpose_set_by: null,
    purpose_set_at: null,
    topic_required: false,
    max_members: null,
    nip29_group_id: null,
  };
}

async function getChannels(
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const pubkey = identity.pubkey();
  const initialEvents = await client.fetchEvents([
    { kinds: [39002], "#p": [pubkey], limit: 1000 },
    { kinds: [39000], limit: 1000 },
    {
      kinds: [30622],
      authors: [pubkey],
      "#p": [pubkey],
      limit: 10,
    },
  ]);
  const membershipEvents = initialEvents.filter(
    (event) => event.kind === 39002,
  );
  const metadataEvents = initialEvents.filter((event) => event.kind === 39000);
  const visibilityEvents = initialEvents.filter(
    (event) => event.kind === 30622,
  );
  const memberships = latestByTag(membershipEvents, "d");
  const metadata = latestByTag(metadataEvents, "d");
  const latestVisibility = visibilityEvents.reduce<RelayEvent | null>(
    (latest, event) => (!latest || isNewer(event, latest) ? event : latest),
    null,
  );
  const hiddenDms = new Set(
    latestVisibility ? tagValues(latestVisibility, "h") : [],
  );
  const channelIds = Array.from(metadata.keys());
  const messages = channelIds.length
    ? await client.fetchEvents({
        kinds: [9, 40002],
        "#h": channelIds,
        limit: Math.min(5000, Math.max(100, channelIds.length * 25)),
      })
    : [];
  const latestMessages = latestByTag(messages, "h");

  return Array.from(metadata, ([id, event]) => {
    const membership = memberships.get(id);
    if (membership) pendingOwnedChannelIds.delete(id);
    return channelFromMetadata(event, membership, latestMessages.get(id));
  })
    .filter(
      (channel) => channel.channel_type !== "dm" || !hiddenDms.has(channel.id),
    )
    .sort((left, right) => {
      const byMessage = (right.last_message_at ?? "").localeCompare(
        left.last_message_at ?? "",
      );
      return byMessage || left.id.localeCompare(right.id);
    });
}

async function fetchChannelMetadata(
  client: RelayQueryClient,
  channelId: string,
): Promise<RelayEvent> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const event = await client.fetchFirstEvent({
      kinds: [39000],
      "#d": [channelId],
      limit: 1,
    });
    if (event) return event;
    if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("channel created but metadata not yet available");
}

async function createChannel(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const input = objectBody(body, "create_channel");
  const name = requiredString(input, "name").trim().toLowerCase();
  if (!name) throw new Error("channel name is required");
  const visibility = requiredString(input, "visibility");
  if (visibility !== "open" && visibility !== "private") {
    throw new Error(`invalid visibility: ${visibility}`);
  }
  const channelType = requiredString(input, "channelType");
  if (channelType !== "stream" && channelType !== "forum") {
    throw new Error(`invalid channel_type: ${channelType}`);
  }
  const channelId = crypto.randomUUID();
  const tags = [
    ["h", channelId],
    ["name", name],
    ["visibility", visibility],
    ["channel_type", channelType],
  ];
  const description = optionalString(input, "description");
  if (description !== undefined) tags.push(["about", description]);
  const ttlSeconds = optionalNumber(input, "ttlSeconds");
  if (ttlSeconds !== undefined) tags.push(["ttl", String(ttlSeconds)]);
  await publishSignedEvent(
    identity,
    client,
    { kind: 9007, content: "", tags },
    "creating the channel",
  );
  pendingOwnedChannelIds.add(channelId);
  const metadata = await fetchChannelMetadata(client, channelId);
  return channelFromMetadata(metadata, undefined, undefined);
}

async function ensureStarterChannels(
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  let channels = await getChannels(identity, client);
  for (const starter of STARTER_CHANNELS) {
    const existing = channels.find(
      (channel) =>
        channel.name.trim().toLowerCase() === starter.name &&
        channel.channel_type === "stream" &&
        channel.visibility === "open" &&
        channel.archived_at === null,
    );
    if (existing?.is_member) continue;
    if (existing) {
      await publishSignedEvent(
        identity,
        client,
        { kind: 9021, content: "", tags: [["h", existing.id]] },
        "joining the starter channel",
      );
      pendingOwnedChannelIds.add(existing.id);
      channels = channels.map((channel) =>
        channel.id === existing.id ? { ...channel, is_member: true } : channel,
      );
      continue;
    }
    const created = await createChannel(
      {
        name: starter.name,
        channelType: "stream",
        visibility: "open",
        description: starter.description,
      },
      identity,
      client,
    );
    channels = [...channels, created];
  }
  return channels;
}

async function updateChannel(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
) {
  const commandBody = objectBody(body, "update_channel");
  const input = objectBody(commandBody.input, "update_channel input");
  const channelId = requiredString(input, "channelId");
  const name = optionalString(input, "name");
  const description = optionalString(input, "description");
  const visibility = optionalString(input, "visibility");
  const ttlSeconds = optionalNullableNumber(input, "ttlSeconds");
  if (
    name === undefined &&
    description === undefined &&
    visibility === undefined &&
    ttlSeconds === undefined
  ) {
    throw new Error(
      "at least one of name, about, visibility, or ttl must be provided",
    );
  }
  if (
    visibility !== undefined &&
    visibility !== "open" &&
    visibility !== "private"
  ) {
    throw new Error('visibility must be "open" or "private"');
  }
  const canonicalName = name?.trim().toLowerCase();
  if (canonicalName !== undefined && !canonicalName) {
    throw new Error("channel name is required");
  }
  const tags: string[][] = [["h", channelId]];
  if (canonicalName !== undefined) tags.push(["name", canonicalName]);
  if (description !== undefined) tags.push(["about", description]);
  if (visibility !== undefined) tags.push(["visibility", visibility]);
  if (ttlSeconds !== undefined) {
    tags.push(["ttl", ttlSeconds === null ? "" : String(ttlSeconds)]);
  }
  await publishSignedEvent(
    identity,
    client,
    { kind: 9002, content: "", tags },
    "updating the channel",
  );
  const metadata = await fetchChannelMetadata(client, channelId);
  return channelDetailFromMetadata(metadata);
}

async function getChannelMembers(body: unknown, client: RelayQueryClient) {
  const channelId = requiredString(
    objectBody(body, "get_channel_members"),
    "channelId",
  );
  const membership = await client.fetchFirstEvent({
    kinds: [39002],
    "#d": [channelId],
    limit: 1,
  });
  if (!membership) {
    if (pendingOwnedChannelIds.has(channelId)) {
      return { members: [], next_cursor: null };
    }
    throw new Error("channel members not found");
  }
  const seen = new Set<string>();
  const members = membership.tags.flatMap((tag) => {
    const pubkey = tag[0] === "p" ? tag[1] : undefined;
    if (!pubkey || seen.has(pubkey)) return [];
    seen.add(pubkey);
    const role = tag[3] || "member";
    return [
      {
        pubkey,
        role,
        is_agent: role === "bot",
        joined_at: null,
        display_name: null,
      },
    ];
  });
  return { members, next_cursor: null };
}

async function getChannelMessagesBefore(
  body: unknown,
  client: RelayQueryClient,
) {
  const input = objectBody(body, "get_channel_messages_before");
  const channelId = requiredString(input, "channelId");
  const before = optionalNumber(input, "before");
  if (before === undefined) throw new TypeError("before must be an integer");
  const beforeId = optionalString(input, "beforeId");
  const since = optionalNumber(input, "since");
  const kinds = optionalKinds(input, "kinds") ?? [...TIMELINE_KINDS];
  const requestedLimit = optionalNumber(input, "limit") ?? 200;
  if (requestedLimit < 0) throw new TypeError("limit must be non-negative");
  const cap = Math.min(requestedLimit, 500);
  const filter: Record<string, unknown> = {
    "#h": [channelId],
    kinds,
    until: before,
    limit: cap,
  };
  if (since !== undefined) filter.since = since;
  if (beforeId) filter.before_id = beforeId;
  const events = await queryBridge(client, [filter]);
  const oldest = events.at(-1);
  return {
    events,
    next_cursor:
      events.length >= cap && oldest
        ? { created_at: oldest.created_at, event_id: oldest.id }
        : null,
  };
}

async function getChannelWindow(body: unknown, client: RelayQueryClient) {
  const input = objectBody(body, "get_channel_window");
  const channelId = requiredString(input, "channelId");
  const requestedLimit = optionalNumber(input, "limitRows") ?? 50;
  if (requestedLimit < 0) throw new TypeError("limitRows must be non-negative");
  const filter: Record<string, unknown> = {
    "#h": [channelId],
    kinds: [...TIMELINE_KINDS],
    limit: Math.min(requestedLimit, 200),
    top_level: true,
    include_summaries: true,
    include_aux: true,
  };
  if (input.cursor !== undefined && input.cursor !== null) {
    const cursor = objectBody(input.cursor, "get_channel_window cursor");
    const createdAt = optionalNumber(cursor, "created_at");
    if (createdAt === undefined) {
      throw new TypeError("created_at must be an integer");
    }
    filter.until = createdAt;
    filter.before_id = requiredString(cursor, "event_id");
  }
  return queryBridge(client, [filter]);
}

function validatePrefixedTags(
  tags: string[][],
  prefix: string,
  field: string,
): void {
  for (const tag of tags) {
    if (tag[0] !== prefix) {
      throw new Error(`${field} tags must use '${prefix}' prefix`);
    }
  }
}

function validateMentionReferenceTags(tags: string[][]): void {
  validatePrefixedTags(tags, "mention", "mention reference");
  for (const tag of tags) {
    if (!tag[1]) throw new Error("mention reference tag missing pubkey");
    validatePubkeys([tag[1]]);
  }
}

function validLinkPreviewText(
  value: string,
  maxBytes: number,
  allowNewlines: boolean,
): boolean {
  return (
    new TextEncoder().encode(value).length <= maxBytes &&
    !Array.from(value).some((character) => {
      const code = character.codePointAt(0) ?? 0;
      const control = code <= 0x1f || (code >= 0x7f && code <= 0x9f);
      return control && !(allowNewlines && character === "\n");
    })
  );
}

function validPreviewMediaPair(
  urlValue: string,
  hash: string,
  relayOrigin: string,
): boolean {
  if (!urlValue && !hash) return true;
  if (!urlValue || !/^[0-9a-f]{64}$/.test(hash)) return false;
  try {
    const url = new URL(urlValue);
    const filename = url.pathname.startsWith("/media/")
      ? url.pathname.slice("/media/".length)
      : "";
    const separator = filename.indexOf(".");
    const pathHash = filename.slice(0, separator);
    const extension = filename.slice(separator + 1);
    return (
      url.origin === relayOrigin &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      filename.length > 0 &&
      !filename.includes("/") &&
      !filename.includes("%") &&
      separator > 0 &&
      pathHash === hash &&
      /^[0-9a-f]{64}$/.test(pathHash) &&
      ["jpg", "png", "gif", "webp"].includes(extension)
    );
  } catch {
    return false;
  }
}

async function validateLinkPreviewTags(tags: string[][]): Promise<void> {
  if (tags.length > 8) {
    throw new Error("too many link preview snapshots (max 8)");
  }
  if (tags.some((tag) => tag[0] === "link-preview" && tag[1] === "none")) {
    if (
      tags.length !== 1 ||
      tags[0].length !== 2 ||
      tags[0][0] !== "link-preview" ||
      tags[0][1] !== "none"
    ) {
      throw new Error("link-preview suppression cannot include snapshots");
    }
    return;
  }
  if (tags.length === 0) return;
  const relayOrigin = new URL(await dispatch<string>("get_relay_http_url"))
    .origin;
  const seen = new Set<string>();
  for (const tag of tags) {
    let canonicalUrl: URL;
    try {
      canonicalUrl = new URL(tag[3] ?? "");
    } catch {
      throw new Error("invalid link-preview snapshot tag");
    }
    const valid =
      tag.length === 11 &&
      tag[0] === "link-preview" &&
      tag[1] === "snapshot" &&
      tag[2] === "1" &&
      canonicalUrl.protocol === "https:" &&
      !canonicalUrl.username &&
      !canonicalUrl.password &&
      !canonicalUrl.hash &&
      !seen.has(tag[3]) &&
      validLinkPreviewText(tag[4], 300, false) &&
      validLinkPreviewText(tag[5], 100, false) &&
      validLinkPreviewText(tag[6], 1000, true) &&
      validPreviewMediaPair(tag[7], tag[8], relayOrigin) &&
      validPreviewMediaPair(tag[9], tag[10], relayOrigin);
    if (!valid) throw new Error("invalid link-preview snapshot tag");
    seen.add(tag[3]);
  }
}

function validatePubkeys(pubkeys: string[]): string[] {
  if (pubkeys.length > 50) throw new Error("too many mentions (max 50)");
  const seen = new Set<string>();
  const result: string[] = [];
  for (const pubkey of pubkeys) {
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new Error(
        `pubkey must be a 64-character hex string (got ${pubkey.length} chars)`,
      );
    }
    const normalized = pubkey.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      result.push(normalized);
    }
  }
  return result;
}

async function resolveThread(
  parentEventId: string,
  client: RelayQueryClient,
): Promise<string> {
  const parent = await client.fetchFirstEvent({
    ids: [parentEventId],
    kinds: [9, 40002, 45001, 45003, 48100],
    limit: 1,
  });
  if (!parent) throw new Error("parent event not found");
  let root: string | null = null;
  let reply: string | null = null;
  for (const tag of parent.tags) {
    if (tag[0] !== "e" || tag.length < 4) continue;
    if (tag[3] === "root") root = tag[1] ?? null;
    if (tag[3] === "reply") reply = tag[1] ?? null;
  }
  const resolved = root ?? reply;
  return resolved && resolved !== parentEventId ? resolved : parentEventId;
}

async function sendChannelMessage(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
  offlinePublisher?: OfflineMessagePublisher,
) {
  const input = objectBody(body, "send_channel_message");
  const channelId = requiredString(input, "channelId");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      channelId,
    )
  ) {
    throw new Error(`invalid channel UUID: ${channelId}`);
  }
  const content = requiredString(input, "content").trim();
  const contentBytes = new TextEncoder().encode(content).length;
  if (contentBytes > 64 * 1024) {
    throw new Error(
      `content exceeds maximum size of 65536 bytes (got ${contentBytes})`,
    );
  }
  const parentEventId = optionalString(input, "parentEventId") ?? null;
  const requestedKind = optionalNumber(input, "kind") ?? 9;
  const mentions = validatePubkeys(optionalStrings(input, "mentionPubkeys"));
  const mediaTags = optionalStringArrays(input, "mediaTags");
  const emojiTags = optionalStringArrays(input, "emojiTags");
  const mentionTags = optionalStringArrays(input, "mentionTags");
  const linkPreviewTags = optionalStringArrays(input, "linkPreviewTags");
  validatePrefixedTags(mediaTags, "imeta", "media");
  validateMentionReferenceTags(mentionTags);

  let kind = 9;
  let rootEventId: string | null = null;
  const tags: string[][] = [["h", channelId]];
  if (requestedKind === 45001) {
    kind = 45001;
  } else if (requestedKind === 45003) {
    kind = 45003;
    if (!parentEventId) {
      throw new Error("forum comment requires parent_event_id");
    }
    rootEventId = await resolveThread(parentEventId, client);
  } else if (parentEventId) {
    rootEventId = await resolveThread(parentEventId, client);
  }
  if (kind === 9) {
    validatePrefixedTags(emojiTags, "emoji", "emoji");
    await validateLinkPreviewTags(linkPreviewTags);
  }
  if (parentEventId && rootEventId) {
    if (parentEventId === rootEventId) {
      tags.push(["e", rootEventId, "", "reply"]);
    } else {
      tags.push(["e", rootEventId, "", "root"]);
      tags.push(["e", parentEventId, "", "reply"]);
    }
  }
  tags.push(...mentions.map((pubkey) => ["p", pubkey]));
  tags.push(...mediaTags, ...mentionTags);
  if (kind === 9) tags.push(...emojiTags, ...linkPreviewTags);

  const signed = parseSignedEvent(identity.sign({ kind, content, tags }));
  const outcome = offlinePublisher
    ? await offlinePublisher.publishOrQueue(signed)
    : {
        event: await client.publishEvent(
          signed,
          "Timed out while sending the message.",
          "Failed while sending the message.",
        ),
        deliveryStatus: "delivered" as const,
      };
  const published = outcome.event;
  const depth = !parentEventId ? 0 : parentEventId === rootEventId ? 1 : 2;
  return {
    event_id: published.id,
    parent_event_id: parentEventId,
    root_event_id: rootEventId,
    depth,
    created_at: published.created_at,
    delivery_status: outcome.deliveryStatus,
  };
}

async function searchMessages(body: unknown, client: RelayQueryClient) {
  const input = objectBody(body, "search_messages");
  const query = requiredString(input, "q").trim();
  const requestedLimit = optionalNumber(input, "limit") ?? 20;
  if (requestedLimit < 0) throw new TypeError("limit must be non-negative");
  const cap = Math.min(requestedLimit, 100);
  const filter: Record<string, unknown> = {
    kinds: [9, 40002, 45001, 45003],
    search: query,
    search_mode: "prefix",
    limit: cap,
  };
  const channelId = optionalString(input, "channelId");
  if (channelId) filter["#h"] = [channelId];
  const authors = optionalStrings(input, "authors")
    .map((author) => author.trim())
    .filter(Boolean);
  if (authors.length) filter.authors = authors;
  const since = optionalNumber(input, "since");
  const until = optionalNumber(input, "until");
  if (since !== undefined) filter.since = since;
  if (until !== undefined) filter.until = until;
  const events = await queryBridge(client, [filter]);
  const total = events.length;
  return {
    hits: events.map((event, index) => ({
      event_id: event.id,
      content: event.content,
      kind: event.kind,
      pubkey: event.pubkey,
      channel_id: tagValue(event, "h"),
      channel_name: null,
      created_at: event.created_at,
      score: total <= 1 ? 1 : 1 - index / total,
    })),
    found: total,
  };
}

export function registerRelayQueryCommands(
  identity: BrowserIdentityManager,
  client: RelayQueryClient = relayClient,
  offlinePublisher?: OfflineMessagePublisher,
): void {
  register("get_profile", () => getProfile(identity, client));
  register("get_user_profile", (body) =>
    getUserProfile(body, identity, client),
  );
  register("get_users_batch", (body) => getUsersBatch(body, client));
  register("update_profile", (body) => updateProfile(body, identity, client));
  register("get_channels", () => getChannels(identity, client));
  register("create_channel", (body) => createChannel(body, identity, client));
  register("ensure_starter_channels", () =>
    ensureStarterChannels(identity, client),
  );
  register("update_channel", (body) => updateChannel(body, identity, client));
  register("get_channel_members", (body) => getChannelMembers(body, client));
  register("get_channel_messages_before", (body) =>
    getChannelMessagesBefore(body, client),
  );
  register("get_channel_window", (body) => getChannelWindow(body, client));
  register("send_channel_message", (body) =>
    sendChannelMessage(body, identity, client, offlinePublisher),
  );
  register("search_messages", (body) => searchMessages(body, client));
}
