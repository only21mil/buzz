import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayQueryClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent" | "publishEvent"
>;

type ObjectBody = Record<string, unknown>;

const pendingOwnedChannelIds = new Set<string>();

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
    owner_pubkey: null,
    has_profile_event: true,
  };
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
  const [membershipEvents, metadataEvents, visibilityEvents] =
    await Promise.all([
      client.fetchEvents({ kinds: [39002], "#p": [pubkey], limit: 1000 }),
      client.fetchEvents({ kinds: [39000], limit: 1000 }),
      client.fetchEvents({
        kinds: [30622],
        authors: [pubkey],
        "#p": [pubkey],
        limit: 10,
      }),
    ]);
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

export function registerRelayQueryCommands(
  identity: BrowserIdentityManager,
  client: RelayQueryClient = relayClient,
): void {
  register("get_profile", () => getProfile(identity, client));
  register("update_profile", (body) => updateProfile(body, identity, client));
  register("get_channels", () => getChannels(identity, client));
  register("create_channel", (body) => createChannel(body, identity, client));
  register("ensure_starter_channels", () =>
    ensureStarterChannels(identity, client),
  );
  register("update_channel", (body) => updateChannel(body, identity, client));
  register("get_channel_members", (body) => getChannelMembers(body, client));
}
