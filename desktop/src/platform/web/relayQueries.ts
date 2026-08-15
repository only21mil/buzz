import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register } from "./registry";

type RelayQueryClient = Pick<
  typeof relayClient,
  "fetchEvents" | "fetchFirstEvent"
>;

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

async function getProfile(
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
    const type =
      tagValue(event, "t") ??
      (event.tags.some((tag) => tag[0] === "hidden") ? "dm" : "stream");
    const privateChannel =
      event.tags.some((tag) => tag[0] === "private") ||
      tagValue(event, "visibility") === "private";
    const participants = Array.from(
      new Set(membership ? tagValues(membership, "p") : tagValues(event, "p")),
    );
    const lastMessage = latestMessages.get(id);
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
      last_message_at: lastMessage
        ? isoTimestamp(lastMessage.created_at)
        : null,
      archived_at:
        tagValue(event, "archived") === "true"
          ? isoTimestamp(event.created_at)
          : null,
      participants,
      participant_pubkeys: participants,
      is_member: memberships.has(id),
      ttl_seconds: tagValue(event, "ttl")
        ? Number(tagValue(event, "ttl"))
        : null,
      ttl_deadline: tagValue(event, "ttl_deadline"),
    };
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

export function registerRelayQueryCommands(
  identity: BrowserIdentityManager,
  client: RelayQueryClient = relayClient,
): void {
  register("get_profile", () => getProfile(identity, client));
  register("get_channels", () => getChannels(identity, client));
}
