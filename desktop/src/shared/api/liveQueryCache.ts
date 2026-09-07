import type { QueryClient } from "@tanstack/react-query";
import type {
  Channel,
  ChannelMember,
  Profile,
  RelayEvent,
  UserProfileSummary,
  UsersBatchResponse,
} from "./types";
import {
  channelMessagesKey,
  channelWindowKey,
} from "@/features/messages/lib/messageQueryKeys";
import {
  mergeTimelineCacheMessages,
  mergeMessages,
} from "@/features/messages/lib/messageMerge";
import { mergeChannelWindowOverlayEvents } from "@/features/messages/lib/projectChannelWindow";
import {
  flattenChannelWindowEvents,
  type ChannelWindowStore,
} from "@/features/messages/lib/channelWindowStore";
import {
  getThreadReference,
  isBroadcastReply,
} from "@/features/messages/lib/threading";
import {
  CHANNEL_MESSAGE_EVENT_KINDS,
  CHANNEL_AUX_EVENT_KINDS,
  CHANNEL_EVENT_KINDS,
  CHANNEL_TIMELINE_CONTENT_KINDS,
} from "@/shared/constants/kinds";

const newContent = new Set<number>(CHANNEL_MESSAGE_EVENT_KINDS);
const messageEvents = new Set<number>([
  ...CHANNEL_EVENT_KINDS,
  ...CHANNEL_TIMELINE_CONTENT_KINDS,
]);
const tag = (event: RelayEvent, name: string) =>
  event.tags.find((item) => item[0] === name)?.[1];

/** Called by the authenticated subscription path before UI and notifications. */
export function applyLiveQueryCache(
  client: QueryClient,
  event: RelayEvent,
  self: string,
): void {
  if (event.kind === 0 || event.kind === 39000 || event.kind === 39002) {
    const key = [
      "cache-event",
      event.kind,
      event.pubkey,
      tag(event, "d") ?? "",
    ];
    const previous = client.getQueryData<RelayEvent>(key);
    if (
      previous &&
      (previous.created_at > event.created_at ||
        (previous.created_at === event.created_at && previous.id <= event.id))
    )
      return;
    if (event.kind === 0 && !applyProfile(client, event, self)) return;
    if (event.kind !== 0) applyChannelSnapshot(client, event, self);
    client.setQueryData(key, event);
    return;
  }

  if (!messageEvents.has(event.kind)) return;
  const channelId = tag(event, "h");
  const thread = getThreadReference(event.tags);
  const auxiliary = (CHANNEL_AUX_EVENT_KINDS as readonly number[]).includes(
    event.kind,
  );
  const references = event.tags
    .filter((item) => item[0] === "e")
    .map((item) => item[1]);
  const cachedQueries = client.getQueryCache().findAll({
    predicate: (query) =>
      ["channel-messages", "channel-window", "thread-replies"].includes(
        String(query.queryKey[0]),
      ),
  });
  const channelIds = new Set(cachedQueries.map((query) => query.queryKey[1]));
  for (const id of channelIds) {
    if (typeof id !== "string") continue;
    const referencesCachedEvent = cachedQueries.some((query) => {
      if (query.queryKey[1] !== id || !query.state.data) return false;
      if (references.includes(String(query.queryKey[2]))) return true;
      const events =
        query.queryKey[0] === "channel-window"
          ? flattenChannelWindowEvents(query.state.data as ChannelWindowStore)
          : (query.state.data as RelayEvent[]);
      return events.some((item) => references.includes(item.id));
    });
    if (id !== channelId && (channelId || !referencesCachedEvent)) continue;
    client.setQueryData<RelayEvent[]>(channelMessagesKey(id), (current) =>
      current ? mergeTimelineCacheMessages(current, event) : current,
    );
    if (!thread.parentId || isBroadcastReply(event.tags) || auxiliary) {
      client.setQueryData<ChannelWindowStore>(
        channelWindowKey(id),
        (current) =>
          current ? mergeChannelWindowOverlayEvents(current, [event]) : current,
      );
    }
    client.setQueriesData<RelayEvent[]>(
      {
        predicate: (candidate) =>
          candidate.queryKey[0] === "thread-replies" &&
          candidate.queryKey[1] === id &&
          (auxiliary
            ? references.includes(String(candidate.queryKey[2])) ||
              (candidate.state.data as RelayEvent[] | undefined)?.some((item) =>
                references.includes(item.id),
              ) === true
            : candidate.queryKey[2] === thread.rootId),
      },
      (current) => (current ? mergeMessages(current, event) : current),
    );
  }
  if (channelId && newContent.has(event.kind)) {
    const at = new Date(event.created_at * 1000).toISOString();
    client.setQueryData<Channel[]>(["channels"], (current) =>
      current?.map((channel) =>
        channel.id === channelId &&
        (!channel.lastMessageAt || channel.lastMessageAt < at)
          ? { ...channel, lastMessageAt: at }
          : channel,
      ),
    );
  }
}

function applyProfile(
  client: QueryClient,
  event: RelayEvent,
  self: string,
): boolean {
  let content: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(event.content);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return false;
    content = parsed as Record<string, unknown>;
  } catch {
    return false;
  }
  const field = (name: string) =>
    typeof content[name] === "string" ? (content[name] as string) : null;
  const profile: Profile = {
    pubkey: event.pubkey,
    displayName: field("display_name") ?? field("name"),
    avatarUrl: field("picture"),
    about: field("about"),
    nip05Handle: field("nip05"),
    ownerPubkey:
      client.getQueryData<Profile>(["user-profile", event.pubkey])
        ?.ownerPubkey ?? null,
    hasProfileEvent: true,
  };
  void client.cancelQueries({
    predicate: (query) =>
      (query.queryKey[0] === "profile" && event.pubkey === self) ||
      (["user-profile", "users-batch", "users-batch-entry"].includes(
        String(query.queryKey[0]),
      ) &&
        query.queryKey.includes(event.pubkey)),
  });
  if (event.pubkey === self) client.setQueryData(["profile"], profile);
  client.setQueryData(["user-profile", event.pubkey], profile);
  const summary = {
    displayName: profile.displayName,
    name: field("name"),
    avatarUrl: profile.avatarUrl,
    nip05Handle: profile.nip05Handle,
    ownerPubkey:
      client.getQueryData<{ summary: UserProfileSummary | null }>([
        "users-batch-entry",
        event.pubkey,
      ])?.summary?.ownerPubkey ?? profile.ownerPubkey,
  };
  client.setQueryData(["users-batch-entry", event.pubkey], {
    summary,
    fetchedAt: Date.now(),
  });
  client.setQueriesData<UsersBatchResponse>(
    {
      predicate: (query) =>
        query.queryKey[0] === "users-batch" &&
        query.queryKey.includes(event.pubkey),
    },
    (current) =>
      current
        ? {
            profiles: {
              ...current.profiles,
              [event.pubkey]: {
                ...summary,
                ownerPubkey:
                  current.profiles[event.pubkey]?.ownerPubkey ??
                  summary.ownerPubkey,
              },
            },
            missing: current.missing.filter((key) => key !== event.pubkey),
          }
        : current,
  );
  client.setQueriesData<ChannelMember[]>(
    {
      predicate: (query) =>
        query.queryKey[0] === "channels" && query.queryKey[2] === "members",
    },
    (current) =>
      current?.map((member) =>
        member.pubkey === event.pubkey
          ? { ...member, displayName: profile.displayName }
          : member,
      ),
  );
  return true;
}

function applyChannelSnapshot(
  client: QueryClient,
  event: RelayEvent,
  self: string,
): void {
  const id = tag(event, "d");
  if (!id) return;
  const channels = client.getQueryData<Channel[]>(["channels"]);
  if (!channels?.some((channel) => channel.id === id)) {
    // Discovery needs the relay's visibility/membership projection for a new id.
    void client.invalidateQueries({ queryKey: ["channels"], exact: true });
    return;
  }
  void client.cancelQueries({ queryKey: ["channels"] });
  const memberTags = event.tags.filter((item) => item[0] === "p");
  const pubkeys = [...new Set(memberTags.map((item) => item[1]))];
  const project = (channel: Channel): Channel => {
    if (channel.id !== id) return channel;
    if (event.kind === 39002)
      return {
        ...channel,
        memberPubkeys: pubkeys,
        memberCount: pubkeys.length,
        participantPubkeys: pubkeys,
        isMember: pubkeys.includes(self),
      };
    const type = tag(event, "t");
    return {
      ...channel,
      name: tag(event, "name") ?? "",
      description: tag(event, "about") ?? "",
      topic: tag(event, "topic") ?? null,
      purpose: tag(event, "purpose") ?? null,
      channelType: type === "dm" || type === "forum" ? type : "stream",
      visibility:
        event.tags.some((item) => item[0] === "private") ||
        tag(event, "visibility") === "private"
          ? "private"
          : "open",
      archivedAt:
        tag(event, "archived") === "true"
          ? new Date(event.created_at * 1000).toISOString()
          : null,
    };
  };
  client.setQueryData<Channel[]>(["channels"], (current) =>
    current?.map(project),
  );
  client.setQueryData<Channel>(["channels", id, "detail"], (current) =>
    current ? project(current) : current,
  );
  if (event.kind !== 39002) return;
  client.setQueryData<ChannelMember[]>(
    ["channels", id, "members"],
    (current) =>
      current
        ? pubkeys.map((pubkey) => {
            const old = current.find((member) => member.pubkey === pubkey);
            const role = memberTags.find((item) => item[1] === pubkey)?.[3];
            const validRole =
              role === "owner" ||
              role === "admin" ||
              role === "guest" ||
              role === "bot"
                ? role
                : "member";
            return {
              pubkey,
              role: validRole,
              isAgent: validRole === "bot",
              joinedAt: old?.joinedAt ?? "",
              displayName: old?.displayName ?? null,
            };
          })
        : current,
  );
  if (!pubkeys.includes(self)) {
    for (const root of [
      "channel-messages",
      "channel-window",
      "thread-replies",
    ]) {
      client.removeQueries({ queryKey: [root, id] });
    }
  }
}
