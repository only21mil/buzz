import {
  resolveUserLabel,
  type UserProfileLookup,
} from "@/features/profile/lib/identity";
import { formatDmParticipantDisplayName } from "@/features/channels/lib/dmParticipantDisplay";
import type { Channel } from "@/shared/api/types";
import { parsePubkeyInput } from "@/shared/lib/nostrUtils";
import { normalizePubkey } from "@/shared/lib/pubkey";

function isGenericDmChannelName(name: string) {
  const normalized = name.trim().toLowerCase();
  return (
    normalized.length === 0 ||
    normalized === "dm" ||
    normalized === "direct message" ||
    normalized === "direct messages" ||
    /^group dm\s*(\(\d+\))?$/.test(normalized)
  );
}

function identifiesDmParticipant(name: string, participantPubkeys: string[]) {
  const parsed = parsePubkeyInput(name);
  return (
    parsed !== null &&
    participantPubkeys.some(
      (pubkey) => normalizePubkey(pubkey) === normalizePubkey(parsed),
    )
  );
}

export function resolveChannelDisplayLabel(
  channel: Channel,
  currentPubkey: string | undefined,
  profiles: UserProfileLookup | undefined,
) {
  if (channel.channelType !== "dm") {
    return channel.name;
  }

  const shouldResolveParticipants =
    isGenericDmChannelName(channel.name) ||
    identifiesDmParticipant(channel.name, channel.participantPubkeys);
  if (!shouldResolveParticipants) {
    return channel.name;
  }

  const participants = channel.participantPubkeys.map((pubkey, index) => ({
    fallbackName: identifiesDmParticipant(channel.participants[index] ?? "", [
      pubkey,
    ])
      ? null
      : (channel.participants[index] ?? null),
    pubkey,
  }));
  const otherParticipants = currentPubkey
    ? participants.filter(
        (participant) =>
          participant.pubkey.toLowerCase() !== currentPubkey.toLowerCase(),
      )
    : participants;
  const resolvedLabels = (
    otherParticipants.length > 0 ? otherParticipants : participants
  ).map((participant) =>
    resolveUserLabel({
      currentPubkey,
      fallbackName: participant.fallbackName,
      profiles,
      pubkey: participant.pubkey,
    }),
  );
  const uniqueLabels = [...new Set(resolvedLabels)];

  return uniqueLabels.length > 0
    ? formatDmParticipantDisplayName(
        uniqueLabels.map((displayName) => ({ displayName })),
      )
    : channel.name;
}
