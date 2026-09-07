import * as React from "react";
import type { Channel } from "@/shared/api/types";
import type { SidebarDmParticipant } from "@/features/sidebar/ui/SidebarSection";
import {
  canPreviewUnreadDm,
  preferredUnreadTarget,
} from "@/features/sidebar/ui/MoreUnreadButton";

/** Resolve offscreen DM previews from the same identities and labels as sidebar rows. */
export function useUnreadDmPreviews({
  directMessages,
  dmChannelLabels,
  dmParticipantsByChannelId,
  unreadMessageBelowChannelIds,
}: {
  directMessages: Channel[];
  dmChannelLabels: Record<string, string>;
  dmParticipantsByChannelId: Record<string, SidebarDmParticipant[]>;
  unreadMessageBelowChannelIds: string[];
}) {
  const unreadDmPreviewsBelow = React.useMemo(
    () =>
      unreadMessageBelowChannelIds.flatMap((channelId) => {
        const channel = directMessages.find(
          (candidate) => candidate.id === channelId,
        );
        const participants = dmParticipantsByChannelId[channelId];
        const participant = participants?.[0];
        if (
          !channel ||
          !participant ||
          !canPreviewUnreadDm(
            channel.participantPubkeys.length,
            participants?.length ?? 0,
          )
        ) {
          return [];
        }
        return [
          {
            accessibleLabel: participant.label,
            avatarUrl: participant.avatarUrl,
            channelId,
            label: dmChannelLabels[channelId] ?? participant.label,
          },
        ];
      }),
    [
      directMessages,
      dmChannelLabels,
      dmParticipantsByChannelId,
      unreadMessageBelowChannelIds,
    ],
  );
  const unreadDmChannelIds = React.useMemo(
    () => new Set(directMessages.map(({ id }) => id)),
    [directMessages],
  );
  const nextUnreadDmBelowId = preferredUnreadTarget(
    unreadMessageBelowChannelIds,
    unreadDmChannelIds,
  );
  return { unreadDmPreviewsBelow, nextUnreadDmBelowId };
}
