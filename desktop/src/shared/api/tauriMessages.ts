import { invokeTauri } from "@/shared/api/tauri";
import type { SendChannelMessageResult } from "@/shared/api/types";

type RawSendChannelMessageResult = {
  event_id: string;
  parent_event_id: string | null;
  root_event_id: string | null;
  depth: number;
  created_at: number;
};

export async function sendChannelMessage(
  channelId: string,
  content: string,
  parentEventId?: string | null,
  mediaTags?: string[][],
  mentionPubkeys?: string[],
  kind?: number,
  emojiTags?: string[][],
  mentionTags?: string[][],
  linkPreviewTags?: string[][],
  rootEventId?: string | null,
): Promise<SendChannelMessageResult> {
  const response = await invokeTauri<RawSendChannelMessageResult>(
    "send_channel_message",
    {
      channelId,
      content,
      parentEventId,
      rootEventId: rootEventId ?? null,
      mediaTags: mediaTags ?? null,
      emojiTags: emojiTags ?? null,
      mentionTags: mentionTags ?? null,
      linkPreviewTags,
      mentionPubkeys: mentionPubkeys ?? null,
      kind: kind ?? null,
    },
  );

  return {
    eventId: response.event_id,
    parentEventId: response.parent_event_id,
    rootEventId: response.root_event_id,
    depth: response.depth,
    createdAt: response.created_at,
  };
}
