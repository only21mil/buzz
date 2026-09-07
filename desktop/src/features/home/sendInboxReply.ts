import { splitOutgoingTags } from "@/features/messages/lib/imetaMediaMarkdown";
import type { PublicationScope } from "@/shared/api/publicationScope";
import { sendChannelMessage } from "@/shared/api/tauriMessages";

/** Carry the composer's immutable scope through the Inbox REST adapter. */
export async function sendInboxReply(input: {
  channelId: string;
  content: string;
  parentEventId: string | null;
  mentionPubkeys: string[];
  mediaTags?: string[][];
  publicationScope?: PublicationScope;
}) {
  const { mediaTags, emojiTags, mentionTags } = splitOutgoingTags(
    input.mediaTags,
  );
  const result = await sendChannelMessage(
    input.channelId,
    input.content,
    input.parentEventId,
    mediaTags,
    input.mentionPubkeys,
    undefined,
    emojiTags,
    mentionTags,
    undefined,
    undefined,
    input.publicationScope,
  );
  return {
    ...result,
    outgoingTags: [...mediaTags, ...emojiTags, ...mentionTags],
  };
}
