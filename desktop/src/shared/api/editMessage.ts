import { preparePublicationScope } from "./preparePublicationScope";
import {
  assertPublicationScope,
  capturePublicationScope,
  type PublicationScope,
} from "./publicationScope";
import { invokeTauri } from "@/shared/api/tauri";

export async function editMessage(
  channelId: string,
  eventId: string,
  content: string,
  mediaTags?: string[][],
  emojiTags?: string[][],
  mentionPubkeys?: string[],
  suppressLinkPreviews?: boolean,
  expectedScope: PublicationScope = capturePublicationScope(),
): Promise<void> {
  expectedScope = await preparePublicationScope(expectedScope);
  assertPublicationScope(expectedScope);
  await invokeTauri("edit_message", {
    input: {
      expectedScope,
      channelId,
      eventId,
      content,
      mediaTags: mediaTags ?? [],
      emojiTags: emojiTags ?? [],
      mentionPubkeys: mentionPubkeys ?? [],
      suppressLinkPreviews: suppressLinkPreviews ?? false,
    },
  });
}
