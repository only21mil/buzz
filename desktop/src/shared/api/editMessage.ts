import { preparePublicationScope } from "@/shared/api/preparePublicationScope";
import {
  assertPublicationScope,
  capturePublicationScope,
  type PublicationScope,
} from "@/shared/api/publicationScope";
import { invokeTauri } from "@/shared/api/tauri";

/** Publish with the captured native identity and community epoch. */
export async function editMessage(
  channelId: string,
  eventId: string,
  content: string,
  mediaTags?: string[][],
  emojiTags?: string[][],
  mentionPubkeys?: string[],
  suppressLinkPreviews?: boolean,
  mentionTags?: string[][],
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
      mentionTags: mentionTags ?? null,
    },
  });
}
