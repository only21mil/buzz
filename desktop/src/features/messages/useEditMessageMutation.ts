import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  assertPublicationScope,
  capturePublicationScope,
  type PublicationScope,
} from "@/shared/api/publicationScope";
import { editMessage } from "@/shared/api/tauri";
import type { Channel, RelayEvent } from "@/shared/api/types";
import { splitOutgoingTags } from "./lib/imetaMediaMarkdown";
import { applyEditTagOverlay } from "./lib/applyEditTagOverlay.mjs";
import { channelMessagesKey, channelWindowKey } from "./lib/messageQueryKeys";
import {
  mapChannelWindowEvents,
  type ChannelWindowStore,
} from "./lib/channelWindowStore";

export function useEditMessageMutation(channel: Channel | null) {
  const queryClient = useQueryClient();

  return useMutation<
    void,
    Error,
    {
      publicationScope?: PublicationScope;
      eventId: string;
      content: string;
      mediaTags?: string[][];
      // Pubkeys of mentions *newly added* by this edit, diffed at the composer.
      // Only these receive a `p` tag so a typo-fix edit re-wakes nobody.
      mentionPubkeys?: string[];
    }
  >({
    mutationFn: async ({
      eventId,
      content,
      mediaTags,
      mentionPubkeys,
      publicationScope = capturePublicationScope(),
    }) => {
      assertPublicationScope(publicationScope);
      if (!channel) {
        throw new Error("No channel selected.");
      }

      // `mediaTags` arrives as the merged outgoing set (imeta + NIP-30 emoji).
      // Split so each rides its own validated Tauri arg — emoji tags must NOT
      // go through the imeta-only `mediaTags` channel (the Rust `imeta_tags`
      // guard rejects any non-imeta prefix), mirroring the send path.
      const { mediaTags: imetaTags, emojiTags } = splitOutgoingTags(mediaTags);

      await editMessage(
        channel.id,
        eventId,
        content,
        imetaTags,
        emojiTags,
        mentionPubkeys,
        undefined,
        publicationScope,
      );
    },
    onSuccess: (_data, { eventId, content, mediaTags }) => {
      if (!channel) {
        return;
      }

      // Apply-on-success cache update: reflect the edit's new content and
      // imeta tag set immediately, so the local cache matches what the
      // receiver overlay (formatTimelineMessages) will produce when the
      // edit event arrives back from the relay. (Not a true optimistic
      // update — runs in onSuccess, not onMutate. Worth bearing the cost
      // only because the edit event round-trip can lag perceptibly.)
      const applyEdit = (message: RelayEvent): RelayEvent => {
        if (message.id !== eventId) return message;
        const nextTags = mediaTags
          ? applyEditTagOverlay(message.tags, mediaTags)
          : message.tags;
        return { ...message, content, tags: nextTags };
      };

      // The WINDOW STORE is the source of truth: every live merge
      // re-flattens it over `channelMessagesKey`, so patching only the
      // flattened array gets reverted by the next live event (see
      // mapChannelWindowEvents). Update the store first, then keep the
      // flattened cache in step for immediate paint.
      queryClient.setQueryData<ChannelWindowStore>(
        channelWindowKey(channel.id),
        (current) =>
          current ? mapChannelWindowEvents(current, applyEdit) : current,
      );
      queryClient.setQueryData<RelayEvent[]>(
        channelMessagesKey(channel.id),
        (current = []) => current.map(applyEdit),
      );
    },
  });
}
