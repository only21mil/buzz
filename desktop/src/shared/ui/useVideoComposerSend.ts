import { useCallback, type RefObject } from "react";
import type { MessageComposerProps } from "@/features/messages/ui/MessageComposer.types";
import type { PublicationScope } from "@/shared/api/publicationScope";
import type { VideoReviewComment } from "./VideoPlayer";

type VideoComposerSend = (
  ...args: [
    ...Parameters<MessageComposerProps["onSend"]>,
    publicationScope?: PublicationScope,
  ]
) => Promise<void>;

/** Preserve composer publication authority through the video-comment adapter. */
export function useVideoComposerSend(
  post: (
    content: string,
    options: {
      publicationScope?: PublicationScope;
      mediaTags?: string[][];
      mentionPubkeys: string[];
      replyTo: VideoReviewComment | null;
      stampTimecode: boolean;
    },
  ) => Promise<void>,
  replyTarget: RefObject<{ comment: VideoReviewComment } | null>,
  postAtCurrentFrame: RefObject<boolean>,
): VideoComposerSend {
  return useCallback<VideoComposerSend>(
    async (
      content,
      mentionPubkeys,
      mediaTags,
      _channelId,
      _threadContext,
      _forceRest,
      publicationScope,
    ) => {
      await post(content, {
        publicationScope,
        mediaTags,
        mentionPubkeys,
        replyTo: replyTarget.current?.comment ?? null,
        stampTimecode: postAtCurrentFrame.current,
      });
    },
    [post, replyTarget, postAtCurrentFrame],
  );
}
