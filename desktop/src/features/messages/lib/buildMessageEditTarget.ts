import type { TimelineMessage } from "@/features/messages/types";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import type { MessageComposerEditTarget } from "../ui/MessageComposer.types";
import { buildEditMentionState } from "./draftMentionRefs";
import { imetaMediaFromTags } from "./imetaMediaMarkdown";

/** Preserve original exact recipient authority when opening an existing message for edit. */
export function buildMessageEditTarget(
  message: TimelineMessage | null,
  profiles: UserProfileLookup | undefined,
  agents: ReadonlySet<string>,
): MessageComposerEditTarget | null {
  return message
    ? {
        ...buildEditMentionState(message.body, message.tags, profiles, (key) =>
          agents.has(key),
        ),
        author: message.author,
        body: message.body,
        id: message.id,
        isThreadReply: Boolean(message.parentId),
        imetaMedia: imetaMediaFromTags(message.tags),
      }
    : null;
}
