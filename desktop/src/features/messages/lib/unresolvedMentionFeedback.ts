import {
  getMentionLikeOffsets,
  getMentionOffsets,
} from "@/shared/lib/mentionBoundaries";

const UNRESOLVED_MENTION_ERROR =
  "That @mention is not linked to a member. Choose a recipient from the mention picker or remove the @ before sending.";

export function unresolvedMentionError(
  text: string,
  resolvedLabels: readonly string[],
): string | null {
  const resolvedOffsets = new Set(
    resolvedLabels.flatMap((label) => getMentionOffsets(text, label)),
  );
  return getMentionLikeOffsets(text).some(
    (offset) => !resolvedOffsets.has(offset),
  )
    ? UNRESOLVED_MENTION_ERROR
    : null;
}
