import type { UseMentionsResult } from "./useMentions";
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

/** Snapshot recipients and reject unresolved text before the send is promoted. */
export function prepareMentionSendTargets(
  text: string,
  mentions: Pick<
    UseMentionsResult,
    "getDraftMentionRefs" | "extractMentionPubkeys" | "extractMentionPersonas"
  >,
  onUnresolvedMention: (message: string) => void,
) {
  const savedMentionRefs = mentions.getDraftMentionRefs(text).slice();
  const resolvedLabels = new Set<string>();
  const selectedMentionPubkeys = mentions.extractMentionPubkeys(
    text,
    [],
    (displayName) => resolvedLabels.add(displayName),
  );
  const selectedPersonas = mentions.extractMentionPersonas(text);
  const error = unresolvedMentionError(text, [
    ...savedMentionRefs.map((ref) => ref.displayName),
    ...resolvedLabels,
    ...selectedPersonas.map((target) => target.displayName),
  ]);
  if (error) {
    onUnresolvedMention(error);
    throw new Error(error);
  }
  return { savedMentionRefs, selectedMentionPubkeys, selectedPersonas };
}
