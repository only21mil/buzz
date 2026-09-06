import { preparePublicationScope } from "./preparePublicationScope";
import {
  assertPublicationScope,
  type PublicationScope,
} from "./publicationScope";
import { signRelayEvent } from "./tauri";
import type { RelayEvent } from "./types";
import { KIND_STREAM_MESSAGE } from "@/shared/constants/kinds";

/** Hold the authored scope through connection preparation, signing and publish. */
export async function sendScopedRelayMessage(
  ensureConnected: () => Promise<void>,
  publish: (
    event: RelayEvent,
    timeout: string,
    error: string,
    scope: PublicationScope,
  ) => Promise<RelayEvent>,
  input: {
    channelId: string;
    content: string;
    mentionPubkeys: string[];
    extraTags: string[][];
    expectedScope: PublicationScope;
  },
): Promise<RelayEvent> {
  const expectedScope = await preparePublicationScope(input.expectedScope);
  await ensureConnected();
  assertPublicationScope(expectedScope);
  const event = await signRelayEvent({
    expectedScope,
    kind: KIND_STREAM_MESSAGE,
    content: input.content.trim(),
    tags: [
      ["h", input.channelId],
      ...input.mentionPubkeys.map((pubkey) => ["p", pubkey]),
      ...input.extraTags,
    ],
  });
  return publish(
    event,
    "Timed out while sending the message.",
    "Failed to send the message.",
    expectedScope,
  );
}
