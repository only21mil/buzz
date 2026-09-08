import type {
  AddChannelMembersInput,
  AddChannelMembersResult,
  RelayAgent,
} from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

/** Select distinct relay-owned seats, preserving separate identities with the same name. */
export function getOwnedAgentsToAdd(
  agents: readonly RelayAgent[],
  currentPubkey: string | null | undefined,
  memberPubkeys: ReadonlySet<string>,
) {
  if (!currentPubkey) return [];
  const owner = normalizePubkey(currentPubkey);
  const members = new Set([...memberPubkeys].map(normalizePubkey));
  const selected = new Map<string, RelayAgent>();
  for (const agent of agents) {
    const pubkey = normalizePubkey(agent.pubkey);
    if (
      agent.ownerPubkey &&
      normalizePubkey(agent.ownerPubkey) === owner &&
      !members.has(pubkey)
    )
      selected.set(pubkey, agent);
  }
  return [...selected.values()];
}

/** Add sequentially and keep confirmed memberships even when profile refresh fails. */
export async function addOwnedChannelAgents(
  channelId: string,
  agents: readonly RelayAgent[],
  addMembers: (
    input: AddChannelMembersInput,
  ) => Promise<AddChannelMembersResult>,
) {
  const added: string[] = [];
  const errors: AddChannelMembersResult["errors"] = [];
  const seen = new Set<string>();
  for (const agent of agents) {
    const pubkey = normalizePubkey(agent.pubkey);
    if (seen.has(pubkey)) continue;
    seen.add(pubkey);
    try {
      const result = await addMembers({
        channelId,
        pubkeys: [pubkey],
        role: "bot",
      });
      const confirmed = result.added.some(
        (key) => normalizePubkey(key) === pubkey,
      );
      const failure = result.errors.find(
        (entry) => normalizePubkey(entry.pubkey) === pubkey,
      );
      if (confirmed) added.push(pubkey);
      if (failure) errors.push({ pubkey, error: failure.error });
      else if (!confirmed)
        errors.push({ pubkey, error: "The relay did not confirm membership." });
    } catch (error) {
      errors.push({
        pubkey,
        error: error instanceof Error ? error.message : "Failed to add agent.",
      });
    }
  }
  return { added, errors };
}
