import type { Channel, ManagedAgent } from "@/shared/api/types";
import type { AgentManagementRequest } from "./agentManagement";

export type AgentManagementReview = {
  agentPubkey: string;
  request: AgentManagementRequest;
};

const MAX_QUEUED_AGENT_MANAGEMENT_REVIEWS = 100;

/** Queues concurrent owner-review requests instead of dropping their dialogs. */
export function enqueueAgentManagementReview(
  activeRequestId: string | null,
  queued: readonly AgentManagementReview[],
  candidate: AgentManagementReview,
): {
  activate: AgentManagementReview | null;
  queued: AgentManagementReview[];
} {
  if (activeRequestId === null) {
    return { activate: candidate, queued: [...queued] };
  }
  if (queued.length >= MAX_QUEUED_AGENT_MANAGEMENT_REVIEWS) {
    return { activate: null, queued: [...queued] };
  }
  return { activate: null, queued: [...queued, candidate] };
}

/** Advances the owner-review dialog queue in FIFO order. */
export function advanceAgentManagementReview(
  queued: readonly AgentManagementReview[],
): {
  activate: AgentManagementReview | null;
  queued: AgentManagementReview[];
} {
  const [activate = null, ...remaining] = queued;
  return { activate, queued: remaining };
}

/**
 * Defers the trust decision until both ownership and channel membership have
 * initialized. A draft may open only when its owned sender and the owner share
 * the claimed originating channel.
 */
export function classifyAgentManagementOrigin(
  agents: readonly Pick<ManagedAgent, "pubkey">[] | undefined,
  channels:
    | readonly Pick<Channel, "id" | "isMember" | "memberPubkeys">[]
    | undefined,
  agentPubkey: string,
  channelId: string,
): "buffer" | "accept" | "reject" {
  if (agents === undefined || channels === undefined) return "buffer";
  const normalizedAgentPubkey = agentPubkey.toLowerCase();
  const isOwnedAgent = agents.some(
    (agent) => agent.pubkey.toLowerCase() === normalizedAgentPubkey,
  );
  const originChannel = channels.find((channel) => channel.id === channelId);
  return isOwnedAgent &&
    originChannel?.isMember === true &&
    originChannel.memberPubkeys.some(
      (pubkey) => pubkey.toLowerCase() === normalizedAgentPubkey,
    )
    ? "accept"
    : "reject";
}
