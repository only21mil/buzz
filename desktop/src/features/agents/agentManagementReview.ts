import type {
  AgentPersona,
  Channel,
  ManagedAgent,
  PersonaReviewContent,
} from "@/shared/api/types";
import { requestTargetsEditablePersona } from "./agentManagement";
import { classifyAgentManagementOrigin } from "./agentManagementBuffer";

/** Recheck the existing intake policy when an owner submits a review. */
export function assertAgentManagementReviewCurrent(input: {
  requestId: string;
  activeRequestId: string | null;
  agentPubkey: string | null;
  channelId: string;
  agents: readonly Pick<ManagedAgent, "pubkey">[] | undefined;
  channels:
    | readonly Pick<Channel, "id" | "isMember" | "memberPubkeys">[]
    | undefined;
}) {
  if (input.requestId !== input.activeRequestId) {
    throw new Error("This draft review is no longer active.");
  }
  if (
    !input.agentPubkey ||
    classifyAgentManagementOrigin(
      input.agents,
      input.channels,
      input.agentPubkey,
      input.channelId,
    ) !== "accept"
  ) {
    throw new Error(
      "Only an agent you still own can request changes from a channel you both belong to.",
    );
  }
}

/** Normalize optional fields and map ordering before comparing review content. */
export function agentManagementReviewContent(
  persona: AgentPersona,
): PersonaReviewContent {
  return {
    id: persona.id,
    displayName: persona.displayName,
    avatarUrl: persona.avatarUrl ?? null,
    systemPrompt: persona.systemPrompt,
    runtime: persona.runtime ?? null,
    model: persona.model ?? null,
    provider: persona.provider ?? null,
    namePool: [...(persona.namePool ?? [])],
    envVars: Object.fromEntries(
      Object.entries(persona.envVars ?? {}).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0,
      ),
    ),
    respondTo: persona.respondTo ?? null,
    respondToAllowlist: [...(persona.respondToAllowlist ?? [])],
    parallelism: persona.parallelism ?? null,
  };
}

/** Bind an update to the editable persona and revision shown to the owner. */
export function assertAgentManagementUpdateTarget(
  reviewed: AgentPersona | null,
  current: AgentPersona | undefined,
  submittedId: string,
) {
  if (
    !reviewed ||
    !requestTargetsEditablePersona(reviewed) ||
    !requestTargetsEditablePersona(current) ||
    reviewed.id !== submittedId ||
    current?.id !== submittedId ||
    reviewed.updatedAt !== current?.updatedAt ||
    reviewed.shared !== current?.shared ||
    JSON.stringify(agentManagementReviewContent(reviewed)) !==
      JSON.stringify(agentManagementReviewContent(current))
  ) {
    throw new Error(
      "This agent changed since the draft opened. Close this review and request a new draft.",
    );
  }
  return {
    expectedUpdatedAt: reviewed.updatedAt,
    expectedContent: agentManagementReviewContent(reviewed),
    expectedShared: reviewed.shared,
  };
}
