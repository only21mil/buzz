import type {
  AgentPersona,
  Channel,
  CreatePersonaInput,
  ManagedAgent,
} from "@/shared/api/types";
import type { DurableDraftItem } from "./durableDraftQueue";
import { classifyAgentManagementOrigin } from "./agentManagementBuffer";

/** Retention does not broaden the existing managed-agent/shared-channel gate. */
export function draftUnavailableReason(
  item: DurableDraftItem,
  agents: ManagedAgent[] | undefined,
  channels: Channel[] | undefined,
): string | null {
  if (item.unavailable || !item.request)
    return item.unavailable ?? "Draft content is unavailable.";
  const eligibility = classifyAgentManagementOrigin(
    agents,
    channels,
    item.event.pubkey,
    item.request.request.channelId,
  );
  if (eligibility === "buffer")
    return "Checking managed agent and channel membership.";
  if (eligibility === "reject")
    return "Unavailable: the sender must be a registered managed agent in a channel you both belong to.";
  return null;
}

/** A temporary definition used only to construct reviewed instance input, never persisted. */
export function draftPersonaForInstance(
  input: CreatePersonaInput,
  requestId: string,
): AgentPersona {
  return {
    id: requestId,
    displayName: input.displayName,
    systemPrompt: input.systemPrompt,
    avatarUrl: input.avatarUrl ?? null,
    runtime: input.runtime ?? null,
    model: input.model ?? null,
    provider: input.provider ?? null,
    namePool: input.namePool ?? [],
    envVars: input.envVars ?? {},
    isBuiltIn: false,
    isActive: true,
    shared: false,
    respondTo: input.behavior?.respondTo ?? null,
    respondToAllowlist: input.behavior?.respondToAllowlist ?? [],
    parallelism: input.behavior?.parallelism ?? null,
    createdAt: "",
    updatedAt: "",
  };
}

export function draftStatusLabel(item: DurableDraftItem): string {
  const operation = item.operation;
  if (
    !operation ||
    operation.state === "prepared" ||
    operation.state === "claimed"
  ) {
    if (item.decision === "applied") return "Applied on an owner device";
    if (item.decision === "rejected") return "Rejected";
  }
  if (operation) {
    if (operation.state === "uncertain")
      return "Result uncertain. Check the existing instance before taking further action.";
    if (operation.state === "saved")
      return "Saved locally; publication or completion is pending.";
    if (operation.state === "applied")
      return operation.action === "start"
        ? "Started"
        : operation.action === "create"
          ? "Created stopped"
          : "Saved";
    if (operation.state === "rejected") return "Rejected";
    return "Approved action retained; completion pending.";
  }
  if (item.decision === "applied") return "Applied on an owner device";
  if (item.decision === "rejected") return "Rejected";
  if (item.decision === "applying") return "Claimed by an owner device";
  return "Awaiting owner review";
}

/** A terminal owner decision closes any competing locally prepared approval. */
export function draftCanResume(item: DurableDraftItem): boolean {
  if (item.operation?.state === "saved") return true;
  return (
    (item.operation?.state === "prepared" ||
      item.operation?.state === "claimed") &&
    item.decision !== "applied" &&
    item.decision !== "rejected"
  );
}
