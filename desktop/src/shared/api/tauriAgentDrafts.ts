import { invokeTauri } from "./tauri";
import { fromRawPersona, type RawPersona } from "./tauriPersonas";
import type {
  AgentPersona,
  CreateManagedAgentInput,
  CreatePersonaInput,
  RelayEvent,
  PersonaReviewContent,
  UpdatePersonaInput,
} from "./types";

export type DraftScope = { owner: string; relayUrl: string };
export type DraftAction = "save" | "create" | "start" | "reject";
export type DraftOperation = {
  requestEventId: string;
  targetId: string;
  action: DraftAction;
  state:
    | "prepared"
    | "claimed"
    | "saved"
    | "applied"
    | "rejected"
    | "uncertain";
  claimEvent: RelayEvent;
  outcomeEvent?: RelayEvent | null;
  persona?: AgentPersona | null;
  error?: string | null;
  input: CreatePersonaInput | UpdatePersonaInput | null;
  instanceInput: CreateManagedAgentInput | null;
  publishShared: boolean;
};
type RawDraftOperation = Omit<DraftOperation, "persona"> & {
  persona?: RawPersona | null;
};
export type DraftQueue = { events: RelayEvent[]; operations: DraftOperation[] };
export type DraftPrepare = DraftScope & {
  requestEventId: string;
  action: DraftAction;
  input: CreatePersonaInput | UpdatePersonaInput | null;
  expectedContent: PersonaReviewContent | null;
  instanceInput: CreateManagedAgentInput | null;
  publishShared: boolean;
};

function operationFromRaw(operation: RawDraftOperation): DraftOperation {
  return {
    ...operation,
    persona: operation.persona ? fromRawPersona(operation.persona) : null,
  };
}

/** Read retained ciphertext and operations without replaying approved effects. */
export async function agentDraftQueue(scope: DraftScope): Promise<DraftQueue> {
  const queue = await invokeTauri<{
    events: RelayEvent[];
    operations: RawDraftOperation[];
  }>("agent_draft_queue", scope);
  return { ...queue, operations: queue.operations.map(operationFromRaw) };
}

/** Verify and retain a relay event in its original owner/community scope. */
export async function agentDraftReceive(
  scope: DraftScope,
  event: RelayEvent,
): Promise<void> {
  await invokeTauri("agent_draft_receive", { ...scope, event });
}

/** Exhaustive keyset history, including multiple pages within one second. */
export async function agentDraftBackfill(
  scope: DraftScope,
  cursor: { until?: number; beforeId?: string; limit: number },
): Promise<RelayEvent[]> {
  return invokeTauri<RelayEvent[]>("agent_draft_backfill", {
    ...scope,
    ...cursor,
  });
}

/** Journal the exact explicitly reviewed action before obtaining its claim. */
export async function agentDraftPrepare(
  input: DraftPrepare,
): Promise<DraftOperation> {
  return operationFromRaw(
    await invokeTauri<RawDraftOperation>("agent_draft_prepare", input),
  );
}

/** Explicitly apply the retained action; native code owns claim and effect idempotency. */
export async function agentDraftApply(
  scope: DraftScope,
  requestEventId: string,
): Promise<DraftOperation> {
  return operationFromRaw(
    await invokeTauri<RawDraftOperation>("agent_draft_apply", {
      ...scope,
      requestEventId,
    }),
  );
}

/** Explicitly retry retained publication/outcome bytes, never create or start again. */
export async function agentDraftConfirm(
  scope: DraftScope,
  requestEventId: string,
): Promise<DraftOperation> {
  return operationFromRaw(
    await invokeTauri<RawDraftOperation>("agent_draft_confirm", {
      ...scope,
      requestEventId,
    }),
  );
}
