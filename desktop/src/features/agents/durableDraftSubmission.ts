import {
  agentDraftApply,
  agentDraftPrepare,
  type DraftAction,
  type DraftScope,
} from "@/shared/api/tauriAgentDrafts";
import type {
  AcpRuntime,
  AgentPersona,
  CreateManagedAgentInput,
  CreatePersonaInput,
  UpdatePersonaInput,
} from "@/shared/api/types";
import type { AgentManagementRequest } from "./agentManagement";
import {
  agentManagementReviewContent,
  assertAgentManagementUpdateTarget,
} from "./agentManagementReview";
import { draftPersonaForInstance } from "./durableDraftReview";
import {
  buildInstanceInputForDefinition,
  resolveStartRuntimeForDefinition,
  type BackendIntent,
} from "./lib/instanceInputForDefinition";

/** The explicit submit transaction. All mutations and publication belong to native apply. */
export async function submitDurableDraft(args: {
  scope: DraftScope;
  requestEventId: string;
  request: AgentManagementRequest;
  action: Exclude<DraftAction, "reject">;
  input: CreatePersonaInput | UpdatePersonaInput;
  reviewed: AgentPersona | null;
  backend: BackendIntent | null;
  currentPersona: () => AgentPersona | undefined;
  availableRuntimes: () => Promise<AcpRuntime[]>;
  assertAvailable: () => void;
  assertCurrent: () => void;
}) {
  // Copy before any asynchronous work so the claim binds to the actual click.
  const input = structuredClone(args.input);
  const backend = structuredClone(args.backend);
  const reviewed = args.reviewed ? structuredClone(args.reviewed) : null;
  args.assertAvailable();
  if (args.request.action === "update") {
    if (!("id" in input) || !reviewed || args.action !== "save")
      throw new Error("This update does not match the reviewed target.");
    Object.assign(
      input,
      assertAgentManagementUpdateTarget(
        reviewed,
        args.currentPersona(),
        input.id,
      ),
    );
  } else if ("id" in input)
    throw new Error("A new draft cannot overwrite an existing agent.");
  let instanceInput: CreateManagedAgentInput | null = null;
  if (args.action === "create" || args.action === "start") {
    const persona = draftPersonaForInstance(input, args.request.requestId);
    const available = await args.availableRuntimes();
    const { runtime } = resolveStartRuntimeForDefinition(persona, available);
    instanceInput = await buildInstanceInputForDefinition(
      persona,
      runtime,
      async () => {
        throw new Error(
          "Upload the selected avatar before submitting this draft.",
        );
      },
      backend ?? undefined,
    );
    instanceInput.spawnAfterCreate = args.action === "start";
    instanceInput.startOnAppLaunch = false;
  }
  args.assertAvailable();
  if (reviewed && "id" in input)
    assertAgentManagementUpdateTarget(
      reviewed,
      args.currentPersona(),
      input.id,
    );
  await agentDraftPrepare({
    ...args.scope,
    requestEventId: args.requestEventId,
    action: args.action,
    input,
    expectedContent: reviewed ? agentManagementReviewContent(reviewed) : null,
    instanceInput,
    publishShared: reviewed?.shared === true,
  });
  args.assertCurrent();
  return agentDraftApply(args.scope, args.requestEventId);
}
