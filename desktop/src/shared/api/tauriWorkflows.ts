import { invokeTauri } from "@/shared/api/tauri";
import type {
  ApprovalActionResponse,
  TriggerWorkflowResponse,
  Workflow,
  WorkflowApproval,
  WorkflowRun,
  WorkflowRunsCursor,
  WorkflowRunsPage,
  WorkflowSaveResult,
  TraceEntry,
} from "@/shared/api/types";

// ── Raw types (snake_case from backend) ───────────────────────────────────

type RawWorkflow = {
  id: string;
  name: string;
  owner_pubkey: string;
  channel_id: string | null;
  definition: Record<string, unknown>;
  status: Workflow["status"];
  created_at: number;
  updated_at: number;
};

type RawWorkflowSaveResponse = RawWorkflow & {
  webhook_secret?: string | null;
};

type RawTraceEntry = {
  step_id: string;
  status: string;
  output?: Record<string, unknown>;
  started_at?: number | null;
  completed_at?: number | null;
  error?: string | null;
};

type RawWorkflowRun = {
  id: string;
  workflow_id: string;
  status: WorkflowRun["status"];
  current_step: number | null;
  execution_trace: RawTraceEntry[];
  started_at: number | null;
  completed_at: number | null;
  error_code?: string | null;
  error_message: string | null;
  created_at: number;
};

type RawWorkflowApproval = {
  approval_ref: string;
  workflow_id: string;
  run_id: string;
  step_id: string;
  step_index: number;
  approver_spec: string;
  status: WorkflowApproval["status"];
  approver_pubkey: string | null;
  note: string | null;
  expires_at: string;
  created_at: number;
};

type RawTriggerWorkflowResponse = {
  event_id: string;
  run_id: string | null;
  workflow_id: string;
  status: "accepted";
};

/**
 * Validate the Rust trigger acknowledgement at the API boundary.
 *
 * `invokeTauri<T>` only provides a compile-time assertion. Keep this runtime
 * check here so a stale or malformed relay response cannot turn into an
 * object full of `undefined` fields in the UI.
 */
export function parseRawTriggerWorkflowResponse(
  value: unknown,
): RawTriggerWorkflowResponse {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid trigger_workflow response");
  }

  const raw = value as Record<string, unknown>;
  const eventId =
    typeof raw.event_id === "string" && raw.event_id.length > 0
      ? raw.event_id
      : undefined;
  const workflowId =
    typeof raw.workflow_id === "string" && raw.workflow_id.length > 0
      ? raw.workflow_id
      : undefined;
  const runId =
    raw.run_id === null
      ? null
      : typeof raw.run_id === "string" && raw.run_id.length > 0
        ? raw.run_id
        : undefined;

  if (
    eventId === undefined ||
    workflowId === undefined ||
    runId === undefined
  ) {
    throw new Error("invalid trigger_workflow response");
  }
  if (raw.status !== "accepted") {
    throw new Error("invalid trigger_workflow response status");
  }

  return {
    event_id: eventId,
    run_id: runId,
    workflow_id: workflowId,
    status: "accepted",
  };
}

type RawApprovalActionResponse = {
  token: string;
  status: string;
  run_id: string;
  workflow_id: string;
};

// ── Conversion functions ──────────────────────────────────────────────────

function fromRawWorkflow(raw: RawWorkflow): Workflow {
  return {
    id: raw.id,
    name: raw.name,
    ownerPubkey: raw.owner_pubkey,
    channelId: raw.channel_id,
    definition: raw.definition,
    status: raw.status,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

function fromRawWorkflowSave(raw: RawWorkflowSaveResponse): WorkflowSaveResult {
  return {
    workflow: fromRawWorkflow(raw),
    webhookSecret: raw.webhook_secret ?? null,
  };
}

function fromRawTraceEntry(raw: RawTraceEntry): TraceEntry {
  return {
    stepId: raw.step_id,
    status: raw.status,
    output: raw.output ?? {},
    startedAt: raw.started_at ?? null,
    completedAt: raw.completed_at ?? null,
    error: raw.error ?? null,
  };
}

function fromRawWorkflowRun(raw: RawWorkflowRun): WorkflowRun {
  return {
    id: raw.id,
    workflowId: raw.workflow_id,
    status: raw.status,
    currentStep: raw.current_step,
    executionTrace: raw.execution_trace.map(fromRawTraceEntry),
    startedAt: raw.started_at,
    completedAt: raw.completed_at,
    errorCode: raw.error_code ?? null,
    errorMessage: raw.error_message,
    createdAt: raw.created_at,
  };
}

export function fromRawApproval(raw: RawWorkflowApproval): WorkflowApproval {
  return {
    approvalRef: raw.approval_ref,
    workflowId: raw.workflow_id,
    runId: raw.run_id,
    stepId: raw.step_id,
    stepIndex: raw.step_index,
    approverSpec: raw.approver_spec,
    status: raw.status,
    approverPubkey: raw.approver_pubkey,
    note: raw.note,
    expiresAt: raw.expires_at,
    createdAt: raw.created_at,
  };
}

function fromRawTriggerResponse(
  raw: RawTriggerWorkflowResponse,
): TriggerWorkflowResponse {
  return {
    eventId: raw.event_id,
    runId: raw.run_id,
    workflowId: raw.workflow_id,
    status: raw.status,
  };
}

function fromRawApprovalResponse(
  raw: RawApprovalActionResponse,
): ApprovalActionResponse {
  return {
    token: raw.token,
    status: raw.status,
    runId: raw.run_id,
    workflowId: raw.workflow_id,
  };
}

// ── Tauri invoke wrappers ─────────────────────────────────────────────────

export async function getChannelWorkflows(
  channelId: string,
): Promise<Workflow[]> {
  const raw = await invokeTauri<RawWorkflow[]>("get_channel_workflows", {
    channelId,
  });
  return raw.map(fromRawWorkflow);
}

/**
 * Fetch workflows across many channels in a single relay round-trip.
 *
 * Replaces the per-channel `Promise.all(getChannelWorkflows)` fanout on the
 * Workflows overview: the backend `#h` filter matches any listed channel, and
 * each returned workflow carries its own `channelId` so callers can group.
 */
export async function getChannelsWorkflows(
  channelIds: string[],
): Promise<Workflow[]> {
  const raw = await invokeTauri<RawWorkflow[]>("get_channels_workflows", {
    channelIds,
  });
  return raw.map(fromRawWorkflow);
}

export async function getWorkflow(workflowId: string): Promise<Workflow> {
  const raw = await invokeTauri<RawWorkflow>("get_workflow", { workflowId });
  return fromRawWorkflow(raw);
}

export async function createWorkflow(
  channelId: string,
  yamlDefinition: string,
): Promise<WorkflowSaveResult> {
  const raw = await invokeTauri<RawWorkflowSaveResponse>("create_workflow", {
    channelId,
    yamlDefinition,
  });
  return fromRawWorkflowSave(raw);
}

export async function updateWorkflow(
  workflowId: string,
  yamlDefinition: string,
): Promise<WorkflowSaveResult> {
  const raw = await invokeTauri<RawWorkflowSaveResponse>("update_workflow", {
    workflowId,
    yamlDefinition,
  });
  return fromRawWorkflowSave(raw);
}

export async function deleteWorkflow(workflowId: string): Promise<void> {
  await invokeTauri("delete_workflow", { workflowId });
}

/** Accept both the legacy array and the additive page envelope. */
export function parseWorkflowRunsPage(value: unknown): WorkflowRunsPage {
  const envelope = Array.isArray(value) ? { runs: value, next: null } : value;
  if (typeof envelope !== "object" || envelope === null)
    throw new Error("invalid workflow runs response");
  const raw = envelope as Record<string, unknown>;
  if (
    !Array.isArray(raw.runs) ||
    !(
      raw.next === null ||
      (typeof raw.next === "object" &&
        raw.next !== null &&
        typeof (raw.next as Record<string, unknown>).before === "string" &&
        typeof (raw.next as Record<string, unknown>).before_id === "string")
    )
  ) {
    throw new Error("invalid workflow runs response");
  }
  for (const run of raw.runs) {
    if (
      typeof run !== "object" ||
      run === null ||
      typeof run.id !== "string" ||
      typeof run.workflow_id !== "string" ||
      ![
        "pending",
        "running",
        "waiting_approval",
        "resume_pending",
        "completed",
        "failed",
        "cancelled",
      ].includes(run.status) ||
      !Array.isArray(run.execution_trace)
    )
      throw new Error("invalid workflow run response");
  }
  return {
    runs: (raw.runs as RawWorkflowRun[]).map(fromRawWorkflowRun),
    next: raw.next as WorkflowRunsCursor | null,
  };
}

export async function getWorkflowRuns(
  workflowId: string,
  limit?: number,
): Promise<WorkflowRun[]> {
  return parseWorkflowRunsPage(
    await invokeTauri<unknown>("get_workflow_runs", {
      workflowId,
      limit: limit ?? null,
    }),
  ).runs;
}

export async function getWorkflowRunsPage(
  workflowId: string,
  cursor: WorkflowRunsCursor | null = null,
  limit = 20,
): Promise<WorkflowRunsPage> {
  return parseWorkflowRunsPage(
    await invokeTauri<unknown>("get_workflow_runs", {
      workflowId,
      limit,
      page: true,
      before: cursor?.before ?? null,
      beforeId: cursor?.before_id ?? null,
    }),
  );
}

export function parseWorkflowApprovals(value: unknown): WorkflowApproval[] {
  const rows = Array.isArray(value)
    ? value
    : typeof value === "object" && value !== null
      ? (value as Record<string, unknown>).approvals
      : null;
  if (!Array.isArray(rows))
    throw new Error("invalid workflow approvals response");
  return rows.map((row) => {
    if (
      typeof row !== "object" ||
      row === null ||
      typeof row.approval_ref !== "string" ||
      "token" in row
    ) {
      throw new Error("invalid workflow approval display reference");
    }
    return fromRawApproval(row as RawWorkflowApproval);
  });
}

export async function getRunApprovals(
  workflowId: string,
  runId: string,
): Promise<WorkflowApproval[]> {
  const raw = await invokeTauri<unknown>("get_run_approvals", {
    workflowId,
    runId,
  });
  return parseWorkflowApprovals(raw);
}

export async function triggerWorkflow(
  workflowId: string,
): Promise<TriggerWorkflowResponse> {
  const raw = parseRawTriggerWorkflowResponse(
    await invokeTauri<unknown>("trigger_workflow", { workflowId }),
  );
  return fromRawTriggerResponse(raw);
}

export async function grantApproval(
  token: string,
  note?: string,
): Promise<ApprovalActionResponse> {
  const raw = await invokeTauri<RawApprovalActionResponse>("grant_approval", {
    token,
    note: note ?? null,
  });
  return fromRawApprovalResponse(raw);
}

export async function denyApproval(
  token: string,
  note?: string,
): Promise<ApprovalActionResponse> {
  const raw = await invokeTauri<RawApprovalActionResponse>("deny_approval", {
    token,
    note: note ?? null,
  });
  return fromRawApprovalResponse(raw);
}
