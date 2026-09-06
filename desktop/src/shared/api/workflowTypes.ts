export type WorkflowStatus = "active" | "disabled" | "archived";

export type Workflow = {
  id: string;
  revision: string;
  name: string;
  ownerPubkey: string;
  channelId: string | null;
  definition: Record<string, unknown>;
  yamlDefinition?: string;
  status: WorkflowStatus;
  createdAt: number;
  updatedAt: number;
};

export type WorkflowSaveResult = {
  workflow: Workflow;
  webhookSecret: string | null;
};

export type WorkflowRunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "waiting_approval"
  | "resume_pending";

export type TraceEntry = {
  stepId: string;
  status: string;
  output: Record<string, unknown>;
  startedAt: number | null;
  completedAt: number | null;
  error: string | null;
};

export type WorkflowRun = {
  id: string;
  workflowId: string;
  status: WorkflowRunStatus;
  currentStep: number | null;
  executionTrace: TraceEntry[];
  startedAt: number | null;
  completedAt: number | null;
  errorCode?: string | null;
  errorMessage: string | null;
  createdAt: number;
};

export type WorkflowApprovalStatus =
  | "pending"
  | "granted"
  | "denied"
  | "expired"
  | "unsatisfiable";

export type WorkflowApproval = {
  /** Display reference only; never a signed decision token. */
  approvalRef: string;
  workflowId: string;
  runId: string;
  stepId: string;
  stepIndex: number;
  approverSpec: string;
  status: WorkflowApprovalStatus;
  approverPubkey: string | null;
  note: string | null;
  expiresAt: string;
  createdAt: number;
};

export type TriggerWorkflowResponse = {
  eventId: string;
  runId: string | null;
  workflowId: string;
  status: "accepted";
};

export type ApprovalActionResponse = {
  token: string;
  status: string;
  runId: string;
  workflowId: string;
};

/** Opaque keyset returned by the relay; preserve timestamp precision. */
export type WorkflowRunsCursor = { before: string; before_id: string };
export type WorkflowRunsPage = {
  runs: WorkflowRun[];
  next: WorkflowRunsCursor | null;
};
