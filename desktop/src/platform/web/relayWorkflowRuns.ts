import { nip98Fetch } from "./nip98";
import { dispatch, register, type InvokeBody } from "./registry";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUN_STATUSES = new Set([
  "pending",
  "running",
  "waiting_approval",
  "resume_pending",
  "completed",
  "failed",
  "cancelled",
]);
const RUN_KEYS = new Set([
  "id",
  "workflow_id",
  "status",
  "current_step",
  "execution_trace",
  "error_message",
  "started_at",
  "completed_at",
  "created_at",
]);
const TRACE_KEYS = new Set([
  "step_id",
  "step_index",
  "status",
  "started_at",
  "completed_at",
  "error",
]);

type WorkflowRunRequest = Parameters<typeof nip98Fetch>[0];
type WorkflowRunFetcher = (request: WorkflowRunRequest) => Promise<Response>;

type WorkflowRunDependencies = {
  fetcher?: WorkflowRunFetcher;
  relayHttpUrl?: () => Promise<string>;
};

function objectBody(body: InvokeBody): Record<string, unknown> {
  if (
    body === undefined ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError("get_workflow_runs requires an object body");
  }
  return body;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`Invalid workflow run schema: unexpected ${label} field`);
    }
  }
}

function nullableInteger(value: unknown): value is number | null {
  return value === null || (Number.isSafeInteger(value) && Number(value) >= 0);
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function parseTraceEntry(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      "Invalid workflow run schema: trace entry must be an object",
    );
  }
  const entry = value as Record<string, unknown>;
  exactKeys(entry, TRACE_KEYS, "trace");
  if (
    typeof entry.step_id !== "string" ||
    entry.step_id.length === 0 ||
    typeof entry.status !== "string" ||
    entry.status.length === 0 ||
    (entry.step_index !== undefined &&
      (!Number.isSafeInteger(entry.step_index) ||
        Number(entry.step_index) < 0)) ||
    (entry.started_at !== undefined && !nullableInteger(entry.started_at)) ||
    (entry.completed_at !== undefined &&
      !nullableInteger(entry.completed_at)) ||
    (entry.error !== undefined && !nullableString(entry.error))
  ) {
    throw new Error("Invalid workflow run schema: malformed trace entry");
  }
  return entry;
}

function parseRun(
  value: unknown,
  expectedWorkflowId: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid workflow run schema: run must be an object");
  }
  const run = value as Record<string, unknown>;
  exactKeys(run, RUN_KEYS, "run");
  if (
    typeof run.id !== "string" ||
    !UUID.test(run.id) ||
    run.workflow_id !== expectedWorkflowId ||
    typeof run.status !== "string" ||
    !RUN_STATUSES.has(run.status) ||
    !nullableInteger(run.current_step) ||
    !Array.isArray(run.execution_trace) ||
    !nullableString(run.error_message) ||
    !nullableInteger(run.started_at) ||
    !nullableInteger(run.completed_at) ||
    !Number.isSafeInteger(run.created_at) ||
    Number(run.created_at) < 0
  ) {
    throw new Error("Invalid workflow run schema: malformed run");
  }
  return {
    ...run,
    execution_trace: run.execution_trace.map(parseTraceEntry),
  };
}

export function parseWorkflowRunsResponse(
  value: unknown,
  expectedWorkflowId: string,
): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    throw new Error("Invalid workflow run schema: expected an array");
  }
  return value.map((run) => parseRun(run, expectedWorkflowId));
}

export async function getBrowserWorkflowRuns(
  body: InvokeBody,
  dependencies: WorkflowRunDependencies = {},
): Promise<Array<Record<string, unknown>>> {
  const input = objectBody(body);
  const workflowId = input.workflowId;
  if (typeof workflowId !== "string" || !UUID.test(workflowId)) {
    throw new TypeError("workflowId must be a UUID");
  }
  const limit = input.limit;
  if (
    limit !== undefined &&
    limit !== null &&
    (!Number.isInteger(limit) || Number(limit) < 1 || Number(limit) > 100)
  ) {
    throw new TypeError("limit must be an integer from 1 through 100");
  }

  const relayHttpUrl = dependencies.relayHttpUrl
    ? await dependencies.relayHttpUrl()
    : await dispatch<string>("get_relay_http_url");
  const url = new URL(
    `workflows/${encodeURIComponent(workflowId)}/runs`,
    `${relayHttpUrl.replace(/\/$/, "")}/`,
  );
  if (typeof limit === "number") url.searchParams.set("limit", String(limit));

  const response = await (dependencies.fetcher ?? nip98Fetch)({
    url: url.toString(),
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Workflow history request failed (${response.status})`);
  }

  let value: unknown;
  try {
    value = (await response.json()) as unknown;
  } catch {
    throw new Error("Invalid workflow run schema: response is not JSON");
  }
  return parseWorkflowRunsResponse(value, workflowId);
}

export function registerWorkflowRunCommands(
  dependencies: WorkflowRunDependencies = {},
): void {
  register("get_workflow_runs", (body) =>
    getBrowserWorkflowRuns(body, dependencies),
  );
}
