import type { RelayEvent } from "@/shared/api/types";
import type { RelayHistoryFilters } from "@/shared/api/relayClientShared";
import { verifyEvent } from "nostr-tools/pure";
import type { BrowserIdentityManager } from "./identity";
import { register, type InvokeBody } from "./registry";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const REQUEST_KEYS = new Set([
  "class",
  "timeout_seconds",
  "approval_id",
  "community_id",
  "channel_id",
  "workflow_id",
  "run_id",
  "definition_hash",
  "step_id",
  "step_index",
  "generation",
  "action_summary",
  "expires_at",
  "tags",
]);

type ApprovalClient = {
  fetchEvents(filter: RelayHistoryFilters): Promise<RelayEvent[]>;
  publishEvent(
    event: RelayEvent,
    timeoutMessage: string,
    errorMessage: string,
  ): Promise<RelayEvent>;
};

type ApprovalWire = {
  token: string;
  workflow_id: string;
  run_id: string;
  step_id: string;
  step_index: number;
  approver_spec: string;
  status: "pending";
  approver_pubkey: null;
  note: null;
  expires_at: string;
  created_at: number;
};

function objectBody(
  body: InvokeBody,
  command: string,
): Record<string, unknown> {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body;
}

function requiredString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string")
    throw new TypeError(`${field} must be a string`);
  return value;
}

function parseRequestContent(
  event: RelayEvent,
  signerPubkey: string,
): ApprovalWire {
  let parsed: unknown;
  try {
    parsed = JSON.parse(event.content) as unknown;
  } catch {
    throw new Error("Invalid workflow approval schema: content is not JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      "Invalid workflow approval schema: content must be an object",
    );
  }
  const value = parsed as Record<string, unknown>;
  if (
    Object.keys(value).some((key) => !REQUEST_KEYS.has(key)) ||
    REQUEST_KEYS.size !== Object.keys(value).length
  ) {
    throw new Error(
      "Invalid workflow approval schema: unexpected request fields",
    );
  }
  const approvalId = value.approval_id;
  const workflowId = value.workflow_id;
  const runId = value.run_id;
  const stepId = value.step_id;
  const stepIndex = value.step_index;
  const expiresAt = value.expires_at;
  const timeoutSeconds = value.timeout_seconds;
  const tags = value.tags;
  const eventTargetsSigner = event.tags.some(
    (tag) => tag[0] === "p" && tag[1] === signerPubkey,
  );
  const eventChannel = event.tags.find((tag) => tag[0] === "h")?.[1];
  const payloadTagsMatch =
    Array.isArray(tags) &&
    tags.some(
      (tag) => Array.isArray(tag) && tag[0] === "p" && tag[1] === signerPubkey,
    ) &&
    tags.some(
      (tag) => Array.isArray(tag) && tag[0] === "h" && tag[1] === eventChannel,
    );
  if (
    event.kind !== 46010 ||
    !verifyEvent(event) ||
    value.class !== "approval_requested" ||
    typeof approvalId !== "string" ||
    !UUID.test(approvalId) ||
    typeof workflowId !== "string" ||
    !UUID.test(workflowId) ||
    typeof runId !== "string" ||
    !UUID.test(runId) ||
    typeof value.channel_id !== "string" ||
    value.channel_id !== eventChannel ||
    typeof value.community_id !== "string" ||
    !UUID.test(value.community_id) ||
    typeof value.definition_hash !== "string" ||
    !HEX_64.test(value.definition_hash) ||
    typeof stepId !== "string" ||
    stepId.length === 0 ||
    !Number.isSafeInteger(stepIndex) ||
    Number(stepIndex) < 0 ||
    !Number.isSafeInteger(value.generation) ||
    Number(value.generation) < 1 ||
    typeof value.action_summary !== "string" ||
    value.action_summary.length === 0 ||
    typeof expiresAt !== "string" ||
    Number.isNaN(Date.parse(expiresAt)) ||
    !Number.isSafeInteger(timeoutSeconds) ||
    Number(timeoutSeconds) < 1 ||
    !eventTargetsSigner ||
    !payloadTagsMatch
  ) {
    throw new Error("Invalid workflow approval schema: malformed request");
  }
  return {
    token: approvalId,
    workflow_id: workflowId,
    run_id: runId,
    step_id: stepId,
    step_index: Number(stepIndex),
    approver_spec: "Current channel approval policy",
    status: "pending",
    approver_pubkey: null,
    note: null,
    expires_at: expiresAt,
    created_at: event.created_at,
  };
}

export function parseApprovalRequests(
  events: RelayEvent[],
  signerPubkey: string,
  workflowId: string,
  runId: string,
): ApprovalWire[] {
  const accepted: ApprovalWire[] = [];
  for (const event of events) {
    try {
      accepted.push(parseRequestContent(event, signerPubkey));
    } catch {
      // Relay history is hostile input. One malformed or drifted event must
      // not suppress other independently valid approval requests.
    }
  }
  return accepted
    .filter(
      (approval) =>
        approval.workflow_id === workflowId && approval.run_id === runId,
    )
    .sort((left, right) => right.created_at - left.created_at);
}

function parseSignedEvent(value: string): RelayEvent {
  const event = JSON.parse(value) as RelayEvent;
  if (
    !event ||
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    typeof event.sig !== "string"
  ) {
    throw new Error("Browser identity returned an invalid approval event");
  }
  return event;
}

export function registerWorkflowApprovalCommands(
  identity: BrowserIdentityManager,
  client: ApprovalClient,
): void {
  const active = new Map<string, ApprovalWire>();
  const decided = new Set<string>();

  register("get_run_approvals", async (body) => {
    const input = objectBody(body, "get_run_approvals");
    const workflowId = requiredString(input, "workflowId");
    const runId = requiredString(input, "runId");
    if (!UUID.test(workflowId) || !UUID.test(runId)) {
      throw new TypeError("workflowId and runId must be canonical UUIDs");
    }
    const pubkey = identity.pubkey();
    const approvals = parseApprovalRequests(
      await client.fetchEvents({
        kinds: [46010],
        "#p": [pubkey],
        limit: 200,
      }),
      pubkey,
      workflowId,
      runId,
    ).filter((approval) => !decided.has(approval.token));
    active.clear();
    for (const approval of approvals) active.set(approval.token, approval);
    return approvals;
  });

  const decide = async (body: InvokeBody, granted: boolean) => {
    const input = objectBody(
      body,
      granted ? "grant_approval" : "deny_approval",
    );
    const approvalId = requiredString(input, "token");
    const approval = active.get(approvalId);
    if (!approval || !UUID.test(approvalId)) {
      throw new Error("Approval is not in the active browser scope");
    }
    const rawNote = input.note;
    if (
      rawNote !== undefined &&
      rawNote !== null &&
      typeof rawNote !== "string"
    ) {
      throw new TypeError("note must be a string or null");
    }
    const note = typeof rawNote === "string" ? rawNote.trim() : "";
    if (!granted && !note) throw new Error("A denial note is required");
    const event = parseSignedEvent(
      identity.sign({
        kind: granted ? 46030 : 46031,
        tags: [["d", approvalId]],
        content: JSON.stringify({
          decision: granted ? "grant" : "deny",
          note: note || null,
        }),
      }),
    );
    await client.publishEvent(
      event,
      "Timed out while submitting the approval decision.",
      "Failed while submitting the approval decision.",
    );
    active.delete(approvalId);
    decided.add(approvalId);
    return {
      token: approvalId,
      status: granted ? "granted" : "denied",
      run_id: approval.run_id,
      workflow_id: approval.workflow_id,
    };
  };

  register("grant_approval", (body) => decide(body, true));
  register("deny_approval", (body) => decide(body, false));
}
