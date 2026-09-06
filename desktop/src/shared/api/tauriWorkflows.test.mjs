import assert from "node:assert/strict";
import test from "node:test";

const { parseRawTriggerWorkflowResponse } = await import("./tauriWorkflows.ts");

test("rejects an event_id-only trigger response", () => {
  assert.throws(
    () =>
      parseRawTriggerWorkflowResponse({
        event_id: "trigger-event",
      }),
    /invalid trigger_workflow response/,
  );
});

test("preserves the relay run id in an accepted trigger response", () => {
  assert.deepEqual(
    parseRawTriggerWorkflowResponse({
      event_id: "trigger-event",
      workflow_id: "workflow-id",
      run_id: "run-id",
      status: "accepted",
    }),
    {
      event_id: "trigger-event",
      workflow_id: "workflow-id",
      run_id: "run-id",
      status: "accepted",
    },
  );
});

const { parseWorkflowRunsPage, parseWorkflowApprovals } = await import(
  "./tauriWorkflows.ts"
);
const run = {
  id: "run",
  workflow_id: "workflow",
  status: "resume_pending",
  current_step: 2,
  execution_trace: [{ step_id: "gate", status: "waiting_approval" }],
  started_at: 1,
  completed_at: null,
  error_message: null,
  created_at: 1,
};

test("legacy history arrays retain resume_pending and nullable error code", () => {
  const page = parseWorkflowRunsPage([run]);
  assert.equal(page.next, null);
  assert.equal(page.runs[0].status, "resume_pending");
  assert.equal(page.runs[0].errorCode, null);
  assert.deepEqual(page.runs[0].executionTrace[0].output, {});
});
test("paged history preserves cursor precision and structured error", () => {
  const next = { before: "2026-09-06T11:00:00.123456Z", before_id: "run" };
  const page = parseWorkflowRunsPage({
    runs: [{ ...run, status: "failed", error_code: "step_timeout" }],
    next,
  });
  assert.deepEqual(page.next, next);
  assert.equal(page.runs[0].errorCode, "step_timeout");
});
test("malformed history envelope and status fail instead of becoming empty history", () => {
  for (const value of [
    null,
    {},
    { runs: [] },
    { runs: [], next: {} },
    [{ ...run, status: "invented" }],
  ]) {
    assert.throws(() => parseWorkflowRunsPage(value), /invalid workflow/);
  }
});
test("durable and legacy evidence is display-only and rejects decision-token shapes", () => {
  const approval = {
    approval_ref: "public-reference",
    workflow_id: "workflow",
    run_id: "run",
    step_id: "gate",
    step_index: 2,
    approver_spec: "owner",
    status: "granted",
    approver_pubkey: null,
    note: null,
    expires_at: "2026-09-06T00:00:00Z",
    created_at: 1,
  };
  assert.equal(
    parseWorkflowApprovals({ approvals: [approval] })[0].approvalRef,
    "public-reference",
  );
  assert.equal(
    parseWorkflowApprovals({ approvals: [approval] })[0].status,
    "granted",
  );
  assert.equal("token" in parseWorkflowApprovals([approval])[0], false);
  assert.throws(
    () => parseWorkflowApprovals([{ ...approval, token: "hash" }]),
    /display reference/,
  );
  assert.throws(
    () => parseWorkflowApprovals([{ ...approval, approval_ref: undefined }]),
    /display reference/,
  );
});
test("duplicate accepted trigger preserves original event and null run", () => {
  assert.deepEqual(
    parseRawTriggerWorkflowResponse({
      event_id: "original",
      workflow_id: "workflow",
      run_id: null,
      status: "accepted",
    }),
    {
      event_id: "original",
      workflow_id: "workflow",
      run_id: null,
      status: "accepted",
    },
  );
});
