import assert from "node:assert/strict";
import test from "node:test";

const { fromRawApproval, parseRawTriggerWorkflowResponse } = await import(
  "./tauriWorkflows.ts"
);

test("maps approval action summaries and preserves native compatibility", () => {
  const approval = {
    token: "approval-id",
    workflow_id: "workflow-id",
    run_id: "run-id",
    step_id: "release",
    step_index: 2,
    approver_spec: "Current channel approval policy",
    status: "pending",
    approver_pubkey: null,
    note: null,
    expires_at: "2026-08-28T00:00:00Z",
    created_at: 1_700_000_000,
  };
  assert.equal(
    fromRawApproval({
      ...approval,
      action_summary: "Promote the reviewed candidate",
    }).actionSummary,
    "Promote the reviewed candidate",
  );
  assert.equal(fromRawApproval(approval).actionSummary, null);
});

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
