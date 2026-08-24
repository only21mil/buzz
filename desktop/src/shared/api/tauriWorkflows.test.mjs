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
