import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  getBrowserWorkflowRuns,
  parseWorkflowRunsResponse,
  registerWorkflowRunCommands,
} from "./relayWorkflowRuns.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const WORKFLOW_ID = "123e4567-e89b-12d3-a456-426614174000";
const RUN_ID = "123e4567-e89b-12d3-a456-426614174001";

function run(overrides = {}) {
  return {
    id: RUN_ID,
    workflow_id: WORKFLOW_ID,
    status: "completed",
    current_step: 1,
    execution_trace: [
      {
        step_id: "notify",
        step_index: 0,
        status: "completed",
        started_at: 100,
        completed_at: 101,
      },
    ],
    error_message: null,
    started_at: 100,
    completed_at: 101,
    created_at: 99,
    ...overrides,
  };
}

afterEach(() => resetRegistryForTests());

test("workflow history uses the authoritative signed HTTP endpoint", async () => {
  let request;
  registerWorkflowRunCommands({
    relayHttpUrl: async () => "https://buzz.example",
    fetcher: async (value) => {
      request = value;
      return Response.json([run()]);
    },
  });

  assert.deepEqual(
    await dispatch("get_workflow_runs", {
      workflowId: WORKFLOW_ID,
      limit: 20,
    }),
    [run()],
  );
  assert.deepEqual(request, {
    url: `https://buzz.example/workflows/${WORKFLOW_ID}/runs?limit=20`,
    method: "GET",
    headers: { Accept: "application/json" },
  });
});

test("workflow history rejects malformed input before a request", async () => {
  let calls = 0;
  const dependencies = {
    relayHttpUrl: async () => "https://buzz.example",
    fetcher: async () => {
      calls += 1;
      return Response.json([]);
    },
  };
  await assert.rejects(
    getBrowserWorkflowRuns({ workflowId: "not-a-uuid" }, dependencies),
    /workflowId must be a UUID/,
  );
  await assert.rejects(
    getBrowserWorkflowRuns(
      { workflowId: WORKFLOW_ID, limit: 101 },
      dependencies,
    ),
    /limit must be an integer/,
  );
  assert.equal(calls, 0);
});

test("workflow history fails closed on response schema drift", () => {
  assert.throws(
    () =>
      parseWorkflowRunsResponse([run({ secret_output: "nope" })], WORKFLOW_ID),
    /unexpected run field/,
  );
  assert.throws(
    () =>
      parseWorkflowRunsResponse(
        [run({ workflow_id: "123e4567-e89b-12d3-a456-426614174999" })],
        WORKFLOW_ID,
      ),
    /malformed run/,
  );
  assert.throws(
    () =>
      parseWorkflowRunsResponse([run({ status: "new_status" })], WORKFLOW_ID),
    /malformed run/,
  );
  assert.throws(
    () =>
      parseWorkflowRunsResponse(
        [
          run({
            execution_trace: [
              { step_id: "notify", status: "done", output: {} },
            ],
          }),
        ],
        WORKFLOW_ID,
      ),
    /unexpected trace field/,
  );
});

test("workflow history does not expose relay error bodies", async () => {
  await assert.rejects(
    getBrowserWorkflowRuns(
      { workflowId: WORKFLOW_ID },
      {
        relayHttpUrl: async () => "https://buzz.example",
        fetcher: async () =>
          new Response("token=secret private trace", { status: 403 }),
      },
    ),
    (error) => {
      assert.match(error.message, /failed \(403\)/);
      assert.doesNotMatch(error.message, /secret|trace/);
      return true;
    },
  );
});
