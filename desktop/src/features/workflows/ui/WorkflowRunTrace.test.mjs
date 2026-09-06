import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { WorkflowRunTrace } from "./WorkflowRunTrace.tsx";

const approval = {
  approvalRef: "display-reference",
  workflowId: "workflow",
  runId: "run",
  stepId: "gate",
  stepIndex: 0,
  approverSpec: "owner",
  status: "granted",
  approverPubkey: null,
  note: "Approved release",
  expiresAt: "2026-09-06T00:00:00Z",
  createdAt: 1,
};
const run = {
  id: "run",
  workflowId: "workflow",
  status: "resume_pending",
  currentStep: 0,
  executionTrace: [],
  startedAt: 1,
  completedAt: null,
  errorMessage: null,
  createdAt: 1,
};

test("recovered run with pending trace renders recorded approval state", () => {
  const html = renderToStaticMarkup(
    React.createElement(WorkflowRunTrace, { run, approvals: [approval] }),
  );
  assert.match(html, /Execution trace is pending/);
  assert.match(html, /Approval: granted/);
  assert.match(html, /Approved release/);
  assert.doesNotMatch(html, /<button|Approval Required|No runs yet/);
});
test("pending and resolved evidence for the same step remain read-only", () => {
  const html = renderToStaticMarkup(
    React.createElement(WorkflowRunTrace, {
      run: {
        ...run,
        executionTrace: [
          {
            stepId: "gate",
            status: "waiting_approval",
            output: {},
            startedAt: null,
            completedAt: null,
            error: null,
          },
        ],
      },
      approvals: [
        { ...approval, approvalRef: "legacy", status: "pending" },
        approval,
      ],
    }),
  );
  assert.match(html, /Approval: pending/);
  assert.match(html, /Approval: granted/);
  assert.match(html, /Respond using the signed approval request/);
  assert.doesNotMatch(html, /<button|<textarea/);
});
