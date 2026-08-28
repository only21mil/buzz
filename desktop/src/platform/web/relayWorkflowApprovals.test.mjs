import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { finalizeEvent } from "nostr-tools/pure";

import {
  parseApprovalRequests,
  registerWorkflowApprovalCommands,
} from "./relayWorkflowApprovals.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const PUBKEY = "a".repeat(64);
const WORKFLOW_ID = "123e4567-e89b-42d3-a456-426614174000";
const RUN_ID = "123e4567-e89b-42d3-a456-426614174001";
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174002";
const COMMUNITY_ID = "123e4567-e89b-42d3-a456-426614174003";
const CHANNEL_ID = "123e4567-e89b-42d3-a456-426614174004";
const REQUEST_SECRET = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 65,
);

function requestEvent(overrides = {}) {
  const tags = [
    ["h", CHANNEL_ID],
    ["p", PUBKEY],
  ];
  return {
    ...finalizeEvent(
      {
        created_at: 1_700_000_000,
        kind: 46010,
        tags,
        content: JSON.stringify({
          class: "approval_requested",
          timeout_seconds: 3600,
          approval_id: APPROVAL_ID,
          community_id: COMMUNITY_ID,
          channel_id: CHANNEL_ID,
          workflow_id: WORKFLOW_ID,
          run_id: RUN_ID,
          definition_hash: "d".repeat(64),
          step_id: "release",
          step_index: 2,
          generation: 3,
          action_summary: "Promote the reviewed candidate",
          expires_at: "2026-08-28T00:00:00Z",
          tags,
        }),
      },
      REQUEST_SECRET,
    ),
    ...overrides,
  };
}

afterEach(() => resetRegistryForTests());

test("approval requests map to the existing native client wire schema", () => {
  assert.deepEqual(
    parseApprovalRequests([requestEvent()], PUBKEY, WORKFLOW_ID, RUN_ID),
    [
      {
        token: APPROVAL_ID,
        workflow_id: WORKFLOW_ID,
        run_id: RUN_ID,
        step_id: "release",
        step_index: 2,
        approver_spec: "Current channel approval policy",
        status: "pending",
        approver_pubkey: null,
        note: null,
        expires_at: "2026-08-28T00:00:00Z",
        created_at: 1_700_000_000,
      },
    ],
  );
});

test("approval parsing isolates schema drift and wrong recipients", () => {
  const drifted = requestEvent();
  drifted.content = JSON.stringify({
    ...JSON.parse(drifted.content),
    new_field: true,
  });
  const wrongRecipient = requestEvent({
    tags: [
      ["h", CHANNEL_ID],
      ["p", "f".repeat(64)],
    ],
  });
  assert.deepEqual(
    parseApprovalRequests(
      [drifted, requestEvent(), wrongRecipient],
      PUBKEY,
      WORKFLOW_ID,
      RUN_ID,
    ).map((approval) => approval.token),
    [APPROVAL_ID],
  );
});

test("decisions require an in-scope request and emit the canonical event", async () => {
  const signed = [];
  const published = [];
  const identity = {
    pubkey: () => PUBKEY,
    sign: (request) => {
      signed.push(request);
      return JSON.stringify({
        ...request,
        id: "1".repeat(64),
        pubkey: PUBKEY,
        created_at: 1_700_000_100,
        sig: "2".repeat(128),
      });
    },
  };
  const client = {
    fetchEvents: async () => [requestEvent()],
    publishEvent: async (event) => {
      published.push(event);
      return event;
    },
  };
  registerWorkflowApprovalCommands(identity, client);

  await assert.rejects(
    dispatch("grant_approval", { token: APPROVAL_ID, note: null }),
    /not in the active browser scope/,
  );
  await dispatch("get_run_approvals", {
    workflowId: WORKFLOW_ID,
    runId: RUN_ID,
  });
  await assert.rejects(
    dispatch("deny_approval", { token: APPROVAL_ID, note: "  " }),
    /denial note is required/,
  );
  assert.deepEqual(
    await dispatch("deny_approval", {
      token: APPROVAL_ID,
      note: " Needs revision ",
    }),
    {
      token: APPROVAL_ID,
      status: "denied",
      run_id: RUN_ID,
      workflow_id: WORKFLOW_ID,
    },
  );
  assert.deepEqual(signed, [
    {
      kind: 46031,
      tags: [["d", APPROVAL_ID]],
      content: JSON.stringify({ decision: "deny", note: "Needs revision" }),
    },
  ]);
  assert.equal(published.length, 1);
  assert.deepEqual(
    await dispatch("get_run_approvals", {
      workflowId: WORKFLOW_ID,
      runId: RUN_ID,
    }),
    [],
  );
});
