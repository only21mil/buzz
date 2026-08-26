import assert from "node:assert/strict";
import test from "node:test";

import {
  advanceAgentManagementReview,
  classifyAgentManagementOrigin,
  enqueueAgentManagementReview,
} from "./agentManagementBuffer.ts";

const AGENT = "a".repeat(64);
const CHANNEL = "channel-1";
const OWNED_AGENT = [{ pubkey: AGENT }];
const SHARED_CHANNEL = [
  { id: CHANNEL, isMember: true, memberPubkeys: [AGENT] },
];

test("buffers a draft until ownership and channel data resolve", () => {
  assert.equal(
    classifyAgentManagementOrigin(undefined, SHARED_CHANNEL, AGENT, CHANNEL),
    "buffer",
  );
  assert.equal(
    classifyAgentManagementOrigin(OWNED_AGENT, undefined, AGENT, CHANNEL),
    "buffer",
  );
});

test("accepts an owned agent drafting from a shared channel", () => {
  assert.equal(
    classifyAgentManagementOrigin(OWNED_AGENT, SHARED_CHANNEL, AGENT, CHANNEL),
    "accept",
  );
});

test("rejects a draft when the owner or agent is outside the claimed channel", () => {
  assert.equal(
    classifyAgentManagementOrigin(
      OWNED_AGENT,
      [{ id: CHANNEL, isMember: false, memberPubkeys: [AGENT] }],
      AGENT,
      CHANNEL,
    ),
    "reject",
  );
  assert.equal(
    classifyAgentManagementOrigin(
      OWNED_AGENT,
      [{ id: CHANNEL, isMember: true, memberPubkeys: [] }],
      AGENT,
      CHANNEL,
    ),
    "reject",
  );
});

test("rejects a draft from an agent this Desktop does not own", () => {
  assert.equal(
    classifyAgentManagementOrigin(
      [{ pubkey: "b".repeat(64) }],
      SHARED_CHANNEL,
      AGENT,
      CHANNEL,
    ),
    "reject",
  );
});

test("serializes Mempool and Genesis review dialogs in arrival order", () => {
  const mempool = {
    agentPubkey: AGENT,
    request: {
      type: "agent_management_request",
      action: "create",
      requestId: "mempool-request",
      request: {
        channelId: CHANNEL,
        displayName: "Mempool",
        systemPrompt: "Watch the mempool.",
      },
    },
  };
  const genesis = {
    agentPubkey: AGENT,
    request: {
      type: "agent_management_request",
      action: "create",
      requestId: "genesis-request",
      request: {
        channelId: CHANNEL,
        displayName: "Genesis",
        systemPrompt: "Track chain state.",
      },
    },
  };

  const first = enqueueAgentManagementReview(null, [], mempool);
  assert.equal(first.activate, mempool);
  assert.deepEqual(first.queued, []);

  const second = enqueueAgentManagementReview(
    mempool.request.requestId,
    first.queued,
    genesis,
  );
  assert.equal(second.activate, null, "active dialog stays open");
  assert.deepEqual(second.queued, [genesis]);

  const advanced = advanceAgentManagementReview(second.queued);
  assert.equal(
    advanced.activate,
    genesis,
    "Genesis opens after Mempool closes",
  );
  assert.deepEqual(advanced.queued, []);
});
