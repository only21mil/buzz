import assert from "node:assert/strict";
import test from "node:test";
import {
  agentManagementReviewContent,
  assertAgentManagementReviewCurrent,
  assertAgentManagementUpdateTarget,
} from "./agentManagementReview.ts";

const agentPubkey = "a".repeat(64);
const admitted = {
  requestId: "draft-1",
  activeRequestId: "draft-1",
  agentPubkey,
  channelId: "channel-1",
  agents: [{ pubkey: agentPubkey }],
  channels: [{ id: "channel-1", isMember: true, memberPubkeys: [agentPubkey] }],
};
const reviewed = {
  id: "persona-1",
  displayName: "Reviewer",
  systemPrompt: "Original prompt",
  sourceTeam: null,
  updatedAt: "revision-1",
  shared: false,
};

test("unchanged admitted review can save only its displayed persona", () => {
  assert.doesNotThrow(() => assertAgentManagementReviewCurrent(admitted));
  assert.deepEqual(
    assertAgentManagementUpdateTarget(reviewed, reviewed, "persona-1"),
    {
      expectedUpdatedAt: "revision-1",
      expectedContent: agentManagementReviewContent(reviewed),
      expectedShared: false,
    },
  );
  assert.throws(() =>
    assertAgentManagementUpdateTarget(reviewed, reviewed, "persona-2"),
  );
});

test("queued, dismissed and unmounted review callbacks cannot save", () => {
  for (const activeRequestId of ["draft-2", null]) {
    assert.throws(() =>
      assertAgentManagementReviewCurrent({ ...admitted, activeRequestId }),
    );
  }
});

test("review rechecks ownership and both memberships at submit time", () => {
  for (const change of [
    { agents: [] },
    { agents: undefined },
    { channels: undefined },
    { agentPubkey: null },
    {
      channels: [
        { id: "channel-1", isMember: false, memberPubkeys: [agentPubkey] },
      ],
    },
    { channels: [{ id: "channel-1", isMember: true, memberPubkeys: [] }] },
  ]) {
    assert.throws(() =>
      assertAgentManagementReviewCurrent({ ...admitted, ...change }),
    );
  }
});

test("deleted, changed and newly team-owned personas reject stale review", () => {
  for (const current of [
    undefined,
    { ...reviewed, updatedAt: "revision-2" },
    { ...reviewed, sourceTeam: "team-1" },
    { ...reviewed, shared: true },
    { ...reviewed, id: "persona-2" },
  ]) {
    assert.throws(() =>
      assertAgentManagementUpdateTarget(reviewed, current, "persona-1"),
    );
  }
  assert.throws(() =>
    assertAgentManagementUpdateTarget(null, reviewed, "persona-1"),
  );
});

test("same-second content changes reject the old review for every editable field", () => {
  for (const change of [
    { displayName: "Replacement" },
    { avatarUrl: "https://example.com/avatar" },
    { systemPrompt: "Replacement prompt" },
    { runtime: "codex" },
    { model: "model-2" },
    { provider: "provider-2" },
    { namePool: ["A"] },
    { envVars: { SETTING: "new" } },
    { respondTo: "all" },
    { respondToAllowlist: [agentPubkey] },
    { parallelism: 2 },
  ]) {
    assert.throws(() =>
      assertAgentManagementUpdateTarget(
        reviewed,
        { ...reviewed, ...change },
        reviewed.id,
      ),
    );
  }
});

test("equivalent serialization and unrelated persona edits preserve the review", () => {
  const snapshot = { ...reviewed, envVars: { Z: "last", A: "first" } };
  const current = {
    ...snapshot,
    runtime: null,
    namePool: [],
    envVars: { A: "first", Z: "last" },
  };
  const unrelated = {
    ...snapshot,
    id: "unrelated",
    systemPrompt: "Changed elsewhere",
  };
  const result = assertAgentManagementUpdateTarget(
    snapshot,
    [unrelated, current].find((p) => p.id === snapshot.id),
    snapshot.id,
  );
  assert.deepEqual(
    result.expectedContent,
    agentManagementReviewContent(snapshot),
  );
  snapshot.envVars.A = "later mutation";
  assert.equal(result.expectedContent.envVars.A, "first");
});
