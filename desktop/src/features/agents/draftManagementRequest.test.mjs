/**
 * Tests for defect 7eabb71a — CLI drafts never reach the Desktop review surface.
 *
 * `buzz agents draft-create` publishes a kind 24200 ephemeral event signed by
 * the owner's CLI key and tagged agent = <CLI signer pubkey> (= owner's key).
 * The owner's key is NOT a registered managed agent, so the
 * knownAgentPubkeys gate in handleRelayObserverEvent dropped the frame before
 * parseAgentManagementRequest ever ran — the draft never reached
 * agentManagementListeners (the review surface).
 *
 * The fix: owner-signed frames bypass the knownAgentPubkeys gate for
 * management requests. The owner's signature authenticates the frame;
 * decryption alone only proves the sender knew the owner's public key.
 *
 * Three invariants:
 *  1. An owner-signed management-request frame with an agent tag NOT in
 *     knownAgentPubkeys reaches agentManagementListeners. (Fails before fix,
 *     passes after.)
 *  2. A stranger-signed management-request frame (signer != owner), encrypted
 *     to the owner, does NOT reach agentManagementListeners. (Passes both
 *     before and after — the hole-closure assertion.)
 *  3. A telemetry frame from an unknown agent is still dropped by the
 *     knownAgentPubkeys gate. (Passes both before and after.)
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { AGENT_MANAGEMENT_REQUEST } from "./agentManagement.ts";
import {
  handleRelayObserverEvent,
  resetAgentObserverStore,
  subscribeAgentManagementRequests,
  _testGetGeneration,
  _testRegisterKnownAgents,
  _testSetOwnerPubkey,
} from "./observerRelayStore.ts";

// ── Constants ─────────────────────────────────────────────────────────────────

const OWNER_PUBKEY = "a".repeat(64);
const STRANGER_PUBKEY = "b".repeat(64);
const MANAGED_AGENT_PUBKEY = "c".repeat(64);
const SUB_ID = "test-draft-sub-1";
const CHANNEL_ID = "7c07e659-3610-42f4-9a5e-1e9973c09da9";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Build a raw kind 24200 relay event (the shape that arrives from the live
 * observer subscription). The `signerPubkey` param is the event's signer
 * (event.pubkey); the `agentTag` param is the "agent" tag value.
 */
function makeRawEvent(signerPubkey, agentTag, overrides = {}) {
  return {
    id: "e".repeat(64),
    pubkey: signerPubkey,
    created_at: 1000,
    kind: 24200,
    tags: [
      ["p", OWNER_PUBKEY],
      ["agent", agentTag],
      ["frame", "telemetry"],
    ],
    content: "encrypted",
    sig: "s".repeat(128),
    ...overrides,
  };
}

/** A management-request (draft-create) payload matching the agent_management_request contract. */
function makeManagementRequestPayload() {
  return {
    type: AGENT_MANAGEMENT_REQUEST,
    action: "create",
    requestId: "draft-8def7780",
    request: {
      channelId: CHANNEL_ID,
      displayName: "Research helper",
      systemPrompt: "Find reliable sources and summarize them.",
    },
  };
}

/** An observer event wrapping a management-request payload. */
function makeManagementRequestObserverEvent() {
  return {
    seq: 1,
    timestamp: "2026-01-01T00:00:01.000Z",
    kind: "agent_management_request",
    agentIndex: 0,
    channelId: CHANNEL_ID,
    sessionId: null,
    turnId: null,
    payload: makeManagementRequestPayload(),
  };
}

/** A plain telemetry observer event (not a management request). */
function makeTelemetryObserverEvent() {
  return {
    seq: 2,
    timestamp: "2026-01-01T00:00:02.000Z",
    kind: "acp_write",
    agentIndex: 0,
    channelId: CHANNEL_ID,
    sessionId: "sess-1",
    turnId: "turn-1",
    payload: {
      method: "session/update",
      params: { update: { sessionUpdate: "text" } },
    },
  };
}

/** Decrypt fn that resolves to the given observer event (mock decrypt). */
function makeDecrypt(returnEvent) {
  return () => Promise.resolve(returnEvent);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("draft management request reaches review surface (defect 7eabb71a)", () => {
  beforeEach(() => {
    resetAgentObserverStore();
  });

  it("test_owner_signed_draft_reaches_review_surface_despite_unknown_agent_tag", async () => {
    // Simulate a fresh Desktop: the owner pubkey is known (so the owner-signed
    // check passes), but no managed agents are registered. The CLI
    // draft-create signs with the owner's key and tags agent = owner's key,
    // which is NOT in knownAgentPubkeys.
    _testSetOwnerPubkey(OWNER_PUBKEY);
    // No _testRegisterKnownAgents call — knownAgentPubkeys is empty, simulating
    // a fresh Desktop with zero managed agents.

    let receivedPubkey = null;
    let receivedRequest = null;
    const unsubscribe = subscribeAgentManagementRequests(
      (agentPubkey, request) => {
        receivedPubkey = agentPubkey;
        receivedRequest = request;
      },
    );

    // The raw event is signed by the owner (event.pubkey = OWNER_PUBKEY) and
    // tags agent = OWNER_PUBKEY (the CLI signer's key = owner's key).
    const rawEvent = makeRawEvent(OWNER_PUBKEY, OWNER_PUBKEY);
    const decryptFn = makeDecrypt(makeManagementRequestObserverEvent());
    const gen = _testGetGeneration();

    await handleRelayObserverEvent(rawEvent, gen, decryptFn);

    unsubscribe();

    assert.ok(
      receivedRequest !== null,
      "owner-signed management request must reach agentManagementListeners",
    );
    assert.equal(
      receivedRequest?.action,
      "create",
      "the management request must carry action=create",
    );
    assert.equal(
      receivedRequest?.requestId,
      "draft-8def7780",
      "the management request must carry the draft requestId",
    );
    assert.equal(
      receivedPubkey,
      OWNER_PUBKEY,
      "the agentPubkey passed to listeners must be the event's agent tag",
    );
  });

  it("test_stranger_signed_draft_does_not_reach_review_surface", async () => {
    // A stranger signs a kind 24200 event encrypted to the owner. The event
    // passes the relay filter (#p = owner), but the signer is NOT the owner.
    // The management request must NOT reach agentManagementListeners — the
    // knownAgentPubkeys gate drops it before decrypt. This is the
    // hole-closure assertion: decryption alone does not authenticate the
    // sender.
    _testSetOwnerPubkey(OWNER_PUBKEY);
    // No managed agents registered — knownAgentPubkeys is empty.

    let received = false;
    const unsubscribe = subscribeAgentManagementRequests(() => {
      received = true;
    });

    // Signed by a stranger, agent tag = stranger (or any non-owner pubkey).
    const rawEvent = makeRawEvent(STRANGER_PUBKEY, STRANGER_PUBKEY);
    const decryptFn = makeDecrypt(makeManagementRequestObserverEvent());
    const gen = _testGetGeneration();

    await handleRelayObserverEvent(rawEvent, gen, decryptFn);

    unsubscribe();

    assert.equal(
      received,
      false,
      "stranger-signed management request must NOT reach agentManagementListeners (hole-closure)",
    );
  });

  it("test_telemetry_from_unknown_agent_still_dropped_by_gate", async () => {
    // A non-owner-signed telemetry frame (not a management request) from an
    // agent not in knownAgentPubkeys must still be dropped by the gate.
    // This is the defense-in-depth that survives the fix.
    _testSetOwnerPubkey(OWNER_PUBKEY);
    // Register a DIFFERENT managed agent so the gate is initialized (non-empty).
    _testRegisterKnownAgents(SUB_ID, [MANAGED_AGENT_PUBKEY]);

    let received = false;
    const unsubscribe = subscribeAgentManagementRequests(() => {
      received = true;
    });

    // Signed by a stranger, agent tag = stranger — not the owner, not a
    // managed agent. The gate must drop it.
    const rawEvent = makeRawEvent(STRANGER_PUBKEY, STRANGER_PUBKEY);
    const decryptFn = makeDecrypt(makeTelemetryObserverEvent());
    const gen = _testGetGeneration();

    await handleRelayObserverEvent(rawEvent, gen, decryptFn);

    unsubscribe();

    assert.equal(
      received,
      false,
      "telemetry from an unknown agent must still be dropped by the knownAgentPubkeys gate",
    );
  });

  it("test_owner_signed_non_management_telemetry_dropped_when_agent_not_registered", async () => {
    // An owner-signed frame that decrypts to a NON-management telemetry event
    // must still apply the knownAgentPubkeys gate for the per-agent event
    // store. The owner-signed bypass is ONLY for management requests.
    _testSetOwnerPubkey(OWNER_PUBKEY);
    // No managed agents registered — knownAgentPubkeys is empty.

    let received = false;
    const unsubscribe = subscribeAgentManagementRequests(() => {
      received = true;
    });

    const rawEvent = makeRawEvent(OWNER_PUBKEY, OWNER_PUBKEY);
    const decryptFn = makeDecrypt(makeTelemetryObserverEvent());
    const gen = _testGetGeneration();

    await handleRelayObserverEvent(rawEvent, gen, decryptFn);

    unsubscribe();

    assert.equal(
      received,
      false,
      "owner-signed non-management telemetry must not route to agentManagementListeners",
    );
  });
});
