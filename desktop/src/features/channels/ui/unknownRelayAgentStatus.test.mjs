import assert from "node:assert/strict";
import test from "node:test";
import { buildChannelAgentSessionCandidates } from "./useChannelAgentSessions.ts";

const relayAgents = ["unknown", "online", "away", "offline"].map((status) => ({
  pubkey: status,
  name: status,
  status,
  channelIds: [],
  channels: [],
}));

test("session projection retains unknown rather than manufacturing deployed status", () => {
  const candidates = buildChannelAgentSessionCandidates({
    managedAgents: [],
    relayAgents,
  });
  assert.deepEqual(
    candidates.map(({ status }) => status),
    ["unknown", "deployed", "deployed", "stopped"],
  );
});

test("local managed evidence survives missing relay evidence", () => {
  const [candidate] = buildChannelAgentSessionCandidates({
    managedAgents: [{ pubkey: "local", name: "Local", status: "running" }],
    relayAgents: [],
  });
  assert.equal(candidate.status, "running");
  assert.equal(candidate.agentSource, "managed");
});
