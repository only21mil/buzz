import assert from "node:assert/strict";
import test from "node:test";
import { buildMentionCandidates } from "./buildMentionCandidates.ts";
import { getMentionableAgentPubkeys } from "../../agents/lib/agentAutocompleteEligibility.ts";
const key = "bb".repeat(32);
const owner = "aa".repeat(32);
function options(managed = true, relay = false) {
  const managedAgentPubkeys = new Set(managed ? [key] : []);
  const relayAgents = relay
    ? [
        {
          pubkey: key,
          name: "Relay name",
          ownerPubkey: owner,
          respondTo: "nobody",
          respondToAllowlist: [],
          channelIds: ["channel"],
        },
      ]
    : [];
  return {
    activeAgentPubkeys: new Set(),
    activePersonaById: new Map(),
    activePersonas: [],
    candidateProfiles: {},
    userSearchResults: [],
    canSearchGlobalUsers: false,
    currentPubkey: owner,
    directoryAgentPubkeys: new Set(relay ? [key] : []),
    isArchivedDiscovery: () => false,
    managedAgentNamesByPubkey: new Map(managed ? [[key, "Renamed Scout"]] : []),
    managedAgentPersonaIds: new Set(),
    managedAgentPersonaIdsByPubkey: new Map(),
    managedAgentPubkeys,
    managedAgents: managed
      ? [
          {
            pubkey: key.toUpperCase(),
            name: "Renamed Scout",
            respondTo: "nobody",
          },
        ]
      : [],
    memberPubkeys: new Set([key]),
    members: [{ pubkey: key, role: "admin", isAgent: true }],
    mentionableAgentPubkeys: getMentionableAgentPubkeys({
      currentPubkey: owner,
      eligibilityScope: { type: "channel", channelId: "channel" },
      managedAgentPubkeys,
      relayAgents,
      sharedChannelIds: new Set(["channel"]),
    }),
    personaNameByPubkey: new Map(),
    relayAgentNamesByPubkey: new Map(),
    relayAgents,
  };
}
test("managed nobody mention needs no relay row and preserves roster authority and renamed identity", () => {
  for (const relay of [false, true]) {
    const candidates = buildMentionCandidates(options(true, relay));
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].pubkey, key);
    assert.equal(candidates[0].displayName, "Renamed Scout");
    assert.equal(candidates[0].role, "admin");
    assert.equal(candidates[0].isManagedAgent, true);
  }
});
test("relay-only nobody remains hidden and archived local identities stay excluded", () => {
  assert.deepEqual(buildMentionCandidates(options(false, true)), []);
  assert.deepEqual(
    buildMentionCandidates({ ...options(), isArchivedDiscovery: () => true }),
    [],
  );
});

test("foreign relay agents retain mentions in owner, admin and guest roles only when channel policy admits the viewer", () => {
  for (const role of ["owner", "admin", "guest"]) {
    for (const allowed of [true, false]) {
      const input = options(false, true);
      input.members = [{ pubkey: key, role, isAgent: true }];
      input.relayAgents[0].ownerPubkey = "dd".repeat(32);
      input.relayAgents[0].respondTo = "allowlist";
      input.relayAgents[0].respondToAllowlist = allowed ? [owner] : [];
      const discover = () =>
        getMentionableAgentPubkeys({
          currentPubkey: owner,
          eligibilityScope: { type: "channel", channelId: "channel" },
          managedAgentPubkeys: input.managedAgentPubkeys,
          relayAgents: input.relayAgents,
          sharedChannelIds: new Set(["channel"]),
        });
      input.mentionableAgentPubkeys = discover();
      const candidates = buildMentionCandidates(input);
      assert.equal(candidates.length, allowed ? 1 : 0);
      if (allowed) {
        assert.equal(candidates[0].pubkey, key);
        assert.equal(candidates[0].role, role);
      }
      input.relayAgents[0].channelIds = ["other-channel"];
      input.mentionableAgentPubkeys = discover();
      assert.deepEqual(buildMentionCandidates(input), []);
    }
  }
});
