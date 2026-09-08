import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { getPublicKey } from "nostr-tools/pure";
import { dispatch, resetRegistryForTests } from "../registry.ts";
import { registerRelayWorkflowsMembersCommands } from "./relayWorkflowsMembers.ts";
import {
  directoryFixture,
  ownedProfile,
  signedEvent,
  testKey,
  viewerKey,
  viewerPubkey,
} from "./relayAgentOwnership.fixtures.mjs";

afterEach(resetRegistryForTests);

test("browser directory establishes ownership from signed profiles and ignores claimed ownership", async () => {
  const fixture = directoryFixture();
  registerRelayWorkflowsMembersCommands(
    { pubkey: () => fixture.owner },
    fixture.client,
  );
  const agents = await dispatch("list_relay_agents");
  assert.equal(
    agents.find((agent) => agent.pubkey === fixture.owned).owner_pubkey,
    fixture.owner,
  );
  assert.notEqual(
    agents.find((agent) => agent.pubkey === fixture.foreign).owner_pubkey,
    fixture.owner,
  );
  assert.equal(
    agents.find((agent) => agent.pubkey === fixture.forged).owner_pubkey,
    null,
  );
  assert.deepEqual(
    fixture.queries.slice(1).map((query) => query.authors),
    [[fixture.owned], [fixture.foreign], [fixture.forged]],
  );
  assert.ok(
    fixture.queries
      .slice(1)
      .every((query) => query.limit === 1 && query.kinds[0] === 0),
  );
});

test("ownership enrichment fails closed for foreign responses, revoked profiles and invalid NIP-OA evidence", async (t) => {
  const key = testKey(6);
  const pubkey = getPublicKey(key);
  const valid = ownedProfile(key);
  const duplicate = signedEvent(key, 0, {}, [...valid.tags, ...valid.tags]);
  const cases = [
    ["foreign response", [ownedProfile(testKey(7))]],
    [
      "latest revoked",
      [valid, signedEvent(key, 0, { owner_pubkey: viewerPubkey }, [], 101)],
    ],
    [
      "latest tampered",
      [
        valid,
        { ...ownedProfile(key, viewerKey, "", 101), content: "tampered" },
      ],
    ],
    ["two auth tags", [duplicate]],
    ["wrong kind condition", [ownedProfile(key, viewerKey, "kind=1")]],
    [
      "expired at profile timestamp",
      [ownedProfile(key, viewerKey, "created_at<100")],
    ],
    [
      "future at profile timestamp",
      [ownedProfile(key, viewerKey, "created_at>100")],
    ],
    [
      "copied attestation",
      [signedEvent(key, 0, {}, ownedProfile(testKey(7)).tags)],
    ],
    ["no profile", []],
  ];
  for (const [name, profiles] of cases) {
    await t.test(name, async () => {
      resetRegistryForTests();
      registerRelayWorkflowsMembersCommands(
        { pubkey: () => viewerPubkey },
        {
          fetchEvents: async (filter) =>
            filter.kinds[0] === 10100
              ? [signedEvent(key, 10100, { owner_pubkey: viewerPubkey })]
              : profiles,
        },
      );
      const agents = await dispatch("list_relay_agents");
      assert.equal(agents[0].pubkey, pubkey);
      assert.equal(agents[0].owner_pubkey, null);
    });
  }
});

test("signed owner conditions apply to the profile timestamp, including replaceable ties", async () => {
  const key = testKey(8);
  const owned = ownedProfile(
    key,
    viewerKey,
    "created_at>99&kind=0&created_at<101",
  );
  const revoked = signedEvent(key, 0, {});
  let profiles = [owned];
  registerRelayWorkflowsMembersCommands(
    { pubkey: () => viewerPubkey },
    {
      fetchEvents: async (filter) =>
        filter.kinds[0] === 10100 ? [signedEvent(key, 10100)] : profiles,
    },
  );
  assert.equal(
    (await dispatch("list_relay_agents"))[0].owner_pubkey,
    viewerPubkey,
  );
  profiles = [owned, revoked];
  assert.equal(
    (await dispatch("list_relay_agents"))[0].owner_pubkey,
    owned.id < revoked.id ? viewerPubkey : null,
  );
  profiles.reverse();
  assert.equal(
    (await dispatch("list_relay_agents"))[0].owner_pubkey,
    owned.id < revoked.id ? viewerPubkey : null,
  );
});
