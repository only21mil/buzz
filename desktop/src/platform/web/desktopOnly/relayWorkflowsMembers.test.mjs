import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayWorkflowsMembersCommands } from "./relayWorkflowsMembers.ts";
import {
  dispatch,
  getUnregisteredCommandMissCount,
  resetRegistryForTests,
} from "../registry.ts";

const PUBKEY = "a".repeat(64);
const TARGET = "b".repeat(64);

const identity = {
  pubkey: () => PUBKEY,
  sign(request) {
    return JSON.stringify({
      kind: request.kind,
      content: request.content,
      tags: request.tags,
      id: `signed-${request.kind}-${request.tags.flat().join("-")}`,
      pubkey: PUBKEY,
      created_at: request.createdAt ?? 100,
      sig: "f".repeat(128),
    });
  },
};

function event({
  id,
  kind,
  createdAt,
  tags = [],
  content = "",
  pubkey = PUBKEY,
}) {
  return {
    id,
    kind,
    created_at: createdAt,
    tags,
    content,
    pubkey,
    sig: "e".repeat(128),
  };
}

function clientFixture({ events = [], firstEvent = null, publishResult } = {}) {
  const calls = { fetchEvents: [], fetchFirstEvent: [], published: [] };
  return {
    calls,
    async fetchEvents(filter) {
      calls.fetchEvents.push(filter);
      return events;
    },
    async fetchFirstEvent(filter) {
      calls.fetchFirstEvent.push(filter);
      return firstEvent;
    },
    async publishEvent(signed, timeoutMessage, sendErrorMessage) {
      calls.published.push({ signed, timeoutMessage, sendErrorMessage });
      return (
        publishResult ?? {
          event_id: signed.id,
          accepted: true,
          message: "",
        }
      );
    },
  };
}

afterEach(() => resetRegistryForTests());

test("relay-member mutations sign the Rust event kinds and tags", async (t) => {
  const cases = [
    {
      command: "add_relay_member",
      body: { targetPubkey: TARGET.toUpperCase(), role: "admin" },
      kind: 9030,
      tags: [
        ["p", TARGET],
        ["role", "admin"],
      ],
    },
    {
      command: "remove_relay_member",
      body: { targetPubkey: TARGET },
      kind: 9031,
      tags: [["p", TARGET]],
    },
    {
      command: "change_relay_member_role",
      body: { targetPubkey: TARGET, newRole: "owner" },
      kind: 9032,
      tags: [
        ["p", TARGET],
        ["role", "owner"],
      ],
    },
  ];

  for (const entry of cases) {
    await t.test(entry.command, async () => {
      resetRegistryForTests();
      const client = clientFixture();
      registerRelayWorkflowsMembersCommands(identity, client);

      const result = await dispatch(entry.command, entry.body);

      assert.equal(client.calls.published.length, 1);
      assert.equal(client.calls.published[0].signed.kind, entry.kind);
      assert.deepEqual(client.calls.published[0].signed.tags, entry.tags);
      assert.deepEqual(result, {
        event_id: client.calls.published[0].signed.id,
        accepted: true,
        message: "",
      });
      assert.equal(getUnregisteredCommandMissCount(), 0);
    });
  }
});

test("workflow reads issue the matching d/h filters and fold YAML records", async (t) => {
  const workflowEvent = event({
    id: "workflow-event",
    kind: 30620,
    createdAt: 42,
    tags: [
      ["d", "workflow-id"],
      ["h", "channel-one"],
    ],
    content: "name: Deploy\nenabled: true\nsteps:\n  - type: notify",
  });
  const cases = [
    {
      command: "get_channel_workflows",
      body: { channelId: "channel-one" },
      method: "fetchEvents",
      filter: { kinds: [30620], "#h": ["channel-one"] },
      result: "array",
    },
    {
      command: "get_channels_workflows",
      body: { channelIds: ["channel-one", "channel-two"] },
      method: "fetchEvents",
      filter: {
        kinds: [30620],
        "#h": ["channel-one", "channel-two"],
      },
      result: "array",
    },
    {
      command: "get_workflow",
      body: { workflowId: "workflow-id" },
      method: "fetchFirstEvent",
      filter: { kinds: [30620], "#d": ["workflow-id"], limit: 1 },
      result: "single",
    },
  ];

  for (const entry of cases) {
    await t.test(entry.command, async () => {
      resetRegistryForTests();
      const client = clientFixture({
        events: [workflowEvent],
        firstEvent: workflowEvent,
      });
      registerRelayWorkflowsMembersCommands(identity, client);

      const result = await dispatch(entry.command, entry.body);
      assert.deepEqual(client.calls[entry.method], [entry.filter]);
      const folded = entry.result === "array" ? result[0] : result;
      assert.deepEqual(folded, {
        id: "workflow-id",
        name: "Deploy",
        owner_pubkey: PUBKEY,
        channel_id: "channel-one",
        definition: {
          name: "Deploy",
          enabled: true,
          steps: [{ type: "notify" }],
        },
        status: "active",
        created_at: 42,
        updated_at: 42,
      });
      assert.equal(getUnregisteredCommandMissCount(), 0);
    });
  }
});

test("get_channels_workflows returns without querying for an empty id set", async () => {
  const client = clientFixture();
  registerRelayWorkflowsMembersCommands(identity, client);

  assert.deepEqual(
    await dispatch("get_channels_workflows", { channelIds: [] }),
    [],
  );
  assert.deepEqual(client.calls.fetchEvents, []);
  assert.equal(getUnregisteredCommandMissCount(), 0);
});

test("workflow mutations publish create/update/delete/trigger wire events", async (t) => {
  await t.test("create_workflow", async () => {
    resetRegistryForTests();
    const client = clientFixture({
      publishResult: { event_id: "created-event", accepted: true },
    });
    registerRelayWorkflowsMembersCommands(identity, client);

    const result = await dispatch("create_workflow", {
      channelId: "channel-one",
      yamlDefinition: "name: Hook\ntrigger:\n  on: message_posted",
    });

    const published = client.calls.published[0].signed;
    assert.equal(published.kind, 30620);
    assert.match(published.tags[0][1], /^[0-9a-f-]{36}$/);
    assert.deepEqual(published.tags[1], ["h", "channel-one"]);
    assert.equal(result.id, published.tags[0][1]);
    assert.equal(result.name, "Hook");
    assert.equal("webhook_secret" in result, false);
    assert.equal(result.owner_pubkey, PUBKEY);
    assert.equal(getUnregisteredCommandMissCount(), 0);
  });

  await t.test(
    "create_workflow with a webhook trigger fails closed",
    async () => {
      resetRegistryForTests();
      const client = clientFixture({
        publishResult: {
          event_id: "created-event",
          accepted: true,
          message:
            'response:{"workflow_id":"new-id","webhook_secret":"secret-1"}',
        },
      });
      registerRelayWorkflowsMembersCommands(identity, client);

      for (const yamlDefinition of [
        "name: Hook\ntrigger:\n  on: webhook",
        "name: Hook\ntrigger:\n  type: webhook",
      ]) {
        await assert.rejects(
          dispatch("create_workflow", {
            channelId: "channel-one",
            yamlDefinition,
          }),
          (error) =>
            error.name === "BrowserUnavailableError" &&
            /webhook/.test(error.message),
        );
      }
      assert.deepEqual(client.calls.published, []);
      assert.equal(getUnregisteredCommandMissCount(), 0);
    },
  );

  await t.test("update_workflow", async () => {
    resetRegistryForTests();
    const prior = event({
      id: "prior-workflow",
      kind: 30620,
      createdAt: 25,
      tags: [
        ["d", "workflow-id"],
        ["h", "channel-one"],
      ],
      content: "name: Old",
    });
    const client = clientFixture({ firstEvent: prior });
    registerRelayWorkflowsMembersCommands(identity, client);

    const result = await dispatch("update_workflow", {
      workflowId: "workflow-id",
      yamlDefinition: "name: Updated\nenabled: false",
    });

    assert.deepEqual(client.calls.fetchFirstEvent[0], {
      kinds: [30620],
      "#d": ["workflow-id"],
      limit: 1,
    });
    assert.equal(client.calls.published[0].signed.kind, 30620);
    assert.deepEqual(client.calls.published[0].signed.tags, [
      ["d", "workflow-id"],
      ["h", "channel-one"],
    ]);
    assert.equal(result.name, "Updated");
    assert.equal(result.created_at, 25);
    assert.equal("webhook_secret" in result, false);
    assert.equal(getUnregisteredCommandMissCount(), 0);
  });

  await t.test("delete_workflow", async () => {
    resetRegistryForTests();
    const client = clientFixture();
    registerRelayWorkflowsMembersCommands(identity, client);

    assert.equal(
      await dispatch("delete_workflow", { workflowId: "workflow-id" }),
      undefined,
    );
    assert.equal(client.calls.published[0].signed.kind, 5);
    assert.deepEqual(client.calls.published[0].signed.tags, [
      ["a", `30620:${PUBKEY}:workflow-id`],
    ]);
    assert.equal(getUnregisteredCommandMissCount(), 0);
  });

  await t.test("trigger_workflow", async () => {
    resetRegistryForTests();
    const client = clientFixture();
    registerRelayWorkflowsMembersCommands(identity, client);

    const result = await dispatch("trigger_workflow", {
      workflowId: "workflow-id",
    });
    assert.equal(client.calls.published[0].signed.kind, 46020);
    assert.deepEqual(client.calls.published[0].signed.tags, [
      ["d", "workflow-id"],
    ]);
    assert.deepEqual(result, {
      event_id: client.calls.published[0].signed.id,
      workflow_id: "workflow-id",
      run_id: null,
      status: "accepted",
    });
    assert.equal(getUnregisteredCommandMissCount(), 0);
  });
});

test("list_relay_members reuses the shared NIP-43 parser", async () => {
  const snapshot = event({
    id: "membership",
    kind: 13534,
    createdAt: 12,
    tags: [
      ["member", PUBKEY, "owner"],
      ["p", TARGET, "wss://relay.test", "admin"],
    ],
  });
  const client = clientFixture({ firstEvent: snapshot });
  registerRelayWorkflowsMembersCommands(identity, client);

  assert.deepEqual(await dispatch("list_relay_members"), {
    members: [
      {
        pubkey: PUBKEY,
        role: "owner",
        added_by: null,
        created_at: "1970-01-01T00:00:12.000Z",
      },
      {
        pubkey: TARGET,
        role: "admin",
        added_by: null,
        created_at: "1970-01-01T00:00:12.000Z",
      },
    ],
  });
  assert.deepEqual(client.calls.fetchFirstEvent, [
    { kinds: [13534], limit: 1 },
  ]);
  assert.equal(getUnregisteredCommandMissCount(), 0);
});

test("list_relay_agents folds sparse and complete kind:10100 profiles", async () => {
  const client = clientFixture({
    events: [
      event({
        id: "agent-one",
        kind: 10100,
        createdAt: 20,
        content: JSON.stringify({
          name: "Scout",
          agent_type: "assistant",
          channels: ["general"],
          channel_ids: ["channel-one"],
          capabilities: ["search"],
          status: "online",
          respond_to: "allowlist",
          respond_to_allowlist: [TARGET],
        }),
      }),
      event({
        id: "agent-two",
        kind: 10100,
        createdAt: 21,
        pubkey: TARGET,
        content: JSON.stringify({ display_name: "Builder" }),
      }),
    ],
  });
  registerRelayWorkflowsMembersCommands(identity, client);

  const result = await dispatch("list_relay_agents");
  assert.deepEqual(result[0], {
    pubkey: PUBKEY,
    name: "Scout",
    agent_type: "assistant",
    channels: ["general"],
    channel_ids: ["channel-one"],
    capabilities: ["search"],
    status: "online",
    respond_to: "allowlist",
    respond_to_allowlist: [TARGET],
  });
  assert.deepEqual(result[1], {
    pubkey: TARGET,
    name: "Builder",
    agent_type: "agent",
    channels: [],
    channel_ids: [],
    capabilities: [],
    status: "offline",
    respond_to: null,
    respond_to_allowlist: [],
  });
  assert.deepEqual(client.calls.fetchEvents, [{ kinds: [10100] }]);
  assert.equal(getUnregisteredCommandMissCount(), 0);
});

test("list_relay_agents preserves named fleet identities without an allowlist", async () => {
  const names = ["Mempool", "Genesis", "Codex-R"];
  const client = clientFixture({
    events: names.map((name, index) =>
      event({
        id: `agent-${index}`,
        kind: 10100,
        createdAt: 30 + index,
        pubkey: index.toString(16).padStart(64, "0"),
        content: JSON.stringify({ name, status: "online" }),
      }),
    ),
  });
  registerRelayWorkflowsMembersCommands(identity, client);

  const result = await dispatch("list_relay_agents");
  assert.deepEqual(
    result.map((agent) => agent.name),
    names,
  );
  assert.deepEqual(client.calls.fetchEvents, [{ kinds: [10100] }]);
});

test("update_profile_at_relay compare-writes through the explicit relay seam", async () => {
  const priorCreatedAt = Math.floor(Date.now() / 1000) + 10;
  let scopedProfile = event({
    id: "profile-prior",
    kind: 0,
    createdAt: priorCreatedAt,
    content: JSON.stringify({
      display_name: "Sats",
      name: "sats",
      picture: " https://example.test/old.png ",
      about: "builder",
      nip05: "sats@example.test",
      ignored: "not preserved",
    }),
  });
  const scopedCalls = { fetch: [], publish: [] };
  const client = {
    ...clientFixture(),
    async fetchEventsAt(relayUrl, filter) {
      scopedCalls.fetch.push({ relayUrl, filter });
      return [scopedProfile];
    },
    async publishEventAt(relayUrl, signed) {
      scopedCalls.publish.push({ relayUrl, signed });
      scopedProfile = signed;
      return signed;
    },
  };
  registerRelayWorkflowsMembersCommands(identity, client);

  const result = await dispatch("update_profile_at_relay", {
    relayUrl: "wss://other-relay.test",
    expectedPubkey: PUBKEY,
    expectedAvatarUrl: "https://example.test/old.png",
    avatarUrl: "https://example.test/new.png",
  });

  assert.equal(scopedCalls.fetch.length, 2);
  assert.deepEqual(scopedCalls.fetch[0], {
    relayUrl: "wss://other-relay.test",
    filter: { kinds: [0], authors: [PUBKEY], limit: 1 },
  });
  assert.equal(scopedCalls.publish[0].relayUrl, "wss://other-relay.test");
  assert.equal(scopedCalls.publish[0].signed.kind, 0);
  assert.deepEqual(scopedCalls.publish[0].signed.tags, []);
  assert.equal(scopedCalls.publish[0].signed.created_at, priorCreatedAt + 1);
  assert.deepEqual(JSON.parse(scopedCalls.publish[0].signed.content), {
    display_name: "Sats",
    name: "sats",
    about: "builder",
    nip05: "sats@example.test",
    picture: "https://example.test/new.png",
  });
  assert.deepEqual(result, {
    pubkey: PUBKEY,
    display_name: "Sats",
    avatar_url: "https://example.test/new.png",
    about: "builder",
    nip05_handle: "sats@example.test",
    owner_pubkey: null,
    has_profile_event: true,
  });
  assert.equal(getUnregisteredCommandMissCount(), 0);
});

test("the registrar covers all thirteen commands without an unregistered miss", async () => {
  const workflowEvent = event({
    id: "workflow",
    kind: 30620,
    createdAt: 10,
    tags: [
      ["d", "workflow-id"],
      ["h", "channel-one"],
    ],
    content: "name: One",
  });
  let scopedProfile = event({
    id: "profile",
    kind: 0,
    createdAt: 10,
    content: JSON.stringify({ picture: "old" }),
  });
  const client = {
    ...clientFixture({ events: [workflowEvent], firstEvent: workflowEvent }),
    async fetchEventsAt() {
      return [scopedProfile];
    },
    async publishEventAt(_relayUrl, signed) {
      scopedProfile = signed;
      return signed;
    },
  };
  registerRelayWorkflowsMembersCommands(identity, client);

  const calls = [
    ["add_relay_member", { targetPubkey: TARGET, role: "member" }],
    ["change_relay_member_role", { targetPubkey: TARGET, newRole: "admin" }],
    [
      "create_workflow",
      { channelId: "channel-one", yamlDefinition: "name: New" },
    ],
    ["delete_workflow", { workflowId: "workflow-id" }],
    ["get_channel_workflows", { channelId: "channel-one" }],
    ["get_channels_workflows", { channelIds: ["channel-one"] }],
    ["get_workflow", { workflowId: "workflow-id" }],
    ["list_relay_agents"],
    ["list_relay_members"],
    ["remove_relay_member", { targetPubkey: TARGET }],
    ["trigger_workflow", { workflowId: "workflow-id" }],
    [
      "update_profile_at_relay",
      {
        relayUrl: "wss://relay.test",
        expectedPubkey: PUBKEY,
        expectedAvatarUrl: "old",
        avatarUrl: "new",
      },
    ],
    [
      "update_workflow",
      { workflowId: "workflow-id", yamlDefinition: "name: Updated" },
    ],
  ];
  for (const [command, body] of calls) await dispatch(command, body);

  assert.equal(getUnregisteredCommandMissCount(), 0);
});
