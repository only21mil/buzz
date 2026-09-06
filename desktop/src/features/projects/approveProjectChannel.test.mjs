import assert from "node:assert/strict";
import test from "node:test";
import { approveProjectChannel } from "./approveProjectChannel.ts";

const owner = "a".repeat(64);
const home = "11111111-1111-4111-8111-111111111111";
const channel = { id: "22222222-2222-4222-8222-222222222222" };
const request = {
  requestId: "approval",
  request: { homeChannelId: home, name: "release", visibility: "private" },
};
function fixture() {
  let head = {
    id: "1".repeat(64),
    kind: 30621,
    pubkey: owner,
    created_at: 1,
    content: "",
    tags: [
      ["d", "app"],
      ["buzz-channel", home],
      ["a", `30617:${owner}:app`],
    ],
  };
  const project = {
    id: `${owner}:app`,
    owner,
    dtag: "app",
    projectChannelId: home,
    legacy: false,
    repositories: [{ owner, channelId: home }],
  };
  const calls = { created: 0, published: 0 };
  const deps = {
    isDesktop: () => true,
    getIdentity: async () => ({ pubkey: owner }),
    getRelayOrigin: () => "https://relay.example",
    fetchProjects: async () => [project],
    fetchEvents: async () => [head],
    createChannel: async () => {
      calls.created++;
      return channel;
    },
    signRelayEvent: async (event) => ({
      ...event,
      created_at: event.createdAt,
      pubkey: owner,
      id: "2".repeat(64),
    }),
    publishEvent: async (event) => {
      calls.published++;
      head = event;
    },
  };
  return { deps, calls, project };
}

test("browser and unrelated owner approval produce no channel or publication", async () => {
  for (const mode of ["browser", "foreign", "ambiguous"]) {
    const { deps, calls, project } = fixture();
    if (mode === "browser") deps.isDesktop = () => false;
    if (mode === "foreign")
      deps.getIdentity = async () => ({ pubkey: "b".repeat(64) });
    if (mode === "ambiguous")
      deps.fetchProjects = async () => [project, { ...project, id: "other" }];
    await assert.rejects(approveProjectChannel(request, new Map(), deps));
    assert.deepEqual(calls, { created: 0, published: 0 });
  }
});

test("approved related channel is published once and verified", async () => {
  const { deps, calls } = fixture();
  assert.equal(await approveProjectChannel(request, new Map(), deps), channel);
  assert.deepEqual(calls, { created: 1, published: 1 });
});

test("lost ACK retries reuse the created channel and accepted project link", async () => {
  const { deps, calls } = fixture();
  const resume = new Map();
  const publish = deps.publishEvent;
  deps.publishEvent = async (event) => {
    await publish(event);
    throw new Error("lost ACK");
  };
  await assert.rejects(
    approveProjectChannel(request, resume, deps),
    /lost ACK/,
  );
  assert.equal(await approveProjectChannel(request, resume, deps), channel);
  assert.deepEqual(calls, { created: 1, published: 1 });
});

test("identity change while signing cannot publish into another identity", async () => {
  const { deps, calls } = fixture();
  deps.signRelayEvent = async (event) => ({ ...event, pubkey: "b".repeat(64) });
  await assert.rejects(
    approveProjectChannel(request, new Map(), deps),
    /Identity or relay changed/,
  );
  assert.equal(calls.published, 0);
});

test("identity rotation before channel creation performs no mutation", async () => {
  const { deps, calls } = fixture();
  let reads = 0;
  deps.getIdentity = async () => ({
    pubkey: ++reads === 1 ? owner : "b".repeat(64),
  });
  await assert.rejects(
    approveProjectChannel(request, new Map(), deps),
    /Identity or relay changed/,
  );
  assert.deepEqual(calls, { created: 0, published: 0 });
});
