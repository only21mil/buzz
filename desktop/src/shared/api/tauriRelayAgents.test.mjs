import assert from "node:assert/strict";
import test from "node:test";
import { listRelayAgents } from "./tauri.ts";
import { revalidateRelayAgents } from "./tauriRelayAgents.ts";
import {
  dispatch,
  CapabilityUnavailableError,
} from "../../platform/web/registry.ts";

const key = "a".repeat(64);
const owner = "b".repeat(64);
const raw = {
  pubkey: key,
  owner_pubkey: owner,
  name: "Remote",
  agent_type: "agent",
  channels: [],
  channel_ids: [],
  capabilities: [],
  status: "unknown",
  respond_to: "owner-only",
  respond_to_allowlist: [],
};

test("both native DTO adapters preserve owner and unknown membership/liveness evidence", async () => {
  const calls = [];
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async (command, args) => {
        calls.push({ command, args });
        return [raw];
      },
    },
  };
  const listed = await listRelayAgents();
  const revalidated = await revalidateRelayAgents([key], "target");
  assert.deepEqual(revalidated, listed);
  assert.equal(revalidated[0].ownerPubkey, owner);
  assert.equal(revalidated[0].status, "unknown");
  assert.deepEqual(revalidated[0].channelIds, []);
  assert.deepEqual(calls[1], {
    command: "revalidate_relay_agents",
    args: { pubkeys: [key], channelId: "target" },
  });
});

test("fresh authority failure rejects without returning previously fetched relay data", async () => {
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async () => {
        throw new Error("relay unavailable");
      },
    },
  };
  await assert.rejects(
    revalidateRelayAgents([key], "target"),
    /relay unavailable/,
  );
});

test("browser has no native revalidation authority fallback", async () => {
  await assert.rejects(
    dispatch("revalidate_relay_agents", {
      pubkeys: [key],
      channelId: "target",
    }),
    CapabilityUnavailableError,
  );
});
