import assert from "node:assert/strict";
import test from "node:test";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useChannelMembersQuery } from "./hooks.ts";
import { invalidateChannelMembersRosters } from "./rosterFreshness.ts";
import {
  buildChannelAgentSessionCandidates,
  getChannelAgentSessionAgents,
} from "./ui/useChannelAgentSessions.ts";

test("late native agent flags survive cold loading, warm remount, and roster invalidation", async () => {
  const dom = new JSDOM("<div id='root'></div>");
  const before = {
    window: globalThis.window,
    document: globalThis.document,
    IS_REACT_ACT_ENVIRONMENT: globalThis.IS_REACT_ACT_ENVIRONMENT,
  };
  Object.assign(globalThis, {
    window: dom.window,
    document: dom.window.document,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  const rawMembers = Array.from({ length: 10_000 }, (_, i) => ({
    pubkey: i.toString(16).padStart(64, "0"),
    role: "member",
    is_agent: i === 500,
    display_name: i === 500 ? "Late agent" : null,
    joined_at: null,
  }));
  rawMembers[9_998].role = "bot";
  let calls = 0;
  let revoked = false;
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      assert.equal(command, "get_channel_members");
      assert.equal(args.channelId, "channel-1");
      calls += 1;
      return {
        members: rawMembers.map((member) => ({
          ...member,
          is_agent: revoked ? false : member.is_agent,
        })),
      };
    },
  };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const root = createRoot(document.getElementById("root"));
  let members;
  function Roster() {
    members = useChannelMembersQuery("channel-1").data;
    return null;
  }
  async function render(show) {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client },
          show ? React.createElement(Roster) : null,
        ),
      );
      await new Promise((resolve) => setImmediate(resolve));
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
    });
  }
  function candidates() {
    return buildChannelAgentSessionCandidates({
      channelMembers: members,
      managedAgents: [],
      relayAgents: [],
    });
  }
  function selected(agents) {
    return getChannelAgentSessionAgents({
      activeChannel: { name: "general" },
      activeChannelId: "channel-1",
      channelMembers: members,
      agents,
    }).map((agent) => agent.pubkey);
  }
  try {
    await render(true);
    assert.equal(calls, 1);
    assert.equal(members.length, 10_000);
    const coldCandidates = candidates();
    assert.ok(
      coldCandidates.every((agent) => agent.agentSource === "member-agent"),
    );
    const expected = [rawMembers[500].pubkey, rawMembers[9_998].pubkey];
    assert.deepEqual(selected(coldCandidates), expected);
    assert.ok(!selected(coldCandidates).includes(rawMembers[9_999].pubkey));
    await render(false);
    await render(true);
    assert.equal(calls, 1);
    assert.deepEqual(selected(candidates()), expected);
    revoked = true;
    await act(async () =>
      invalidateChannelMembersRosters(client, ["channel-1"]),
    );
    await render(true);
    assert.equal(calls, 2);
    assert.deepEqual(selected(coldCandidates), [rawMembers[9_998].pubkey]);
    assert.deepEqual(selected(candidates()), [rawMembers[9_998].pubkey]);
  } finally {
    await act(async () => root.unmount());
    client.clear();
    dom.window.close();
    Object.assign(globalThis, before);
  }
});
