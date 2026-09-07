import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test, { after, afterEach, before } from "node:test";
import * as React from "react";
import * as jsx from "react/jsx-runtime";
import { JSDOM } from "jsdom";
import ts from "typescript";
import {
  addOwnedChannelAgents,
  getOwnedAgentsToAdd,
} from "../../agents/lib/ownedChannelAgents.ts";
import { canAddChannelMembers } from "../lib/channelMemberAdmission.ts";
import { normalizePubkey } from "../../../shared/lib/pubkey.ts";
import { listRelayAgents } from "../../../shared/api/tauri.ts";
import { registerRelayWorkflowsMembersCommands } from "../../../platform/web/desktopOnly/relayWorkflowsMembers.ts";
import { directoryFixture } from "../../../platform/web/desktopOnly/relayAgentOwnership.fixtures.mjs";
import {
  dispatch,
  resetRegistryForTests,
} from "../../../platform/web/registry.ts";

function load(name, stubs) {
  const exports = {};
  vm.runInNewContext(
    ts.transpileModule(
      fs.readFileSync(new URL(`./${name}.tsx`, import.meta.url), "utf8"),
      {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
          jsx: ts.JsxEmit.ReactJSX,
        },
      },
    ).outputText,
    {
      exports,
      Error,
      Map,
      Set,
      require(key) {
        if (key === "react") return React;
        if (key === "react/jsx-runtime") return jsx;
        assert.ok(key in stubs, `unmocked dependency: ${key}`);
        return stubs[key];
      },
    },
  );
  return exports;
}
const wrap = ({ children }) => React.createElement("div", null, children);
const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
before(() =>
  Object.assign(globalThis, {
    document: dom.window.document,
    window: dom.window,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  }),
);
afterEach(async () => (await import("@testing-library/react")).cleanup());
after(() => dom.window.close());
const key = "bb".repeat(32);
const other = "cc".repeat(32);
const owner = "aa".repeat(32);

const genericModule = new Proxy(
  {},
  { get: (_target, key) => (key === "__esModule" ? false : wrap) },
);
const { MembersSidebarMemberCard } = load("MembersSidebarMemberCard", {
  "lucide-react": genericModule,
  "@/features/agents/lib/managedAgentControlActions": {},
  "@/features/profile/ui/ProfileAvatar": genericModule,
  "@/features/presence/ui/PresenceBadge": genericModule,
  "@/features/agents/managedAgentRuntimeStatus": {},
  "@/shared/lib/pubkey": { truncatePubkey: (x) => x },
  "@/shared/lib/cn": { cn: (...x) => x.join(" ") },
  "@/shared/ui/badge": genericModule,
  "@/shared/ui/dropdown-menu": new Proxy(
    {},
    {
      get: (_target, name) =>
        name === "DropdownMenuItem" || name === "DropdownMenuSubTrigger"
          ? ({ children, ...props }) =>
              React.createElement(
                "button",
                { type: "button", ...props },
                children,
              )
          : wrap,
    },
  ),
});
const cardProps = {
  canChangeRole: true,
  canModerate: false,
  canRemoveMember: false,
  isActionPending: false,
  isArchived: false,
  member: { pubkey: key, role: "bot" },
  memberIsBot: true,
  memberLabel: "Scout",
  memberAvatarLabel: "S",
  viewerIsOwner: true,
};
test("authorized agent role control dispatches admin; owner, unauthorized and archived controls stay guarded", async () => {
  const { render, fireEvent } = await import("@testing-library/react");
  const changes = [];
  const view = render(
    React.createElement(MembersSidebarMemberCard, {
      ...cardProps,
      onChangeRole: (...x) => changes.push(x),
    }),
  );
  fireEvent.click(view.getByTestId(`sidebar-role-admin-${key}`));
  assert.equal(changes[0][1], "admin");
  view.rerender(
    React.createElement(MembersSidebarMemberCard, {
      ...cardProps,
      member: { pubkey: key, role: "admin" },
    }),
  );
  assert.ok(view.getByText("agent · admin"));
  view.rerender(
    React.createElement(MembersSidebarMemberCard, {
      ...cardProps,
      canChangeRole: false,
    }),
  );
  assert.equal(view.queryByTestId(`sidebar-change-role-${key}`), null);
  view.rerender(
    React.createElement(MembersSidebarMemberCard, {
      ...cardProps,
      member: { pubkey: key, role: "owner" },
    }),
  );
  assert.equal(view.queryByTestId(`sidebar-change-role-${key}`), null);
  view.rerender(
    React.createElement(MembersSidebarMemberCard, {
      ...cardProps,
      isArchived: true,
    }),
  );
  assert.equal(view.getByTestId(`sidebar-role-admin-${key}`).disabled, true);
});

function ownedSetup({
  failSecond = false,
  viewer = owner,
  directoryAgents,
  fetchDirectory,
} = {}) {
  const roster = [{ pubkey: viewer, role: "owner" }];
  const channel = {
    id: "channel",
    channelType: "stream",
    visibility: "private",
    archivedAt: null,
  };
  const agents = directoryAgents ?? [
    { pubkey: key, ownerPubkey: owner, name: "First" },
    { pubkey: other, ownerPubkey: owner, name: "Second" },
  ];
  const query = (get) => ({
    data: get(),
    isSuccess: true,
    refetch: async () => ({ data: get() }),
  });
  const calls = [];
  const { AddOwnedChannelAgents } = load("AddOwnedChannelAgents", {
    "@tanstack/react-query": { useQueryClient: () => ({}) },
    "@/features/agents/hooks": {
      useRelayAgentsQuery: () => ({
        ...query(() => agents),
        refetch: async () => ({
          data: fetchDirectory ? await fetchDirectory() : agents,
        }),
      }),
    },
    "@/features/agents/lib/ownedChannelAgents": {
      addOwnedChannelAgents,
      getOwnedAgentsToAdd,
    },
    "@/features/channels/hooks": {
      useChannelMembersQuery: () => query(() => roster),
      useChannelsQuery: () => query(() => [channel]),
      invalidateChannelState: async () => {},
    },
    "@/features/channels/lib/channelMemberAdmission": { canAddChannelMembers },
    "@/features/identity-archive/hooks": {
      useIsArchivedPredicate: () => () => false,
    },
    "@/shared/api/hooks": {
      useIdentityQuery: () => query(() => ({ pubkey: viewer })),
    },
    "@/shared/api/tauri": {
      addChannelMembers: async (input) => {
        calls.push(input);
        return input.pubkeys[0] === other && failSecond
          ? { added: [], errors: [{ pubkey: other, error: "Denied" }] }
          : { added: input.pubkeys, errors: [] };
      },
    },
    "@/shared/lib/pubkey": { normalizePubkey },
    "@/shared/ui/button": {
      Button: ({ variant, ...props }) =>
        React.createElement("button", { type: "button", ...props }),
    },
    "@/shared/ui/checkbox": {
      Checkbox: ({ onCheckedChange, ...props }) =>
        React.createElement("input", {
          ...props,
          type: "checkbox",
          onChange: (event) => onCheckedChange(event.target.checked),
        }),
    },
  });
  return { AddOwnedChannelAgents, calls, roster, channel, agents };
}
test("bulk partial failure shows per-agent outcomes and retries only failed agents", async () => {
  const { render, fireEvent, waitFor } = await import("@testing-library/react");
  const { AddOwnedChannelAgents, calls } = ownedSetup({ failSecond: true });
  const view = render(
    React.createElement(AddOwnedChannelAgents, { channelId: "channel" }),
  );
  fireEvent.click(view.getByRole("button", { name: /Add all my agents/ }));
  await waitFor(() => assert.ok(view.getByText("Second: Denied")));
  assert.ok(view.getByText("Added: First."));
  assert.equal(view.queryByLabelText("First"), null);
  fireEvent.click(view.getByRole("button", { name: /Add all my agents/ }));
  await waitFor(() => assert.equal(calls.length, 3));
  assert.deepEqual(
    calls.map((x) => x.pubkeys[0]),
    [key, other, other],
  );
});
test("selected add excludes unchecked agents and revalidates revoked channel authority", async () => {
  const { render, fireEvent, waitFor } = await import("@testing-library/react");
  const setup = ownedSetup();
  const view = render(
    React.createElement(setup.AddOwnedChannelAgents, { channelId: "channel" }),
  );
  fireEvent.click(view.getByLabelText("Second"));
  fireEvent.click(view.getByRole("button", { name: "Add selected agents" }));
  await waitFor(() => assert.ok(view.getByText("Added: Second.")));
  assert.deepEqual(
    setup.calls.map((x) => x.pubkeys[0]),
    [other],
  );
  setup.roster[0].role = "member";
  fireEvent.click(view.getByRole("button", { name: /Add all my agents/ }));
  await waitFor(() =>
    assert.ok(view.getByText("You can no longer add agents to this channel.")),
  );
  assert.equal(setup.calls.length, 1);
});

test("browser Add agents keeps relay attachment available while hiding native creation", async () => {
  const { render, fireEvent, waitFor } = await import("@testing-library/react");
  resetRegistryForTests();
  const fixture = directoryFixture();
  registerRelayWorkflowsMembersCommands(
    { pubkey: () => fixture.owner },
    fixture.client,
  );
  window.__TAURI_INTERNALS__ = { invoke: dispatch };
  const setup = ownedSetup({
    viewer: fixture.owner,
    directoryAgents: await listRelayAgents(),
    fetchDirectory: listRelayAgents,
  });
  const empty = [];
  const noPersonas = new Set();
  const { AddChannelBotDialog } = load("AddChannelBotDialog", {
    "lucide-react": genericModule,
    "@/features/agents/hooks": {
      useCreateChannelManagedAgentsMutation: () => ({
        reset() {},
        isPending: false,
      }),
      usePersonasQuery: () => ({ data: empty }),
      useTeamsQuery: () => ({ data: empty }),
    },
    "@/features/personas/hooks": { usePersonasQuery: () => ({ data: empty }) },
    "@/features/teams/hooks": { useTeamsQuery: () => ({ data: empty }) },
    "@/features/agents/lib/resolvePersonaRuntime": {
      resolvePersonaRuntime() {},
    },
    "@/features/channels/ui/AddChannelBotPersonasSection": {
      AddChannelBotPersonasSection: () =>
        React.createElement("div", null, "Native personas"),
    },
    "@/features/channels/ui/AddChannelBotTeamsSection": {
      AddChannelBotTeamsSection: () =>
        React.createElement("div", null, "Native teams"),
    },
    "@/features/channels/ui/useInChannelPersonaIds": {
      useInChannelPersonaIds: () => noPersonas,
    },
    "./AddOwnedChannelAgents": {
      AddOwnedChannelAgents: setup.AddOwnedChannelAgents,
    },
    "@/platform/web/capabilities": {
      Capability: { ManagedAgents: "managed-agents" },
      useCapability: () => false,
    },
    "@/shared/ui/button": {
      Button: ({ variant, size, ...props }) =>
        React.createElement("button", { type: "button", ...props }),
    },
    "@/shared/ui/chooser-dialog-content": {
      ChooserDialogContent: ({ children, footer }) =>
        React.createElement("div", null, children, footer),
    },
    "@/shared/ui/dialog": { Dialog: wrap },
    "@/features/agents/lib/catalog": { getActivePersonas: (x) => x },
    "@/features/agents/lib/teamPersonas": { getUsableTeams: (x) => x },
  });
  const view = render(
    React.createElement(AddChannelBotDialog, {
      channelId: "channel",
      open: true,
      providers: [],
      onOpenChange() {},
      onCreateAgent() {},
    }),
  );
  assert.ok(view.getByLabelText("Owned Scout"));
  assert.equal(view.queryByLabelText("Foreign Scout"), null);
  assert.equal(view.queryByLabelText("Forged Scout"), null);
  assert.equal(view.queryByText("Native personas"), null);
  assert.equal(view.queryByText(/Install an agent runtime/), null);
  assert.equal(view.queryByRole("button", { name: "Add agent" }), null);
  const addAll = view.getByRole("button", { name: "Add all my agents (1)" });
  assert.equal(addAll.disabled, false);
  fireEvent.click(view.getByLabelText("Owned Scout"));
  fireEvent.click(view.getByRole("button", { name: "Add selected agents" }));
  await waitFor(() => assert.ok(view.getByText("Added: Owned Scout.")));
  assert.deepEqual(
    setup.calls.map((call) => call.pubkeys[0]),
    [fixture.owned],
  );
  assert.equal(
    fixture.queries.filter((query) => query.kinds[0] === 10100).length,
    2,
  );
  resetRegistryForTests();
  delete window.__TAURI_INTERNALS__;
});

test("browser attachment rechecks signed ownership before adding all owned agents", async () => {
  const { render, fireEvent, waitFor } = await import("@testing-library/react");
  resetRegistryForTests();
  const fixture = directoryFixture();
  registerRelayWorkflowsMembersCommands(
    { pubkey: () => fixture.owner },
    fixture.client,
  );
  window.__TAURI_INTERNALS__ = { invoke: dispatch };
  const setup = ownedSetup({
    viewer: fixture.owner,
    directoryAgents: await listRelayAgents(),
    fetchDirectory: listRelayAgents,
  });
  const view = render(
    React.createElement(setup.AddOwnedChannelAgents, { channelId: "channel" }),
  );
  // Revoke the only owned profile after the dialog's initial directory load.
  fixture.events.splice(
    fixture.events.findIndex(
      (event) => event.kind === 0 && event.pubkey === fixture.owned,
    ),
    1,
  );
  fireEvent.click(view.getByRole("button", { name: "Add all my agents (1)" }));
  await waitFor(() => assert.ok(view.getByText("No agents were added.")));
  assert.deepEqual(setup.calls, []);
  resetRegistryForTests();
  delete window.__TAURI_INTERNALS__;
});
