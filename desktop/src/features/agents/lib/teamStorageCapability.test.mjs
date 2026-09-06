import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addTeamFromCatalog,
  createTeam,
  updateTeam,
  deleteTeam,
  setTeamShared,
  exportTeamSnapshot,
  encodeTeamSnapshotForSend,
  previewTeamSnapshotImport,
  confirmTeamSnapshotImport,
} from "@/shared/api/tauriTeams";
import { fetchTeamCatalogPublications } from "./teamCatalogRelay.ts";
import { TEAM_STORAGE_UNAVAILABLE } from "./teamStorageCapability.ts";
import { registerAgentsRuntimeBuilderlabCommands } from "@/platform/web/desktopOnly/agentsRuntimeBuilderlab";
import {
  CapabilityUnavailableError,
  dispatch,
  resetRegistryForTests,
} from "@/platform/web/registry";

const source = {
  ownerPubkey: "a".repeat(64),
  teamDTag: "crew",
  eventId: "b".repeat(64),
};

test("browser team entrypoints reject before native invocation", async () => {
  globalThis.isTauri = false;
  let invocations = 0;
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: () => {
        invocations++;
        throw new Error("unexpected native invocation");
      },
    },
  };
  for (const action of [
    () => fetchTeamCatalogPublications(),
    () => addTeamFromCatalog(source),
    () => setTeamShared("team", true),
    () => createTeam({ name: "team", personaIds: [] }),
    () => updateTeam({ id: "team", name: "team", personaIds: [] }),
    () => deleteTeam("team"),
    () => exportTeamSnapshot("team", "none", "png"),
    () => encodeTeamSnapshotForSend("team", "none", "png"),
    () => previewTeamSnapshotImport([], "team.png"),
    () => confirmTeamSnapshotImport({ fileBytes: [], keepAllowlist: false }),
  ]) {
    await assert.rejects(action, { message: TEAM_STORAGE_UNAVAILABLE });
  }
  assert.equal(invocations, 0);
  delete globalThis.window;
});

test("browser PAL rejects catalog and revalidation commands with explicit capability errors", async () => {
  resetRegistryForTests();
  registerAgentsRuntimeBuilderlabCommands();
  for (const command of [
    "fetch_team_catalog",
    "set_team_shared",
    "add_team_from_catalog",
    "revalidate_relay_agents",
  ]) {
    await assert.rejects(
      () => dispatch(command),
      (error) => error instanceof CapabilityUnavailableError,
    );
  }
  resetRegistryForTests();
});

test("desktop adoption sends only the viewed coordinate and maps native provenance", async () => {
  globalThis.isTauri = true;
  const calls = [];
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: (command, body) => {
        calls.push({ command, body });
        return Promise.resolve({
          team: {
            id: "local",
            name: "Crew",
            description: null,
            persona_ids: ["member"],
            shared: false,
            catalog_source: {
              owner_pubkey: source.ownerPubkey,
              team_d_tag: source.teamDTag,
            },
            created_at: "now",
            updated_at: "now",
          },
          alreadyPresent: false,
        });
      },
    },
  };
  const result = await addTeamFromCatalog(source);
  assert.deepEqual(calls, [
    { command: "add_team_from_catalog", body: { input: source } },
  ]);
  assert.deepEqual(result.team.catalogSource, {
    ownerPubkey: source.ownerPubkey,
    teamDTag: source.teamDTag,
  });
  assert.equal(result.alreadyPresent, false);
  delete globalThis.window;
  delete globalThis.isTauri;
});
