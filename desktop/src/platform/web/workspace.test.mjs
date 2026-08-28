import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { dispatch, resetRegistryForTests } from "./registry.ts";
import { BrowserWorkspace, registerWorkspaceCommands } from "./workspace.ts";

afterEach(() => resetRegistryForTests());

const identity = { pubkey: () => "a".repeat(64) };

test("workspace installs and returns a validated relay context", async () => {
  const workspace = new BrowserWorkspace("https://relay.example/app/");
  registerWorkspaceCommands(workspace, identity);
  await dispatch("apply_workspace", {
    relayUrl: "wss://relay.example/",
    reposDir: null,
  });
  assert.equal(await dispatch("get_relay_ws_url"), "wss://relay.example");
  assert.equal(await dispatch("get_relay_http_url"), "https://relay.example");
  assert.deepEqual(await dispatch("get_active_workspace"), {
    relay_url: "wss://relay.example",
    pubkey: "a".repeat(64),
  });
});

test("workspace rejects a relay outside the hosted application origin", async () => {
  registerWorkspaceCommands(
    new BrowserWorkspace("https://relay.example/app/"),
    identity,
  );
  await assert.rejects(
    dispatch("apply_workspace", {
      relayUrl: "wss://other.example",
      reposDir: null,
    }),
    /must match the application origin/,
  );
});

test("workspace rejects filesystem-only repository configuration", async () => {
  registerWorkspaceCommands(
    new BrowserWorkspace("https://relay.example/app/"),
    identity,
  );
  await assert.rejects(
    dispatch("apply_workspace", {
      relayUrl: "wss://relay.example",
      reposDir: "/home/example/repos",
    }),
    /do not support a local repositories directory/,
  );
});
