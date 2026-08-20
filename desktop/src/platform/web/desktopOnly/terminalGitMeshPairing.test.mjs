import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  BrowserUnavailableError,
  resetCapabilityOffForTests,
} from "./capabilityOff.ts";
import { registerTerminalGitMeshPairingCommands } from "./terminalGitMeshPairing.ts";
import {
  CapabilityUnavailableError,
  dispatch,
  getUnregisteredCommandMissCount,
  resetRegistryForTests,
} from "../registry.ts";

const COMMANDS = [
  { name: "archive_events", mode: "throw" },
  { name: "cancel_pairing", mode: "throw" },
  { name: "clone_project_repository", mode: "throw" },
  { name: "confirm_pairing_sas", mode: "throw" },
  { name: "create_project_remote_branch", mode: "throw" },
  { name: "delete_project_remote_branch", mode: "throw" },
  { name: "discover_git_bash_prerequisite", value: null },
  { name: "get_git_identity", value: { name: null, email: null } },
  { name: "get_media_proxy_port", value: 0 },
  { name: "get_project_local_repo_diff", value: null },
  { name: "get_project_local_repo_snapshot", value: null },
  {
    name: "get_project_repo_diff",
    value: { files: [], additions: 0, deletions: 0, commit_body: null },
  },
  {
    name: "get_project_repo_sync_status",
    value: {
      local_path: null,
      local_branch: null,
      local_branches: [],
      local_head: null,
      local_short_head: null,
      remote_branch: null,
      remote_head: null,
      remote_short_head: null,
      merge_base: null,
      ahead_count: 0,
      behind_count: 0,
      has_uncommitted_changes: false,
      has_untracked_files: false,
      can_push: false,
      push_block_reason: "Local Git is unavailable in the browser build.",
      can_pull: false,
      pull_block_reason: "Local Git is unavailable in the browser build.",
    },
  },
  { name: "list_project_local_repositories", value: [] },
  { name: "merge_project_pull_request", mode: "throw" },
  { name: "mesh_installed_models", value: [] },
  {
    name: "mesh_model_catalog",
    value: {
      gpuName: null,
      vramDisplay: "",
      vramGb: 0,
      recommended: null,
      entries: [],
    },
  },
  {
    name: "mesh_node_status",
    value: {
      state: "off",
      mode: null,
      health: { status: "ok" },
      apiBaseUrl: null,
      consoleUrl: null,
      modelId: null,
      modelName: null,
    },
  },
  {
    name: "mesh_serving_usage",
    value: {
      inflight: 0,
      peakInflight: 0,
      requestsServed: 0,
      tokensServed: 0,
      tokensPerSecond: 0,
      localAttempts: 0,
      remoteAttempts: 0,
      endpointAttempts: 0,
      peers: 0,
    },
  },
  { name: "mesh_start_node", mode: "throw" },
  { name: "mesh_stop_node", mode: "throw" },
  { name: "open_project_merge_recovery_terminal", mode: "throw" },
  { name: "open_project_terminal", mode: "throw" },
  { name: "publish_project_pull_request_merged_status", mode: "throw" },
  { name: "pull_project_local_repository", mode: "throw" },
  { name: "push_project_local_repository", mode: "throw" },
  { name: "read_archived_events", value: [] },
  { name: "sign_project_pull_request_review_request", mode: "throw" },
  { name: "sign_project_pull_request_status", mode: "throw" },
  { name: "start_identity_recovery_pairing", mode: "throw" },
  { name: "start_pairing", mode: "throw" },
  { name: "terminal_ack", mode: "throw" },
  { name: "terminal_attach", mode: "throw" },
  { name: "terminal_close", mode: "throw" },
  { name: "terminal_detach", mode: "throw" },
  { name: "terminal_focus", mode: "throw" },
  { name: "terminal_input", mode: "throw" },
  { name: "terminal_resize", mode: "throw" },
  { name: "terminal_scroll", mode: "throw" },
  { name: "terminal_viewport_ready", mode: "throw" },
  { name: "validate_repos_dir", mode: "throw" },
];

afterEach(() => {
  resetRegistryForTests();
  resetCapabilityOffForTests();
});

test("terminal/git/mesh/pairing PAL registers every command with its contract", async () => {
  registerTerminalGitMeshPairingCommands();

  for (const spec of COMMANDS) {
    if (spec.mode === "throw") {
      await assert.rejects(dispatch(spec.name), (error) => {
        assert.equal(error.name, "BrowserUnavailableError");
        assert.ok(error instanceof BrowserUnavailableError);
        assert.ok(error instanceof CapabilityUnavailableError);
        return true;
      });
      continue;
    }

    const first = await dispatch(spec.name);
    const second = await dispatch(spec.name);
    assert.deepEqual(first, spec.value, spec.name);
    assert.deepEqual(second, spec.value, spec.name);
    if (spec.value && typeof spec.value === "object") {
      assert.notStrictEqual(
        second,
        first,
        `${spec.name} must return fresh values`,
      );
    }
  }

  assert.equal(getUnregisteredCommandMissCount(), 0);
});
