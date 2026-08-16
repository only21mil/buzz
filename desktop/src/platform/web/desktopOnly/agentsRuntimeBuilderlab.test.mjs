import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { BrowserUnavailableError } from "./capabilityOff.ts";
import { registerAgentsRuntimeBuilderlabCommands } from "./agentsRuntimeBuilderlab.ts";
import {
  CapabilityUnavailableError,
  dispatch,
  getUnregisteredCommandMissCount,
  resetRegistryForTests,
} from "../registry.ts";

const MUTATIONS = [
  "archive_builderlab_community",
  "bind_builderlab_nostr_identity",
  "cancel_builderlab_login",
  "card_mint_save_openai_key",
  "clear_builderlab_auth",
  "confirm_agent_snapshot_import",
  "connect_acp_runtime",
  "preview_agent_snapshot_import",
  "create_builderlab_community",
  "create_managed_agent",
  "delete_builderlab_nostr_identity",
  "delete_custom_harness",
  "delete_managed_agent",
  "deny_approval",
  "encode_agent_snapshot_for_send",
  "export_agent_snapshot",
  "grant_approval",
  "install_acp_runtime",
  "mint_agent_card",
  "put_agent_session_config",
  "put_managed_agent_runtime_lifecycle",
  "restart_managed_agent_runtime",
  "save_custom_harness",
  "send_managed_agent_channel_message",
  "set_agent_managed_profiles",
  "set_global_agent_config",
  "set_managed_agent_auto_restart",
  "set_managed_agent_start_on_app_launch",
  "start_builderlab_login",
  "start_managed_agent",
  "start_managed_agent_runtime",
  "stop_managed_agent",
  "stop_managed_agent_runtime",
  "transfer_builderlab_community",
  "unarchive_builderlab_community",
  "update_managed_agent",
];

const READS = [
  ["card_mint_key_status", "none"],
  ["check_builderlab_community_name", { available: false }],
  ["discover_acp_auth_methods", { methods: [] }],
  [
    "discover_agent_models",
    {
      agentName: "",
      agentVersion: "",
      models: [],
      agentDefaultModel: null,
      selectedModel: null,
      supportsSwitching: false,
    },
  ],
  [
    "discover_managed_agent_prereqs",
    {
      acp: { command: "", resolved_path: null, available: false },
      mcp: { command: "", resolved_path: null, available: false },
    },
  ],
  [
    "get_agent_config_surface",
    {
      runtimeId: null,
      runtimeLabel: null,
      isPreSpawn: true,
      normalized: {
        model: null,
        provider: null,
        mode: null,
        thinkingEffort: null,
        maxOutputTokens: null,
        contextLimit: null,
        systemPrompt: null,
      },
      advanced: [],
      extensions: [],
      sources: {
        acpNative: "notApplicable",
        acpConfigOptions: "notApplicable",
        envVars: "notApplicable",
        configFile: "notApplicable",
        configFilePath: null,
        mcpConfigFilePath: null,
      },
    },
  ],
  [
    "get_agent_memory",
    {
      core: null,
      memories: [],
      truncated: false,
      fetchedAt: 0,
    },
  ],
  [
    "get_agent_models",
    {
      agentName: "",
      agentVersion: "",
      models: [],
      agentDefaultModel: null,
      selectedModel: null,
      supportsSwitching: false,
    },
  ],
  ["get_builderlab_auth", null],
  ["get_builderlab_nostr_identity", { identity: null }],
  [
    "get_global_agent_config",
    {
      env_vars: {},
      provider: null,
      model: null,
      preferred_runtime: null,
    },
  ],
  ["get_managed_agent_log", { content: "", log_path: "" }],
  ["get_run_approvals", []],
  ["list_agent_cards", []],
  ["list_builderlab_communities", { communities: [] }],
  ["list_managed_agent_runtimes", []],
  ["list_managed_agents", []],
  ["load_agent_card", ""],
  ["probe_backend_provider", { ok: false }],
  ["reconcile_managed_agent_runtimes", []],
];

const NOOPS = [
  ["agent_access_owner_only", false],
  ["agent_metric_archive_default_enabled", true],
  ["discover_backend_providers", []],
  ["get_baked_build_env", []],
  ["get_baked_build_env_keys", []],
  ["get_model_status", { stt: "not_downloaded", tts: "not_downloaded" }],
  ["get_runtime_file_config", null],
];

afterEach(() => resetRegistryForTests());

test("registers every agents/runtime/Builderlab command with its browser behavior", async () => {
  registerAgentsRuntimeBuilderlabCommands();

  for (const command of MUTATIONS) {
    await assert.rejects(dispatch(command), (error) => {
      assert.equal(error.name, "BrowserUnavailableError");
      assert.ok(error instanceof BrowserUnavailableError);
      assert.ok(error instanceof CapabilityUnavailableError);
      return true;
    });
  }

  for (const [command, expected] of [...READS, ...NOOPS]) {
    const first = await dispatch(command);
    const second = await dispatch(command);
    assert.deepEqual(first, expected, command);
    assert.deepEqual(second, expected, command);
    if (expected !== null && typeof expected === "object") {
      assert.notStrictEqual(
        first,
        second,
        `${command} must return a fresh value`,
      );
    }
  }

  assert.equal(getUnregisteredCommandMissCount(), 0);
});
