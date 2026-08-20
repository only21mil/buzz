import { register } from "../registry";
import { registerOffMutation, registerOffRead } from "./capabilityOff";

type DefaultFactory = () => unknown;

const CAPABILITY_OFF_MUTATIONS: ReadonlyArray<readonly [string, string]> = [
  // Builderlab account and community mutations.
  [
    "archive_builderlab_community",
    "Builderlab communities need the desktop app",
  ],
  [
    "bind_builderlab_nostr_identity",
    "Builderlab identity binding needs the desktop app",
  ],
  ["cancel_builderlab_login", "Builderlab login needs the desktop app"],
  ["clear_builderlab_auth", "Builderlab sign-out needs the desktop app"],
  [
    "create_builderlab_community",
    "Builderlab communities need the desktop app",
  ],
  [
    "delete_builderlab_nostr_identity",
    "Builderlab identity removal needs the desktop app",
  ],
  ["start_builderlab_login", "Builderlab login needs the desktop app"],
  [
    "transfer_builderlab_community",
    "Builderlab community transfers need the desktop app",
  ],
  [
    "unarchive_builderlab_community",
    "Builderlab communities need the desktop app",
  ],

  // Persona cards and snapshots.
  ["card_mint_save_openai_key", "persona card keys need the desktop app"],
  [
    "confirm_agent_snapshot_import",
    "agent snapshot imports need the desktop app",
  ],
  [
    "preview_agent_snapshot_import",
    "agent snapshot imports need the desktop app",
  ],
  [
    "encode_agent_snapshot_for_send",
    "agent snapshot exports need the desktop app",
  ],
  ["export_agent_snapshot", "agent snapshot exports need the desktop app"],
  ["mint_agent_card", "persona cards need the desktop app"],

  // Local ACP runtimes and harnesses.
  ["connect_acp_runtime", "local runtime authentication needs the desktop app"],
  ["create_managed_agent", "managed agents need the desktop app"],
  ["delete_custom_harness", "local harnesses need the desktop app"],
  ["delete_managed_agent", "managed agents need the desktop app"],
  ["install_acp_runtime", "local runtime installation needs the desktop app"],
  ["put_agent_session_config", "agent sessions need the desktop app"],
  [
    "put_managed_agent_runtime_lifecycle",
    "managed-agent runtimes need the desktop app",
  ],
  [
    "restart_managed_agent_runtime",
    "managed-agent runtimes need the desktop app",
  ],
  ["save_custom_harness", "local harnesses need the desktop app"],
  ["start_managed_agent", "managed agents need the desktop app"],
  [
    "start_managed_agent_runtime",
    "managed-agent runtimes need the desktop app",
  ],
  ["stop_managed_agent", "managed agents need the desktop app"],
  ["stop_managed_agent_runtime", "managed-agent runtimes need the desktop app"],
  ["update_managed_agent", "managed agents need the desktop app"],

  // Workflow approvals.
  ["deny_approval", "workflow approvals need the desktop app"],
  ["grant_approval", "workflow approvals need the desktop app"],

  // Managed-agent settings and messaging.
  [
    "send_managed_agent_channel_message",
    "managed-agent messaging needs the desktop app",
  ],
  ["set_agent_managed_profiles", "agent settings need the desktop app"],
  ["set_global_agent_config", "agent settings need the desktop app"],
  [
    "set_managed_agent_auto_restart",
    "managed-agent settings need the desktop app",
  ],
  [
    "set_managed_agent_start_on_app_launch",
    "managed-agent settings need the desktop app",
  ],
];

const CAPABILITY_OFF_READS: ReadonlyArray<readonly [string, DefaultFactory]> = [
  // Builderlab account and community reads.
  ["check_builderlab_community_name", () => ({ available: false })],
  ["get_builderlab_auth", () => null],
  ["get_builderlab_nostr_identity", () => ({ identity: null })],
  ["list_builderlab_communities", () => ({ communities: [] })],

  // Persona cards and snapshots.
  ["card_mint_key_status", () => "none"],
  ["list_agent_cards", () => []],
  ["load_agent_card", () => ""],

  // Agent discovery and runtime state reads.
  ["discover_acp_auth_methods", () => ({ methods: [] })],
  [
    "discover_agent_models",
    () => ({
      agentName: "",
      agentVersion: "",
      models: [],
      agentDefaultModel: null,
      selectedModel: null,
      supportsSwitching: false,
    }),
  ],
  [
    "discover_managed_agent_prereqs",
    () => ({
      acp: { command: "", resolved_path: null, available: false },
      mcp: { command: "", resolved_path: null, available: false },
    }),
  ],
  [
    "get_agent_config_surface",
    () => ({
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
    }),
  ],
  [
    "get_agent_memory",
    () => ({
      core: null,
      memories: [],
      truncated: false,
      fetchedAt: 0,
    }),
  ],
  [
    "get_agent_models",
    () => ({
      agentName: "",
      agentVersion: "",
      models: [],
      agentDefaultModel: null,
      selectedModel: null,
      supportsSwitching: false,
    }),
  ],
  [
    "get_global_agent_config",
    () => ({
      env_vars: {},
      provider: null,
      model: null,
      preferred_runtime: null,
    }),
  ],
  ["get_managed_agent_log", () => ({ content: "", log_path: "" })],
  ["get_run_approvals", () => []],
  ["list_managed_agent_runtimes", () => []],
  ["list_managed_agents", () => []],
  ["probe_backend_provider", () => ({ ok: false })],
  ["reconcile_managed_agent_runtimes", () => []],
];

const NOOP_READS: ReadonlyArray<readonly [string, DefaultFactory]> = [
  // Build and distribution policy defaults.
  ["agent_access_owner_only", () => false],
  ["agent_metric_archive_default_enabled", () => true],
  ["discover_backend_providers", () => []],
  ["get_baked_build_env", () => []],
  ["get_baked_build_env_keys", () => []],

  // Browser-safe model and runtime idle states.
  [
    "get_model_status",
    () => ({ stt: "not_downloaded", tts: "not_downloaded" }),
  ],
  ["get_runtime_file_config", () => null],
];

export function registerAgentsRuntimeBuilderlabCommands(): void {
  for (const [command, hint] of CAPABILITY_OFF_MUTATIONS) {
    registerOffMutation(command, hint);
  }
  for (const [command, factory] of CAPABILITY_OFF_READS) {
    registerOffRead(command, factory);
  }
  for (const [command, factory] of NOOP_READS) {
    register(command, factory);
  }
}
