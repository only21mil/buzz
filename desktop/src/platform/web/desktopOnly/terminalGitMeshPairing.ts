import { register } from "../registry";
import { registerOffMutation, registerOffRead } from "./capabilityOff";

type MutationSpec = readonly [command: string, hint: string];

const ARCHIVE_MUTATIONS: readonly MutationSpec[] = [
  ["archive_events", "local archives need the desktop app"],
];

const PAIRING_MUTATIONS: readonly MutationSpec[] = [
  ["cancel_pairing", "pairing needs the desktop app"],
  ["confirm_pairing_sas", "pairing needs the desktop app"],
  [
    "start_identity_recovery_pairing",
    "identity recovery needs the desktop app",
  ],
  ["start_pairing", "pairing needs the desktop app"],
];

const PROJECT_GIT_MUTATIONS: readonly MutationSpec[] = [
  ["clone_project_repository", "project repositories need the desktop app"],
  ["create_project_remote_branch", "project git needs the desktop app"],
  ["delete_project_remote_branch", "project git needs the desktop app"],
  ["merge_project_pull_request", "project git needs the desktop app"],
  [
    "open_project_merge_recovery_terminal",
    "project terminals need the desktop app",
  ],
  ["open_project_terminal", "project terminals need the desktop app"],
  [
    "publish_project_pull_request_merged_status",
    "project signing needs the desktop app",
  ],
  ["pull_project_local_repository", "project git needs the desktop app"],
  ["push_project_local_repository", "project git needs the desktop app"],
  [
    "sign_project_pull_request_review_request",
    "project signing needs the desktop app",
  ],
  ["sign_project_pull_request_status", "project signing needs the desktop app"],
  ["validate_repos_dir", "repository paths need the desktop app"],
];

const MESH_MUTATIONS: readonly MutationSpec[] = [
  ["mesh_start_node", "mesh compute needs the desktop app"],
  ["mesh_stop_node", "mesh compute needs the desktop app"],
];

const TERMINAL_MUTATIONS: readonly MutationSpec[] = [
  ["terminal_ack", "terminals need the desktop app"],
  ["terminal_attach", "terminals need the desktop app"],
  ["terminal_close", "terminals need the desktop app"],
  ["terminal_detach", "terminals need the desktop app"],
  ["terminal_focus", "terminals need the desktop app"],
  ["terminal_input", "terminals need the desktop app"],
  ["terminal_resize", "terminals need the desktop app"],
  ["terminal_scroll", "terminals need the desktop app"],
  ["terminal_viewport_ready", "terminals need the desktop app"],
];

function registerMutations(specs: readonly MutationSpec[]): void {
  for (const [command, hint] of specs) registerOffMutation(command, hint);
}

export function registerTerminalGitMeshPairingCommands(): void {
  // Local archive commands.
  registerMutations(ARCHIVE_MUTATIONS);
  registerOffRead("read_archived_events", () => []);

  // Pairing commands.
  registerMutations(PAIRING_MUTATIONS);

  // Project repository reads use the raw snake_case wire shapes expected by
  // projectGit.ts before its mapping into the shared camelCase API types.
  registerOffRead("get_project_local_repo_diff", () => null);
  registerOffRead("get_project_local_repo_snapshot", () => null);
  registerOffRead("get_project_repo_diff", () => ({
    files: [],
    additions: 0,
    deletions: 0,
    commit_body: null,
  }));
  // README, file listing and commit history all ride the repository snapshot,
  // which the desktop builds from a local git clone. Failing closed here (rather
  // than an empty snapshot) lets the UI show its explicit "needs the desktop
  // app" state instead of a repository that looks empty or commit-less.
  registerOffMutation(
    "get_project_repo_snapshot",
    "repository README, files and commits are not available in the web app yet",
  );
  registerOffRead("get_project_repo_sync_status", () => ({
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
  }));
  registerOffRead("list_project_local_repositories", () => []);
  registerMutations(PROJECT_GIT_MUTATIONS);

  // Browser-safe desktop prerequisite and identity defaults.
  register("discover_git_bash_prerequisite", () => null);
  register("get_git_identity", () => ({ name: null, email: null }));
  register("get_media_proxy_port", () => 0);

  // Mesh status and catalog reads use the camelCase types consumed directly by
  // tauriMesh.ts.
  registerOffRead("mesh_installed_models", () => []);
  registerOffRead("mesh_model_catalog", () => ({
    gpuName: null,
    vramDisplay: "",
    vramGb: 0,
    recommended: null,
    entries: [],
  }));
  registerOffRead("mesh_node_status", () => ({
    state: "off",
    mode: null,
    health: { status: "ok" },
    apiBaseUrl: null,
    consoleUrl: null,
    modelId: null,
    modelName: null,
  }));
  registerOffRead("mesh_serving_usage", () => ({
    inflight: 0,
    peakInflight: 0,
    requestsServed: 0,
    tokensServed: 0,
    tokensPerSecond: 0,
    localAttempts: 0,
    remoteAttempts: 0,
    endpointAttempts: 0,
    peers: 0,
  }));
  registerMutations(MESH_MUTATIONS);

  // Native PTY commands cannot be represented by browser APIs.
  registerMutations(TERMINAL_MUTATIONS);
}
