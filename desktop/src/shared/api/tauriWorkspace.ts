import { invokeTauri } from "./tauri";

export async function applyCommunity(
  relayUrl: string,
  nsec?: string,
  reposDir?: string,
  agentManagedProfiles?: boolean,
  threadScopedAcpSessions?: boolean,
): Promise<void> {
  await invokeTauri("apply_workspace", {
    relayUrl,
    nsec: nsec ?? null,
    reposDir: reposDir ?? null,
    agentManagedProfiles: agentManagedProfiles ?? false,
    threadScopedAcpSessions: threadScopedAcpSessions ?? false,
  });
}

// Validate a candidate repos dir without mutating the filesystem. Rejects
// with a human-readable reason; resolves for a valid or empty path.
export async function validateReposDir(dir: string): Promise<void> {
  await invokeTauri("validate_repos_dir", { dir });
}

export const setPreventSleepActive = (active: boolean) =>
  invokeTauri("set_prevent_sleep_active", { active });

export const setAgentManagedProfiles = (enabled: boolean) =>
  invokeTauri("set_agent_managed_profiles", { enabled });

export const setThreadScopedAcpSessions = (enabled: boolean) =>
  invokeTauri("set_thread_scoped_acp_sessions", { enabled });
