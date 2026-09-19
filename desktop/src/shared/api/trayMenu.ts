import { invokeTauri } from "@/shared/api/tauri";

/** Best-effort teardown: a missing native tray must not interrupt community switching. */
export async function clearTrayAgentActivity(): Promise<void> {
  try {
    await invokeTauri("clear_tray_agent_activity");
  } catch {
    console.warn(
      "[tray] Failed to clear agent activity during community teardown",
    );
  }
}
