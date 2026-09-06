import { isTauri } from "@tauri-apps/api/core";

export const TEAM_STORAGE_UNAVAILABLE =
  "Local team storage is unavailable in the browser. Use the desktop app to browse, share, or add teams.";

export function hasLocalTeamStorage(): boolean {
  return isTauri();
}

export function requireLocalTeamStorage(): void {
  if (!hasLocalTeamStorage()) throw new Error(TEAM_STORAGE_UNAVAILABLE);
}
