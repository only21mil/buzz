import { register } from "./registry";

const COSMETIC_VOID_COMMANDS = [
  "set_window_vibrancy",
  "title_bar_double_click",
  "perform_sidebar_default_haptic",
  "update_tray_agent_activity",
  "clear_tray_agent_activity",
  "set_prevent_sleep_active",
  "relay_reconnect_hook",
] as const;

export function registerNoopCommands(): void {
  for (const command of COSMETIC_VOID_COMMANDS) {
    register(command, () => undefined);
  }
  register("take_tray_actions", () => []);
  register("requeue_tray_actions", () => undefined);
  register("is_auto_update_supported", () => false);
  register("relay_reconnect_hook_configured", () => false);
  // Optional desktop-only enrichment mounted by the channel screen. Empty
  // values preserve the browser's message/profile path without advertising
  // local managed-agent capabilities.
  register("list_managed_agents", () => []);
  register("list_personas", () => []);
  register("list_relay_agents", () => []);
  register("get_relay_self", () => null);
  register("has_managed_agent_channel_message_marker", () => false);
}
