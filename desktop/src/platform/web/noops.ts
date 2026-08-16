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
  // Optional desktop-only enrichment mounted by the channel screen. The
  // managed-agent/persona/relay-agent commands are owned by the desktopOnly
  // modules (lane 3); only the relay-self stub remains here.
  register("get_relay_self", () => null);
}
