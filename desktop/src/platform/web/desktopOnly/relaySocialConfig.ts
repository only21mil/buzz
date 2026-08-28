// Browser PAL registrations for desktop-local teams, personas, templates, and archive state.
import type { BrowserIdentityManager } from "../identity";
import { register } from "../registry";
import { registerOffMutation } from "./capabilityOff";

const TEAM_SNAPSHOT_MUTATIONS = [
  ["confirm_team_snapshot_import", "team snapshots need the desktop app"],
  ["encode_team_snapshot_for_send", "team snapshots need the desktop app"],
  ["export_team_snapshot", "team snapshots need the desktop app"],
  ["preview_team_snapshot_import", "team snapshots need the desktop app"],
] as const;

const TEMPLATE_MUTATIONS = [
  ["create_channel_template", "channel templates need the desktop app"],
  ["delete_channel_template", "channel templates need the desktop app"],
  ["duplicate_channel_template", "channel templates need the desktop app"],
  ["update_channel_template", "channel templates need the desktop app"],
] as const;

const PERSONA_MUTATIONS = [
  ["create_persona", "personas need the desktop app"],
  ["delete_persona", "personas need the desktop app"],
  ["reconcile_inbound_persona_event", "persona sync needs the desktop app"],
  ["set_persona_active", "personas need the desktop app"],
  ["set_persona_shared", "persona sharing needs the desktop app"],
  ["update_persona", "personas need the desktop app"],
  ["update_persona_and_publish", "persona sharing needs the desktop app"],
] as const;

const TEAM_MUTATIONS = [
  ["create_team", "teams need the desktop app"],
  ["delete_team", "teams need the desktop app"],
  ["update_team", "teams need the desktop app"],
] as const;

const ARCHIVE_MUTATIONS = [
  ["create_save_subscription", "local archive needs the desktop app"],
  ["delete_save_subscription", "local archive needs the desktop app"],
  ["index_observer_channel_id", "local archive needs the desktop app"],
  ["merge_save_subscription_kinds", "local archive needs the desktop app"],
  ["remove_save_subscription_kind", "local archive needs the desktop app"],
] as const;

const ARCHIVE_ARRAY_READS = [
  "read_archived_observer_events_for_channel",
  "read_unindexed_observer_rows",
] as const;

const DESKTOP_LOCAL_ARRAY_READS = [
  "list_channel_templates",
  "list_personas",
  "list_save_subscriptions",
  "list_teams",
] as const;

function registerMutations(
  commands: readonly (readonly [string, string])[],
): void {
  for (const [command, hint] of commands) {
    registerOffMutation(command, hint);
  }
}

export function registerRelaySocialConfigCommands(
  _identity: BrowserIdentityManager,
): void {
  // Team snapshot mutations require native codecs, files, and local state.
  registerMutations(TEAM_SNAPSHOT_MUTATIONS);

  // Channel template mutations persist desktop-local template records.
  registerMutations(TEMPLATE_MUTATIONS);

  // Persona mutations manage native runtime files and publication state.
  registerMutations(PERSONA_MUTATIONS);

  // Team mutations manage native team and plugin state.
  registerMutations(TEAM_MUTATIONS);

  // Local archive mutations require the native SQLite archive.
  registerMutations(ARCHIVE_MUTATIONS);

  // Desktop-local reads are inert in the browser and return fresh arrays.
  for (const command of [
    ...ARCHIVE_ARRAY_READS,
    ...DESKTOP_LOCAL_ARRAY_READS,
  ]) {
    register(command, () => []);
  }

  // The browser has no local archive capability, so the default is disabled.
  register("observer_archive_default_enabled", () => false);
}
