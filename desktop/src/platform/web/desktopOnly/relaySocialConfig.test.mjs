import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { BrowserUnavailableError } from "./capabilityOff.ts";
import { registerRelaySocialConfigCommands } from "./relaySocialConfig.ts";
import {
  CapabilityUnavailableError,
  dispatch,
  getUnregisteredCommandMissCount,
  resetRegistryForTests,
} from "../registry.ts";

const THROW_COMMANDS = [
  "confirm_team_snapshot_import",
  "create_channel_template",
  "create_persona",
  "create_save_subscription",
  "create_team",
  "delete_channel_template",
  "delete_persona",
  "delete_save_subscription",
  "delete_team",
  "duplicate_channel_template",
  "encode_team_snapshot_for_send",
  "export_team_snapshot",
  "index_observer_channel_id",
  "merge_save_subscription_kinds",
  "preview_team_snapshot_import",
  "reconcile_inbound_persona_event",
  "remove_save_subscription_kind",
  "set_persona_active",
  "set_persona_shared",
  "update_channel_template",
  "update_persona",
  "update_persona_and_publish",
  "update_team",
];

const READ_COMMANDS = [
  ["get_workflow_runs", []],
  ["list_channel_templates", []],
  ["list_personas", []],
  ["list_save_subscriptions", []],
  ["list_teams", []],
  ["read_archived_observer_events_for_channel", []],
  ["read_unindexed_observer_rows", []],
  ["observer_archive_default_enabled", false],
];

afterEach(() => resetRegistryForTests());

test("relaySocialConfig registers every command with its browser behavior", async () => {
  registerRelaySocialConfigCommands({});

  for (const command of THROW_COMMANDS) {
    await assert.rejects(dispatch(command), (error) => {
      assert.equal(error.name, "BrowserUnavailableError");
      assert.ok(error instanceof BrowserUnavailableError);
      assert.ok(error instanceof CapabilityUnavailableError);
      return true;
    });
  }

  for (const [command, expected] of READ_COMMANDS) {
    const first = await dispatch(command);
    const second = await dispatch(command);
    assert.deepEqual(first, expected);
    assert.deepEqual(second, expected);
    if (Array.isArray(expected)) {
      assert.notStrictEqual(first, second);
    }
  }

  assert.equal(getUnregisteredCommandMissCount(), 0);
});
