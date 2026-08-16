import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { BrowserUnavailableError } from "./capabilityOff.ts";
import { registerHuddleVoiceTtsCommands } from "./huddleVoiceTts.ts";
import {
  CapabilityUnavailableError,
  dispatch,
  getUnregisteredCommandMissCount,
  resetRegistryForTests,
} from "../registry.ts";

const THROW_COMMANDS = [
  "add_agent_to_huddle",
  "close_huddle_companion",
  "confirm_huddle_active",
  "delete_pocket_voice",
  "end_huddle",
  "import_pocket_voice",
  "interrupt_huddle_speech",
  "join_huddle",
  "leave_huddle",
  "open_huddle_window",
  "preview_pocket_voice",
  "reconnect_huddle_audio",
  "remove_agent_from_huddle",
  "set_audio_output_device",
  "set_huddle_manual_mic_unmuted",
  "set_huddle_transcription_enabled",
  "set_pocket_voice",
  "set_tts_enabled",
  "set_voice_input_mode",
  "speak_agent_message",
  "start_huddle",
];

const READ_CASES = [
  { command: "ensure_huddle_agent_voice_settings", expected: {}, fresh: true },
  { command: "get_huddle_agent_pubkeys", expected: [], fresh: true },
  {
    command: "get_tts_settings",
    expected: {
      version: 1,
      agentTextToSpeech: false,
      voicePreferences: [],
    },
    fresh: true,
  },
  { command: "get_voice_input_mode", expected: "push_to_talk", fresh: false },
  { command: "list_voice_registry", expected: [], fresh: true },
  {
    command: "sync_agents_to_active_huddle",
    expected: undefined,
    fresh: false,
  },
];

afterEach(() => resetRegistryForTests());

test("registers every huddle and voice PAL command", async () => {
  registerHuddleVoiceTtsCommands();

  for (const command of THROW_COMMANDS) {
    await assert.rejects(
      dispatch(command),
      (error) =>
        error instanceof BrowserUnavailableError &&
        error instanceof CapabilityUnavailableError &&
        error.name === "BrowserUnavailableError",
    );
  }

  for (const { command, expected, fresh } of READ_CASES) {
    const first = await dispatch(command);
    const second = await dispatch(command);
    assert.deepEqual(first, expected, `${command} first result`);
    assert.deepEqual(second, expected, `${command} second result`);
    if (fresh) assert.notStrictEqual(first, second, `${command} fresh result`);
  }

  assert.equal(getUnregisteredCommandMissCount(), 0);
});
