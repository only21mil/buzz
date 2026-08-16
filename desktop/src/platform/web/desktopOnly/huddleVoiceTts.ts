import { register } from "../registry";
import { registerOffMutation } from "./capabilityOff";

export function registerHuddleVoiceTtsCommands(): void {
  // Huddle lifecycle and companion-window mutations.
  registerOffMutation(
    "add_agent_to_huddle",
    "huddle membership needs the desktop app",
  );
  registerOffMutation(
    "close_huddle_companion",
    "huddle companion windows need the desktop app",
  );
  registerOffMutation(
    "confirm_huddle_active",
    "huddle audio needs the desktop app",
  );
  registerOffMutation("end_huddle", "huddle lifecycle needs the desktop app");
  registerOffMutation("join_huddle", "huddle audio needs the desktop app");
  registerOffMutation("leave_huddle", "huddle lifecycle needs the desktop app");
  registerOffMutation(
    "open_huddle_window",
    "huddle companion windows need the desktop app",
  );
  registerOffMutation(
    "reconnect_huddle_audio",
    "huddle audio needs the desktop app",
  );
  registerOffMutation(
    "remove_agent_from_huddle",
    "huddle membership needs the desktop app",
  );
  registerOffMutation("start_huddle", "huddle audio needs the desktop app");

  // Pocket voice settings and speech mutations.
  registerOffMutation(
    "delete_pocket_voice",
    "Pocket voice files need the desktop app",
  );
  registerOffMutation(
    "import_pocket_voice",
    "Pocket voice files need the desktop app",
  );
  registerOffMutation(
    "interrupt_huddle_speech",
    "huddle speech needs the desktop app",
  );
  registerOffMutation(
    "preview_pocket_voice",
    "Pocket voice preview needs the desktop app",
  );
  registerOffMutation(
    "set_pocket_voice",
    "Pocket voice settings need the desktop app",
  );
  registerOffMutation(
    "set_tts_enabled",
    "Pocket speech settings need the desktop app",
  );
  registerOffMutation(
    "speak_agent_message",
    "Pocket speech needs the desktop app",
  );

  // Huddle audio, input, and transcription mutations.
  registerOffMutation(
    "set_audio_output_device",
    "huddle audio devices need the desktop app",
  );
  registerOffMutation(
    "set_huddle_manual_mic_unmuted",
    "huddle microphone control needs the desktop app",
  );
  registerOffMutation(
    "set_huddle_transcription_enabled",
    "huddle transcription needs the desktop app",
  );
  registerOffMutation(
    "set_voice_input_mode",
    "huddle input modes need the desktop app",
  );

  // Browser-safe huddle and voice reads.
  register("ensure_huddle_agent_voice_settings", () => ({}));
  register("get_huddle_agent_pubkeys", () => []);
  register("get_tts_settings", () => ({
    version: 1,
    agentTextToSpeech: false,
    voicePreferences: [],
  }));
  register("get_voice_input_mode", () => "push_to_talk");
  register("list_voice_registry", () => []);

  // Agent enrollment is inert when no browser huddle is active.
  register("sync_agents_to_active_huddle", () => undefined);
}
