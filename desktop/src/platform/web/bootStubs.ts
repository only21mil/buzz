import { registerNoopCommands } from "./noops";
import { BrowserIdentityManager, registerIdentityCommands } from "./identity";
import { registerRelayQueryCommands } from "./relayQueries";
import { installMediaAuthServiceWorker } from "./mediaAuth";
import { registerMediaCommands } from "./mediaUpload";
import { register } from "./registry";
import { registerWebSocketCommands } from "./websocket";
import { BrowserWorkspace, registerWorkspaceCommands } from "./workspace";

export const INACTIVE_HUDDLE_STATE = {
  phase: "idle",
  parent_channel_id: null,
  ephemeral_channel_id: null,
  huddle_thread_event_id: null,
  participants: [],
  agent_pubkeys: [],
  agent_voice_settings: {},
  is_creator: false,
  tts_enabled: true,
  transcription_enabled: false,
  voice_input_mode: "push_to_talk",
} as const;

export function registerBootStubs(): void {
  register("get_os_idle_seconds", () => null);
  register("get_huddle_state", () => INACTIVE_HUDDLE_STATE);
  register("get_audio_output_device", () => null);
  register("list_audio_output_devices", () => []);
  register("check_pipeline_hotstart", () => undefined);
  register("is_shared_identity", () => false);
  register("read_clipboard_text", () => navigator.clipboard.readText());
  register("copy_text_to_clipboard", (body) => {
    const text =
      body &&
      !Array.isArray(body) &&
      !(body instanceof ArrayBuffer) &&
      !(body instanceof Uint8Array)
        ? body.text
        : undefined;
    if (typeof text !== "string") {
      throw new TypeError("copy_text_to_clipboard requires a text string");
    }
    return navigator.clipboard.writeText(text);
  });
}

export async function installBrowserPal(): Promise<void> {
  registerNoopCommands();
  registerBootStubs();
  registerWebSocketCommands();
  const identity = await BrowserIdentityManager.create();
  registerIdentityCommands(identity);
  registerWorkspaceCommands(new BrowserWorkspace(), identity);
  registerRelayQueryCommands(identity);
  registerMediaCommands();
  await installMediaAuthServiceWorker();
}
