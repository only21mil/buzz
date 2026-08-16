import { registerNoopCommands } from "./noops";
import { registerAgentsRuntimeBuilderlabCommands } from "./desktopOnly/agentsRuntimeBuilderlab";
import { registerHuddleVoiceTtsCommands } from "./desktopOnly/huddleVoiceTts";
import { registerRelayCryptoSocialCommands } from "./desktopOnly/relayCryptoSocial";
import { registerRelaySocialConfigCommands } from "./desktopOnly/relaySocialConfig";
import { registerRelayWorkflowsMembersCommands } from "./desktopOnly/relayWorkflowsMembers";
import { registerRepoSnapshotCommands } from "./desktopOnly/repoSnapshot";
import { registerTerminalGitMeshPairingCommands } from "./desktopOnly/terminalGitMeshPairing";
import { BrowserIdentityManager, registerIdentityCommands } from "./identity";
import { registerMessageMutationCommands } from "./messageMutations";
import { registerRelayChannelAdminCommands } from "./relayChannelAdmin";
import { registerRelayDiscoveryCommands } from "./relayDiscovery";
import { registerRelayMembershipCommands } from "./relayMembership";
import { registerRelayMessageReadCommands } from "./relayMessageReads";
import { registerRelayQueryCommands } from "./relayQueries";
import { installMediaAuthServiceWorker } from "./mediaAuth";
import { registerMediaCommands } from "./mediaUpload";
import { registerOnboardingCommands } from "./onboarding";
import { registerRelayCanvasCommands } from "./relayCanvas";
import { registerRelayDmCommands } from "./relayDms";
import { registerRelayPeopleCommands } from "./relayPeople";
import { register } from "./registry";
import { registerRelaySocialCommands } from "./relaySocial";
import { registerLinkPreviewCommands } from "./webLinkPreview";
import { registerWebMediaTransferCommands } from "./webMediaTransfer";
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
  register("get_audio_output_device", () => ""); // "" = system default
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
  registerOnboardingCommands();
  registerWebSocketCommands();
  const identity = await BrowserIdentityManager.create();
  registerIdentityCommands(identity);
  registerWorkspaceCommands(new BrowserWorkspace(), identity);
  registerRelayQueryCommands(identity);
  registerMessageMutationCommands(identity);
  registerRelayChannelAdminCommands(identity);
  registerRelayDiscoveryCommands();
  registerRelayMembershipCommands(identity);
  registerRelayMessageReadCommands();
  registerRelayPeopleCommands(identity);
  registerRelayDmCommands(identity);
  registerRelayCanvasCommands(identity);
  registerRelaySocialCommands(identity);
  registerMediaCommands();
  registerTerminalGitMeshPairingCommands();
  registerRepoSnapshotCommands(identity);
  registerHuddleVoiceTtsCommands();
  registerAgentsRuntimeBuilderlabCommands();
  registerRelaySocialConfigCommands(identity);
  registerRelayWorkflowsMembersCommands(identity);
  registerRelayCryptoSocialCommands(identity);
  registerWebMediaTransferCommands();
  registerLinkPreviewCommands();
  await installMediaAuthServiceWorker();
}
