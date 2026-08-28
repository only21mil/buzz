import { relayClient } from "@/shared/api/relayClient";
import { toast } from "sonner";
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
import { registerRelayMembershipStatusCommands } from "./relayMembershipStatus";
import { registerRelayMessageReadCommands } from "./relayMessageReads";
import { registerRelayQueryCommands } from "./relayQueries";
import { registerWorkflowRunCommands } from "./relayWorkflowRuns";
import { registerWorkflowApprovalCommands } from "./relayWorkflowApprovals";
import { installMediaAuthServiceWorker } from "./mediaAuth";
import { registerMediaCommands } from "./mediaUpload";
import {
  createOfflineMessagePublisher,
  OFFLINE_MESSAGE_STATUS_EVENT,
  type OfflineMessageDeliveryStatus,
  OfflineMessageRetryDriver,
} from "./offlineMessageOutbox";
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
  const workspace = new BrowserWorkspace();
  registerWorkspaceCommands(workspace, identity);
  let wakeMessageOutbox = () => {};
  const messagePublisher = createOfflineMessagePublisher(
    () => ({ relayUrl: workspace.wsUrl(), pubkey: identity.pubkey() }),
    relayClient,
    undefined,
    () => wakeMessageOutbox(),
  );
  window.addEventListener(OFFLINE_MESSAGE_STATUS_EVENT, (rawEvent) => {
    const status = (rawEvent as CustomEvent<OfflineMessageDeliveryStatus>)
      .detail;
    if (
      !status ||
      status.pubkey !== identity.pubkey() ||
      status.relayUrl !== workspace.wsUrl()
    ) {
      return;
    }
    const id = `offline-message:${status.eventId}`;
    if (status.state === "queued") {
      toast.info("Message queued for delivery", { id });
    } else if (status.state === "delivered") {
      toast.success("Queued message delivered", { id });
    } else if (status.state === "expired") {
      toast.error("Queued message expired before delivery", { id });
    } else {
      toast.error("Queued message could not be delivered", { id });
    }
  });
  registerRelayQueryCommands(identity, relayClient, messagePublisher);
  const messageOutboxRetryDriver = new OfflineMessageRetryDriver(
    () => messagePublisher.flush(),
    {
      onError: (error) => {
        console.warn("Unable to flush the offline message outbox", error);
      },
    },
  );
  wakeMessageOutbox = () => messageOutboxRetryDriver.wake();
  const flushMessageOutbox = () => messageOutboxRetryDriver.wake();
  const flushVisibleMessageOutbox = () => {
    if (document.visibilityState === "visible") flushMessageOutbox();
  };
  window.addEventListener("online", flushMessageOutbox);
  window.addEventListener("focus", flushMessageOutbox);
  document.addEventListener("visibilitychange", flushVisibleMessageOutbox);
  relayClient.subscribeToReconnects(flushMessageOutbox);
  flushMessageOutbox();
  registerMessageMutationCommands(identity);
  registerRelayChannelAdminCommands(identity);
  registerRelayDiscoveryCommands();
  registerRelayMembershipCommands(identity);
  registerRelayMembershipStatusCommands(workspace, identity, relayClient);
  registerRelayMessageReadCommands();
  registerRelayPeopleCommands(identity);
  registerRelayDmCommands(identity);
  registerRelayCanvasCommands(identity);
  registerRelaySocialCommands(identity);
  registerMediaCommands(workspace);
  registerTerminalGitMeshPairingCommands();
  registerRepoSnapshotCommands(identity);
  registerHuddleVoiceTtsCommands();
  registerAgentsRuntimeBuilderlabCommands();
  registerWorkflowApprovalCommands(identity, relayClient);
  registerRelaySocialConfigCommands(identity);
  registerRelayWorkflowsMembersCommands(identity);
  registerWorkflowRunCommands();
  registerRelayCryptoSocialCommands(identity);
  registerWebMediaTransferCommands(workspace);
  registerLinkPreviewCommands();
  await installMediaAuthServiceWorker(workspace);
}
