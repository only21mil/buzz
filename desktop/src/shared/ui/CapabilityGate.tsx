import type { ReactNode } from "react";
import { Capability, useCapability } from "@/platform/web/capabilities";

const CAPABILITY_MESSAGE: Record<Capability, string> = {
  [Capability.Terminal]: "Open Buzz desktop to use a terminal.",
  [Capability.Mesh]: "Open Buzz desktop to manage compute sharing.",
  [Capability.LocalGit]: "Open Buzz desktop to manage local repositories.",
  [Capability.Pairing]:
    "Open Buzz desktop to pair another device. You can also sign in with your recovery key.",
  [Capability.Transcode]: "Open Buzz desktop to convert media.",
  [Capability.LocalArchive]: "Open Buzz desktop to manage your local archive.",
  [Capability.LinkPreview]: "Link previews are unavailable here.",
  [Capability.HuddleAudio]: "Open Buzz desktop to start or join a huddle.",
  [Capability.AddCommunity]: "Adding a community is unavailable here.",
  [Capability.HostedCommunities]:
    "Open Buzz desktop to sign in and create or manage hosted communities. You can join an existing community in this browser using its address.",
  [Capability.ManagedAgents]: "Open Buzz desktop to configure and run agents.",
};

/** Keep unavailable feature effects and controls unmounted. */
export function CapabilityGate({
  capability,
  children,
  fallback,
}: {
  capability: Capability;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const available = useCapability(capability);
  return available ? (
    children
  ) : fallback !== undefined ? (
    fallback
  ) : (
    <p className="p-6 text-sm text-muted-foreground" role="status">
      {CAPABILITY_MESSAGE[capability]}
    </p>
  );
}
