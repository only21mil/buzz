import * as React from "react";

export const Capability = {
  Terminal: "terminal",
  Mesh: "mesh",
  LocalGit: "local-git",
  Pairing: "pairing",
  Transcode: "transcode",
  LocalArchive: "local-archive",
  LinkPreview: "link-preview",
  HuddleAudio: "huddle-audio",
  AddCommunity: "add-community",
  HostedCommunities: "hosted-communities",
  ManagedAgents: "managed-agents",
} as const;
export type Capability = (typeof Capability)[keyof typeof Capability];

// Desktop and the desktop test bridge keep their native capabilities. Browser
// startup begins closed until its PAL has installed the implemented features.
const availableCapabilities = new Set<Capability>(
  import.meta.env?.MODE === "web" ? [] : Object.values(Capability),
);

/** Set the browser contract before any feature UI is mounted. */
export function initializeBrowserCapabilities(): void {
  for (const capability of Object.values(Capability)) {
    setCapabilityAvailable(
      capability,
      capability === Capability.AddCommunity ||
        capability === Capability.LinkPreview,
    );
  }
}
const subscribers = new Set<() => void>();

export function isCapabilityAvailable(capability: Capability): boolean {
  return availableCapabilities.has(capability);
}

export function setCapabilityAvailable(
  capability: Capability,
  available: boolean,
): void {
  const changed = available
    ? !availableCapabilities.has(capability)
    : availableCapabilities.has(capability);
  if (!changed) return;

  if (available) availableCapabilities.add(capability);
  else availableCapabilities.delete(capability);
  for (const subscriber of subscribers) subscriber();
}

export function useCapability(capability: Capability): boolean {
  return React.useSyncExternalStore(
    (subscriber) => {
      subscribers.add(subscriber);
      return () => subscribers.delete(subscriber);
    },
    () => isCapabilityAvailable(capability),
    () => isCapabilityAvailable(capability),
  );
}
