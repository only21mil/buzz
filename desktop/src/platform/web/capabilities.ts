import * as React from "react";

export enum Capability {
  Terminal = "terminal",
  Mesh = "mesh",
  LocalGit = "local-git",
  Pairing = "pairing",
  Transcode = "transcode",
  LocalArchive = "local-archive",
  LinkPreview = "link-preview",
  HuddleAudio = "huddle-audio",
  AddCommunity = "add-community",
}

const availableCapabilities = new Set<Capability>();
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
    () => false,
  );
}
