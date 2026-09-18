import { normalizePubkey } from "@/shared/lib/pubkey";

/** Presentation provenance only; neither hosting location nor availability. */
export function isOwnedAgentNotManagedOnDevice({
  currentPubkey,
  ownerPubkey,
  localInventoryReady,
  isLocallyManaged,
}: {
  currentPubkey?: string;
  ownerPubkey?: string | null;
  localInventoryReady: boolean;
  isLocallyManaged: boolean;
}): boolean {
  return Boolean(
    localInventoryReady &&
      !isLocallyManaged &&
      currentPubkey &&
      ownerPubkey &&
      normalizePubkey(ownerPubkey) === normalizePubkey(currentPubkey),
  );
}
