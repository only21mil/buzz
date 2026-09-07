import { useIdentityQuery } from "@/shared/api/hooks";
import { getCachedRelayOrigin } from "@/shared/lib/mediaUrl";

/** The relay and signer shared by collection reads and mutation callbacks. */
export function useProjectCollectionScope() {
  const identity = useIdentityQuery();
  const relayOrigin = getCachedRelayOrigin();
  return relayOrigin && identity.data?.pubkey
    ? { relayOrigin, pubkey: identity.data.pubkey }
    : null;
}
