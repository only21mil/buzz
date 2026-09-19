import { useIdentityQuery } from "@/shared/api/hooks";
import { useRelayOrigin } from "@/shared/lib/useRelayOrigin";

import type { ProjectCollectionScope } from "./projectCollectionScope";

/** Waits for both parts of the active project collection identity. */
export function useProjectCollectionScope(): ProjectCollectionScope | null {
  const identity = useIdentityQuery();
  const relayOrigin = useRelayOrigin();
  return identity.data?.pubkey && relayOrigin
    ? { pubkey: identity.data.pubkey, relayOrigin }
    : null;
}
