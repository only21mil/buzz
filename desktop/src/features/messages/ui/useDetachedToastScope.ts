import { useLayoutEffect } from "react";
import { setDetachedToastScope } from "@/features/messages/lib/detachedToastScope";

/** Keep detached warnings bound to the applied shell and its current identity. */
export function useDetachedToastScope(
  relayUrl: string | undefined,
  signerPubkey: string | undefined,
): void {
  useLayoutEffect(
    () =>
      setDetachedToastScope({
        relayUrl: relayUrl ?? "",
        signerPubkey: signerPubkey ?? null,
      }),
    [relayUrl, signerPubkey],
  );
}
