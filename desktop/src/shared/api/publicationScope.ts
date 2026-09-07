/** Immutable authority for an authored send; route navigation keeps this scope. */
export type PublicationScope = Readonly<{
  pubkey: string;
  relayUrl: string;
  generation: number;
  nativeEpoch?: number;
}>;

let current: PublicationScope = Object.freeze({
  pubkey: "",
  relayUrl: "",
  generation: 0,
});

/** Called by the identity/community draft lifecycle, including explicit reset. */
export function setPublicationScope(
  pubkey: string,
  relayUrl: string,
  reset = false,
): void {
  if (reset || current.pubkey !== pubkey || current.relayUrl !== relayUrl) {
    current = Object.freeze({
      pubkey,
      relayUrl,
      generation: current.generation + 1,
    });
  }
}

/** Capture before the first asynchronous preparation step. */
export function capturePublicationScope(): PublicationScope {
  return current;
}

/** Returning to the same identity/relay does not revive an old authored send. */
export function isPublicationScopeCurrent(scope: PublicationScope): boolean {
  return (
    scope.generation === current.generation &&
    scope.pubkey === current.pubkey &&
    scope.relayUrl === current.relayUrl
  );
}

/** Reject stale continuations before signing or handing an event to transport. */
export function assertPublicationScope(scope: PublicationScope): void {
  if (!isPublicationScopeCurrent(scope))
    throw new Error(
      "Message cancelled because the identity or community changed.",
    );
}

/** Compare canonical relay origins while preserving path and query case. */
export function assertPublicationRelay(
  scope: PublicationScope,
  relayUrl: string | null,
): void {
  assertPublicationScope(scope);
  const canonical = (value: string) =>
    new URL(value.trim().replace(/\/+$/, "")).toString().replace(/\/+$/, "");
  if (!relayUrl || canonical(relayUrl) !== canonical(scope.relayUrl))
    throw new Error("Message relay changed before publication.");
}

/** The completed signature must belong to the authored scope as well. */
export function assertPublicationSigner(
  scope: PublicationScope,
  pubkey: string,
): void {
  assertPublicationScope(scope);
  if (pubkey !== scope.pubkey)
    throw new Error("Message signer changed before publication.");
}
