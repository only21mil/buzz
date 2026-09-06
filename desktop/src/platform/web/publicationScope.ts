import {
  assertPublicationScope,
  type PublicationScope,
} from "@/shared/api/publicationScope";
import type { BrowserIdentityManager } from "./identity";

/** Validate optional legacy command scope before the browser signer is used. */
export function expectedPublicationScope(
  value: unknown,
  identity: BrowserIdentityManager,
): PublicationScope | undefined {
  if (value == null) return undefined;
  if (
    typeof value !== "object" ||
    !("pubkey" in value) ||
    !("relayUrl" in value) ||
    !("generation" in value) ||
    typeof value.pubkey !== "string" ||
    typeof value.relayUrl !== "string" ||
    typeof value.generation !== "number"
  )
    throw new Error("Invalid message publication scope.");
  const scope = value as PublicationScope;
  assertPublicationScope(scope);
  if (identity.pubkey() !== scope.pubkey)
    throw new Error("Message signer changed before publication.");
  return scope;
}
