import { isTauri } from "@tauri-apps/api/core";
import { invokeTauri } from "./tauri";
import {
  assertPublicationRelay,
  assertPublicationScope,
  assertPublicationSigner,
  type PublicationScope,
} from "./publicationScope";

/** Bind native authority before renderer preparation; browser signing shares its renderer epoch. */
export async function preparePublicationScope(
  scope: PublicationScope,
): Promise<PublicationScope> {
  assertPublicationScope(scope);
  if (!isTauri() || scope.nativeEpoch !== undefined) return scope;
  const native = await invokeTauri<{
    pubkey: string;
    relayUrl: string;
    nativeEpoch: number;
  }>("get_message_publication_scope");
  assertPublicationScope(scope);
  if (!Number.isSafeInteger(native.nativeEpoch) || native.nativeEpoch < 0)
    throw new Error("Invalid native publication epoch.");
  assertPublicationSigner(scope, native.pubkey);
  assertPublicationRelay(scope, native.relayUrl);
  return Object.freeze({ ...scope, nativeEpoch: native.nativeEpoch });
}
