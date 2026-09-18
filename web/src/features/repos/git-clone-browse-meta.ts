/**
 * Shared clone status for git browse hooks.
 *
 * `ensureClone` can return a cached tree when refresh fails; browse hooks
 * surface that through these fields instead of failing the whole page.
 */

import type { CloneResult } from "./git-client";

export interface GitCloneBrowseMeta {
  cloneError: unknown;
  isCloneLoading: boolean;
  isCloneStale: boolean;
  cloneFetchError: unknown;
}

export function gitCloneBrowseMeta(
  cloneData: Pick<CloneResult, "stale" | "fetchError"> | undefined,
  cloneError: unknown,
  isCloneLoading: boolean,
): GitCloneBrowseMeta {
  return {
    cloneError: cloneError ?? null,
    isCloneLoading: Boolean(isCloneLoading),
    isCloneStale: cloneData?.stale === true,
    cloneFetchError: cloneData?.fetchError ?? null,
  };
}

export function cloneFetchErrorMessage(fetchError: unknown): string | null {
  if (fetchError instanceof Error) return fetchError.message;
  if (typeof fetchError === "string" && fetchError.length > 0)
    return fetchError;
  return null;
}
