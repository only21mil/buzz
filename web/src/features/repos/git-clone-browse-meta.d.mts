import type { EnsureCloneResult } from "./git-client";

export interface GitCloneBrowseMeta {
  cloneError: unknown;
  isCloneLoading: boolean;
  isCloneStale: boolean;
  cloneFetchError: unknown;
}

export function gitCloneBrowseMeta(
  cloneData: EnsureCloneResult | undefined,
  cloneError: unknown,
  isCloneLoading: boolean,
): GitCloneBrowseMeta;

export function cloneFetchErrorMessage(fetchError: unknown): string | null;
