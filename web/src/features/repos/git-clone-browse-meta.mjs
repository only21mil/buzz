/**
 * Shared clone status for git browse hooks.
 *
 * `ensureClone` can return a cached tree when refresh fails; browse hooks
 * surface that through these fields instead of failing the whole page.
 */

/** @typedef {{ stale?: boolean, fetchError?: unknown }} CloneData */

/**
 * @param {CloneData | undefined} cloneData
 * @param {unknown} cloneError
 * @param {boolean} isCloneLoading
 */
export function gitCloneBrowseMeta(cloneData, cloneError, isCloneLoading) {
  return {
    cloneError: cloneError ?? null,
    isCloneLoading: Boolean(isCloneLoading),
    isCloneStale: cloneData?.stale === true,
    cloneFetchError: cloneData?.fetchError ?? null,
  };
}

/** @param {unknown} fetchError */
export function cloneFetchErrorMessage(fetchError) {
  if (fetchError instanceof Error) return fetchError.message;
  if (typeof fetchError === "string" && fetchError.length > 0)
    return fetchError;
  return null;
}
