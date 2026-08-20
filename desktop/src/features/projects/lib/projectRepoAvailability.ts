export type ProjectRepoUnavailableReason =
  | "missing"
  | "access"
  | "unbound"
  | "authentication"
  | "network"
  | "ref"
  | "browser"
  | "unknown";

/** Copy for the `browser` reason, shared by the files, activity and README surfaces. */
export const BROWSER_REPOSITORY_UNAVAILABLE_MESSAGE =
  "README, files, and commits aren’t available in the web app yet — branches, issues, and pull requests are. Open this repository in the Buzz desktop app to browse its contents.";

export function projectRepoUnavailableReason(
  error: unknown,
): ProjectRepoUnavailableReason {
  const message =
    error instanceof Error
      ? error.message.toLowerCase()
      : typeof error === "string"
        ? error.toLowerCase()
        : "";

  if (!message) return "missing";
  // The browser build has no git client yet; its PAL rejects repository
  // snapshot reads with BrowserUnavailableError (see platform/web/desktopOnly).
  if (/not available in the browser build/.test(message)) return "browser";
  // The relay's author-only unbound-repository remediation ("run: buzz repos
  // bind … has no channel binding, so the relay cannot authorize access") must
  // win over the generic authentication match below.
  if (/has no channel binding|buzz repos bind/.test(message)) return "unbound";
  if (
    /\b(?:401|403)\b|authenticat|authoriz|permission denied|access denied/.test(
      message,
    )
  ) {
    return "authentication";
  }
  if (
    /\b404\b|repository not found|repository does not exist|not found on the relay/.test(
      message,
    )
  ) {
    return "missing";
  }
  if (
    /remote branch .* not found|could not resolve the requested repository ref|the requested repository ref changed|couldn't find remote ref/.test(
      message,
    )
  ) {
    return "ref";
  }
  if (
    /remote helper .* aborted session|error while loading shared libraries|version `openssl/.test(
      message,
    )
  ) {
    return "network";
  }
  if (
    /timed? out|could not resolve host|failed to connect|connection (?:refused|reset)|network is unreachable|offline/.test(
      message,
    )
  ) {
    return "network";
  }
  return "unknown";
}

/**
 * The relay deliberately answers channel-ACL denials with the same 404 as a
 * genuinely absent repository (SEC-005 anti-enumeration), so the git error
 * alone cannot distinguish "never initialized" from "you have no access".
 * The announcement events ARE visible to every relay member though, so the
 * client can re-classify a `missing` result using the repository's
 * `buzz-channel` binding and the viewer's own channel memberships:
 *
 * - no binding at all → `unbound` (the relay refuses access for everyone
 *   until the owner binds a channel)
 * - bound to a channel the viewer is not a member of → `access`
 * - bound to a channel the viewer IS a member of → keep `missing` (the
 *   repository truly has no git data pointer on the relay)
 *
 * `memberChannelIds === null` means memberships are still loading — the
 * reason is left untouched rather than guessed.
 */
export function refineRepoUnavailableReason(input: {
  reason: ProjectRepoUnavailableReason;
  repositoryChannelId: string | null | undefined;
  memberChannelIds: readonly string[] | null;
}): ProjectRepoUnavailableReason {
  if (input.reason !== "missing") return input.reason;
  if (!input.repositoryChannelId) return "unbound";
  if (input.memberChannelIds === null) return input.reason;
  return input.memberChannelIds.includes(input.repositoryChannelId)
    ? input.reason
    : "access";
}
