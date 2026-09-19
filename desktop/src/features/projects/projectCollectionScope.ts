export type ProjectCollectionScope = { relayOrigin: string; pubkey: string };

/** Identifies a collection without matching local repository or activity queries. */
export function projectCollectionQueryKey(
  scope: ProjectCollectionScope | null,
) {
  return [
    "projects",
    "collection",
    scope ? normalizeProjectCollectionOrigin(scope.relayOrigin) : "",
    scope?.pubkey.toLowerCase() ?? "",
  ] as const;
}

/** Uses the same origin for startup WebSocket URLs and resolved HTTP URLs. */
export function normalizeProjectCollectionOrigin(relayUrl: string): string {
  const url = new URL(relayUrl);
  if (url.protocol === "wss:") url.protocol = "https:";
  if (url.protocol === "ws:") url.protocol = "http:";
  return url.origin;
}
