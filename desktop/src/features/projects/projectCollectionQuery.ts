import type { RelayEvent } from "@/shared/api/types";
import {
  buildProjectsFromFetcher,
  fetchProjectEventsExhaustively,
  type FetchProjectEventsExhaustively,
} from "./projectEnumeration";
import {
  readProjectSnapshot,
  writeProjectSnapshot,
  type ProjectSnapshotScope,
} from "./projectSnapshot";

// Retain the fork's existing freshness interval until relay trials justify changing it.
export const PROJECTS_STALE_TIME_MS = 60_000;
export function projectCollectionQueryKey(scope: ProjectSnapshotScope | null) {
  return [
    "projects",
    "collection",
    scope?.relayOrigin ?? "",
    scope?.pubkey.toLowerCase() ?? "",
  ] as const;
}

export function projectCollectionQueryOptions(
  scope: ProjectSnapshotScope | null,
  deps: {
    fetchExhaustively?: FetchProjectEventsExhaustively;
    storage?: Storage;
    hiddenAddresses?: Set<string>;
  } = {},
) {
  return {
    enabled: !!scope,
    queryKey: projectCollectionQueryKey(scope),
    queryFn: async ({ signal }: { signal: AbortSignal }) => {
      if (!scope) throw new Error("Project identity is not ready.");
      const events = new Map<string, RelayEvent>();
      const projects = await buildProjectsFromFetcher(
        async (kinds, filter) => {
          signal.throwIfAborted();
          const rows = deps.fetchExhaustively
            ? await deps.fetchExhaustively(kinds, filter)
            : await fetchProjectEventsExhaustively(
                kinds,
                filter,
                undefined,
                signal,
              );
          for (const event of rows) events.set(event.id, event);
          return rows;
        },
        {
          relayOrigin: scope.relayOrigin,
          hiddenAddresses: deps.hiddenAddresses,
        },
      );
      signal.throwIfAborted();
      writeProjectSnapshot(scope, [...events.values()], deps.storage);
      return projects;
    },
    initialData: () =>
      scope
        ? readProjectSnapshot(scope, deps.storage)?.filter(
            (project) => !deps.hiddenAddresses?.has(project.projectAddress),
          )
        : undefined,
    initialDataUpdatedAt: 0,
    // A live read must replace non-serialized snapshot provenance.
    structuralSharing: false as const,
    staleTime: PROJECTS_STALE_TIME_MS,
  };
}
