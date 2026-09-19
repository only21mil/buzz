import type { QueryClient } from "@tanstack/react-query";
import type { fetchProjects } from "./projectFetch";
import { PROJECTS_QUERY_KEY, getProjectSnapshotScope } from "./projectSnapshot";
import {
  projectCollectionQueryKey,
  type ProjectCollectionScope,
} from "./projectCollectionScope";
export { projectCollectionQueryKey } from "./projectCollectionScope";
import {
  markProjectCollectionAuthoritative,
  persistProjectSnapshot,
  PROJECT_QUERY_STRUCTURAL_SHARING,
} from "./projectSnapshot";

/** Shares a provenance-aware collection within the community query client. */
export function projectCollectionQueryOptions(
  queryClient: QueryClient,
  fetchProjectsFn: typeof fetchProjects = async (...args) =>
    (await import("./projectFetch")).fetchProjects(...args),
  scope: ProjectCollectionScope | null | undefined = getProjectSnapshotScope(
    queryClient,
  ),
) {
  return {
    enabled: scope !== null,
    queryKey:
      scope === undefined
        ? PROJECTS_QUERY_KEY
        : projectCollectionQueryKey(scope),
    queryFn: async ({ signal }: { signal: AbortSignal }) => {
      if (scope === null) throw new Error("Project identity is not ready.");
      const projects = await fetchProjectsFn(undefined, signal, scope);
      signal.throwIfAborted();
      markProjectCollectionAuthoritative(queryClient, scope);
      persistProjectSnapshot(queryClient, projects, scope);
      return projects;
    },
    structuralSharing: PROJECT_QUERY_STRUCTURAL_SHARING,
    staleTime: 5 * 60_000,
    gcTime:
      typeof window === "undefined" ? Number.POSITIVE_INFINITY : 30 * 60_000,
  };
}
