import type { QueryClient } from "@tanstack/react-query";
import type { fetchProjects } from "./projectFetch";
import { projectsQueryKey } from "./projectDeletionMutation";
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
) {
  return {
    queryKey: projectsQueryKey,
    queryFn: async ({ signal }: { signal: AbortSignal }) => {
      const projects = await fetchProjectsFn(undefined, signal);
      signal.throwIfAborted();
      markProjectCollectionAuthoritative(queryClient);
      persistProjectSnapshot(queryClient, projects);
      return projects;
    },
    structuralSharing: PROJECT_QUERY_STRUCTURAL_SHARING,
    staleTime: 5 * 60_000,
    gcTime:
      typeof window === "undefined" ? Number.POSITIVE_INFINITY : 30 * 60_000,
  };
}
