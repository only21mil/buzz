import type { QueryClient } from "@tanstack/react-query";
import type { Project } from "./projectModels";
import { deleteProject } from "./projectDeletion";
import { projectCollectionMutationOptions } from "./projectCollectionMutation";
import type { ProjectCollectionScope } from "./projectCollectionScope";
export const projectsQueryKey = ["projects"] as const;

/** Refreshes the captured collection even when a publication acknowledgement is lost. */
export function projectDeletionMutationOptions(
  queryClient: QueryClient,
  scope: ProjectCollectionScope | null,
  deleteProjectFn: (project: Project) => Promise<void> = deleteProject,
) {
  return projectCollectionMutationOptions(
    queryClient,
    scope,
    deleteProjectFn,
    (current, _data, project) =>
      current.filter((item) => item.id !== project.id),
  );
}
