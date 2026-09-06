import type { QueryClient } from "@tanstack/react-query";
import type { Project } from "./projectModels";
import { deleteProject } from "./projectDeletion";
import { projectCollectionMutationOptions } from "./projectCollectionMutation";
import type { ProjectSnapshotScope } from "./projectSnapshot";

/** Refresh uncertain deletions and remove confirmed deletions from their scope. */
export function projectDeletionMutationOptions(
  queryClient: QueryClient,
  scope: ProjectSnapshotScope | null,
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
