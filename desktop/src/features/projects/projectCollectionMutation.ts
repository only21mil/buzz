import type { QueryClient } from "@tanstack/react-query";
import { projectCollectionQueryKey } from "./projectCollectionQuery";
import type { Project } from "./projectModels";
import type { ProjectSnapshotScope } from "./projectSnapshot";

/** Capture the collection at mutation start, including across hook rerenders. */
export function projectCollectionMutationOptions<Data, Variables>(
  queryClient: QueryClient,
  scope: ProjectSnapshotScope | null,
  mutationFn: (variables: Variables) => Promise<Data>,
  update: (current: Project[], data: Data, variables: Variables) => Project[],
) {
  return {
    mutationFn,
    onMutate: () => {
      if (!scope) throw new Error("Project identity is not ready.");
      return projectCollectionQueryKey(scope);
    },
    onSuccess: (
      data: Data,
      variables: Variables,
      key: ReturnType<typeof projectCollectionQueryKey> | undefined,
    ) => {
      if (key)
        queryClient.setQueryData<Project[]>(key, (current = []) =>
          update(current, data, variables),
        );
    },
    onSettled: (
      _data: Data | undefined,
      _error: Error | null,
      _variables: Variables,
      key: ReturnType<typeof projectCollectionQueryKey> | undefined,
    ) => {
      if (key)
        return queryClient.invalidateQueries({ queryKey: key, exact: true });
    },
  };
}
