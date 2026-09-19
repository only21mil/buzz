import { projectCollectionMutationOptions } from "./projectCollectionMutation";
import type { ProjectCollectionScope } from "./projectCollectionScope";
import { useProjectCollectionScope } from "./useProjectCollectionScope";
import * as React from "react";
import {
  type QueryClient,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

import {
  channelsQueryKey,
  upsertCachedChannel,
} from "@/features/channels/hooks";
import { useApplyTemplate } from "@/features/channel-templates/useApplyTemplate";

import {
  createProject,
  type CreateProjectInput,
  type CreateProjectResult,
  type CreateProjectResumeState,
} from "@/features/projects/createProject";
import { addProjectToSidebar } from "@/features/projects/lib/projectSidebarMembership";
import {
  applyProjectHomeCanvas,
  PROJECT_HOME_TEMPLATE_ID,
} from "@/features/projects/lib/projectHomeTemplate";
import { markProjectDataAuthoritative } from "@/features/projects/projectSnapshot";
import type { Channel } from "@/shared/api/types";
import { getCachedRelayOrigin } from "@/shared/lib/mediaUrl";

export type { CreateProjectInput, CreateProjectResult };

/** Inserts a confirmed creation into the collection captured at submission. */
export function createProjectMutationOptions(
  queryClient: QueryClient,
  scope: ProjectCollectionScope | null,
  mutationFn: (input: CreateProjectInput) => Promise<CreateProjectResult>,
) {
  return projectCollectionMutationOptions(
    queryClient,
    scope,
    mutationFn,
    (current, { project }) => {
      markProjectDataAuthoritative(project, "local-write");
      return [
        project,
        ...current.filter(
          (candidate) =>
            candidate.id !== project.id &&
            !(
              candidate.legacy &&
              candidate.owner === project.owner &&
              candidate.dtag === project.dtag
            ),
        ),
      ];
    },
  );
}

/** Mutation that creates a project home and inserts it into the caches. */
export function useCreateProjectMutation() {
  const queryClient = useQueryClient();
  const scope = useProjectCollectionScope();
  const { applyAgents, applyCanvas } = useApplyTemplate();
  const resumeRef = React.useRef<CreateProjectResumeState>({
    channels: new Map(),
    projectIds: new Set(),
  });

  const options = createProjectMutationOptions(queryClient, scope, (input) =>
    createProject(input, resumeRef.current),
  );
  return useMutation({
    ...options,
    onSuccess: async (result, input, key) => {
      options.onSuccess(result, input, key);
      const { channel, project } = result;
      markProjectDataAuthoritative(project, "local-write");
      addProjectToSidebar(
        project.projectAddress,
        key?.[2] ?? getCachedRelayOrigin(),
        project.owner,
      );
      if (channel) {
        queryClient.setQueryData(
          channelsQueryKey,
          (current: Channel[] | undefined) =>
            upsertCachedChannel(current, channel),
        );
        void queryClient.invalidateQueries({
          queryKey: channelsQueryKey,
          refetchType: "none",
        });
        const useProjectHomeTemplate =
          input.templateId === undefined ||
          input.templateId === PROJECT_HOME_TEMPLATE_ID;
        if (useProjectHomeTemplate) {
          const applied = await applyProjectHomeCanvas({
            channelId: channel.id,
            project,
          });
          if (!applied) {
            toast.warning(
              "Project created, but its project-home canvas could not be added.",
            );
          }
        } else if (input.templateId) {
          await Promise.all([
            applyCanvas(input.templateId, channel.id, channel.name),
            applyAgents(input.templateId, channel.id),
          ]);
        }
      }
    },
  });
}
