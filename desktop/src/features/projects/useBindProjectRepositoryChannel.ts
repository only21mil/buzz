import { projectCollectionMutationOptions } from "./projectCollectionMutation";
import type { ProjectCollectionScope } from "./projectCollectionScope";
import { useProjectCollectionScope } from "./useProjectCollectionScope";
import {
  type QueryClient,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";

import type { Repository } from "@/features/projects/hooks";
import { eventToRepository } from "@/features/projects/projectModels";
import { buildRepositoryChannelBindingTemplate } from "@/features/projects/projectRepositoryCreation";
import { inheritProjectDataProvenance } from "@/features/projects/projectSnapshot";
import { relayClient } from "@/shared/api/relayClient";
import { signRelayEvent } from "@/shared/api/tauri";
import { getIdentity } from "@/shared/api/tauriIdentity";
import { getCachedRelayOrigin } from "@/shared/lib/mediaUrl";

type BindProjectRepositoryChannelInput = {
  channelId: string;
  repository: Repository;
};

async function bindProjectRepositoryChannel({
  channelId,
  repository,
}: BindProjectRepositoryChannelInput): Promise<Repository> {
  const identity = await getIdentity();
  const template = buildRepositoryChannelBindingTemplate({
    channelId,
    ownerPubkey: identity.pubkey,
    repository,
  });
  const event = await signRelayEvent({
    ...template,
    createdAt: Math.max(
      Math.floor(Date.now() / 1_000),
      repository.createdAt + 1,
    ),
  });
  await relayClient.publishEvent(
    event,
    "Timed out repairing repository access.",
    "Failed to repair repository access.",
  );

  const updated = eventToRepository(event, getCachedRelayOrigin());
  if (!updated) {
    throw new Error("Repository access was repaired but could not be read.");
  }
  return updated;
}

/** Applies a binding to its captured collection without promoting snapshot rows. */
export function bindProjectRepositoryChannelMutationOptions(
  queryClient: QueryClient,
  scope: ProjectCollectionScope | null,
  mutationFn = bindProjectRepositoryChannel,
) {
  return projectCollectionMutationOptions(
    queryClient,
    scope,
    mutationFn,
    (current, repository) =>
      current.map((project) =>
        project.repositories.some(
          (candidate) => candidate.repoAddress === repository.repoAddress,
        )
          ? inheritProjectDataProvenance(project, {
              ...project,
              repositories: project.repositories.map((candidate) =>
                candidate.repoAddress === repository.repoAddress
                  ? repository
                  : candidate,
              ),
            })
          : project,
      ),
  );
}

export function useBindProjectRepositoryChannelMutation() {
  const queryClient = useQueryClient();
  const scope = useProjectCollectionScope();
  return useMutation(
    bindProjectRepositoryChannelMutationOptions(queryClient, scope),
  );
}
