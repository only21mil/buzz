import { getCachedRelayOrigin } from "@/shared/lib/mediaUrl";
import { isTauri } from "@tauri-apps/api/core";
import { relayClient } from "@/shared/api/relayClient";
import { createChannel } from "@/shared/api/tauriChannels";
import { signRelayEvent } from "@/shared/api/tauri";
import { getIdentity } from "@/shared/api/tauriIdentity";
import type { Channel, RelayEvent } from "@/shared/api/types";
import { fetchProjects } from "./hooks";
import { eventToExplicitProject, eventToRepository } from "./projectModels";
import { hasAuthoritativeHomeBinding } from "./lib/projectHomeChannel";
import { findProjectHomeByChannelId } from "./lib/projectHomeChannel";
import { buildProjectRelatedChannelPatchTemplate } from "./projectChannelCreation";
import type { ProjectChannelRequest } from "./projectChannelRequest";

export type ProjectChannelApprovalState = Map<string, Channel>;

/** An explicit owner approval is the only caller allowed to create/link a request. */
export async function approveProjectChannel(
  request: ProjectChannelRequest,
  resume: ProjectChannelApprovalState,
  deps = {
    isDesktop: isTauri,
    getIdentity,
    fetchProjects,
    createChannel,
    getRelayOrigin: getCachedRelayOrigin,
    fetchEvents: relayClient.fetchEvents.bind(relayClient),
    publishEvent: relayClient.publishEvent.bind(relayClient),
    signRelayEvent,
  },
): Promise<Channel> {
  if (!deps.isDesktop())
    throw new Error("Project channel creation requires the desktop app.");
  const origin = deps.getRelayOrigin();
  const identity = await deps.getIdentity();
  const project = findProjectHomeByChannelId(
    request.request.homeChannelId,
    await deps.fetchProjects(),
  );
  if (
    !project ||
    project.owner.toLowerCase() !== identity.pubkey.toLowerCase()
  ) {
    throw new Error("Only the signing project owner can approve this channel.");
  }
  if (request.request.templateName)
    throw new Error("Choose a channel template after creating this channel.");
  const filter = {
    kinds: [30621],
    authors: [project.owner],
    "#d": [project.dtag],
    limit: 1,
  };
  const readHead = async () => {
    const [head] = await deps.fetchEvents(filter);
    if (
      head?.kind !== 30621 ||
      head.pubkey.toLowerCase() !== identity.pubkey.toLowerCase() ||
      !head.tags.some((tag) => tag[0] === "d" && tag[1] === project.dtag)
    ) {
      throw new Error("The current project head could not be verified.");
    }
    const liveProject = eventToExplicitProject(head, new Map(), new Map());
    const authorityChanged = () =>
      new Error(
        "Project home authority changed. Refresh before retrying approval.",
      );
    if (liveProject?.projectChannelId !== request.request.homeChannelId)
      throw authorityChanged();
    // Re-read the repositories that authorized the reviewed home. Enumeration
    // may predate both the winning project head and a repository replacement.
    const repositories = [];
    for (const repository of project.repositories) {
      if (!liveProject.repositoryAddresses.includes(repository.repoAddress))
        continue;
      const [event] = await deps.fetchEvents({
        kinds: [30617],
        authors: [repository.owner],
        "#d": [repository.dtag],
        limit: 1,
      });
      const current = event && eventToRepository(event, origin);
      if (current?.repoAddress === repository.repoAddress)
        repositories.push(current);
    }
    if (!hasAuthoritativeHomeBinding({ ...liveProject, repositories }))
      throw authorityChanged();
    return head;
  };
  const head = await readHead();
  // The caller clears resume state on relay/identity change. Include the signer
  // as a further guard against reusing another owner's partial operation.
  const key = `${identity.pubkey.toLowerCase()}:${request.requestId}`;
  let channel = resume.get(key);
  if (!channel) {
    if (
      deps.getRelayOrigin() !== origin ||
      (await deps.getIdentity()).pubkey.toLowerCase() !==
        identity.pubkey.toLowerCase()
    )
      throw new Error(
        "Identity or relay changed during approval. Refresh before retrying.",
      );
    channel = await deps.createChannel({
      name: request.request.name,
      description: request.request.description,
      visibility: request.request.visibility,
      ttlSeconds: request.request.ttlSeconds,
      channelType: "stream",
    });
    resume.set(key, channel);
  }
  const confirmed = await readHead();
  if (confirmed.id !== head.id)
    throw new Error(
      "The project changed during channel creation. Retry to link the created channel.",
    );
  const template = buildProjectRelatedChannelPatchTemplate({
    channelId: channel.id,
    liveHead: confirmed,
    ownerPubkey: identity.pubkey,
  });
  if (!template.alreadyBound) {
    const event: RelayEvent = await deps.signRelayEvent({
      ...template.project,
      createdAt: Math.max(
        Math.floor(Date.now() / 1000),
        confirmed.created_at + 1,
      ),
    });
    if (
      event.pubkey.toLowerCase() !== identity.pubkey.toLowerCase() ||
      deps.getRelayOrigin() !== origin ||
      (await deps.getIdentity()).pubkey.toLowerCase() !==
        identity.pubkey.toLowerCase()
    )
      throw new Error(
        "Identity or relay changed during approval. Refresh before retrying.",
      );
    // A lost ACK is uncertain, so retain the new channel for an idempotent retry.
    // Never delete it: a concurrently accepted project head may already link it.
    await deps.publishEvent(
      event,
      "Could not confirm the project link. Retry to verify the created channel.",
      "Could not link the created channel. Retry to verify it.",
    );
  }
  const winner = await readHead();
  if (
    !winner.tags.some(
      (tag) => tag[0] === "buzz-related-channel" && tag[1] === channel.id,
    )
  ) {
    throw new Error(
      "A concurrent update replaced the channel link. Retry to link the created channel.",
    );
  }
  resume.delete(key);
  return channel;
}
