import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

import {
  createInputFromRequest,
  requestTargetsEditablePersona,
  type AgentManagementRequest,
} from "./agentManagement";
import { subscribeAgentManagementRequests } from "./observerRelayStore";
import {
  managedAgentsQueryKey,
  personasQueryKey,
  useAcpRuntimesQuery,
  useCreateManagedAgentMutation,
  useCreatePersonaMutation,
  useManagedAgentsQuery,
  usePersonasQuery,
  useUpdatePersonaMutation,
} from "./hooks";
import {
  availableRuntimesForStart,
  createManagedInstanceForDefinition,
  type BackendIntent,
} from "./lib/instanceInputForDefinition";
import { useCreatedAgentChannelAttachment } from "./useCreatedAgentChannelAttachment";
import {
  advanceAgentManagementReview,
  classifyAgentManagementOrigin,
  enqueueAgentManagementReview,
  type AgentManagementReview,
} from "./agentManagementBuffer";
import { channelsQueryKey, useChannelsQuery } from "@/features/channels/hooks";
import { resolveManagedAgentAvatarUrl } from "./ui/managedAgentAvatar";
import type { AgentCreateIntent } from "./ui/agentCreateIntent";
import { editPersonaDialogState } from "./ui/personaDialogState";
import type {
  AgentPersona,
  Channel,
  ManagedAgent,
  CreatePersonaInput,
  UpdatePersonaInput,
} from "@/shared/api/types";

import {
  assertAgentManagementReviewCurrent,
  assertAgentManagementUpdateTarget,
} from "./agentManagementReview";

export function updateInputFromRequest(
  request: Extract<AgentManagementRequest, { action: "update" }>,
  current: UpdatePersonaInput,
): UpdatePersonaInput {
  const changes = request.request;
  return {
    ...current,
    displayName: changes.displayName ?? current.displayName,
    systemPrompt: changes.systemPrompt ?? current.systemPrompt,
    runtime: changes.runtime ?? current.runtime,
    provider: changes.provider ?? current.provider,
    model: changes.model ?? current.model,
    ...(changes.respondTo
      ? {
          behavior: {
            respondTo: changes.respondTo,
            respondToAllowlist: [],
            parallelism: current.behavior?.parallelism,
          },
        }
      : {}),
  };
}

export function useAgentManagement() {
  const queryClient = useQueryClient();
  const personasQuery = usePersonasQuery();
  const managedAgentsQuery = useManagedAgentsQuery();
  const channelsQuery = useChannelsQuery();
  const runtimesQuery = useAcpRuntimesQuery({ enabled: true });
  const createPersonaMutation = useCreatePersonaMutation();
  const updatePersonaMutation = useUpdatePersonaMutation();
  const createAgentMutation = useCreateManagedAgentMutation();
  const [request, setRequest] = React.useState<AgentManagementRequest | null>(
    null,
  );
  const [reviewTarget, setReviewTarget] = React.useState<{
    requestId: string;
    persona: AgentPersona;
  } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const createdAgentAttachment = useCreatedAgentChannelAttachment();
  const seenRequestIds = React.useRef(new Set<string>());
  const pendingRequestId = React.useRef<string | null>(null);
  const sourceAgentPubkey = React.useRef<string | null>(null);
  const managedAgentsRef = React.useRef(managedAgentsQuery.data);
  const channelsRef = React.useRef(channelsQuery.data);
  const bufferedRequestsRef = React.useRef<AgentManagementReview[]>([]);
  const queuedReviewsRef = React.useRef<AgentManagementReview[]>([]);

  const activateReview = React.useEffectEvent(
    (review: AgentManagementReview) => {
      pendingRequestId.current = review.request.requestId;
      sourceAgentPubkey.current = review.agentPubkey;
      setError(null);
      setReviewTarget(null);
      setRequest(review.request);
    },
  );

  const acceptOwnedRequest = React.useEffectEvent(
    (agentPubkey: string, next: AgentManagementRequest) => {
      if (
        classifyAgentManagementOrigin(
          managedAgentsRef.current,
          channelsRef.current,
          agentPubkey,
          next.request.channelId,
        ) !== "accept" ||
        seenRequestIds.current.has(next.requestId)
      ) {
        return;
      }
      seenRequestIds.current.add(next.requestId);
      const queued = enqueueAgentManagementReview(
        pendingRequestId.current,
        queuedReviewsRef.current,
        { agentPubkey, request: next },
      );
      queuedReviewsRef.current = queued.queued;
      if (queued.activate) activateReview(queued.activate);
    },
  );

  React.useEffect(() => {
    managedAgentsRef.current = managedAgentsQuery.data;
    channelsRef.current = channelsQuery.data;
    if (managedAgentsQuery.data && channelsQuery.data) {
      const buffered = bufferedRequestsRef.current.splice(0);
      for (const candidate of buffered) {
        acceptOwnedRequest(candidate.agentPubkey, candidate.request);
      }
    }
  }, [channelsQuery.data, managedAgentsQuery.data]);

  React.useEffect(
    () =>
      subscribeAgentManagementRequests((agentPubkey, next) => {
        // Observer frames are owner-scoped and authenticated. Any managed agent
        // this Desktop owns may draft a change; defer the ownership decision
        // until the managed-agent query has initialized so ephemeral requests
        // cannot disappear during startup.
        if (
          classifyAgentManagementOrigin(
            managedAgentsRef.current,
            channelsRef.current,
            agentPubkey,
            next.request.channelId,
          ) === "buffer"
        ) {
          bufferedRequestsRef.current.push({ agentPubkey, request: next });
          if (bufferedRequestsRef.current.length > 100) {
            bufferedRequestsRef.current.shift();
          }
          return;
        }
        acceptOwnedRequest(agentPubkey, next);
      }),
    [],
  );

  React.useEffect(
    () => () => {
      // A callback retained by an old dialog cannot save after community remount.
      pendingRequestId.current = null;
      sourceAgentPubkey.current = null;
    },
    [],
  );

  const matchingPersonas = React.useMemo(() => {
    if (request?.action !== "update") return [];
    const target = request.request.agentName.trim().toLocaleLowerCase();
    return (personasQuery.data ?? []).filter(
      (persona) =>
        persona.displayName.trim().toLocaleLowerCase() === target &&
        requestTargetsEditablePersona(persona),
    );
  }, [personasQuery.data, request]);
  const currentPersona =
    matchingPersonas.length === 1 ? matchingPersonas[0] : undefined;

  React.useEffect(() => {
    if (request?.action !== "update" || !currentPersona) return;
    setReviewTarget((previous) =>
      previous?.requestId === request.requestId
        ? previous
        : { requestId: request.requestId, persona: currentPersona },
    );
  }, [currentPersona, request]);
  const reviewedPersona =
    reviewTarget?.requestId === request?.requestId
      ? (reviewTarget?.persona ?? null)
      : null;

  const isPending =
    createPersonaMutation.isPending ||
    updatePersonaMutation.isPending ||
    createAgentMutation.isPending;

  function assertReviewIsCurrent(requestId: string, channelId: string) {
    assertAgentManagementReviewCurrent({
      requestId,
      activeRequestId: pendingRequestId.current,
      agentPubkey: sourceAgentPubkey.current,
      channelId,
      agents: queryClient.getQueryData<ManagedAgent[]>(managedAgentsQueryKey),
      channels: queryClient.getQueryData<Channel[]>(channelsQueryKey),
    });
  }

  async function submitCreate(
    input: CreatePersonaInput | UpdatePersonaInput,
    intent: AgentCreateIntent,
    backendIntent: BackendIntent | null,
  ): Promise<boolean> {
    if (request?.action !== "create" || "id" in input) {
      return false;
    }
    setError(null);
    try {
      assertReviewIsCurrent(request.requestId, request.request.channelId);
      const runtimes = await availableRuntimesForStart(runtimesQuery);
      const runtime = runtimes.find(
        (candidate) => candidate.id === input.runtime,
      );
      if (!runtime) {
        throw new Error("Choose an available runtime for this agent.");
      }

      const avatarUrl = await resolveManagedAgentAvatarUrl(
        input.avatarUrl,
        undefined,
        runtime.avatarUrl,
      );
      assertReviewIsCurrent(request.requestId, request.request.channelId);
      const persona = await createPersonaMutation.mutateAsync({
        ...input,
        avatarUrl,
      });

      if (intent === "definition_stopped" || intent === "definition_start") {
        const targetChannel = (channelsQuery.data ?? []).find(
          (channel) => channel.id === request.request.channelId,
        );
        assertReviewIsCurrent(request.requestId, request.request.channelId);
        await createManagedInstanceForDefinition({
          backendIntent: backendIntent ?? undefined,
          createManagedAgent: createAgentMutation.mutateAsync,
          mode: intent === "definition_stopped" ? "stopped" : "start",
          persona,
          presentCreatedAgent: createdAgentAttachment.presentCreatedAgent,
          runtime,
          targetChannel: {
            id: request.request.channelId,
            name: targetChannel?.name ?? "this channel",
          },
        });
      }

      await Promise.all([
        queryClient.invalidateQueries({ queryKey: personasQueryKey }),
        queryClient.invalidateQueries({ queryKey: managedAgentsQueryKey }),
      ]);
      // AgentCreateDialogRouter closes the completed create review. Keeping the
      // queue advance there prevents a successful submit from dismissing both
      // the current dialog and the next queued review.
      return true;
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Could not save this agent.",
      );
      return false;
    }
  }

  async function submitUpdate(input: CreatePersonaInput | UpdatePersonaInput) {
    if (request?.action !== "update" || !("id" in input)) {
      return false;
    }
    setError(null);
    try {
      assertReviewIsCurrent(request.requestId, request.request.channelId);
      const current = queryClient
        .getQueryData<AgentPersona[]>(personasQueryKey)
        ?.find((persona) => persona.id === reviewedPersona?.id);
      const reviewRevision = assertAgentManagementUpdateTarget(
        reviewedPersona,
        current,
        input.id,
      );
      await updatePersonaMutation.mutateAsync({
        ...input,
        ...reviewRevision,
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: personasQueryKey }),
        queryClient.invalidateQueries({ queryKey: managedAgentsQueryKey }),
      ]);
      if (pendingRequestId.current === request.requestId) dismiss();
      return true;
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Could not save this agent.",
      );
      return false;
    }
  }

  function dismiss() {
    const next = advanceAgentManagementReview(queuedReviewsRef.current);
    queuedReviewsRef.current = next.queued;
    if (next.activate) {
      activateReview(next.activate);
      return;
    }
    pendingRequestId.current = null;
    sourceAgentPubkey.current = null;
    setRequest(null);
  }

  const createInitialValues = React.useMemo(
    () =>
      request?.action === "create" ? createInputFromRequest(request) : null,
    [request],
  );

  const editInitialValues = React.useMemo(() => {
    if (request?.action !== "update" || !reviewedPersona) return null;
    return updateInputFromRequest(
      request,
      editPersonaDialogState(reviewedPersona)
        .initialValues as UpdatePersonaInput,
    );
  }, [reviewedPersona, request]);

  const editError = React.useMemo(() => {
    if (request?.action !== "update") return error;
    if (error) return error;
    if (matchingPersonas.length > 1) {
      return "More than one personal agent has that name. Rename it in Agents, then ask the agent again.";
    }
    if (!currentPersona) {
      return "Agents can only update a personal agent profile by its current name.";
    }
    return null;
  }, [currentPersona, error, matchingPersonas.length, request]);

  return {
    request,
    createInitialValues,
    editInitialValues,
    editError,
    error,
    ...createdAgentAttachment,
    isPending,
    runtimes: runtimesQuery.data ?? [],
    runtimeCatalogStatus: runtimesQuery.isLoading
      ? ("loading" as const)
      : runtimesQuery.isError
        ? ("error" as const)
        : ("ready" as const),
    submitCreate,
    submitUpdate,
    dismiss,
  };
}
