import { isTauri } from "@tauri-apps/api/core";
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { classifyAgentManagementOrigin } from "@/features/agents/agentManagementBuffer";
import { subscribeProjectChannelRequests } from "@/features/agents/observerRelayStore";
import { useManagedAgentsQuery } from "@/features/agents/hooks";
import { useChannelsQuery, channelsQueryKey } from "@/features/channels/hooks";
import { useIdentityQuery } from "@/shared/api/hooks";
import { getCachedRelayOrigin } from "@/shared/lib/mediaUrl";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { useProjectsQuery, projectsQueryKey } from "../hooks";
import { findProjectHomeByChannelId } from "../lib/projectHomeChannel";
import {
  approveProjectChannel,
  type ProjectChannelApprovalState,
} from "../approveProjectChannel";
import {
  createProjectChannelRequestQueue,
  enqueueProjectChannelRequest,
  advanceProjectChannelRequestQueue,
  type AcceptedProjectChannelRequest,
} from "../projectChannelRequestQueue";

/** Desktop review surface. Observing a request never creates a channel. */
export function ProjectChannelRequestDialog() {
  if (!isTauri()) return null;
  return <ScopedProjectChannelRequestDialog />;
}

function ScopedProjectChannelRequestDialog() {
  const identity = useIdentityQuery();
  const scope = `${getCachedRelayOrigin()}:${identity.data?.pubkey ?? ""}`;
  return <DesktopProjectChannelRequestDialog key={scope} />;
}

function DesktopProjectChannelRequestDialog() {
  const identity = useIdentityQuery();
  const agents = useManagedAgentsQuery();
  const channels = useChannelsQuery();
  const projects = useProjectsQuery();
  const queryClient = useQueryClient();
  const [state] = React.useState(() => ({
    queue: createProjectChannelRequestQueue(),
    buffered: [] as AcceptedProjectChannelRequest[],
    resume: new Map() as ProjectChannelApprovalState,
  }));
  const [active, setActive] =
    React.useState<AcceptedProjectChannelRequest | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [pending, setPending] = React.useState(false);
  const receive = React.useEffectEvent(
    (
      agentPubkey: string,
      request: AcceptedProjectChannelRequest["request"],
    ) => {
      const decision = classifyAgentManagementOrigin(
        agents.data,
        channels.data,
        agentPubkey,
        request.request.homeChannelId,
      );
      if (decision === "buffer") {
        if (state.buffered.length < 100)
          state.buffered.push({ agentPubkey, request });
        return;
      }
      if (decision !== "accept") return;
      const result = enqueueProjectChannelRequest(state.queue, {
        agentPubkey,
        request,
      });
      if (result.status === "show") {
        setActive(result.candidate);
        setError(null);
      }
    },
  );
  React.useEffect(() => {
    if (agents.data && channels.data)
      for (const item of state.buffered.splice(0))
        receive(item.agentPubkey, item.request);
  }, [agents.data, channels.data, state]);
  React.useEffect(() => {
    setActive(null);
    setError(null);
    return subscribeProjectChannelRequests((agent, request) =>
      receive(agent, request),
    );
  }, []);
  const project = findProjectHomeByChannelId(
    active?.request.request.homeChannelId,
    projects.data ?? [],
  );
  const canApprove =
    !!project &&
    !!identity.data &&
    project.owner.toLowerCase() === identity.data.pubkey.toLowerCase() &&
    !active?.request.request.templateName;
  function dismiss() {
    if (!pending) {
      setActive(advanceProjectChannelRequestQueue(state.queue));
      setError(null);
    }
  }
  async function approve() {
    if (!active || !canApprove || pending) return;
    if (
      classifyAgentManagementOrigin(
        agents.data,
        channels.data,
        active.agentPubkey,
        active.request.request.homeChannelId,
      ) !== "accept"
    ) {
      setError("The requesting agent no longer has access to this home.");
      return;
    }
    setPending(true);
    setError(null);
    try {
      await approveProjectChannel(active.request, state.resume);
      setActive(advanceProjectChannelRequestQueue(state.queue));
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Could not create project channel.",
      );
    } finally {
      setPending(false);
      void queryClient.invalidateQueries({ queryKey: projectsQueryKey });
      void queryClient.invalidateQueries({ queryKey: channelsQueryKey });
    }
  }
  const request = active?.request.request;
  return (
    <Dialog
      open={!!active}
      onOpenChange={(open) => {
        if (!open) dismiss();
      }}
    >
      <DialogContent>
        <DialogTitle>Create project channel?</DialogTitle>
        <DialogDescription>
          Review the request for {project?.name ?? "this project"}.
        </DialogDescription>
        {request ? (
          <div className="space-y-2">
            <p>
              #{request.name} · {request.visibility}
            </p>
            <p>{request.description}</p>
            {request.ttlSeconds ? (
              <p>Expires after {request.ttlSeconds} seconds of inactivity.</p>
            ) : null}
            {request.templateName ? (
              <p>Requested template: {request.templateName}</p>
            ) : null}
          </div>
        ) : null}
        {!canApprove ? (
          <p className="text-sm text-muted-foreground">
            This request requires the signing project owner and a channel
            without a template.
          </p>
        ) : null}
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
        <div className="flex justify-end gap-2">
          <Button disabled={pending} onClick={dismiss} variant="outline">
            Cancel
          </Button>
          <Button
            disabled={!canApprove || pending}
            onClick={() => void approve()}
          >
            {pending ? "Creating…" : "Create channel"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
