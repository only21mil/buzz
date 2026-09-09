import { AgentManagementDialogs } from "@/features/agents/ui/AgentManagementDialogs";
import { DurableDraftReviewDialog } from "@/features/agents/ui/DurableDraftReviewDialog";
import { RequestedAgentCreateDialogs } from "@/features/agents/ui/RequestedAgentCreateDialogs";
import { ProjectChannelRequestDialog } from "@/features/projects/ui/ProjectChannelRequestDialog";

export function OwnerReviewDialogs() {
  return (
    <>
      <RequestedAgentCreateDialogs />
      <AgentManagementDialogs />
      <DurableDraftReviewDialog />
      <ProjectChannelRequestDialog />
    </>
  );
}
