import { AgentManagementDialogs } from "@/features/agents/ui/AgentManagementDialogs";
import { RequestedAgentCreateDialogs } from "@/features/agents/ui/RequestedAgentCreateDialogs";
import { ProjectChannelRequestDialog } from "@/features/projects/ui/ProjectChannelRequestDialog";

export function OwnerReviewDialogs() {
  return (
    <>
      <RequestedAgentCreateDialogs />
      <AgentManagementDialogs />
      <ProjectChannelRequestDialog />
    </>
  );
}
