import { useCallback, useState, type ReactNode } from "react";
import type { ProfilePanelView } from "./UserProfilePanelUtils";
import type { AgentPersona } from "@/shared/api/types";
import { DurableDraftQueue } from "@/features/agents/ui/DurableDraftQueue";

/** Keep the owner draft queue before the selected agent profile content. */
export function withDraftQueue(
  body: ReactNode,
  isBot: boolean,
  pubkey: string | null | undefined,
  persona: Pick<AgentPersona, "id" | "displayName"> | null | undefined,
): ReactNode {
  return (
    <>
      {isBot ? (
        <DurableDraftQueue
          agentPubkey={pubkey ?? undefined}
          personaId={persona?.id}
          personaName={persona?.displayName}
        />
      ) : null}
      {body}
    </>
  );
}

/** Preserve controlled and internal profile-view navigation. */
export function useProfilePanelView(
  controlledView: ProfilePanelView | undefined,
  onViewChange:
    | ((view: ProfilePanelView, options?: { replace?: boolean }) => void)
    | undefined,
) {
  const [internalView, setInternalView] = useState<ProfilePanelView>("summary");
  const view = controlledView ?? internalView;
  const setView = useCallback(
    (nextView: ProfilePanelView, options?: { replace?: boolean }) => {
      if (onViewChange) {
        onViewChange(nextView, options);
        return;
      }
      setInternalView(nextView);
    },
    [onViewChange],
  );
  return [view, setView] as const;
}
