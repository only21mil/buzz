import { Capability, isCapabilityAvailable } from "@/platform/web/capabilities";
import { useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { toast } from "sonner";

import type { Repository } from "@/features/projects/hooks";
import { projectCloneErrorPresentation } from "@/features/projects/lib/projectGitError";
import {
  openProjectMergeRecoveryTerminal,
  openProjectTerminal,
} from "@/shared/api/projectGit";

export function projectTerminalLabel(hasLocalCheckout: boolean) {
  return hasLocalCheckout ? "Open in Terminal" : "Clone & open in Terminal";
}

/**
 * Opens the OS terminal at a project's local checkout, cloning first when
 * only a remote exists. Handles the clone progress/success/error toasts and
 * refreshes project queries after a clone so local-checkout state updates.
 */
export function useOpenProjectTerminal(reposDir?: string | null) {
  const queryClient = useQueryClient();

  return React.useCallback(
    async (
      project: Repository,
      options: { branch?: string | null; hasLocalCheckout: boolean },
    ) => {
      if (!isCapabilityAvailable(Capability.Terminal)) return;
      const toastId = options.hasLocalCheckout
        ? undefined
        : toast.loading(`Cloning ${project.name}…`);
      try {
        const result = await openProjectTerminal({
          reposDir,
          projectDtag: project.dtag,
          cloneUrl: project.cloneUrls[0] ?? null,
          defaultBranch: options.branch ?? project.defaultBranch ?? null,
        });
        if (result.mismatch) {
          const command = result.worktreeCommand;
          toast.error("Selected branch needs a worktree", {
            description: result.mismatch,
            id: toastId,
            duration: Number.POSITIVE_INFINITY,
            action: command
              ? {
                  label: "Copy command",
                  onClick: () => {
                    void navigator.clipboard.writeText(command).then(
                      () => toast.success("Worktree command copied."),
                      () =>
                        toast.error(
                          "Couldn’t copy the command. Select it from the message.",
                        ),
                    );
                  },
                }
              : undefined,
          });
          return;
        }
        if (result.cloned) {
          toast.success(`Cloned to ${result.path}`, { id: toastId });
          void queryClient.invalidateQueries({
            queryKey: ["project", project.id],
          });
          void queryClient.invalidateQueries({ queryKey: ["projects"] });
        } else if (toastId !== undefined) {
          toast.dismiss(toastId);
        }
      } catch (error) {
        const presentation = options.hasLocalCheckout
          ? {
              title: "Couldn’t open terminal",
              description:
                "Buzz could not open this checkout in your configured terminal.",
            }
          : projectCloneErrorPresentation(error, project.cloneUrls[0]);
        toast.error(presentation.title, {
          description: presentation.description,
          id: toastId,
        });
      }
    },
    [queryClient, reposDir],
  );
}

/** Open merge recovery for the selected repository and workspace directory. */
export function useOpenProjectMergeRecoveryTerminal(
  repository: Repository | null | undefined,
  reposDir?: string | null,
) {
  return React.useCallback(
    async (input: {
      expectedCommit: string;
      sourceBranch: string;
      sourceCloneUrl: string;
      targetBranch: string;
    }) => {
      const targetCloneUrl = repository?.cloneUrls[0];
      if (!repository || !targetCloneUrl) {
        throw new Error("No project selected.");
      }
      return openProjectMergeRecoveryTerminal({
        ...input,
        projectDtag: repository.dtag,
        reposDir: reposDir,
        targetCloneUrl,
      });
    },
    [reposDir, repository],
  );
}
