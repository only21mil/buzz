import * as React from "react";

export function useProjectRepositoryRefSelection(input: {
  branchOptions: string[];
  defaultBranch: string | null;
  projectAvailable: boolean;
  projectPending: boolean;
  /** Identity of the repository the options describe. A switch to a
   * different repository resets the selection even when the new repository
   * happens to have a branch or tag with the same name — carrying `release`
   * from repo A into repo B would silently retarget files, actions, and
   * agent context at a ref the user never chose. */
  repositoryId: string | null;
  tags: Array<{ name: string }>;
}) {
  const [selectedBranch, setSelectedBranch] = React.useState<string | null>(
    null,
  );
  const [selectedTag, setSelectedTag] = React.useState<string | null>(null);
  const [selectedLocalBranch, setSelectedLocalBranch] = React.useState<
    string | null
  >(null);
  const [selectionRepositoryId, setSelectionRepositoryId] = React.useState(
    input.repositoryId,
  );
  // Reset during render (not in an effect) so a repository switch can never
  // paint one frame with the previous repository's same-named selection.
  if (selectionRepositoryId !== input.repositoryId) {
    setSelectionRepositoryId(input.repositoryId);
    setSelectedBranch(null);
    setSelectedTag(null);
    setSelectedLocalBranch(null);
  }
  const staleSelection = selectionRepositoryId !== input.repositoryId;
  const activeBranch =
    (staleSelection ? null : selectedBranch) ??
    input.defaultBranch ??
    input.branchOptions[0] ??
    null;

  React.useEffect(() => {
    if (!input.projectAvailable) {
      if (input.projectPending) return;
      setSelectedBranch(null);
      setSelectedTag(null);
      setSelectedLocalBranch(null);
      return;
    }
    setSelectedBranch((currentBranch) => {
      if (
        currentBranch &&
        (input.branchOptions.includes(currentBranch) ||
          currentBranch === selectedLocalBranch)
      ) {
        return currentBranch;
      }
      return input.defaultBranch ?? input.branchOptions[0] ?? null;
    });
    // Once published, a local choice follows normal remote-removal fallback.
    setSelectedLocalBranch((branch) =>
      branch && input.branchOptions.includes(branch) ? null : branch,
    );
    setSelectedTag((currentTag) => {
      if (currentTag && input.tags.some((tag) => tag.name === currentTag)) {
        return currentTag;
      }
      return null;
    });
  }, [
    input.branchOptions,
    input.defaultBranch,
    input.projectAvailable,
    input.projectPending,
    input.tags,
    selectedLocalBranch,
  ]);

  const selectBranch = React.useCallback(
    (branch: string | null) => {
      setSelectedBranch(branch);
      setSelectedTag(null);
      // The menu also offers discovered local branches/worktrees that are
      // absent from the remote/PR options. Keep that deliberate selection.
      setSelectedLocalBranch(
        branch && !input.branchOptions.includes(branch) ? branch : null,
      );
    },
    [input.branchOptions],
  );
  const selectTag = React.useCallback((tag: string) => {
    setSelectedTag(tag);
  }, []);

  return {
    activeBranch,
    selectBranch,
    selectedTag: staleSelection ? null : selectedTag,
    selectTag,
  };
}
