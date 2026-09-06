import * as React from "react";

/** Capture one edit visit and its authored revision across asynchronous work. */
export function useEditSubmissionOwnership(
  editTargetId: string | null,
  getComposerRevision: () => number,
) {
  const owner = React.useMemo(
    () => ({ active: true, editTargetId, getComposerRevision }),
    [editTargetId, getComposerRevision],
  );
  const currentOwner = React.useRef(owner);
  currentOwner.current = owner;
  React.useLayoutEffect(() => {
    owner.active = true;
    return () => {
      owner.active = false;
    };
  }, [owner]);

  return React.useCallback(() => {
    const revision = owner.getComposerRevision();
    return () =>
      owner.active &&
      currentOwner.current === owner &&
      owner.getComposerRevision() === revision;
  }, [owner]);
}
