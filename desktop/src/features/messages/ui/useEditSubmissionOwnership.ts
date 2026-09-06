import * as React from "react";

import type { ImetaMedia } from "@/features/messages/lib/imetaMediaMarkdown";

const noRevision = () => 0;
const applyUpdate = (update: () => void) => update();

/** Capture one edit visit and its authored revision across asynchronous work. */
export function useEditSubmissionOwnership(
  editTargetId: string | null,
  getComposerRevision: () => number,
  getMediaRevision: () => number = noRevision,
  getSpoilerRevision: () => number = noRevision,
  runComposerUpdate: (
    update: () => void,
    media?: ImetaMedia[],
  ) => void = applyUpdate,
) {
  const owner = React.useMemo(
    () => ({
      active: true,
      editTargetId,
      getComposerRevision,
      getMediaRevision,
      getSpoilerRevision,
    }),
    [editTargetId, getComposerRevision, getMediaRevision, getSpoilerRevision],
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
    let mediaRevision = getMediaRevision();
    let spoilerRevision = getSpoilerRevision();
    const isCurrent = () =>
      owner.active &&
      currentOwner.current === owner &&
      owner.getComposerRevision() === revision &&
      getMediaRevision() === mediaRevision &&
      getSpoilerRevision() === spoilerRevision;
    return {
      isCurrent,
      // A clear or recovery belongs to this submission only. Other pending
      // submissions and later authored changes remain revoked.
      runUpdate: (update: () => void, media?: ImetaMedia[]) => {
        if (!isCurrent()) return;
        runComposerUpdate(update, media);
        mediaRevision = getMediaRevision();
        spoilerRevision = getSpoilerRevision();
      },
    };
  }, [owner, getMediaRevision, getSpoilerRevision, runComposerUpdate]);
}
