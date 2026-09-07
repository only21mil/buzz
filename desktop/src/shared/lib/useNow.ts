import * as React from "react";

import { useDocumentVisible } from "@/shared/lib/useDocumentVisible";

/**
 * Returns `Date.now()`, re-rendering the calling component every `intervalMs`.
 * Each consumer owns one `setInterval` cleaned up on unmount — mount the hook
 * only where a live clock is actually displayed so idle components never tick.
 */
export function useNow(intervalMs: number, pauseWhileHidden = true): number {
  const [now, setNow] = React.useState(() => Date.now());
  const documentVisible = useDocumentVisible();

  React.useEffect(() => {
    if (pauseWhileHidden && !documentVisible) return;

    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [documentVisible, intervalMs, pauseWhileHidden]);

  return now;
}
