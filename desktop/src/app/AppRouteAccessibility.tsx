import * as React from "react";
import { useLocation } from "@tanstack/react-router";

const ROUTE_LABELS: ReadonlyArray<[prefix: string, label: string]> = [
  ["/channels/", "Channel"],
  ["/messages/new", "New message"],
  ["/agents", "Agents"],
  ["/workflows", "Workflows"],
  ["/projects", "Projects"],
  ["/pulse", "Pulse"],
  ["/settings", "Settings"],
];

export function routeAnnouncement(pathname: string): string {
  const match = ROUTE_LABELS.find(([prefix]) => pathname.startsWith(prefix));
  return `${match?.[1] ?? "Home"} view`;
}

export function focusMainContent(): void {
  document.getElementById("main-content")?.focus({ preventScroll: true });
}

export function focusMainContentAfterRouteChange(
  activeAtRouteChange: Element | null,
): void {
  const main = document.getElementById("main-content");
  const activeNow = document.activeElement;

  // Destination routes can intentionally autofocus their own controls. Keep
  // that focus when it landed inside the main region after the route changed.
  if (
    main &&
    activeNow !== activeAtRouteChange &&
    activeNow &&
    main.contains(activeNow)
  ) {
    return;
  }
  main?.focus({ preventScroll: true });
}

/** Keyboard and screen-reader support for client-side route changes. */
export function AppRouteAccessibility() {
  const location = useLocation();
  const previousPath = React.useRef(location.pathname);
  // biome-ignore lint/correctness/useExhaustiveDependencies: pathname is the invalidation key for the pre-commit focus snapshot
  const activeBeforeRouteCommit = React.useMemo(
    () => document.activeElement,
    [location.pathname],
  );
  const [announcement, setAnnouncement] = React.useState("");

  React.useEffect(() => {
    if (previousPath.current === location.pathname) return;
    previousPath.current = location.pathname;
    setAnnouncement(routeAnnouncement(location.pathname));
    const frame = window.requestAnimationFrame(() => {
      focusMainContentAfterRouteChange(activeBeforeRouteCommit);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeBeforeRouteCommit, location.pathname]);

  const handleSkipLink = React.useCallback(
    (event: React.MouseEvent<HTMLAnchorElement>) => {
      event.preventDefault();
      focusMainContent();
    },
    [],
  );

  return (
    <>
      {/* biome-ignore lint/a11y/useValidAnchor: this is a semantic skip link; hash-history requires intercepting its fragment navigation */}
      <a
        className="fixed left-3 top-3 z-[100] -translate-y-20 rounded-md bg-background px-3 py-2 text-sm font-medium text-foreground shadow-lg transition-transform focus:translate-y-0 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
        href="#main-content"
        onClick={handleSkipLink}
      >
        Skip to main content
      </a>
      <div aria-atomic="true" aria-live="polite" className="sr-only">
        {announcement}
      </div>
    </>
  );
}
