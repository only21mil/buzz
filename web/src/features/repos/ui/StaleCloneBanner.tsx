import { cloneFetchErrorMessage } from "../git-clone-browse-meta";

export function StaleCloneBanner({ fetchError }: { fetchError: unknown }) {
  const detail = cloneFetchErrorMessage(fetchError);

  return (
    <div
      role="status"
      className="mt-6 rounded-md border border-chart-4/40 bg-chart-4/15 px-4 py-4 text-black dark:text-white"
    >
      <h2 className="text-sm font-semibold">
        Showing cached repository contents
      </h2>
      <p className="mt-1 text-sm leading-relaxed text-black/70 dark:text-white/70">
        The relay did not confirm the latest revision, so this view may be out
        of date.
        {detail ? ` ${detail}.` : ""}
      </p>
    </div>
  );
}
