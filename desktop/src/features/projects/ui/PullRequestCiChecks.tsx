import { isTauri } from "@tauri-apps/api/core";
import { useQuery } from "@tanstack/react-query";

import type { ProjectPullRequest, Repository } from "@/features/projects/hooks";
import { ciRefetchInterval } from "@/features/projects/lib/ciPolling";

function stateLabel(value: string): string {
  return value.replaceAll("_", " ");
}

export function PullRequestCiChecks({
  project,
  pullRequest,
}: {
  project: Repository;
  pullRequest: ProjectPullRequest;
}) {
  const browser = !isTauri();
  const channelId = project.channelId ?? null;
  const query = useQuery({
    queryKey: [
      "pull-request-ci",
      project.repoAddress,
      pullRequest.id,
      channelId,
    ],
    enabled: browser && channelId !== null,
    queryFn: async () => {
      const { getPullRequestCiStatuses } = await import(
        "@/platform/web/relayCiStatus"
      );
      return getPullRequestCiStatuses({
        targetRepoA: project.repoAddress,
        channelId: channelId as string,
        pullRequestId: pullRequest.id,
      });
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: ({ state }) => ciRefetchInterval(state.data),
  });

  if (!browser) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        No checks have been reported for this pull request yet.
      </p>
    );
  }
  if (!channelId) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        CI checks require a channel-bound Buzz repository.
      </p>
    );
  }
  if (query.isPending) {
    return (
      <p aria-live="polite" className="p-4 text-sm text-muted-foreground">
        Loading CI checks…
      </p>
    );
  }
  if (query.error) {
    return (
      <p role="alert" className="p-4 text-sm text-destructive">
        {query.error.message}
      </p>
    );
  }
  const statuses = query.data?.statuses ?? [];
  const failures = query.data?.failures ?? [];
  const rejectedRequestCount = query.data?.rejectedRequestCount ?? 0;
  const truncatedRunCount = query.data?.truncatedRunCount ?? null;
  const runDiscoveryTruncated = query.data?.runDiscoveryTruncated ?? false;
  const discoveryWindowSaturated =
    query.data?.discoveryWindowSaturated ?? false;
  if (
    statuses.length === 0 &&
    failures.length === 0 &&
    rejectedRequestCount === 0 &&
    !runDiscoveryTruncated
  ) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        No checks have been reported for this pull request yet.
      </p>
    );
  }

  return (
    <section
      aria-label="Continuous integration checks"
      className="space-y-3 p-4"
    >
      {rejectedRequestCount > 0 ? (
        <p className="text-destructive text-sm" role="alert">
          {rejectedRequestCount} malformed CI request event
          {rejectedRequestCount === 1 ? " was" : "s were"} ignored.
        </p>
      ) : null}
      {discoveryWindowSaturated ? (
        <p className="text-muted-foreground text-sm" role="status">
          The CI discovery window is saturated. Older runs for this pull request
          may be omitted.
        </p>
      ) : runDiscoveryTruncated && truncatedRunCount !== null ? (
        <p className="text-muted-foreground text-sm" role="status">
          Showing the 20 newest CI runs. {truncatedRunCount} older run
          {truncatedRunCount === 1 ? " was" : "s were"} omitted by the browser
          limit.
        </p>
      ) : null}
      {failures.map((failure) => (
        <article
          className="rounded-lg border border-destructive/50 px-3 py-2"
          key={`failure:${failure.run_id}`}
        >
          <h3 className="font-medium text-sm">
            Run {failure.run_id.slice(0, 8)}
          </h3>
          <p className="text-destructive text-sm" role="alert">
            {failure.message}
          </p>
        </article>
      ))}
      {statuses.map((status) => (
        <article
          className="rounded-lg border border-border/60"
          key={status.run_id}
        >
          <header className="flex items-center justify-between gap-3 border-border/60 border-b px-3 py-2">
            <h3 className="font-medium text-sm">
              Run {status.run_id.slice(0, 8)}
            </h3>
            <span
              className="rounded-full bg-muted px-2 py-1 text-xs capitalize"
              role="status"
            >
              {stateLabel(status.state)}
            </span>
          </header>
          {status.rejected.untrusted_count > 0 ? (
            <p className="px-3 py-2 text-destructive text-sm" role="alert">
              Status signer not trusted by browser configuration. Ignored{" "}
              {status.rejected.untrusted_count} linked CI status event
              {status.rejected.untrusted_count === 1 ? "" : "s"}.
            </p>
          ) : null}
          {status.rejected.malformed_count > 0 ||
          status.rejected.unexpected_request_count > 0 ? (
            <p
              className="px-3 py-2 text-muted-foreground text-sm"
              role="status"
            >
              Ignored{" "}
              {status.rejected.malformed_count +
                status.rejected.unexpected_request_count}{" "}
              malformed or unexpected linked CI event
              {status.rejected.malformed_count +
                status.rejected.unexpected_request_count ===
              1
                ? ""
                : "s"}
              .
            </p>
          ) : null}
          <ul aria-label="CI job graph" className="divide-y divide-border/50">
            {status.reduction.jobs.map((job) => (
              <li
                className="flex items-center gap-3 px-3 py-2 text-sm"
                key={`${job.job_id}:${job.attempt}`}
              >
                <span className="min-w-0 flex-1 truncate">
                  {job.name || job.job_id}
                </span>
                {job.required ? (
                  <span className="text-muted-foreground text-xs">
                    required
                  </span>
                ) : null}
                <span className="text-muted-foreground text-xs">
                  attempt {job.attempt}
                </span>
                <span className="capitalize">
                  {stateLabel(job.state ?? "pending")}
                </span>
              </li>
            ))}
          </ul>
        </article>
      ))}
    </section>
  );
}
