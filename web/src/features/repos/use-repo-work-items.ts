import { useQuery } from "@tanstack/react-query";
import { queryEvents } from "@/shared/lib/nostr-client";
import { relayWsUrl } from "@/shared/lib/relay-url";
import {
  parseRepoWorkItems,
  repoWorkItemFilters,
  type RepoWorkItems,
} from "./repo-work-items.mjs";

export async function fetchRepoWorkItems(
  repoAddress: string,
): Promise<RepoWorkItems> {
  const filters = repoWorkItemFilters(repoAddress);
  const [
    issueEvents,
    pullRequestEvents,
    updateEvents,
    commentEvents,
    statuses,
  ] = await Promise.all([
    queryEvents(relayWsUrl(), filters.issues),
    queryEvents(relayWsUrl(), filters.pullRequests),
    queryEvents(relayWsUrl(), filters.pullRequestUpdates),
    queryEvents(relayWsUrl(), filters.comments),
    queryEvents(relayWsUrl(), filters.statuses),
  ]);

  return parseRepoWorkItems({
    issueEvents,
    pullRequestEvents,
    updateEvents,
    commentEvents,
    statusEvents: statuses,
  });
}

export function useRepoWorkItems(
  repoAddress: string,
  { enabled = true }: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: ["repo-work-items", repoAddress],
    queryFn: () => fetchRepoWorkItems(repoAddress),
    enabled: enabled && Boolean(repoAddress),
    staleTime: 60_000,
  });
}
