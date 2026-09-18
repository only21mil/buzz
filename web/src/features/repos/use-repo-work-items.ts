import { useQuery } from "@tanstack/react-query";
import { queryEvents } from "@/shared/lib/nostr-client";
import { relayWsUrl } from "@/shared/lib/relay-url";
import {
  parseRepoWorkItems,
  partitionRepoWorkItemEvents,
  repoWorkItemFilters,
  type RepoWorkItems,
} from "./repo-work-items.mjs";

export async function fetchRepoWorkItems(
  repoAddress: string,
): Promise<RepoWorkItems> {
  // One REQ with all five filters: one socket and one AUTH exchange per
  // page load instead of five.
  const filters = repoWorkItemFilters(repoAddress);
  const events = await queryEvents(relayWsUrl(), [
    filters.issues,
    filters.pullRequests,
    filters.pullRequestUpdates,
    filters.comments,
    filters.statuses,
  ]);
  return parseRepoWorkItems(partitionRepoWorkItemEvents(events));
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
