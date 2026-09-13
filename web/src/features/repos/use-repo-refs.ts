import { useQuery } from "@tanstack/react-query";
import { queryEvents } from "@/shared/lib/nostr-client";
import { relayHttpBaseUrl, relayWsUrl } from "@/shared/lib/relay-url";
import { getRelaySelf } from "@/shared/lib/relay-self.mjs";
import {
  parseRefs,
  refsFilter,
  selectTrustedRefsEvents,
  type RepoRefs,
} from "./repo-refs.mjs";

export type { RepoRefs };

async function fetchRepoRefs(repoId: string): Promise<RepoRefs> {
  // kind:30618 is relay-signed. Constrain the query to the relay's own
  // pubkey (NIP-11 `self`) and drop anything else client-side — without
  // this, a member with ReposWrite could publish spoofed refs. A `null`
  // self (ephemeral-key relay) falls back to the unfiltered query.
  const relaySelf = await getRelaySelf(relayHttpBaseUrl()).catch(() => null);
  const events = await queryEvents(relayWsUrl(), refsFilter(repoId, relaySelf));
  return parseRefs(selectTrustedRefsEvents(events, relaySelf));
}

export function useRepoRefs(repoId: string, { preview = false } = {}) {
  const mockRefs: RepoRefs = {
    branches: ["main"],
    tags: ["v0.1.0"],
    head: { ref: "main", sha: "a".repeat(40) },
  };

  return useQuery({
    queryKey: preview ? ["repo-refs", "mock", repoId] : ["repo-refs", repoId],
    queryFn: preview ? async () => mockRefs : () => fetchRepoRefs(repoId),
    initialData: preview ? mockRefs : undefined,
    staleTime: 60_000,
  });
}
