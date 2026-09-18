import type { NostrEvent, NostrFilter } from "@/shared/lib/nostr-client";

export interface RepoRefs {
  branches: string[];
  tags: string[];
  head: { ref: string; sha: string } | null;
}

export const REPO_STATE_KIND: 30618;

export function refsFilter(
  repoId: string,
  relaySelf: string | null,
): NostrFilter;

export function selectTrustedRefsEvents(
  events: NostrEvent[],
  relaySelf: string | null,
): NostrEvent[];

export function parseRefs(events: NostrEvent[]): RepoRefs;
