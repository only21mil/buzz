import type { RelayEvent } from "./types";

/**
 * Forward keyset cursor for the server-side thread read (`get_thread_replies`).
 *
 * The event-id tiebreak is load-bearing: thread replies routinely share a
 * `createdAt` second (bursty threads), so a timestamp-only cursor would skip
 * every tied reply past the page limit. The pair `(createdAt, eventId)` orders
 * replies unambiguously and lets paging resume strictly after the last event.
 */
export type ThreadCursor = {
  createdAt: number;
  eventId: string;
};

export type ThreadRepliesResponse = {
  /** Explicit server capability for this page; absent means use legacy backfill. */
  auxIncluded?: boolean;
  /** Reply subtree, plus root/reply auxiliary events when auxIncluded is true. The root content event is excluded. */
  events: RelayEvent[];
  /** Present only when a full page was returned — pass back to fetch the next page. */
  nextCursor: ThreadCursor | null;
};
