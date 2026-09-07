import * as React from "react";
import { isTauri } from "@tauri-apps/api/core";

import { relayClient } from "@/shared/api/relayClient";
import { reconcileInboundPersonaEvent } from "@/shared/api/tauriPersonas";
import type { RelayEvent } from "@/shared/api/types";
import {
  KIND_DELETION,
  KIND_MANAGED_AGENT,
  KIND_PERSONA,
  KIND_TEAM,
  KIND_TEAM_CATALOG,
} from "@/shared/constants/kinds";

// Persona/team/managed-agent projections (upserts), the owner's own team
// catalog heads (30178), plus kind:5 NIP-09 deletions, so a tombstone published
// by another device also removes the local record here.
//
// The 30178 head has no local record — it is retained only as this device's
// publication witness, so a second device's boot reconcile and interactive
// refresh have a row to supersede or retract. Without it, device B never learns
// device A published, and B's later edit or delete cannot update A's
// discoverable catalog entry.
const PERSONA_SYNC_KINDS = [
  KIND_PERSONA,
  KIND_TEAM,
  KIND_MANAGED_AGENT,
  KIND_TEAM_CATALOG,
  KIND_DELETION,
];

// One history page. The relay clamps a REQ `limit` to its advertised
// `max_limit` (1000; `crates/buzz-db` `DEFAULT_MAX_PAGE_LIMIT`), so a single
// query can never return an owner's complete history once it exceeds the page —
// `startPersonaSync` pages to exhaustion (see `fetchOwnerHistoryToExhaustion`).
const PERSONA_HISTORY_PAGE_LIMIT = 500;

// Bounded retry for a transient backfill failure. A deterministic
// dense-boundary rejection is NOT retried (a retry cannot clear a genuinely
// dense second); only network/transport rejections are. After the last attempt
// the pipeline falls to degraded-live rather than looping forever.
const BACKFILL_MAX_ATTEMPTS = 3;
const BACKFILL_RETRY_BASE_DELAY_MS = 500;

// Thrown when `fetchOwnerHistoryToExhaustion` reaches a full page whose oldest
// event cannot advance the time-only cursor: more than one page of events share
// the boundary second, and the WS filter has no `(created_at, id)` cursor to
// escape it. Distinct from a transport error so the caller fails loudly into
// degraded-live instead of silently proceeding with partial history.
export class PersonaHistoryDenseBoundaryError extends Error {
  constructor(boundarySecond: number) {
    super(
      `owner history has >1 page of events at created_at ${boundarySecond}; ` +
        `the time-only relay cursor cannot page past it`,
    );
    this.name = "PersonaHistoryDenseBoundaryError";
  }
}

async function backfillBackoff(attempt: number): Promise<void> {
  const ms = BACKFILL_RETRY_BASE_DELAY_MS * 2 ** attempt;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function eventDTag(event: RelayEvent): string | null {
  return event.tags.find((tag) => tag[0] === "d")?.[1] ?? null;
}

function eventIsNewer(candidate: RelayEvent, current: RelayEvent): boolean {
  return (
    candidate.created_at > current.created_at ||
    (candidate.created_at === current.created_at && candidate.id < current.id)
  );
}

// The catalog dependency set: the 30178 head and the 30175/30176 coordinates a
// team-catalog refresh resolves against. Degraded-live holds every live event
// that could drive (or destructively re-trigger) a catalog refresh against an
// unhydrated store — see `dispatchLive`. A kind-5 deletion is held whenever ANY
// parseable `a` tag names a dependency coordinate (`<kind>:<owner>:<d_tag>`):
// Rust's `parse_deletion_coordinate` scans all `a` tags and routes the first
// signer-owned dependency target, so classifying on the first tag alone would
// dispatch a deletion that Rust still routes destructively (a foreign/malformed
// first tag ahead of an owned 30176). We do not duplicate Rust's signer/owner
// validation — false-positive holding during an abnormal self-healing state is
// safer than letting a Rust-routable destructive tombstone through.
const CATALOG_DEPENDENCY_KINDS: ReadonlySet<number> = new Set([
  KIND_PERSONA,
  KIND_TEAM,
  KIND_TEAM_CATALOG,
]);

function deletionTargetsDependency(event: RelayEvent): boolean {
  return event.tags.some((tag) => {
    if (tag[0] !== "a" || !tag[1]) return false;
    const kind = Number.parseInt(tag[1].split(":", 1)[0], 10);
    return !Number.isNaN(kind) && CATALOG_DEPENDENCY_KINDS.has(kind);
  });
}

function isCatalogDependencyEvent(event: RelayEvent): boolean {
  if (event.kind === KIND_DELETION) {
    return deletionTargetsDependency(event);
  }
  return CATALOG_DEPENDENCY_KINDS.has(event.kind);
}

/**
 * Keep only the NIP-33 head for each managed-agent coordinate in a startup
 * backfill. Applying historical policy revisions one by one can stop and start
 * the same runtime for every revision; the retained store only needs the final
 * head. Other event kinds stay in relay order because persona/team projections
 * do not trigger runtime policy transitions and deletion ordering is separate.
 */
export function coalesceManagedAgentBackfill(
  events: readonly RelayEvent[],
): RelayEvent[] {
  const heads = new Map<string, RelayEvent>();

  for (const event of events) {
    if (event.kind !== KIND_MANAGED_AGENT) continue;
    const dTag = eventDTag(event);
    if (!dTag) continue;
    const coordinate = `${event.pubkey.toLowerCase()}:${dTag.toLowerCase()}`;
    const current = heads.get(coordinate);
    if (!current || eventIsNewer(event, current)) heads.set(coordinate, event);
  }

  return events.filter((event) => {
    if (event.kind !== KIND_MANAGED_AGENT) return true;
    const dTag = eventDTag(event);
    if (!dTag) return true;
    return (
      heads.get(`${event.pubkey.toLowerCase()}:${dTag.toLowerCase()}`) === event
    );
  });
}

/**
 * Dispatch owner catalog heads (30178) AFTER their constituents within the
 * complete hydration batch. A freshly shared 30178 head is typically newer than
 * the 30176 team and 30175 personas it projects, so relay newest-first order
 * places it first. Reconciling in that raw order lets the inbound team refresh
 * run while device B's personas have not hydrated: member resolution fails, and
 * the resolution-failure arm purges the just-retained witness and queues a
 * dominating false tombstone — deleting the owner's valid catalog entry on
 * ordinary first sync.
 *
 * The stable partition preserves relay order within each group. It does not
 * establish member readiness on returning devices with retained witnesses, or
 * for later live team edits: native inbound refresh also defers unresolved
 * memberships. The hydration boundary awaits successful native applies before
 * releasing buffered dependency operations.
 */
export function orderCatalogHeadsLast(
  events: readonly RelayEvent[],
): RelayEvent[] {
  const constituents = events.filter(
    (event) => event.kind !== KIND_TEAM_CATALOG,
  );
  const catalogHeads = events.filter(
    (event) => event.kind === KIND_TEAM_CATALOG,
  );
  return [...constituents, ...catalogHeads];
}

// Fetch the owner's complete persona/team/agent/deletion history, paging past
// the relay's per-query `max_limit` clamp. The relay serves each REQ newest-first
// (`created_at DESC, id ASC`) and clamps `limit` to its advertised ceiling, so a
// single 500-event query cannot return a large owner's full history: a newer
// 30178/30176 could land in-page while an older required 30175 constituent falls
// outside it, and the ordered-last partition can only reorder what came back.
// Paging with the `until` time cursor (the only cursor the WS REQ filter exposes —
// the DB `before_id` keyset is REST-only) walks the full window to exhaustion.
//
// `until` is inclusive (`created_at <= until`), so each page re-returns the rows
// at the boundary second; `seen` dedupes them. A page shorter than the limit means
// the window is exhausted.
//
// A FULL page whose oldest event does not advance the cursor below the current
// `until` means more than one page of events share that boundary second. The WS
// filter exposes no `(created_at, id)` cursor to escape a dense second, so
// silently stopping there would drop every older event — including a required
// 30175 constituent — and leave hydration falsely "complete". Fail loudly with
// `PersonaHistoryDenseBoundaryError` so the caller degrades explicitly rather
// than projecting partial history as exhaustive.
async function fetchOwnerHistoryToExhaustion(
  pubkey: string,
): Promise<RelayEvent[]> {
  const collected: RelayEvent[] = [];
  const seen = new Set<string>();
  let until: number | undefined;

  for (;;) {
    const page = await relayClient.fetchEvents({
      kinds: PERSONA_SYNC_KINDS,
      authors: [pubkey],
      limit: PERSONA_HISTORY_PAGE_LIMIT,
      ...(until === undefined ? {} : { until }),
    });

    let added = 0;
    let oldest = Number.POSITIVE_INFINITY;
    for (const event of page) {
      if (event.created_at < oldest) oldest = event.created_at;
      if (seen.has(event.id)) continue;
      seen.add(event.id);
      collected.push(event);
      added += 1;
    }

    if (page.length < PERSONA_HISTORY_PAGE_LIMIT) break;
    // A full page that cannot lower the cursor is an unadvanceable dense second.
    if (until !== undefined && oldest >= until)
      throw new PersonaHistoryDenseBoundaryError(oldest);
    if (added === 0) throw new PersonaHistoryDenseBoundaryError(oldest);
    until = oldest;
  }

  return collected;
}

// Start the persona/team/agent/deletion sync for `pubkey` on `relayUrl`:
// exhaustive backfill of existing heads + tombstones, then a live subscription.
// Returns a disposer that closes the live subscription. Extracted from the hook
// so the wiring is unit-testable without a React renderer (see
// `usePersonaSync.test.mjs`).
//
// `relayUrl` is the community this subscription is bound to, and every reconcile
// carries it as the event's arrival relay. Capturing it here — rather than
// letting the backend read whichever workspace is active when the reconcile runs
// — is what keeps an in-flight event out of the next community's scoped store.
//
// STARTUP ORDER. The live subscription is established FIRST and its ready
// boundary awaited, THEN the backfill runs. The live REQ only registers at the
// relay once `subscribe()`'s `sendRawWithReconnectRetry` completes, so starting
// the backfill first opens a gap: an owner event published after the history
// REQ's EOSE but before the live REQ registers is returned by neither path, and
// the device holds stale state until remount. Subscribing first means every
// such event is delivered live (and buffered) instead of lost.
//
// If the initial live registration REJECTS (relay unreachable, or a terminal
// auth state — `relayClientSession.subscribe()` deletes the sub and rethrows),
// the rejection is consumed, the pipeline enters degraded-live, and the backfill
// still runs so history hydrates. Sequencing the backfill inside the
// subscription's `.then()` must not make a subscription failure suppress
// hydration — nor leave an unhandled rejection.
//
// HYDRATION BOUNDARY. Once the live subscription is ready, its events feed one
// reconcile chain shared with the backfill. A live/replayed 30178 that arrives
// before the backfill has reconciled its 30175/30176 constituents reproduces the
// false-tombstone purge (member resolution fails against an unhydrated store).
// Live events are therefore BUFFERED until the complete, dependency-ordered
// backfill has been dispatched, then drained in arrival order. Setting `hydrated`
// and draining the buffer are synchronous and uninterrupted, so no live event can
// slip past the boundary. Steady-state live events (after hydration) reconcile
// immediately.
//
// DEDUPE. Because the live sub registers before the backfill fetches history, an
// event published in that window is delivered live (buffered) AND returned by
// the backfill query. The backend already skips an equal-id retained echo before
// any runtime refresh (`inbound_event_outcome()` on the serialized reconcile
// chain), so a duplicate is not destructive — but re-dispatching it still crosses
// IPC and re-enters the backend for no reason. The drain drops any buffered event
// whose id the backfill already reconciled to avoid that redundant round-trip.
// Steady-state events post-drain carry ids the backfill never saw, so they are
// unaffected.
//
// FAILURE POLICY. A transient backfill fetch failure is retried with bounded
// backoff. If backfill cannot complete (retries exhausted, or a deterministic
// dense-boundary error), the pipeline enters DEGRADED-LIVE rather than leaving
// the subscription permanently inert: the boundary still opens so buffered and
// future live events keep reconciling, but the whole catalog dependency set
// (30178, its 30175/30176 constituents, and kind-5 deletions targeting them) is
// dropped because those events could drive a catalog refresh against an
// unhydrated store. 30177 runtime policy stays live. Degraded state self-heals
// on the next effect re-run.
export function startPersonaSync(
  pubkey: string,
  relayUrl: string,
  onCancelled: () => boolean,
): () => Promise<void> {
  if (!isTauri()) return async () => {};
  // Reconcile in dispatch order. Managed-agent reconciliation can await a remote
  // provider deployment after releasing the local store lock; firing commands
  // independently lets an older broad policy finish after a newer restrictive
  // one. One chain per owner/relay subscription makes the newest event the last
  // deployment without serializing unrelated identities or communities.
  let reconcileChain = Promise.resolve();
  const reconcile = (event: RelayEvent): Promise<void> => {
    const applied = reconcileChain.then(async () => {
      if (event.pubkey !== pubkey || onCancelled()) return;
      await reconcileInboundPersonaEvent(JSON.stringify(event), relayUrl);
    });
    // Keep the serializer usable after an error, but return the rejected apply
    // to its caller. Only that caller can decide whether hydration succeeded.
    reconcileChain = applied.catch(() => {});
    return applied;
  };

  // Event ids the backfill successfully reconciled. The live subscription registers
  // before the backfill queries history, so an event published in that window
  // is delivered live (buffered) AND returned by the backfill. The backend
  // dedupes an equal-id echo, so the duplicate is harmless, but the drain skips
  // it to avoid a redundant IPC round-trip. Populated during backfill, consulted
  // once at drain.
  const backfillReconciledIds = new Set<string>();

  // Live events that arrive before the backfill finishes hydrating are held
  // here and drained once the constituents are reconciled. `hydrated` opens the
  // boundary; `degraded` records that hydration ended in failure rather than a
  // complete backfill (see the backfill runner below).
  let hydrated = false;
  let degraded = false;

  // Dispatch a live (post-boundary or drained-buffer) event. In DEGRADED mode
  // the owner's constituents were never fully hydrated, so the whole catalog
  // dependency set is held: the 30178 head itself, its 30175/30176
  // constituents, and any kind-5 deletion targeting one of those coordinates.
  //
  // Native upserts defer missing members, but signed deletions still retract
  // immediately. Incomplete history or a failed save therefore keeps the whole
  // dependency set held. Managed-agent policy can continue independently.
  // After retry exhaustion, the next effect run refetches history to self-heal.
  // Serialize retries as well as applies: later dependency operations cannot
  // overtake a failed save. Managed-agent policy remains live after exhaustion.
  let liveChain = Promise.resolve();
  const dispatchLive = (event: RelayEvent) => {
    liveChain = liveChain.then(async () => {
      if (onCancelled()) return;
      if (degraded && isCatalogDependencyEvent(event)) {
        liveBuffer.push(event);
        return;
      }
      for (let attempt = 0; attempt < BACKFILL_MAX_ATTEMPTS; attempt += 1) {
        try {
          await reconcile(event);
          return;
        } catch (error) {
          if (onCancelled()) return;
          if (attempt < BACKFILL_MAX_ATTEMPTS - 1) {
            await backfillBackoff(attempt);
            continue;
          }
          console.warn(
            "[usePersonaSync] live apply failed; holding dependencies:",
            error,
          );
          degraded = true;
          liveBuffer.push(event);
        }
      }
    });
  };

  const liveBuffer: RelayEvent[] = [];
  const onLiveEvent = (event: RelayEvent) => {
    if (event.pubkey !== pubkey) return;
    if (hydrated) {
      dispatchLive(event);
    } else {
      liveBuffer.push(event);
    }
  };

  // Open the hydration boundary and drain buffered live events. Setting
  // `hydrated` and draining are synchronous and uninterrupted, so no live event
  // can slip past the boundary. `degraded` must be set before this runs so the
  // drain applies the same catalog-hold policy as future live events.
  const openBoundaryAndDrain = () => {
    hydrated = true;
    const buffered = liveBuffer.splice(0);
    for (const event of buffered) {
      if (backfillReconciledIds.has(event.id)) continue;
      dispatchLive(event);
    }
  };

  // Exhaustive one-shot backfill (closes the fresh-start gap that live-only
  // subscription + reconnect-replay cannot recover). Coalesce managed-agent
  // revisions, defer 30178 catalog heads past their constituents, dispatch the
  // ordered batch successfully, THEN drain buffered live events.
  //
  // A transient fetch failure is retried with bounded backoff; a deterministic
  // `PersonaHistoryDenseBoundaryError` is NOT retried (a dense second cannot
  // clear on retry). When every attempt fails the pipeline transitions to
  // degraded-live rather than leaving the subscription permanently inert:
  // `hydrated` still opens so buffered and future live events keep reconciling,
  // with catalog dependencies held (see `dispatchLive`).
  const runBackfill = async () => {
    // Keep the fetched batch across apply retries. A changed relay response
    // must not erase an event whose native save failed.
    let history: RelayEvent[] | undefined;
    for (let attempt = 0; attempt < BACKFILL_MAX_ATTEMPTS; attempt += 1) {
      try {
        history ??= orderCatalogHeadsLast(
          coalesceManagedAgentBackfill(
            await fetchOwnerHistoryToExhaustion(pubkey),
          ),
        );
        if (onCancelled()) return;
        for (const event of history) {
          if (backfillReconciledIds.has(event.id)) continue;
          await reconcile(event);
          if (onCancelled()) return;
          backfillReconciledIds.add(event.id);
        }
        openBoundaryAndDrain();
        return;
      } catch (error) {
        if (onCancelled()) return;
        const transient = !(error instanceof PersonaHistoryDenseBoundaryError);
        if (transient && attempt < BACKFILL_MAX_ATTEMPTS - 1) {
          console.warn(
            `[usePersonaSync] backfill attempt ${attempt + 1} failed, retrying:`,
            error,
          );
          await backfillBackoff(attempt);
          continue;
        }
        console.warn(
          "[usePersonaSync] backfill failed; entering degraded-live sync:",
          error,
        );
        degraded = true;
        if (history) {
          liveBuffer.push(
            ...history.filter((event) => !backfillReconciledIds.has(event.id)),
          );
        }
        openBoundaryAndDrain();
        return;
      }
    }
  };

  // Establish the live subscription FIRST and await its ready boundary before
  // starting the backfill. `subscribeLive` resolves only after `subscribe()`
  // has registered the REQ at the relay (or hit its readiness timeout), so any
  // owner event published between the backfill's EOSE and live registration is
  // delivered to `onLiveEvent` (buffered) rather than missed by both paths.
  // Events arriving before the backfill dispatches are held in `liveBuffer`;
  // `openBoundaryAndDrain` releases them.
  let unsub: (() => Promise<void>) | null = null;
  void relayClient
    .subscribeLive(
      { kinds: PERSONA_SYNC_KINDS, authors: [pubkey], limit: 0 },
      onLiveEvent,
    )
    .then((dispose) => {
      if (onCancelled()) {
        void dispose();
        return;
      }
      unsub = dispose;
      void runBackfill();
    })
    .catch((error) => {
      // The initial live registration failed: `subscribe()` deleted the sub and
      // rethrew (relay unreachable, or a terminal auth state that its own
      // reconnect retries cannot clear). There is no outer restart —
      // `usePersonaSync` remounts only on `[pubkey, relayUrl]` change — so we
      // must not leave both paths inert or leak an unhandled rejection. Consume
      // it, enter degraded-live, and still backfill so history hydrates. No live
      // sub registered, so `liveBuffer` is empty and no future live event will
      // arrive; `degraded` records the device is live-blind until the next
      // effect re-run self-heals. Backfill reconciles history directly, so a
      // successful backfill still hydrates the full catalog.
      if (onCancelled()) return;
      console.warn(
        "[usePersonaSync] live subscription failed; backfilling in degraded-live sync:",
        error,
      );
      degraded = true;
      void runBackfill();
    });

  return async () => {
    if (unsub) await unsub();
  };
}

// Subscribes to this device's own persona/team/agent projection + deletion
// events and patches each into the local store. The subscription is keyed on
// the active pubkey and relay: an identity or community switch re-runs the
// effect, whose cleanup closes the old subscription before a new one opens on
// the new filter — so no stale-coordinate subscription survives, and every
// reconcile is attributed to the community it was subscribed to.
//
// A fresh device that comes online AFTER another already published gets no
// history from a live-only subscription: relayClient's replayLiveSubscriptions
// only replays from a since-cursor that is undefined until the first live
// event arrives. So `startPersonaSync` does an explicit one-shot history fetch
// up front and feeds each event through the same reconcile path.
export function usePersonaSync(
  pubkey: string | undefined,
  relayUrl: string | undefined,
): void {
  React.useEffect(() => {
    if (!pubkey || !relayUrl || !isTauri()) return;
    let cancelled = false;
    const dispose = startPersonaSync(pubkey, relayUrl, () => cancelled);
    return () => {
      cancelled = true;
      void dispose();
    };
  }, [pubkey, relayUrl]);
}
