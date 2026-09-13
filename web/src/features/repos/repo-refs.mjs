/**
 * Pure helpers for NIP-34 ref-state reads (kind:30618).
 *
 * The relay signs these events with its own key, so every read constrains
 * the filter to the relay's NIP-11 `self` pubkey and drops events from any
 * other author. Without that, any member with write access could publish
 * spoofed refs for someone else's repo.
 */

export const REPO_STATE_KIND = 30618;

/**
 * Build the REQ filter for a repo's ref state. The authors constraint
 * applies only when the relay's own pubkey is known; relays on ephemeral
 * keys advertise no `self`, and an unfiltered query is the only option.
 */
export function refsFilter(repoId, relaySelf) {
  const filter = { kinds: [REPO_STATE_KIND], "#d": [repoId] };
  if (relaySelf) {
    filter.authors = [relaySelf];
  }
  return filter;
}

/**
 * Client-side author check. The relay enforces the authors filter, but a
 * stale cache or a lax relay could still hand back spoofed events, so drop
 * anything not signed by the relay when its pubkey is known.
 */
export function selectTrustedRefsEvents(events, relaySelf) {
  if (!relaySelf) return events;
  return events.filter((event) => event && event.pubkey === relaySelf);
}

/** Keep the latest event per (pubkey, kind, d-tag) — NIP-33 ordering. */
function dedupLatest(events) {
  const best = new Map();
  for (const event of events) {
    const d = event.tags.find((tag) => tag[0] === "d")?.[1] ?? "";
    const key = `${event.pubkey}:${event.kind}:${d}`;
    const prev = best.get(key);
    if (!prev || event.created_at > prev.created_at) {
      best.set(key, event);
    }
  }
  return [...best.values()];
}

export function parseRefs(events) {
  const latest = dedupLatest(events);
  const branches = [];
  const tags = [];
  let head = null;

  for (const event of latest) {
    for (const tag of event.tags) {
      const [name, value] = tag;
      if (!name || !value) continue;

      if (name === "HEAD" && value.startsWith("ref: refs/heads/")) {
        // HEAD points to a branch ref — find its SHA from a matching branch tag
        const branchName = value.replace("ref: refs/heads/", "");
        head = { ref: branchName, sha: "" };
      } else if (name.startsWith("refs/heads/")) {
        branches.push(name.replace("refs/heads/", ""));
      } else if (name.startsWith("refs/tags/")) {
        tags.push(name.replace("refs/tags/", ""));
      }
    }
  }

  // Resolve HEAD SHA from the matching branch
  if (head) {
    for (const event of latest) {
      for (const tag of event.tags) {
        if (tag[0] === `refs/heads/${head.ref}` && tag[1]) {
          head = { ref: head.ref, sha: tag[1] };
          break;
        }
      }
      if (head.sha) break;
    }
  }

  return { branches, tags, head };
}
