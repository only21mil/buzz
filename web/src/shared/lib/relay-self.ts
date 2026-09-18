/**
 * Relay identity for the web client.
 *
 * The relay signs NIP-34 ref-state events (kind:30618) with its own key and
 * advertises that key as the NIP-11 `self` field (served at `GET /info`).
 * Reads that must only trust relay-signed state resolve it here, then
 * constrain their Nostr filter to `authors: [relaySelf]` and drop any event
 * whose pubkey does not match.
 *
 * A `null` result is a valid answer (the relay runs an ephemeral key and
 * advertises no `self`); callers fall back to the unfiltered query. Network
 * and malformed-document failures reject so callers can tell "unknown" apart
 * from "no self".
 */

const HEX_PUBKEY_RE = /^[0-9a-f]{64}$/;

let cachedUrl: string | null = null;
let cachedPromise: Promise<string | null> | null = null;

export function isRelaySelfPubkey(value: unknown): value is string {
  return typeof value === "string" && HEX_PUBKEY_RE.test(value);
}

async function fetchRelaySelf(baseUrl: string): Promise<string | null> {
  const response = await fetch(`${baseUrl}/info`, {
    headers: { Accept: "application/nostr+json" },
  });
  if (!response.ok) {
    throw new Error(`Relay info request failed: HTTP ${response.status}`);
  }
  const doc: unknown = await response.json();
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error("Malformed relay info document");
  }
  const self = (doc as { self?: unknown }).self;
  return isRelaySelfPubkey(self) ? self : null;
}

/**
 * Resolve the relay's NIP-11 `self` pubkey (hex) or `null` when it
 * advertises none. The result is cached per base URL; failures are not
 * cached so a later call retries.
 */
export function getRelaySelf(baseUrl: string): Promise<string | null> {
  if (!cachedPromise || cachedUrl !== baseUrl) {
    const promise = fetchRelaySelf(baseUrl);
    cachedUrl = baseUrl;
    cachedPromise = promise;
    promise.catch(() => {
      if (cachedUrl === baseUrl) {
        cachedUrl = null;
        cachedPromise = null;
      }
    });
    return promise;
  }
  return cachedPromise;
}

/** Drop the cached value (tests). */
export function resetRelaySelfCache(): void {
  cachedUrl = null;
  cachedPromise = null;
}
