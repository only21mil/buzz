type BrowserLocation = Pick<Location, "href" | "origin" | "protocol">;

function currentLocation(): BrowserLocation | undefined {
  return typeof globalThis.location === "undefined"
    ? undefined
    : globalThis.location;
}

function expectedRelayOrigin(location: BrowserLocation): string {
  const expected = new URL(location.origin);
  expected.protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return expected.origin;
}

/**
 * Validate the browser relay transport boundary.
 *
 * The hosted client is intentionally same-origin. It has no browser UI for
 * adding communities, so accepting an arbitrary socket URL would only create
 * a credential-egress path. Tests and non-browser tooling can omit a location.
 */
export function normalizeBrowserRelayUrl(
  value: string,
  location: BrowserLocation | undefined = currentLocation(),
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Relay URL is invalid");
  }

  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("Relay URL must use ws:// or wss://");
  }
  if (url.username || url.password) {
    throw new Error("Relay URL must not contain credentials");
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Relay URL must target the relay origin");
  }
  if (location && url.origin !== expectedRelayOrigin(location)) {
    throw new Error("Browser relay URL must match the application origin");
  }

  return url.toString().replace(/\/$/, "");
}

export function relayHttpUrlFromBrowserRelay(relayUrl: string): string {
  const url = new URL(relayUrl);
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("Relay URL must use ws:// or wss://");
  }
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  return url.toString().replace(/\/$/, "");
}
