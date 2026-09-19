const PREFIX = "/api/admin/v1";

export class ApiFailure extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/// Auth mode the relay requires, discovered via a single unauthenticated
/// probe: `200` means `disabled` (no credential), anything else means
/// `nip98` (fail-secure; NIP-98 is the only authenticated mode).
export type AuthMode = "nip98" | "disabled";

interface Nostr98 {
  signEvent(event: {
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
  }): Promise<Record<string, unknown>>;
}

function nostrExtension(): Nostr98 {
  const nostr = (window as Window & { nostr?: Nostr98 }).nostr;
  if (!nostr) throw new Error("No NIP-07 extension available");
  return nostr;
}

/// Sign a NIP-98 kind-27235 event for the URL plus method via the NIP-07
/// browser extension. Throws when no extension is present or signing fails.
///
/// Every call mints a fresh `nonce` tag. Without it, two same-URL requests
/// in one second sign byte-identical events (only `u`, `method`, and
/// 1-second `created_at` vary), their ids collide, and the relay replay
/// guard rejects the second. The verifier ignores unknown tags, so the nonce
/// only makes each event unique.
///
/// For body-bearing requests the caller passes `body`; a `payload` tag with
/// the hex SHA-256 of the exact bytes ships alongside. The relay rejects a
/// body-bearing request whose `payload` tag is absent or mismatched, so the
/// hash must cover the identical bytes the request sends.
async function signNip98(
  url: string,
  method: string,
  body?: Uint8Array,
): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceHex = Array.from(nonce, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const tags: string[][] = [
    ["u", url],
    ["method", method],
    ["nonce", nonceHex],
  ];
  if (body !== undefined) {
    const digest = await crypto.subtle.digest("SHA-256", body as BufferSource);
    const payloadHex = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    tags.push(["payload", payloadHex]);
  }
  const event = await nostrExtension().signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  });
  return `Nostr ${btoa(JSON.stringify(event))}`;
}

async function send(
  path: string,
  accept: string,
  authMode: AuthMode,
  init?: { method?: string; body?: Uint8Array; contentType?: string },
): Promise<Response> {
  const method = init?.method ?? "GET";
  const body = init?.body;
  const doRequest = async () => {
    const headers: Record<string, string> = { accept };
    if (init?.contentType) headers["content-type"] = init.contentType;
    if (authMode === "nip98") {
      const url = `${location.protocol}//${location.host}${PREFIX}${path}`;
      headers.authorization = await signNip98(url, method, body);
    }
    return fetch(`${PREFIX}${path}`, {
      method,
      credentials: "same-origin",
      headers,
      body: body as BodyInit | undefined,
    });
  };

  let response = await doRequest();
  if (response.status === 401 && authMode === "nip98") {
    // Re-sign once with a fresh event (clock skew, key rotation). A second
    // 401 surfaces below. No retry loop.
    response = await doRequest();
  }
  if (response.status === 401) {
    throw new ApiFailure(401, "The admin credential was rejected.");
  }
  if (!response.ok) {
    const envelope = await response.json().catch(() => null);
    throw new ApiFailure(
      response.status,
      envelope?.error?.message ?? `Request failed (${response.status})`,
    );
  }
  return response;
}

export async function request<T>(path: string, authMode: AuthMode): Promise<T> {
  const response = await send(path, "application/json", authMode);
  return response.json() as Promise<T>;
}

/// Discover the relay auth mode with one unauthenticated request: `200`
/// means `disabled`, anything else (including network failure) means
/// `nip98`. Fail-secure by construction.
export async function probeAuthMode(): Promise<AuthMode> {
  try {
    const response = await fetch(`${PREFIX}/probe`, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    return response.status === 200 ? "disabled" : "nip98";
  } catch {
    return "nip98";
  }
}

/// Fetch an attachment through the credentialed API and return an object URL
/// for rendering. `<img src>` and `<a href>` carry no Authorization header,
/// so in NIP-98 mode bytes must flow through here. Callers revoke the URL
/// when it is replaced or unmounted.
export async function requestObjectUrl(
  path: string,
  authMode: AuthMode,
): Promise<string> {
  const response = await send(path, "*/*", authMode);
  const blob = await response.blob();
  return URL.createObjectURL(blob);
}
