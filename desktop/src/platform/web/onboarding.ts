import { type InvokeBody, register } from "./registry";

const MAX_JOIN_POLICY_RESPONSE_BYTES = 4 * 1024 * 1024;
const JOIN_POLICY_REQUEST_TIMEOUT_MS = 15_000;

type BrowserFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function relayUrlFromBody(body: InvokeBody): string {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array ||
    typeof body.relayUrl !== "string"
  ) {
    throw new TypeError("fetch_join_policy requires a relayUrl string");
  }
  return body.relayUrl;
}

export function joinPolicyUrl(relayUrl: string): URL {
  let url: URL;
  try {
    url = new URL(relayUrl.trim());
  } catch {
    throw new Error("invalid relay URL");
  }

  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("relay URL must use ws:// or wss://");
  }
  if (url.username || url.password) {
    throw new Error("relay URL must not contain credentials");
  }

  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/api/join-policy`;
  url.search = "";
  url.hash = "";
  return url;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (
    contentLength !== null &&
    Number(contentLength) > MAX_JOIN_POLICY_RESPONSE_BYTES
  ) {
    throw new Error("relay returned oversized join policy");
  }

  const reader = response.body?.getReader();
  if (!reader) {
    try {
      return JSON.parse(await response.text());
    } catch {
      throw new Error("relay returned malformed join policy");
    }
  }

  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_JOIN_POLICY_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("relay returned oversized join policy");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("relay returned malformed join policy");
  }
}

export async function fetchBrowserJoinPolicy(
  body: InvokeBody,
  fetchImpl: BrowserFetch = globalThis.fetch,
  timeoutMs = JOIN_POLICY_REQUEST_TIMEOUT_MS,
): Promise<unknown | null> {
  const url = joinPolicyUrl(relayUrlFromBody(body));
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted) {
        throw new Error("join policy request timed out");
      }
      throw new Error(
        `join policy request failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const bodyJson = await readBoundedJson(response);
    if (
      typeof bodyJson !== "object" ||
      bodyJson === null ||
      !("policy" in bodyJson)
    ) {
      return null;
    }
    return bodyJson.policy ?? null;
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error("join policy request timed out");
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export function registerOnboardingCommands(
  fetchImpl: BrowserFetch = globalThis.fetch,
): void {
  register("discover_acp_providers", () => []);
  register("fetch_join_policy", (body) =>
    fetchBrowserJoinPolicy(body, fetchImpl),
  );
}
