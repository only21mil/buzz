import type { BrowserIdentityManager } from "../identity";
import { nip98Fetch } from "../nip98";
import { dispatch, register, type InvokeBody } from "../registry";
import { BrowserUnavailableError } from "./capabilityOff";

const SNAPSHOT_TIMEOUT_MS = 15_000;
const OWNER_RE = /^[0-9a-f]{64}$/;
const REPO_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const BROWSER_UNAVAILABLE_HINT =
  "repository README, files and commits need the relay's snapshot endpoint (relay update pending) or the desktop app";

type ObjectBody = Record<string, unknown>;

function objectBody(body: InvokeBody): ObjectBody {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError("get_project_repo_snapshot requires an object body");
  }
  return body;
}

function optionalString(
  body: ObjectBody,
  field: string,
  required = false,
): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) {
    if (required) throw new TypeError(`${field} must be a string`);
    return undefined;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function relayHttpUrl(value: string): string {
  const url = new URL(value.trim());
  if (url.protocol === "wss:") url.protocol = "https:";
  else if (url.protocol === "ws:") url.protocol = "http:";
  else if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Relay URL must use ws://, wss://, http://, or https://");
  }
  return url.toString().replace(/\/$/, "");
}

async function activeRelayHttpUrl(): Promise<string> {
  return relayHttpUrl(await dispatch<string>("get_relay_http_url"));
}

function snapshotUrl(
  cloneUrlValue: string,
  relayUrlValue: string,
  ref: string | undefined,
): string {
  let cloneUrl: URL;
  try {
    cloneUrl = new URL(cloneUrlValue.trim());
  } catch {
    throw new TypeError("cloneUrl must be an absolute HTTPS URL");
  }
  if (cloneUrl.protocol !== "https:") {
    throw new TypeError("cloneUrl must use HTTPS");
  }

  const relayUrl = new URL(relayUrlValue);
  if (cloneUrl.origin !== relayUrl.origin) {
    throw new TypeError("cloneUrl must use the active relay origin");
  }
  if (
    cloneUrl.username ||
    cloneUrl.password ||
    cloneUrl.search ||
    cloneUrl.hash
  ) {
    throw new TypeError("cloneUrl must be a relay repository URL");
  }

  const match = /^\/git\/([^/]+)\/([^/]+)$/.exec(cloneUrl.pathname);
  if (!match) {
    throw new TypeError(
      "cloneUrl path must be /git/<64-hex owner>/<repository>[.git]",
    );
  }
  const [, owner, repoSegment] = match;
  const repo = repoSegment.endsWith(".git")
    ? repoSegment.slice(0, -4)
    : repoSegment;
  if (
    !OWNER_RE.test(owner) ||
    !REPO_RE.test(repo) ||
    repo.startsWith(".") ||
    repo.includes("..")
  ) {
    throw new TypeError(
      "cloneUrl path must be /git/<64-hex owner>/<repository>[.git]",
    );
  }

  const url = new URL(`/git/${owner}/${repo}/snapshot`, relayUrl.origin);
  if (ref !== undefined) url.searchParams.set("ref", ref);
  url.searchParams.set("commits", "20");
  return url.href;
}

function isAbortError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    error.name === "AbortError"
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function getProjectRepoSnapshot(
  bodyValue: InvokeBody,
  identity: BrowserIdentityManager,
): Promise<unknown> {
  const body = objectBody(bodyValue);
  const cloneUrl = optionalString(body, "cloneUrl", true) as string;
  const ref =
    optionalString(body, "targetCommit") ??
    optionalString(body, "targetRef") ??
    optionalString(body, "baseBranch") ??
    optionalString(body, "defaultBranch");
  const url = snapshotUrl(cloneUrl, await activeRelayHttpUrl(), ref);
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(
    () => controller.abort(),
    SNAPSHOT_TIMEOUT_MS,
  );

  try {
    let response: Response;
    try {
      response = await nip98Fetch(
        { url, method: "GET", signal: controller.signal },
        { signEvent: async (template) => identity.sign(template) },
      );
    } catch (error) {
      if (controller.signal.aborted || isAbortError(error)) {
        throw new Error("snapshot request timed out");
      }
      throw new Error(
        `snapshot request failed to connect: ${errorMessage(error)}`,
      );
    }

    if ([404, 405, 501].includes(response.status)) {
      throw new BrowserUnavailableError(
        "get_project_repo_snapshot",
        BROWSER_UNAVAILABLE_HINT,
      );
    }
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        `snapshot request authentication failed (HTTP ${response.status})`,
      );
    }
    if (!response.ok) {
      const responseBody = (await response.text().catch(() => "")).slice(
        0,
        200,
      );
      throw new Error(
        `snapshot request failed (HTTP ${response.status}): ${responseBody}`,
      );
    }

    let snapshot: unknown;
    try {
      snapshot = await response.json();
    } catch (error) {
      if (controller.signal.aborted || isAbortError(error)) {
        throw new Error("snapshot request timed out");
      }
      throw new Error("snapshot response was not valid JSON");
    }
    if (
      typeof snapshot !== "object" ||
      snapshot === null ||
      !("files" in snapshot) ||
      !Array.isArray(snapshot.files)
    ) {
      throw new Error("snapshot response must be an object with a files array");
    }
    return snapshot;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export function registerRepoSnapshotCommands(
  identity: BrowserIdentityManager,
): void {
  register("get_project_repo_snapshot", (body) =>
    getProjectRepoSnapshot(body, identity),
  );
}
