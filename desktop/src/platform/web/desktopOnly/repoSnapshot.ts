import type { BrowserIdentityManager } from "../identity";
import { nip98Fetch } from "../nip98";
import { dispatch, register, type InvokeBody } from "../registry";
import { BrowserUnavailableError } from "./capabilityOff";

const SNAPSHOT_TIMEOUT_MS = 15_000;
const MAX_DATE_SECONDS = 8_640_000_000_000;
const OWNER_RE = /^[0-9a-f]{64}$/;
const REPO_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const BROWSER_UNAVAILABLE_HINT =
  "repository README, files and commits need the relay's snapshot endpoint (relay update pending) or the desktop app";

type ObjectBody = Record<string, unknown>;

type RepoSnapshotOptions = {
  timeoutMs?: number;
};

type RepoSnapshotCommit = {
  hash: string;
  short_hash: string;
  author_name: string;
  author_email: string;
  subject: string;
  timestamp: number;
};

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
    throw new TypeError("cloneUrl must be an absolute HTTP(S) URL");
  }

  const relayUrl = new URL(relayUrlValue);
  if (
    !["http:", "https:"].includes(cloneUrl.protocol) ||
    cloneUrl.protocol !== relayUrl.protocol
  ) {
    throw new TypeError(
      "cloneUrl must use HTTPS unless the active relay uses HTTP",
    );
  }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDateTimestamp(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) && Math.abs(value as number) <= MAX_DATE_SECONDS
  );
}

function isNullableDateTimestamp(value: unknown): value is number | null {
  return value === null || isDateTimestamp(value);
}

function isCommit(value: unknown): value is RepoSnapshotCommit {
  return (
    isRecord(value) &&
    typeof value.hash === "string" &&
    typeof value.short_hash === "string" &&
    typeof value.author_name === "string" &&
    typeof value.author_email === "string" &&
    typeof value.subject === "string" &&
    isDateTimestamp(value.timestamp)
  );
}

function isFile(value: unknown): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    typeof value.path === "string" &&
    typeof value.kind === "string" &&
    (value.size === null ||
      (Number.isSafeInteger(value.size) && (value.size as number) >= 0)) &&
    (value.preview_content === null ||
      typeof value.preview_content === "string") &&
    isNullableDateTimestamp(value.last_changed_at) &&
    (value.latest_commit === null || isCommit(value.latest_commit))
  );
}

function isSnapshot(value: unknown): value is Record<string, unknown> & {
  latest_commit: RepoSnapshotCommit | null;
  files: Record<string, unknown>[];
} {
  if (
    !isRecord(value) ||
    !(value.latest_commit === null || isCommit(value.latest_commit)) ||
    !Array.isArray(value.files) ||
    !value.files.every(isFile)
  ) {
    return false;
  }
  if (
    value.commits !== undefined &&
    (!Array.isArray(value.commits) || !value.commits.every(isCommit))
  ) {
    return false;
  }
  return (
    value.contributors === undefined ||
    (Array.isArray(value.contributors) &&
      value.contributors.every(
        (contributor) =>
          isRecord(contributor) &&
          typeof contributor.name === "string" &&
          typeof contributor.email === "string" &&
          Number.isSafeInteger(contributor.commit_count) &&
          (contributor.commit_count as number) >= 0 &&
          isDateTimestamp(contributor.last_commit_at),
      ))
  );
}

async function getProjectRepoSnapshot(
  bodyValue: InvokeBody,
  identity: BrowserIdentityManager,
  options: RepoSnapshotOptions,
): Promise<unknown> {
  const body = objectBody(bodyValue);
  const cloneUrl = optionalString(body, "cloneUrl", true) as string;
  const ref =
    optionalString(body, "targetRef") ??
    optionalString(body, "targetCommit") ??
    optionalString(body, "defaultBranch");
  const targetCommit = optionalString(body, "targetCommit");
  const url = snapshotUrl(cloneUrl, await activeRelayHttpUrl(), ref);
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? SNAPSHOT_TIMEOUT_MS,
  );

  try {
    let response: Response;
    let fetchIssued = false;
    try {
      response = await nip98Fetch(
        { url, method: "GET", signal: controller.signal },
        {
          signEvent: async (template) => identity.sign(template),
          fetch: (input, init) => {
            fetchIssued = true;
            return fetch(input, init);
          },
        },
      );
    } catch (error) {
      if (controller.signal.aborted || isAbortError(error)) {
        throw new Error("snapshot request timed out");
      }
      if (!fetchIssued) {
        throw new Error(
          `snapshot request could not be signed: ${errorMessage(error)}`,
        );
      }
      throw new Error(
        `snapshot request failed to connect: ${errorMessage(error)}`,
      );
    }

    if (response.status === 404) {
      const marker = await response.json().catch(() => null);
      if (isRecord(marker) && typeof marker.message === "string") {
        throw new Error(marker.message);
      }
      throw new BrowserUnavailableError(
        "get_project_repo_snapshot",
        BROWSER_UNAVAILABLE_HINT,
      );
    }
    if ([405, 501].includes(response.status)) {
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
    if (response.status === 429) {
      throw new Error("relay is busy generating the snapshot; timed out");
    }
    if (response.status === 504) {
      throw new Error("relay timed out generating the snapshot");
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
    if (!isSnapshot(snapshot)) {
      throw new Error("snapshot response has an unexpected shape");
    }
    if (
      targetCommit !== undefined &&
      (snapshot.latest_commit === null ||
        snapshot.latest_commit.hash.toLowerCase() !==
          targetCommit.toLowerCase())
    ) {
      throw new Error("the requested repository ref changed");
    }
    return snapshot;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export function registerRepoSnapshotCommands(
  identity: BrowserIdentityManager,
  options: RepoSnapshotOptions = {},
): void {
  register("get_project_repo_snapshot", (body) =>
    getProjectRepoSnapshot(body, identity, options),
  );
}
