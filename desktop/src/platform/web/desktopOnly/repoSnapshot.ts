import type { BrowserIdentityManager } from "../identity";
import { buildNip98Authorization } from "../nip98";
import { dispatch, register, type InvokeBody } from "../registry";
import { BrowserUnavailableError } from "./capabilityOff";

export const REPO_SNAPSHOT_SCHEMA_VERSION = 1;
export const REPO_SNAPSHOT_FETCH_LIMIT_BYTES = 25 * 1024 * 1024;
export const REPO_SNAPSHOT_PREVIEW_LIMIT_BYTES = 64 * 1024;

const REPO_SNAPSHOT_COMMAND = "get_project_repo_snapshot";
const README_PATTERNS = ["readme.md", "readme", "readme.rst", "readme.txt"];
const HEX_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const HEX_PUBKEY = /^[0-9a-f]{64}$/i;

export type RawRepoCommit = {
  hash: string;
  short_hash: string;
  author_name: string;
  author_email: string;
  timestamp: number;
  subject: string;
};

export type RawRepoFile = {
  path: string;
  kind: string;
  size: number | null;
  preview_content: string | null;
  last_changed_at: number | null;
  latest_commit: RawRepoCommit | null;
};

export type RawRepoSnapshot = {
  latest_commit: RawRepoCommit | null;
  commit_count: number | null;
  commits: RawRepoCommit[];
  files: RawRepoFile[];
  contributors: Array<{
    name: string;
    email: string;
    commit_count: number;
    last_commit_at: number;
  }>;
};

export type SnapshotFileSource = {
  path: string;
  kind: "blob" | "commit";
  oid: string;
};

export type SnapshotReader = {
  readCommit(oid: string): Promise<RawRepoCommit>;
  listFiles(oid: string): Promise<SnapshotFileSource[]>;
  readBlob(oid: string, path: string): Promise<Uint8Array>;
};

export type SelectedRepoRef = {
  ref: string;
  expectedCommit: string | null;
};

export type ValidatedRepoUrl = {
  url: string;
  owner: string;
  repo: string;
};

export type RepoSnapshotLoadInput = ValidatedRepoUrl & {
  authorization: string;
  pubkey: string;
  selectedRef: SelectedRepoRef;
  assertIdentityScope: () => void;
};

type RepoSnapshotLoader = (
  input: RepoSnapshotLoadInput,
) => Promise<RawRepoSnapshot>;

type RegisterRepoSnapshotOptions = {
  loadSnapshot?: RepoSnapshotLoader;
};

function objectBody(body: InvokeBody): Record<string, unknown> {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${REPO_SNAPSHOT_COMMAND} requires an object body`);
  }
  return body;
}

function optionalString(
  body: Record<string, unknown>,
  field: string,
): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function cleanBranch(value: string | null): string | null {
  let branch = value?.trim() ?? "";
  while (branch.startsWith("refs/heads/")) {
    branch = branch.slice("refs/heads/".length);
  }
  if (
    !branch ||
    branch.startsWith("-") ||
    branch.startsWith("/") ||
    branch.endsWith("/") ||
    branch.includes("..") ||
    !/^[a-z0-9/_.-]+$/i.test(branch)
  ) {
    return null;
  }
  return branch;
}

function cleanTargetRef(value: string | null): string | null {
  const targetRef = value?.trim() ?? "";
  for (const prefix of ["refs/tags/", "refs/nostr/"]) {
    if (!targetRef.startsWith(prefix)) continue;
    const name = targetRef.slice(prefix.length);
    return cleanBranch(name) === name ? `${prefix}${name}` : null;
  }
  return null;
}

/** Match the desktop command's target-ref/commit/default-branch precedence. */
export function selectRepoRef(args: {
  defaultBranch?: string | null;
  baseBranch?: string | null;
  targetRef?: string | null;
  targetCommit?: string | null;
}): SelectedRepoRef {
  const targetRef = cleanTargetRef(args.targetRef ?? null);
  const targetCommit = HEX_COMMIT.test(args.targetCommit?.trim() ?? "")
    ? (args.targetCommit?.trim().toLowerCase() ?? null)
    : null;
  return {
    ref:
      targetRef ??
      targetCommit ??
      cleanBranch(args.defaultBranch ?? null) ??
      "HEAD",
    expectedCommit: targetCommit,
  };
}

/** Restrict browser git to the active relay's HTTPS origin and Buzz repo path. */
export function validateRepoCloneUrl(
  cloneUrl: string,
  activeRelayHttpUrl: string,
): ValidatedRepoUrl {
  const clone = new URL(cloneUrl);
  const relay = new URL(activeRelayHttpUrl);
  if (
    clone.protocol !== "https:" ||
    relay.protocol !== "https:" ||
    clone.origin !== relay.origin ||
    clone.username ||
    clone.password ||
    clone.search ||
    clone.hash
  ) {
    throw new Error(
      "Browser repository URLs must use credential-free HTTPS on the active relay origin.",
    );
  }

  const segments = clone.pathname.split("/").filter(Boolean);
  const gitIndex = segments.lastIndexOf("git");
  const owner = segments[gitIndex + 1] ?? "";
  const repoSegment = segments[gitIndex + 2] ?? "";
  const repo = repoSegment.endsWith(".git")
    ? repoSegment.slice(0, -".git".length)
    : repoSegment;
  if (
    gitIndex < 0 ||
    segments.length !== gitIndex + 3 ||
    !HEX_PUBKEY.test(owner) ||
    owner !== owner.toLowerCase() ||
    !repo ||
    repo.length > 64 ||
    repo.startsWith(".") ||
    repo.includes("..") ||
    !/^[a-z0-9._-]+$/i.test(repo)
  ) {
    throw new Error("Clone URL must point at a Buzz git repository.");
  }

  return { url: clone.href, owner, repo };
}

export function repoSnapshotCacheName(
  pubkey: string,
  owner: string,
  repo: string,
): string {
  if (!HEX_PUBKEY.test(pubkey) || !HEX_PUBKEY.test(owner)) {
    throw new Error("Repository cache scope requires hexadecimal pubkeys.");
  }
  if (!/^[a-z0-9._-]{1,64}$/i.test(repo)) {
    throw new Error("Repository cache scope requires a valid repository name.");
  }
  return `buzz-git-${REPO_SNAPSHOT_SCHEMA_VERSION}-${pubkey.toLowerCase()}-${owner.toLowerCase()}-${repo}`;
}

function formatMib(bytes: number): string {
  const mib = Math.ceil((bytes / (1024 * 1024)) * 10) / 10;
  return mib.toFixed(1).replace(/\.0$/, "");
}

export function assertRepositoryWithinSize(
  bytes: number,
  limitBytes = REPO_SNAPSHOT_FETCH_LIMIT_BYTES,
): void {
  if (bytes <= limitBytes) return;
  throw new BrowserUnavailableError(
    REPO_SNAPSHOT_COMMAND,
    `Repository is too large to browse in the web app yet (${formatMib(bytes)} MiB; ${formatMib(limitBytes)} MiB limit); use the desktop app`,
  );
}

export function findReadmePath(
  files: readonly SnapshotFileSource[],
): string | null {
  for (const pattern of README_PATTERNS) {
    const match = files.find(
      (file) =>
        file.kind === "blob" &&
        !file.path.includes("/") &&
        file.path.toLowerCase() === pattern,
    );
    if (match) return match.path;
  }
  return null;
}

function textPreview(bytes: Uint8Array): string | null {
  if (bytes.length > REPO_SNAPSHOT_PREVIEW_LIMIT_BYTES) return null;
  if (bytes.includes(0)) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function comparePaths(
  left: SnapshotFileSource,
  right: SnapshotFileSource,
): number {
  return left.path < right.path ? -1 : left.path > right.path ? 1 : 0;
}

/** Assemble the desktop snake_case wire shape from a shallow commit tree. */
export async function assembleRepoSnapshot(
  reader: SnapshotReader,
  oid: string | null,
): Promise<RawRepoSnapshot> {
  if (!oid) {
    return {
      latest_commit: null,
      commit_count: null,
      commits: [],
      files: [],
      contributors: [],
    };
  }

  const latestCommit = await reader.readCommit(oid);
  const sources = (await reader.listFiles(oid))
    .sort(comparePaths)
    .slice(0, 250);
  const files: RawRepoFile[] = [];
  for (const source of sources) {
    if (source.kind !== "blob") {
      files.push({
        path: source.path,
        kind: source.kind,
        size: null,
        preview_content: null,
        last_changed_at: null,
        latest_commit: null,
      });
      continue;
    }
    const bytes = await reader.readBlob(oid, source.path);
    files.push({
      path: source.path,
      kind: "blob",
      size: bytes.length,
      preview_content: textPreview(bytes),
      last_changed_at: null,
      latest_commit: null,
    });
  }

  return {
    latest_commit: latestCommit,
    commit_count: null,
    commits: [latestCommit],
    files,
    contributors: [
      {
        name: latestCommit.author_name,
        email: latestCommit.author_email,
        commit_count: 1,
        last_commit_at: latestCommit.timestamp,
      },
    ],
  };
}

async function defaultLoadSnapshot(
  input: RepoSnapshotLoadInput,
): Promise<RawRepoSnapshot> {
  const { loadRepoSnapshot } = await import("./repoSnapshotGit");
  return loadRepoSnapshot(input);
}

/** Clear one identity's membership-gated repo caches, or every known identity. */
export async function purgeRepoSnapshotCache(pubkey?: string): Promise<void> {
  const { purgeRepoSnapshotGitCache } = await import("./repoSnapshotGit");
  await purgeRepoSnapshotGitCache(pubkey);
}

export function registerRepoSnapshotCommands(
  identity: BrowserIdentityManager,
  options: RegisterRepoSnapshotOptions = {},
): void {
  const loadSnapshot = options.loadSnapshot ?? defaultLoadSnapshot;
  register(REPO_SNAPSHOT_COMMAND, async (body) => {
    const record = objectBody(body);
    const cloneUrl = optionalString(record, "cloneUrl");
    if (!cloneUrl) throw new TypeError("cloneUrl must be a string");
    const pubkey = identity.pubkey().toLowerCase();
    const identityScope = identity.repoSnapshotScope();
    const assertIdentityScope = () => {
      if (identity.repoSnapshotScope() !== identityScope) {
        throw new Error(
          "Browser identity changed while loading the repository.",
        );
      }
    };
    const selectedRef = selectRepoRef({
      defaultBranch: optionalString(record, "defaultBranch"),
      baseBranch: optionalString(record, "baseBranch"),
      targetRef: optionalString(record, "targetRef"),
      targetCommit: optionalString(record, "targetCommit"),
    });
    const validated = validateRepoCloneUrl(
      cloneUrl,
      await dispatch<string>("get_relay_http_url"),
    );
    assertIdentityScope();
    const authorization = await buildNip98Authorization(
      { url: validated.url, method: "GET" },
      { signEvent: async (request) => identity.sign(request) },
    );
    assertIdentityScope();
    const snapshot = await loadSnapshot({
      ...validated,
      authorization,
      pubkey,
      selectedRef,
      assertIdentityScope,
    });
    assertIdentityScope();
    return snapshot;
  });
}
