import type { HttpClient } from "isomorphic-git";

import {
  assembleRepoSnapshot,
  assertRepositoryWithinSize,
  repoSnapshotCacheName,
  type RepoSnapshotLoadInput,
  type SnapshotFileSource,
} from "./repoSnapshot";

const CACHE_MANIFEST_PREFIX = "buzz-git-cache-v1-";
const CACHE_MAX_REPOSITORIES = 5;
const CACHE_MAX_TOTAL_BYTES = 100 * 1024 * 1024;
const REF_MARKER_PATH = "/.buzz-snapshot-ref";

type CacheEntry = {
  name: string;
  lastUsed: number;
  sizeBytes: number;
};

type CacheManifest = {
  version: 1;
  entries: CacheEntry[];
};

type GitDependencies = Awaited<ReturnType<typeof loadGitDependencies>>;
type LightningFs = InstanceType<GitDependencies["LightningFS"]>;

const cacheOperations = new Map<string, Promise<unknown>>();

async function loadGitDependencies() {
  const bufferModule = (await import("buffer")) as unknown as {
    Buffer: unknown;
  };
  if (typeof (globalThis as Record<string, unknown>).Buffer === "undefined") {
    (globalThis as Record<string, unknown>).Buffer = bufferModule.Buffer;
  }
  const [git, httpModule, lightningModule] = await Promise.all([
    import("isomorphic-git"),
    import("isomorphic-git/http/web"),
    import("@isomorphic-git/lightning-fs"),
  ]);
  return {
    git,
    http: httpModule.default,
    LightningFS: lightningModule.default,
  };
}

function manifestKey(pubkey: string): string {
  return `${CACHE_MANIFEST_PREFIX}${pubkey.toLowerCase()}`;
}

function readManifest(pubkey: string): CacheManifest {
  if (typeof localStorage === "undefined") return { version: 1, entries: [] };
  try {
    const parsed: unknown = JSON.parse(
      localStorage.getItem(manifestKey(pubkey)) ?? "null",
    );
    if (!parsed || typeof parsed !== "object")
      return { version: 1, entries: [] };
    const entries = (parsed as CacheManifest).entries;
    if (!Array.isArray(entries)) return { version: 1, entries: [] };
    return {
      version: 1,
      entries: entries.filter(
        (entry) =>
          entry &&
          typeof entry.name === "string" &&
          entry.name.startsWith(`buzz-git-1-${pubkey.toLowerCase()}-`) &&
          typeof entry.lastUsed === "number" &&
          typeof entry.sizeBytes === "number",
      ),
    };
  } catch {
    return { version: 1, entries: [] };
  }
}

function writeManifest(pubkey: string, manifest: CacheManifest): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(manifestKey(pubkey), JSON.stringify(manifest));
}

async function wipeCache(
  LightningFS: GitDependencies["LightningFS"],
  name: string,
) {
  const fs = new LightningFS(name, { wipe: true });
  await fs.promises.stat("/");
  await fs.promises.flush();
}

async function recordCacheUse(
  dependencies: GitDependencies,
  pubkey: string,
  name: string,
  sizeBytes: number,
): Promise<void> {
  const evicted = await withCacheLock(`manifest:${pubkey}`, async () => {
    const entries = readManifest(pubkey)
      .entries.filter((entry) => entry.name !== name)
      .concat({ name, lastUsed: Date.now(), sizeBytes })
      .sort((left, right) => right.lastUsed - left.lastUsed);
    const retained: CacheEntry[] = [];
    const removed: CacheEntry[] = [];
    let retainedBytes = 0;
    for (const entry of entries) {
      if (
        retained.length < CACHE_MAX_REPOSITORIES &&
        retainedBytes + entry.sizeBytes <= CACHE_MAX_TOTAL_BYTES
      ) {
        retained.push(entry);
        retainedBytes += entry.sizeBytes;
      } else {
        removed.push(entry);
      }
    }
    writeManifest(pubkey, { version: 1, entries: retained });
    return removed;
  });
  await Promise.all(
    evicted.map((entry) =>
      entry.name === name
        ? wipeCache(dependencies.LightningFS, entry.name)
        : withCacheLock(entry.name, () =>
            wipeCache(dependencies.LightningFS, entry.name),
          ),
    ),
  );
}

function withCacheLock<T>(
  name: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = cacheOperations.get(name) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  cacheOperations.set(name, current);
  return current.finally(() => {
    if (cacheOperations.get(name) === current) cacheOperations.delete(name);
  });
}

function budgetedHttp(
  http: HttpClient,
  assertIdentityScope: () => void,
): HttpClient {
  let receivedBytes = 0;
  return {
    async request(request) {
      assertIdentityScope();
      const response = await http.request(request);
      assertIdentityScope();
      const advertised = Number(response.headers?.["content-length"] ?? "");
      if (Number.isFinite(advertised) && advertised > 0) {
        assertRepositoryWithinSize(receivedBytes + advertised);
      }
      if (!response.body) return response;
      const body = response.body;
      return {
        ...response,
        body: (async function* boundedBody() {
          for await (const chunk of body) {
            assertIdentityScope();
            receivedBytes += chunk.byteLength;
            assertRepositoryWithinSize(receivedBytes);
            yield chunk;
          }
        })(),
      };
    },
  };
}

async function resetForRef(
  dependencies: GitDependencies,
  fs: LightningFs,
  cacheName: string,
  ref: string,
): Promise<LightningFs> {
  try {
    const storedRef = await fs.promises.readFile(REF_MARKER_PATH, "utf8");
    if (storedRef === ref) return fs;
  } catch {
    // A missing marker means an empty or pre-schema cache and must be rebuilt.
  }
  await wipeCache(dependencies.LightningFS, cacheName);
  return new dependencies.LightningFS(cacheName);
}

async function listTreeFiles(
  dependencies: GitDependencies,
  fs: LightningFs,
  dir: string,
  oid: string,
): Promise<SnapshotFileSource[]> {
  const files: SnapshotFileSource[] = [];
  const visit = async (prefix = "") => {
    const result = await dependencies.git.readTree({
      fs,
      dir,
      oid,
      filepath: prefix || undefined,
    });
    const entries = [...result.tree].sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
    );
    for (const entry of entries) {
      const path = prefix ? `${prefix}/${entry.path}` : entry.path;
      if (entry.type === "tree") {
        await visit(path);
      } else {
        files.push({ path, kind: entry.type, oid: entry.oid });
      }
    }
  };
  await visit();
  return files;
}

export async function loadRepoSnapshot(
  input: RepoSnapshotLoadInput,
): Promise<Awaited<ReturnType<typeof assembleRepoSnapshot>>> {
  const cacheName = repoSnapshotCacheName(
    input.pubkey,
    input.owner,
    input.repo,
  );
  return withCacheLock(cacheName, async () => {
    const dependencies = await loadGitDependencies();
    input.assertIdentityScope();
    let fs = new dependencies.LightningFS(cacheName);
    fs = await resetForRef(dependencies, fs, cacheName, input.selectedRef.ref);
    const dir = `/${input.owner}/${input.repo}`;
    await dependencies.git.init({ fs, dir });
    await dependencies.git.addRemote({
      fs,
      dir,
      remote: "origin",
      url: input.url,
      force: true,
    });
    await recordCacheUse(
      dependencies,
      input.pubkey,
      cacheName,
      await fs.promises.du("/"),
    );
    const fetched = await dependencies.git.fetch({
      fs,
      http: budgetedHttp(dependencies.http, input.assertIdentityScope),
      dir,
      url: input.url,
      ref: input.selectedRef.ref,
      depth: 1,
      singleBranch: true,
      tags: false,
      headers: { Authorization: input.authorization },
    });
    input.assertIdentityScope();
    const oid = fetched.fetchHead;
    if (
      input.selectedRef.expectedCommit &&
      oid?.toLowerCase() !== input.selectedRef.expectedCommit
    ) {
      throw new Error(
        "The requested repository ref changed. Refresh and try again.",
      );
    }
    await fs.promises.writeFile(REF_MARKER_PATH, input.selectedRef.ref, "utf8");

    const snapshot = await assembleRepoSnapshot(
      {
        async readCommit(commitOid) {
          input.assertIdentityScope();
          const { commit } = await dependencies.git.readCommit({
            fs,
            dir,
            oid: commitOid,
          });
          input.assertIdentityScope();
          return {
            hash: commitOid,
            short_hash: commitOid.slice(0, 7),
            author_name: commit.author.name,
            author_email: commit.author.email,
            timestamp: commit.author.timestamp,
            subject: commit.message.split(/\r?\n/, 1)[0] ?? "",
          };
        },
        async listFiles(commitOid) {
          input.assertIdentityScope();
          const files = await listTreeFiles(dependencies, fs, dir, commitOid);
          input.assertIdentityScope();
          return files;
        },
        async readBlob(commitOid, path) {
          input.assertIdentityScope();
          const { blob } = await dependencies.git.readBlob({
            fs,
            dir,
            oid: commitOid,
            filepath: path,
          });
          input.assertIdentityScope();
          return blob;
        },
      },
      oid,
    );
    input.assertIdentityScope();
    await fs.promises.flush();
    await recordCacheUse(
      dependencies,
      input.pubkey,
      cacheName,
      await fs.promises.du("/"),
    );
    return snapshot;
  });
}

export async function purgeRepoSnapshotGitCache(
  pubkey?: string,
): Promise<void> {
  if (typeof localStorage === "undefined") return;
  const pubkeys = pubkey
    ? [pubkey.toLowerCase()]
    : Array.from({ length: localStorage.length }, (_, index) =>
        localStorage.key(index),
      )
        .filter(
          (key): key is string =>
            key?.startsWith(CACHE_MANIFEST_PREFIX) ?? false,
        )
        .map((key) => key.slice(CACHE_MANIFEST_PREFIX.length));
  for (const scopedPubkey of pubkeys) {
    const entries = await withCacheLock(
      `manifest:${scopedPubkey}`,
      async () => {
        const scopedEntries = readManifest(scopedPubkey).entries;
        localStorage.removeItem(manifestKey(scopedPubkey));
        return scopedEntries;
      },
    );
    if (entries.length > 0) {
      const dependencies = await loadGitDependencies();
      await Promise.all(
        entries.map((entry) =>
          withCacheLock(entry.name, () =>
            wipeCache(dependencies.LightningFS, entry.name),
          ),
        ),
      );
    }
  }
}
