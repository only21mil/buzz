import {
  projectCollectionQueryKey,
  type ProjectCollectionScope,
} from "./projectCollectionScope";
import type { QueryClient } from "@tanstack/react-query";

import { normalizeRelayUrl } from "@/features/profile/lib/selfProfileStorage";
import { setLocalStorageItemWithRecovery } from "@/shared/lib/localStorageQuota";
import type { Project } from "./projectModels";

const STORAGE_KEY_PREFIX = "buzz-projects.v1";
export const PROJECTS_QUERY_KEY = ["projects"] as const;
/** Project provenance is non-enumerable, so equal relay rows must replace snapshots. */
export const PROJECT_QUERY_STRUCTURAL_SHARING = false;
const PROJECT_PROVENANCE = Symbol("project-provenance");
type ProjectProvenance = "local-write" | "relay";

type ProjectSnapshotScope = {
  pubkey: string;
  relayUrl: string;
};

type StoredProjectSnapshot = {
  integrity: string;
  ownerPubkey: string;
  projects: Project[];
  updatedAt: number;
  version: 1;
};

const snapshotScopes = new WeakMap<QueryClient, ProjectSnapshotScope>();
const authoritativeProjectCollections = new WeakMap<QueryClient, Set<string>>();

/** Returns the community scope registered when its snapshot was seeded. */
export function getProjectSnapshotScope(
  queryClient: QueryClient,
): ProjectCollectionScope | undefined {
  const scope = snapshotScopes.get(queryClient);
  return scope
    ? { pubkey: scope.pubkey, relayOrigin: scope.relayUrl }
    : undefined;
}

function scopeId(scope: ProjectCollectionScope | undefined) {
  return JSON.stringify(
    scope ? projectCollectionQueryKey(scope) : PROJECTS_QUERY_KEY,
  );
}

/** Marks one project's origin without upgrading sibling snapshot rows. */
export function markProjectDataAuthoritative<T extends Project>(
  project: T,
  provenance: ProjectProvenance,
): T {
  Object.defineProperty(project, PROJECT_PROVENANCE, {
    configurable: true,
    value: provenance,
  });
  return project;
}

/** Returns whether this exact project came from a live read or local write. */
export function isProjectDataAuthoritative(
  project: Project | null | undefined,
): boolean {
  return Boolean(
    project &&
      (project as Project & { [PROJECT_PROVENANCE]?: ProjectProvenance })[
        PROJECT_PROVENANCE
      ],
  );
}

/** Returns whether relay reads validated this project's repository models. */
export function isProjectRelayValidated(
  project: Project | null | undefined,
): boolean {
  return (
    (
      project as
        | (Project & { [PROJECT_PROVENANCE]?: ProjectProvenance })
        | null
        | undefined
    )?.[PROJECT_PROVENANCE] === "relay"
  );
}

/** Copies non-serialized provenance when replacing one cached project object. */
export function inheritProjectDataProvenance<T extends Project>(
  source: Project,
  replacement: T,
): T {
  const provenance = (
    source as Project & { [PROJECT_PROVENANCE]?: ProjectProvenance }
  )[PROJECT_PROVENANCE];
  return provenance
    ? markProjectDataAuthoritative(replacement, provenance)
    : replacement;
}

/** Records that exhaustive relay enumeration completed for this query client. */
export function markProjectCollectionAuthoritative(
  queryClient: QueryClient,
  scope = getProjectSnapshotScope(queryClient),
): void {
  const scopes =
    authoritativeProjectCollections.get(queryClient) ?? new Set<string>();
  scopes.add(scopeId(scope));
  authoritativeProjectCollections.set(queryClient, scopes);
}

/** Returns whether exhaustive relay enumeration completed for this client. */
export function isProjectCollectionAuthoritative(
  queryClient: QueryClient,
  scope = getProjectSnapshotScope(queryClient),
): boolean {
  return (
    authoritativeProjectCollections.get(queryClient)?.has(scopeId(scope)) ??
    false
  );
}

/** Keeps the active-channel fast path live while only a snapshot is present. */
export function shouldUseScopedProjectHomeLookup({
  collectionIsAuthoritative,
  hasEnumeratedProjectHome,
  isHuddleTranscript,
}: {
  collectionIsAuthoritative: boolean;
  hasEnumeratedProjectHome: boolean;
  isHuddleTranscript: boolean;
}): boolean {
  return (
    !isHuddleTranscript &&
    !hasEnumeratedProjectHome &&
    !collectionIsAuthoritative
  );
}

function projectSnapshotRelayPrefix(relayUrl: string): string {
  const url = new URL(normalizeRelayUrl(relayUrl));
  if (url.protocol === "https:") url.protocol = "wss:";
  if (url.protocol === "http:") url.protocol = "ws:";
  return `${STORAGE_KEY_PREFIX}:${url.origin}:`;
}

export function projectSnapshotKey(
  relayUrl: string,
  ownerPubkey: string,
): string {
  return `${projectSnapshotRelayPrefix(relayUrl)}${ownerPubkey.toLowerCase()}`;
}

function snapshotIntegrity(ownerPubkey: string, projects: Project[]): string {
  const value = JSON.stringify([ownerPubkey.toLowerCase(), projects]);
  let result = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    result ^= value.charCodeAt(index);
    result = Math.imul(result, 0x01000193);
  }
  return (result >>> 0).toString(16).padStart(8, "0");
}

function isProject(value: unknown): value is Project {
  if (typeof value !== "object" || value === null) return false;
  const project = value as Partial<Project>;
  return (
    typeof project.id === "string" &&
    typeof project.owner === "string" &&
    typeof project.projectAddress === "string" &&
    (typeof project.projectChannelId === "string" ||
      project.projectChannelId === null) &&
    Array.isArray(project.repositoryAddresses) &&
    Array.isArray(project.repositories) &&
    typeof project.legacy === "boolean"
  );
}

function parseProjectSnapshot(
  value: unknown,
  ownerPubkey: string,
): Project[] | null {
  if (typeof value !== "object" || value === null) return null;
  const snapshot = value as Partial<StoredProjectSnapshot>;
  if (
    snapshot.version !== 1 ||
    snapshot.ownerPubkey?.toLowerCase() !== ownerPubkey.toLowerCase() ||
    !Array.isArray(snapshot.projects) ||
    !snapshot.projects.every(isProject) ||
    typeof snapshot.integrity !== "string" ||
    snapshot.integrity !== snapshotIntegrity(ownerPubkey, snapshot.projects)
  ) {
    return null;
  }
  return snapshot.projects;
}

export function readProjectSnapshot(
  relayUrl: string,
  ownerPubkey: string,
): Project[] | null {
  try {
    const raw = window.localStorage.getItem(
      projectSnapshotKey(relayUrl, ownerPubkey),
    );
    return raw ? parseProjectSnapshot(JSON.parse(raw), ownerPubkey) : null;
  } catch {
    return null;
  }
}

/**
 * Seeds the last fully validated project collection into a community's fresh
 * query client. Timestamp zero keeps it stale so the relay revalidates it.
 */
export function seedProjectSnapshot(
  queryClient: QueryClient,
  scope: ProjectSnapshotScope,
): void {
  snapshotScopes.set(queryClient, scope);
  const projects = readProjectSnapshot(scope.relayUrl, scope.pubkey);
  if (projects) {
    queryClient.setQueryData(
      projectCollectionQueryKey({
        pubkey: scope.pubkey,
        relayOrigin: scope.relayUrl,
      }),
      projects,
      { updatedAt: 0 },
    );
  }
}

/** Persists a successful complete enumeration for the current community. */
export function persistProjectSnapshot(
  queryClient: QueryClient,
  projects: Project[],
  collectionScope = getProjectSnapshotScope(queryClient),
): void {
  const scope = collectionScope
    ? { pubkey: collectionScope.pubkey, relayUrl: collectionScope.relayOrigin }
    : undefined;
  if (!scope) return;
  try {
    const snapshot: StoredProjectSnapshot = {
      integrity: snapshotIntegrity(scope.pubkey, projects),
      ownerPubkey: scope.pubkey.toLowerCase(),
      projects,
      updatedAt: Date.now(),
      version: 1,
    };
    setLocalStorageItemWithRecovery(
      projectSnapshotKey(scope.relayUrl, scope.pubkey),
      JSON.stringify(snapshot),
    );
  } catch {
    // Snapshot persistence is optional; live relay data remains authoritative.
  }
}

/** Removes every identity's project snapshot for a deleted community. */
export function removeProjectSnapshotForRelay(relayUrl: string): void {
  try {
    const prefix = projectSnapshotRelayPrefix(relayUrl);
    const keys: string[] = [];
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (key?.startsWith(prefix)) keys.push(key);
    }
    for (const key of keys) window.localStorage.removeItem(key);
  } catch {
    // Storage access failures are non-fatal.
  }
}
