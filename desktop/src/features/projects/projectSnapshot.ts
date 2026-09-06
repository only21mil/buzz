import type { RelayEvent } from "@/shared/api/types";
import { buildProjectReadModels, type Project } from "./projectModels";
import { markProjectSnapshotRow } from "./projectSnapshotProvenance";

export { isProjectSnapshotRow } from "./projectSnapshotProvenance";

export type ProjectSnapshotScope = { relayOrigin: string; pubkey: string };
const PREFIX = "buzz.projects.events.v1:";
const MAX_BYTES = 2_000_000;
const MAX_EVENTS = 10_000;
const MAX_AGE_MS = 24 * 60 * 60_000;
function normalizedScope(scope: ProjectSnapshotScope): ProjectSnapshotScope {
  const url = new URL(scope.relayOrigin);
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    !/^[0-9a-f]{64}$/i.test(scope.pubkey)
  )
    throw new Error("Invalid project snapshot scope.");
  return { relayOrigin: url.origin, pubkey: scope.pubkey.toLowerCase() };
}
export function projectSnapshotKey(scope: ProjectSnapshotScope): string {
  const value = normalizedScope(scope);
  return `${PREFIX}${encodeURIComponent(value.relayOrigin)}:${value.pubkey}`;
}
function isEvent(value: unknown): value is RelayEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<RelayEvent>;
  return (
    typeof event.id === "string" &&
    /^[0-9a-f]{64}$/i.test(event.id) &&
    typeof event.pubkey === "string" &&
    /^[0-9a-f]{64}$/i.test(event.pubkey) &&
    typeof event.kind === "number" &&
    [30617, 30621, 5].includes(event.kind) &&
    Number.isSafeInteger(event.created_at) &&
    (event.created_at ?? -1) >= 0 &&
    typeof event.content === "string" &&
    event.content.length <= 65_536 &&
    Array.isArray(event.tags) &&
    event.tags.length <= 1024 &&
    event.tags.every(
      (tag) =>
        Array.isArray(tag) &&
        tag.length <= 1024 &&
        tag.every((part) => typeof part === "string" && part.length <= 8192),
    )
  );
}

/** Persist only complete raw enumeration; cached projections never grant authority. */
export function writeProjectSnapshot(
  scope: ProjectSnapshotScope,
  events: RelayEvent[],
  storage?: Storage,
  now = Date.now(),
): void {
  try {
    storage ??= typeof window === "undefined" ? undefined : window.localStorage;
    if (!storage) return;
    if (events.length > MAX_EVENTS || !events.every(isEvent)) return;
    const value = {
      ...normalizedScope(scope),
      version: 1,
      updatedAt: now,
      events,
    };
    const raw = JSON.stringify(value);
    if (raw.length <= MAX_BYTES)
      storage.setItem(projectSnapshotKey(scope), raw);
  } catch {
    /* Optional startup cache must not fail a live read. */
  }
}

/** Rebuild through the live model parser, then mark every row as display-only. */
export function readProjectSnapshot(
  scope: ProjectSnapshotScope,
  storage?: Storage,
  now = Date.now(),
): Project[] | undefined {
  try {
    storage ??= typeof window === "undefined" ? undefined : window.localStorage;
    if (!storage) return undefined;
    const raw = storage.getItem(projectSnapshotKey(scope));
    if (!raw || raw.length > MAX_BYTES) return undefined;
    const value = JSON.parse(raw) as Record<string, unknown>;
    const expected = normalizedScope(scope);
    if (
      value.version !== 1 ||
      value.relayOrigin !== expected.relayOrigin ||
      value.pubkey !== expected.pubkey ||
      typeof value.updatedAt !== "number" ||
      !Number.isSafeInteger(value.updatedAt) ||
      value.updatedAt > now ||
      now - value.updatedAt > MAX_AGE_MS ||
      !Array.isArray(value.events) ||
      value.events.length > MAX_EVENTS ||
      !value.events.every(isEvent)
    )
      return undefined;
    const events = value.events;
    const projects = buildProjectReadModels({
      projectEvents: events.filter((event) => event.kind === 30621),
      repositoryEvents: events.filter((event) => event.kind === 30617),
      deletionEvents: events.filter((event) => event.kind === 5),
      relayOrigin: expected.relayOrigin,
    });
    for (const project of projects) markProjectSnapshotRow(project);
    return projects;
  } catch {
    return undefined;
  }
}

export function removeProjectSnapshotForRelay(
  relayUrl: string,
  storage?: Storage,
): void {
  try {
    storage ??= typeof window === "undefined" ? undefined : window.localStorage;
    if (!storage) return;
    const url = new URL(
      relayUrl.replace(/^wss:/, "https:").replace(/^ws:/, "http:"),
    );
    const prefix = `${PREFIX}${encodeURIComponent(url.origin)}:`;
    const target = storage;
    const keys = Array.from({ length: target.length }, (_, index) =>
      target.key(index),
    );
    for (const key of keys)
      if (key?.startsWith(prefix)) storage.removeItem(key);
  } catch {
    /* Storage failures are nonfatal. */
  }
}
