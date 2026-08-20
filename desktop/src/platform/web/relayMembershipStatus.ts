import { emit } from "./shims/event";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { verifyEvent } from "nostr-tools/pure";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { register, type InvokeBody } from "./registry";
import type { BrowserWorkspace } from "./workspace";

const NIP_43_MEMBERSHIP_LIST = 13534;
const HEX_PUBKEY = /^[0-9a-f]{64}$/i;

type RelayQueryClient = {
  fetchFirstEvent(filter: {
    authors?: string[];
    kinds: number[];
    limit: number;
  }): Promise<RelayEvent | null>;
};

type BrowserFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function objectBody(
  body: InvokeBody,
  command: string,
): Record<string, unknown> {
  if (
    body === undefined ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body;
}

function relayHttpUrl(relayUrl: string): string {
  const url = new URL(relayUrl);
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("Relay URL must use ws:// or wss://");
  }
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  return url.toString().replace(/\/$/, "");
}

async function fetchRelayInformation(
  url: string,
  fetchImpl: BrowserFetch,
): Promise<{ supported_nips: number[] }> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      cache: "no-store",
      credentials: "omit",
      headers: { Accept: "application/nostr+json" },
    });
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`Relay information request failed${detail}`);
  }
  if (!response.ok) {
    throw new Error(
      `Relay information request failed (HTTP ${response.status})`,
    );
  }
  let value: unknown;
  try {
    value = (await response.json()) as unknown;
  } catch {
    throw new Error("Relay returned malformed NIP-11 document");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Relay returned malformed NIP-11 document");
  }
  const supportedNips = (value as Record<string, unknown>).supported_nips;
  if (supportedNips === undefined) return { supported_nips: [] };
  if (
    !Array.isArray(supportedNips) ||
    !supportedNips.every(
      (nip) =>
        typeof nip === "number" &&
        Number.isInteger(nip) &&
        nip >= 0 &&
        nip <= 4_294_967_295,
    )
  ) {
    throw new Error("Relay returned malformed NIP-11 document");
  }
  return { supported_nips: supportedNips };
}

export async function relayRequiresMembership(
  body: InvokeBody,
  workspace: BrowserWorkspace,
  fetchImpl: BrowserFetch = globalThis.fetch,
): Promise<boolean> {
  const input = objectBody(body, "relay_requires_membership");
  const override = input.relayUrl;
  if (override !== undefined && typeof override !== "string") {
    throw new TypeError("relayUrl must be a string");
  }
  const base = override ? relayHttpUrl(override) : workspace.httpUrl();
  const info = await fetchRelayInformation(`${base}/info`, fetchImpl);
  return info.supported_nips.includes(43);
}

function relayMembersFromEvent(event: RelayEvent): Array<{
  pubkey: string;
  role: string;
}> {
  const seen = new Set<string>();
  const members: Array<{ pubkey: string; role: string }> = [];
  for (const tag of event.tags) {
    if (tag[0] !== "member" || !tag[1] || seen.has(tag[1])) continue;
    seen.add(tag[1]);
    members.push({ pubkey: tag[1], role: tag[2] || "member" });
  }
  for (const tag of event.tags) {
    if (tag[0] !== "p" || !tag[1] || seen.has(tag[1])) continue;
    seen.add(tag[1]);
    members.push({ pubkey: tag[1], role: tag[3] || "member" });
  }
  return members;
}

export async function getMyRelayMembership(
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
): Promise<{ member: { pubkey: string; role: string } | null }> {
  const event = await client.fetchFirstEvent({
    kinds: [NIP_43_MEMBERSHIP_LIST],
    limit: 1,
  });
  const pubkey = identity.pubkey().toLowerCase();
  const member = event
    ? relayMembersFromEvent(event).find(
        (candidate) => candidate.pubkey.toLowerCase() === pubkey,
      )
    : undefined;
  return { member: member ?? null };
}

function validNipOaConditions(conditions: string): boolean {
  if (conditions === "") return true;
  return conditions.split("&").every((clause) => {
    const match = /^(kind=|created_at<|created_at>)(0|[1-9][0-9]*)$/.exec(
      clause,
    );
    if (!match) return false;
    const value = Number(match[2]);
    return (
      Number.isSafeInteger(value) &&
      value <= (match[1] === "kind=" ? 65_535 : 4_294_967_295)
    );
  });
}

export async function resolveOaOwner(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
): Promise<{ owner: string; is_me: boolean } | null> {
  const input = objectBody(body, "resolve_oa_owner");
  if (
    typeof input.targetPubkey !== "string" ||
    !HEX_PUBKEY.test(input.targetPubkey)
  ) {
    throw new TypeError("targetPubkey must be a 64-character hex pubkey");
  }
  const targetPubkey = input.targetPubkey.toLowerCase();
  const event = await client.fetchFirstEvent({
    authors: [targetPubkey],
    kinds: [0],
    limit: 1,
  });
  if (
    event?.kind !== 0 ||
    event.pubkey.toLowerCase() !== targetPubkey ||
    !verifyEvent(event)
  ) {
    return null;
  }
  for (const auth of event?.tags ?? []) {
    if (auth[0] !== "auth" || auth.length !== 4) continue;
    const [, owner, conditions, signature] = auth;
    if (
      !owner ||
      conditions === undefined ||
      !signature ||
      !/^[0-9a-f]{64}$/.test(owner) ||
      !/^[0-9a-f]{128}$/.test(signature) ||
      owner === targetPubkey ||
      !validNipOaConditions(conditions)
    ) {
      continue;
    }
    const message = sha256(
      utf8ToBytes(`nostr:agent-auth:${targetPubkey}:${conditions}`),
    );
    if (!schnorr.verify(hexToBytes(signature), message, hexToBytes(owner))) {
      continue;
    }
    return { owner, is_me: owner === identity.pubkey().toLowerCase() };
  }
  return null;
}

export async function showNativeNotification(body: InvokeBody): Promise<void> {
  const input = objectBody(body, "show_native_notification");
  if (typeof input.title !== "string") {
    throw new TypeError("title must be a string");
  }
  if (
    input.body !== undefined &&
    input.body !== null &&
    typeof input.body !== "string"
  ) {
    throw new TypeError("body must be a string");
  }
  if (
    typeof Notification === "undefined" ||
    Notification.permission !== "granted"
  ) {
    return;
  }
  const notification = new Notification(input.title, {
    body: typeof input.body === "string" ? input.body : undefined,
    silent: true,
  });
  notification.onclick = () => {
    void emit("native-notification-activated", input.target ?? null);
    globalThis.window?.focus();
    notification.close();
  };
}

export function registerRelayMembershipStatusCommands(
  workspace: BrowserWorkspace,
  identity: BrowserIdentityManager,
  client: RelayQueryClient,
  fetchImpl: BrowserFetch = globalThis.fetch,
): void {
  register("relay_requires_membership", (body) =>
    relayRequiresMembership(body, workspace, fetchImpl),
  );
  register("get_my_relay_membership", () =>
    getMyRelayMembership(identity, client),
  );
  register("resolve_oa_owner", (body) =>
    resolveOaOwner(body, identity, client),
  );
  register("show_native_notification", showNativeNotification);
}
