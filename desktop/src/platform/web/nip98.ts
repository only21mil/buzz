import type { RelayEvent } from "@/shared/api/types";
import { assertNoEncryptedKeyBackupEgress } from "@/shared/lib/keyBackupEgress";

import { dispatch } from "./registry";

const NIP98_KIND = 27235;

type EventTemplate = {
  kind: number;
  content: string;
  tags: string[][];
};

type SignEvent = (template: EventTemplate) => Promise<string | RelayEvent>;

export type Nip98Request = {
  url: string;
  method: string;
  body?: string | Uint8Array;
};

type Nip98Options = {
  signEvent?: SignEvent;
  nonce?: () => string;
};

function requestBytes(
  body: Nip98Request["body"],
): Uint8Array<ArrayBuffer> | undefined {
  if (body === undefined) return undefined;
  return typeof body === "string"
    ? new TextEncoder().encode(body)
    : Uint8Array.from(body);
}

function assertNoKeyBackup(bytes: Uint8Array | undefined): void {
  if (!bytes) return;
  const text = new TextDecoder().decode(bytes);
  assertNoEncryptedKeyBackupEgress(text, "relay HTTP request");
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function utf8Base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function exactHttpUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TypeError("NIP-98 requires an absolute HTTP(S) URL");
  }
  return parsed.href;
}

async function defaultSignEvent(template: EventTemplate): Promise<string> {
  return dispatch<string>("sign_event", template);
}

function parseSignedEvent(value: string | RelayEvent): RelayEvent {
  const event = typeof value === "string" ? JSON.parse(value) : value;
  if (
    typeof event !== "object" ||
    event === null ||
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    typeof event.sig !== "string"
  ) {
    throw new Error("sign_event returned an invalid signed event");
  }
  return event;
}

function assertSignedTemplate(
  event: RelayEvent,
  template: EventTemplate,
): void {
  if (
    event.kind !== template.kind ||
    event.content !== template.content ||
    JSON.stringify(event.tags) !== JSON.stringify(template.tags)
  ) {
    throw new Error("sign_event changed the NIP-98 request template");
  }
}

export async function buildNip98Authorization(
  request: Nip98Request,
  options: Nip98Options = {},
): Promise<string> {
  const url = exactHttpUrl(request.url);
  const method = request.method.toUpperCase();
  const bytes = requestBytes(request.body);
  assertNoKeyBackup(bytes);

  const tags: string[][] = [
    ["u", url],
    ["method", method],
  ];
  if (bytes) tags.push(["payload", await sha256Hex(bytes)]);
  tags.push(["nonce", (options.nonce ?? crypto.randomUUID.bind(crypto))()]);

  const template: EventTemplate = { kind: NIP98_KIND, content: "", tags };
  const event = parseSignedEvent(
    await (options.signEvent ?? defaultSignEvent)(template),
  );
  assertSignedTemplate(event, template);
  return `Nostr ${utf8Base64(JSON.stringify(event))}`;
}

export async function nip98Fetch(
  request: Nip98Request & {
    headers?: HeadersInit;
    signal?: AbortSignal;
  },
  options: Nip98Options & { fetch?: typeof fetch } = {},
): Promise<Response> {
  const authorization = await buildNip98Authorization(request, options);
  const headers = new Headers(request.headers);
  headers.set("Authorization", authorization);
  const body = requestBytes(request.body);

  return (options.fetch ?? fetch)(exactHttpUrl(request.url), {
    method: request.method.toUpperCase(),
    headers,
    body: typeof request.body === "string" ? request.body : body,
    signal: request.signal,
  });
}
