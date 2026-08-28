import type { RelayEvent } from "@/shared/api/types";
import { assertNoIdentityKeyEgress } from "@/shared/lib/keyBackupEgress";

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

type PreparedRequest = {
  url: string;
  method: string;
  bytes: Uint8Array<ArrayBuffer> | undefined;
  body: string | Uint8Array<ArrayBuffer> | undefined;
};

function requestBytes(
  body: Nip98Request["body"],
): Uint8Array<ArrayBuffer> | undefined {
  if (body === undefined) return undefined;
  return typeof body === "string"
    ? new TextEncoder().encode(body)
    : Uint8Array.from(body);
}

function assertNoIdentityKey(bytes: Uint8Array | undefined): void {
  if (!bytes) return;
  const text = new TextDecoder().decode(bytes);
  assertNoIdentityKeyEgress(text, "relay HTTP request");
}

function assertNoIdentityKeyText(value: string, context: string): void {
  assertNoIdentityKeyEgress(value, context);
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

function prepareRequest(request: Nip98Request): PreparedRequest {
  const url = exactHttpUrl(request.url);
  assertNoIdentityKeyText(url, "relay HTTP URL");
  const bytes = requestBytes(request.body);
  assertNoIdentityKey(bytes);
  return {
    url,
    method: request.method.toUpperCase(),
    bytes,
    body: typeof request.body === "string" ? request.body : bytes,
  };
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

async function buildAuthorization(
  request: PreparedRequest,
  options: Nip98Options = {},
): Promise<string> {
  const tags: string[][] = [
    ["u", request.url],
    ["method", request.method],
  ];
  if (request.bytes) tags.push(["payload", await sha256Hex(request.bytes)]);
  tags.push(["nonce", (options.nonce ?? crypto.randomUUID.bind(crypto))()]);

  const template: EventTemplate = { kind: NIP98_KIND, content: "", tags };
  const event = parseSignedEvent(
    await (options.signEvent ?? defaultSignEvent)(template),
  );
  assertSignedTemplate(event, template);
  return `Nostr ${utf8Base64(JSON.stringify(event))}`;
}

export async function buildNip98Authorization(
  request: Nip98Request,
  options: Nip98Options = {},
): Promise<string> {
  return buildAuthorization(prepareRequest(request), options);
}

export async function nip98Fetch(
  request: Nip98Request & {
    headers?: HeadersInit;
    signal?: AbortSignal;
  },
  options: Nip98Options & { fetch?: typeof fetch } = {},
): Promise<Response> {
  const prepared = prepareRequest(request);
  const headers = new Headers(request.headers);
  for (const [name, value] of headers) {
    assertNoIdentityKeyText(name, "relay HTTP header name");
    assertNoIdentityKeyText(value, "relay HTTP header value");
  }
  const authorization = await buildAuthorization(prepared, options);
  headers.set("Authorization", authorization);

  return (options.fetch ?? fetch)(prepared.url, {
    method: prepared.method,
    headers,
    body: prepared.body,
    credentials: "omit",
    signal: request.signal,
  });
}
