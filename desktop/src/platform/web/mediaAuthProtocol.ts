import { verifyEvent, type Event as NostrEvent } from "nostr-tools/pure";

export const BLOSSOM_AUTH_KIND = 24242;
const GET_AUTH_LIFETIME_SECONDS = 600;
const MEDIA_PATH_RE = /^\/media\/([\da-f]{64})(?:\.[^/?#]+)?$/;

export type SignEventTemplate = {
  kind: number;
  content: string;
  createdAt?: number;
  tags: string[][];
};

type Signer = (template: Required<SignEventTemplate>) => Promise<string>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function equalTags(left: unknown, right: string[][]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function mediaHashFromUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.origin !== window.location.origin) return null;
    return MEDIA_PATH_RE.exec(url.pathname)?.[1] ?? null;
  } catch {
    return null;
  }
}

export function serverAuthority(value: string): string {
  return new URL(value).host.toLowerCase();
}

export function buildMediaGetAuthTemplate(
  value: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): Required<SignEventTemplate> {
  const sha256 = mediaHashFromUrl(value);
  if (!sha256) throw new Error("media auth requires a same-origin media URL");
  return {
    kind: BLOSSOM_AUTH_KIND,
    content: "Get buzz-media",
    createdAt: nowSeconds,
    tags: [
      ["t", "get"],
      ["x", sha256],
      ["expiration", String(nowSeconds + GET_AUTH_LIFETIME_SECONDS)],
      ["server", serverAuthority(value)],
    ],
  };
}

function parseSignedEvent(
  eventJson: string,
  template: Required<SignEventTemplate>,
): NostrEvent {
  const parsed: unknown = JSON.parse(eventJson);
  if (
    !isRecord(parsed) ||
    parsed.kind !== template.kind ||
    parsed.content !== template.content ||
    parsed.created_at !== template.createdAt ||
    !equalTags(parsed.tags, template.tags) ||
    typeof parsed.pubkey !== "string" ||
    typeof parsed.id !== "string" ||
    typeof parsed.sig !== "string"
  ) {
    throw new Error("sign_event returned an event that changed the template");
  }

  const event = parsed as unknown as NostrEvent;
  if (!verifyEvent(event)) {
    throw new Error("sign_event returned an invalid signature");
  }
  return event;
}

export async function blossomAuthorizationWithSigner(
  template: Required<SignEventTemplate>,
  signEvent: Signer,
): Promise<string> {
  const eventJson = await signEvent(template);
  const event = parseSignedEvent(eventJson, template);
  return `Nostr ${base64UrlEncode(JSON.stringify(event))}`;
}
