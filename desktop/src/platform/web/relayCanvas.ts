import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import type { BrowserIdentityManager } from "./identity";
import { type InvokeBody, register } from "./registry";

const MAX_CONTENT_BYTES = 64 * 1024;

type RelayCanvasClient = Pick<
  typeof relayClient,
  "fetchFirstEvent" | "publishEvent"
>;

function objectBody(
  body: InvokeBody,
  command: string,
): Record<string, unknown> {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body;
}

function requiredString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function canonicalUuid(value: string): string | null {
  let candidate = value;
  if (candidate.toLowerCase().startsWith("urn:uuid:")) {
    candidate = candidate.slice(9);
  }
  if (candidate.startsWith("{") && candidate.endsWith("}")) {
    candidate = candidate.slice(1, -1);
  }

  const compact = candidate.includes("-")
    ? /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/.test(
        candidate,
      )
      ? candidate.replaceAll("-", "")
      : null
    : /^[0-9a-fA-F]{32}$/.test(candidate)
      ? candidate
      : null;
  if (!compact) return null;

  const lower = compact.toLowerCase();
  return `${lower.slice(0, 8)}-${lower.slice(8, 12)}-${lower.slice(12, 16)}-${lower.slice(16, 20)}-${lower.slice(20)}`;
}

function parseSignedEvent(value: string): RelayEvent {
  const event = JSON.parse(value) as RelayEvent;
  if (
    !event ||
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    typeof event.sig !== "string"
  ) {
    throw new Error("Browser identity returned an invalid signed event");
  }
  return event;
}

/** Query the latest channel canvas using the desktop command wire shape. */
export async function getCanvas(body: InvokeBody, client: RelayCanvasClient) {
  const channelId = requiredString(objectBody(body, "get_canvas"), "channelId");
  const event = await client.fetchFirstEvent({
    kinds: [40100],
    "#h": [channelId],
    limit: 1,
  });

  if (!event) {
    return {
      content: "",
      event_id: null,
      updated_at: null,
      author: null,
    };
  }

  return {
    content: event.content,
    event_id: event.id,
    updated_at: event.created_at,
    author: event.pubkey,
  };
}

/** Sign and publish a channel canvas update using kind 40100. */
export async function setCanvas(
  body: InvokeBody,
  identity: BrowserIdentityManager,
  client: RelayCanvasClient,
) {
  const input = objectBody(body, "set_canvas");
  const channelId = requiredString(input, "channelId");
  const content = requiredString(input, "content");
  const normalizedChannelId = canonicalUuid(channelId);
  if (!normalizedChannelId) {
    throw new Error(`invalid channel UUID: ${channelId}`);
  }
  const contentBytes = new TextEncoder().encode(content).byteLength;
  if (contentBytes > MAX_CONTENT_BYTES) {
    throw new Error(
      `content exceeds maximum size of ${MAX_CONTENT_BYTES} bytes (got ${contentBytes})`,
    );
  }

  const signed = parseSignedEvent(
    identity.sign({
      kind: 40100,
      content,
      tags: [["h", normalizedChannelId]],
    }),
  );
  const published = await client.publishEvent(
    signed,
    "Timed out while setting the canvas.",
    "Failed while setting the canvas.",
  );
  return { ok: true, event_id: published.id };
}

/** Register browser PAL implementations of get_canvas and set_canvas. */
export function registerRelayCanvasCommands(
  identity: BrowserIdentityManager,
  client: RelayCanvasClient = relayClient,
): void {
  register("get_canvas", (body) => getCanvas(body, client));
  register("set_canvas", (body) => setCanvas(body, identity, client));
}
