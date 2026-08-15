import {
  blossomAuthorizationWithSigner,
  buildMediaGetAuthTemplate,
  mediaHashFromUrl,
  type SignEventTemplate,
} from "./mediaAuthProtocol";
import { dispatch } from "./registry";

const MEDIA_AUTH_REQUEST = "buzz:media-auth-request";
const MEDIA_AUTH_RESPONSE = "buzz:media-auth-response";

type MediaAuthRequest = {
  type: typeof MEDIA_AUTH_REQUEST;
  requestId: string;
  url: string;
};

type MediaAuthResponse = {
  type: typeof MEDIA_AUTH_RESPONSE;
  requestId: string;
  authorization?: string;
};

let messageHandlerInstalled = false;
const pendingHeaders = new Map<string, Promise<string>>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export async function blossomAuthorization(
  template: Required<SignEventTemplate>,
): Promise<string> {
  return blossomAuthorizationWithSigner(template, (event) =>
    dispatch<string>("sign_event", event),
  );
}

export function mediaAuthorization(value: string): Promise<string> {
  const sha256 = mediaHashFromUrl(value);
  if (!sha256) {
    return Promise.reject(
      new Error("media auth requires a same-origin media URL"),
    );
  }

  const active = pendingHeaders.get(sha256);
  if (active) return active;

  const request = blossomAuthorization(buildMediaGetAuthTemplate(value));
  pendingHeaders.set(sha256, request);
  void request.finally(() => {
    if (pendingHeaders.get(sha256) === request) pendingHeaders.delete(sha256);
  });
  return request;
}

function isMediaAuthRequest(value: unknown): value is MediaAuthRequest {
  return (
    isRecord(value) &&
    value.type === MEDIA_AUTH_REQUEST &&
    typeof value.requestId === "string" &&
    typeof value.url === "string"
  );
}

async function handleMediaAuthMessage(event: MessageEvent): Promise<void> {
  if (!isMediaAuthRequest(event.data)) return;
  const port = event.ports[0];
  if (!port) return;

  const response: MediaAuthResponse = {
    type: MEDIA_AUTH_RESPONSE,
    requestId: event.data.requestId,
  };
  try {
    response.authorization = await mediaAuthorization(event.data.url);
  } catch {
    // Refused/unavailable signing fails closed in the worker. Never return the
    // signer error because provider messages can contain identity details.
  }
  port.postMessage(response);
}

function installMessageHandler(): void {
  if (messageHandlerInstalled) return;
  navigator.serviceWorker.addEventListener("message", (event) => {
    void handleMediaAuthMessage(event);
  });
  messageHandlerInstalled = true;
}

async function waitForController(timeoutMs: number): Promise<void> {
  if (navigator.serviceWorker.controller) return;
  await new Promise<void>((resolve) => {
    const timeout = window.setTimeout(done, timeoutMs);
    function done() {
      window.clearTimeout(timeout);
      navigator.serviceWorker.removeEventListener("controllerchange", done);
      resolve();
    }
    navigator.serviceWorker.addEventListener("controllerchange", done, {
      once: true,
    });
  });
}

export async function installMediaAuthServiceWorker(): Promise<void> {
  if (!("serviceWorker" in navigator)) return;
  installMessageHandler();

  const configuredBase = import.meta.env?.BASE_URL ?? "/app/";
  const base = new URL(configuredBase, window.location.origin);
  const script = new URL("media-auth-sw.js", base);
  try {
    await navigator.serviceWorker.register(script, {
      scope: base.pathname,
      type: "module",
      updateViaCache: "none",
    });
    await Promise.race([
      navigator.serviceWorker.ready,
      new Promise((resolve) => window.setTimeout(resolve, 5_000)),
    ]);
    await waitForController(2_000);
  } catch {
    // Keep the shell usable, but media requests remain fail-closed because no
    // worker will attach authentication.
  }
}
