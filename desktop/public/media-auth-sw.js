const MEDIA_AUTH_REQUEST = "buzz:media-auth-request";
const MEDIA_AUTH_RESPONSE = "buzz:media-auth-response";
const MEDIA_AUTH_TIMEOUT_MS = 5_000;

self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

export function shouldAuthenticateMediaRequest(request) {
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  const url = new URL(request.url);
  return (
    url.origin === self.location.origin && url.pathname.startsWith("/media/")
  );
}

function authorizationFromClient(client, url) {
  return new Promise((resolve) => {
    const requestId = crypto.randomUUID();
    const channel = new MessageChannel();
    const timeout = setTimeout(() => resolve(undefined), MEDIA_AUTH_TIMEOUT_MS);
    channel.port1.onmessage = (event) => {
      const data = event.data;
      if (
        data?.type !== MEDIA_AUTH_RESPONSE ||
        data.requestId !== requestId ||
        typeof data.authorization !== "string" ||
        !data.authorization.startsWith("Nostr ")
      ) {
        return;
      }
      clearTimeout(timeout);
      resolve(data.authorization);
    };
    client.postMessage({ type: MEDIA_AUTH_REQUEST, requestId, url }, [
      channel.port2,
    ]);
  });
}

async function requestAuthorization(event) {
  const direct = event.clientId
    ? await self.clients.get(event.clientId)
    : undefined;
  const client =
    direct ??
    (
      await self.clients.matchAll({ includeUncontrolled: true, type: "window" })
    )[0];
  return client
    ? authorizationFromClient(client, event.request.url)
    : undefined;
}

export function authenticatedRequest(request, authorization) {
  const headers = new Headers(request.headers);
  headers.set("Authorization", authorization);
  return new Request(request.url, {
    method: request.method,
    headers,
    cache: request.cache,
    credentials: "same-origin",
    mode: "same-origin",
    redirect: "manual",
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    signal: request.signal,
  });
}

export async function authenticatedMediaFetch(
  event,
  authorize = requestAuthorization,
  fetcher = fetch,
) {
  const request = event.request;
  if (!shouldAuthenticateMediaRequest(request)) return fetcher(request);
  if (request.headers.has("Authorization")) return fetcher(request);

  const authorization = await authorize(event);
  if (!authorization) {
    return new Response("Media authentication unavailable", { status: 401 });
  }
  return fetcher(authenticatedRequest(request, authorization));
}

self.addEventListener("fetch", (event) => {
  if (!shouldAuthenticateMediaRequest(event.request)) return;
  event.respondWith(authenticatedMediaFetch(event));
});
