import assert from "node:assert/strict";
import test from "node:test";

import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";

import {
  registerMediaCommands,
  sniffImageMime,
  uploadBrowserMedia,
} from "./mediaUpload.ts";
import { dispatch, register, resetRegistryForTests } from "./registry.ts";
import { listen } from "./shims/event.ts";
import { BrowserWorkspace } from "./workspace.ts";

const previousFetch = globalThis.fetch;
const previousWindow = globalThis.window;

globalThis.window = {
  location: {
    href: "https://relay.example/app/",
    origin: "https://relay.example",
  },
};

function installSigner() {
  const secret = generateSecretKey();
  register("sign_event", (body) =>
    JSON.stringify(
      finalizeEvent(
        {
          kind: body.kind,
          content: body.content,
          created_at: body.createdAt,
          tags: body.tags,
        },
        secret,
      ),
    ),
  );
}

function descriptor(sha256, size) {
  return {
    url: `https://relay.example/media/${sha256}.png`,
    sha256,
    size,
    type: "image/png",
    uploaded: 1,
  };
}

test("browser upload signs and sends the exact copied bytes", async () => {
  installSigner();
  const source = Uint8Array.from([1, 2, 3, 4]);
  let captured;
  const events = [];
  const stopPhase = await listen("media-upload-phase", (event) =>
    events.push([event.event, event.payload]),
  );
  const stopProgress = await listen("media-upload-progress", (event) =>
    events.push([event.event, event.payload]),
  );
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), init };
    const body = new Uint8Array(await new Response(init.body).arrayBuffer());
    const sha256 = init.headers.get("X-SHA-256");
    assert.deepEqual([...body], [1, 2, 3, 4]);
    return Response.json(descriptor(sha256, body.byteLength));
  };

  const result = await uploadBrowserMedia(source, {
    headers: {
      "x-buzz-content-type": "aW1hZ2UvcG5n",
      "x-buzz-filename": "cGhvdG8ucG5n",
      "x-buzz-progress-id": "dXBsb2FkLTE",
    },
  });
  stopPhase();
  stopProgress();
  source.fill(9);

  assert.equal(captured.url, "https://relay.example/upload");
  assert.equal(captured.init.method, "PUT");
  assert.equal(captured.init.redirect, "manual");
  assert.equal(captured.init.credentials, "same-origin");
  assert.equal(captured.init.headers.get("Content-Type"), "image/png");
  assert.match(captured.init.headers.get("Authorization"), /^Nostr /);
  assert.equal(result.sha256, captured.init.headers.get("X-SHA-256"));
  assert.equal(result.filename, "photo.png");
  assert.deepEqual(events, [
    ["media-upload-phase", { id: "upload-1", phase: "preparing" }],
    ["media-upload-phase", { id: "upload-1", phase: "uploading" }],
    ["media-upload-progress", { id: "upload-1", sent: 0, total: 4 }],
    ["media-upload-progress", { id: "upload-1", sent: 4, total: 4 }],
    ["media-upload-phase", { id: "upload-1", phase: "finishing" }],
  ]);
});

test("browser upload falls back only when the standard endpoint is absent", async () => {
  installSigner();
  const paths = [];
  globalThis.fetch = async (url, init) => {
    const path = new URL(url).pathname;
    paths.push(path);
    if (path === "/upload") return new Response("missing", { status: 404 });
    return Response.json(
      descriptor(init.headers.get("X-SHA-256"), init.body.byteLength),
    );
  };

  await uploadBrowserMedia(Uint8Array.from([5, 6, 7]));
  assert.deepEqual(paths, ["/upload", "/media/upload"]);
});

test("browser upload rejects a descriptor not bound to the signed bytes", async () => {
  installSigner();
  globalThis.fetch = async () => Response.json(descriptor("f".repeat(64), 3));
  await assert.rejects(
    uploadBrowserMedia(Uint8Array.from([5, 6, 7])),
    /descriptor for different bytes/,
  );
});

test("fetch_media_bytes rejects an oversized response before buffering", async () => {
  registerMediaCommands(new BrowserWorkspace());
  globalThis.fetch = async () =>
    new Response(Uint8Array.from([1]), {
      headers: {
        "Content-Length": String(50 * 1024 * 1024 + 1),
        "Content-Type": "image/png",
      },
    });
  await assert.rejects(
    dispatch("fetch_media_bytes", {
      url: `https://relay.example/media/${"a".repeat(64)}.png`,
    }),
    /50MB limit/,
  );
});

test("registered media commands follow the active browser workspace relay", async () => {
  const workspace = new BrowserWorkspace();
  workspace.apply({ relayUrl: "wss://relay-b.example", reposDir: null });
  registerMediaCommands(workspace);
  installSigner();
  let requestedUrl;
  globalThis.fetch = async (url, init) => {
    requestedUrl = String(url);
    const sha256 = init.headers.get("X-SHA-256");
    return Response.json({
      ...descriptor(sha256, init.body.byteLength),
      url: `https://relay-b.example/media/${sha256}.png`,
    });
  };

  const result = await dispatch(
    "upload_media_bytes_raw",
    Uint8Array.from([8, 9]),
  );

  assert.equal(requestedUrl, "https://relay-b.example/upload");
  assert.equal(result.url.startsWith("https://relay-b.example/media/"), true);
});

test("registered media commands reject the browser shell origin after a relay switch", async () => {
  const workspace = new BrowserWorkspace();
  workspace.apply({ relayUrl: "wss://relay-b.example", reposDir: null });
  registerMediaCommands(workspace);
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return new Response();
  };

  await assert.rejects(
    dispatch("fetch_media_bytes", {
      url: `https://relay.example/media/${"a".repeat(64)}.png`,
    }),
    /same-origin media URLs/,
  );
  assert.equal(fetched, false);
});

test("image sniffing rejects a malformed JPEG prefix", () => {
  assert.equal(sniffImageMime(Uint8Array.from([0xff, 0xd8, 0x00])), null);
  assert.equal(
    sniffImageMime(Uint8Array.from([0xff, 0xd8, 0xff, 0xe0])),
    "image/jpeg",
  );
});

test.afterEach(() => {
  resetRegistryForTests();
  globalThis.fetch = previousFetch;
});

test.after(() => {
  globalThis.window = previousWindow;
});
