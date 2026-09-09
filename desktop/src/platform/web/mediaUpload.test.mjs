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

for (const [filename, advisoryMime] of [
  ["report.html", "text/html"],
  ["report.htm", ""],
  ["REPORT.HTML", undefined],
  ["misleading.txt", "text/plain"],
]) {
  test(`HTML upload preserves bytes, signed hash and filename: ${filename}`, async () => {
    installSigner();
    const bytes = new TextEncoder().encode(
      "<!DOCTYPE html><script>globalThis.__htmlExecuted=true</script>",
    );
    globalThis.fetch = async (url, init) => {
      assert.equal(String(url), "https://relay.example/upload");
      assert.deepEqual(
        new Uint8Array(await new Response(init.body).arrayBuffer()),
        bytes,
      );
      const hash = Buffer.from(
        await crypto.subtle.digest("SHA-256", bytes),
      ).toString("hex");
      assert.equal(init.headers.get("X-SHA-256"), hash);
      const auth = JSON.parse(
        Buffer.from(
          init.headers.get("Authorization").slice(6),
          "base64url",
        ).toString(),
      );
      assert.ok(auth.tags.some((tag) => tag[0] === "x" && tag[1] === hash));
      return Response.json({
        url: `https://relay.example/media/${hash}.html`,
        sha256: hash,
        size: bytes.length,
        type: "text/html",
        uploaded: 1,
      });
    };
    const headers = {
      "x-buzz-filename": Buffer.from(filename).toString("base64"),
    };
    if (advisoryMime !== undefined)
      headers["x-buzz-content-type"] =
        Buffer.from(advisoryMime).toString("base64");
    const result = await uploadBrowserMedia(bytes, { headers });
    assert.equal(result.filename, filename);
    assert.equal(result.type, "text/html");
    assert.equal(result.size, bytes.length);
  });
}

test("browser image editor refuses HTML response bytes", async () => {
  registerMediaCommands(new BrowserWorkspace());
  installSigner();
  globalThis.fetch = async () =>
    new Response("<!DOCTYPE html><script>alert(1)</script>", {
      headers: { "Content-Type": "text/html" },
    });
  await assert.rejects(
    dispatch("fetch_media_bytes", {
      url: `https://relay.example/media/${"a".repeat(64)}.html`,
    }),
    /requires image content/,
  );
});

function fakePicker(files, event = "change") {
  const previousDocument = globalThis.document;
  let removed = false;
  const input = new EventTarget();
  input.files = files;
  input.remove = () => {
    removed = true;
  };
  input.click = () =>
    queueMicrotask(() => input.dispatchEvent(new Event(event)));
  globalThis.document = { createElement: () => input };
  return {
    removed: () => removed,
    restore: () => {
      globalThis.document = previousDocument;
    },
  };
}

function uploadOptions(progressId) {
  return {
    headers: {
      "x-buzz-progress-id": Buffer.from(progressId).toString("base64"),
    },
  };
}

test("picker rejects a file one byte over its limit before reading it", async () => {
  registerMediaCommands(new BrowserWorkspace());
  let read = false;
  const picker = fakePicker([
    {
      size: 100 * 1024 * 1024 + 1,
      arrayBuffer: async () => {
        read = true;
        throw new Error("must not read");
      },
    },
  ]);
  try {
    await assert.rejects(
      dispatch("pick_and_upload_media", {}),
      /Maximum is 100MB/,
    );
    assert.equal(read, false);
    assert.equal(picker.removed(), true);
  } finally {
    picker.restore();
  }
});

test("picker size preflight allows the exact advertised boundary", async () => {
  registerMediaCommands(new BrowserWorkspace());
  let read = false;
  const picker = fakePicker([
    {
      size: 100 * 1024 * 1024,
      arrayBuffer: async () => {
        read = true;
        throw new Error("synthetic read stop");
      },
    },
  ]);
  try {
    await assert.rejects(
      dispatch("pick_and_upload_media", {}),
      /synthetic read stop/,
    );
    assert.equal(read, true);
  } finally {
    picker.restore();
  }
});

test("array upload rejects an oversized sparse input before copying", async () => {
  const data = [];
  data.length = 100 * 1024 * 1024 + 1;
  data[Symbol.iterator] = () => {
    throw new Error("must not copy");
  };
  await assert.rejects(uploadBrowserMedia({ data }), /Maximum is 100MB/);
});

test("picker cancel settles and removes its input", async () => {
  registerMediaCommands(new BrowserWorkspace());
  const picker = fakePicker([], "cancel");
  try {
    assert.deepEqual(await dispatch("pick_and_upload_media", {}), []);
    assert.equal(picker.removed(), true);
  } finally {
    picker.restore();
  }
});

test("cancel while preparing stops upload before signing or fetching and allows retry", async () => {
  registerMediaCommands(new BrowserWorkspace());
  let signed = 0;
  register("sign_event", () => {
    signed += 1;
    throw new Error("must not sign");
  });
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    throw new Error("must not fetch");
  };
  const stop = await listen("media-upload-phase", (event) => {
    if (event.payload.phase === "preparing") {
      return dispatch("cancel_media_upload", {
        progressId: "cancel-preparing",
      });
    }
  });
  try {
    await assert.rejects(
      uploadBrowserMedia(
        new Uint8Array([1]),
        uploadOptions("cancel-preparing"),
      ),
      { name: "AbortError" },
    );
    assert.equal(signed, 0);
    assert.equal(fetched, false);
  } finally {
    stop();
  }
  installSigner();
  globalThis.fetch = async (_url, init) =>
    Response.json(
      descriptor(init.headers.get("X-SHA-256"), init.body.byteLength),
    );
  await uploadBrowserMedia(
    new Uint8Array([1]),
    uploadOptions("cancel-preparing"),
  );
});

test("cancel during file read prevents a later upload", async () => {
  registerMediaCommands(new BrowserWorkspace());
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    throw new Error("must not fetch");
  };
  const picker = fakePicker([
    {
      size: 1,
      name: "note.txt",
      type: "text/plain",
      arrayBuffer: async () => {
        await dispatch("cancel_media_upload", { progressId: "cancel-read" });
        return new Uint8Array([1]).buffer;
      },
    },
  ]);
  try {
    await assert.rejects(
      dispatch("pick_and_upload_media", { progressId: "cancel-read" }),
      { name: "AbortError" },
    );
    assert.equal(fetched, false);
  } finally {
    picker.restore();
  }
});

test("fallback cancels unused response body before retrying", async () => {
  installSigner();
  let canceled = false;
  const paths = [];
  globalThis.fetch = async (url, init) => {
    paths.push(new URL(url).pathname);
    if (paths.length === 1) {
      return new Response(
        new ReadableStream({
          cancel() {
            canceled = true;
          },
        }),
        { status: 404 },
      );
    }
    assert.equal(canceled, true);
    return Response.json(
      descriptor(init.headers.get("X-SHA-256"), init.body.byteLength),
    );
  };
  await uploadBrowserMedia(new Uint8Array([1]));
  assert.deepEqual(paths, ["/upload", "/media/upload"]);
});

test("descriptor stream over its limit is canceled and releases the reader", async () => {
  installSigner();
  let canceled = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(64 * 1024 + 1));
    },
    cancel() {
      canceled = true;
    },
  });
  globalThis.fetch = async () => new Response(body);
  await assert.rejects(
    uploadBrowserMedia(new Uint8Array([1])),
    /descriptor exceeds the 64KB limit/,
  );
  assert.equal(canceled, true);
  assert.equal(body.locked, false);
});

test("descriptor exactly at its limit succeeds", async () => {
  installSigner();
  globalThis.fetch = async (_url, init) => {
    const json = JSON.stringify(descriptor(init.headers.get("X-SHA-256"), 1));
    return new Response(json.padEnd(64 * 1024, " "));
  };
  const result = await uploadBrowserMedia(new Uint8Array([1]));
  assert.equal(result.size, 1);
});

test("rejected image response is canceled before any read", async () => {
  registerMediaCommands(new BrowserWorkspace());
  let canceled = false;
  const body = new ReadableStream({
    cancel() {
      canceled = true;
    },
  });
  globalThis.fetch = async () =>
    new Response(body, {
      headers: {
        "Content-Type": "image/png",
        "Content-Length": String(50 * 1024 * 1024 + 1),
      },
    });
  await assert.rejects(
    dispatch("fetch_media_bytes", {
      url: `https://relay.example/media/${"a".repeat(64)}.png`,
    }),
    /50MB limit/,
  );
  assert.equal(canceled, true);
  assert.equal(body.locked, false);
});

test("upload transport failure clears cancellation ownership for retry", async () => {
  installSigner();
  globalThis.fetch = async () => {
    throw new Error("network down");
  };
  const options = uploadOptions("network-retry");
  await assert.rejects(
    uploadBrowserMedia(new Uint8Array([1]), options),
    /network down/,
  );
  globalThis.fetch = async (_url, init) =>
    Response.json(descriptor(init.headers.get("X-SHA-256"), 1));
  await uploadBrowserMedia(new Uint8Array([1]), options);
});
