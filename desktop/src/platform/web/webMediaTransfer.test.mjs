import assert from "node:assert/strict";
import test from "node:test";

import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";

import { dispatch, register, resetRegistryForTests } from "./registry.ts";
import {
  copyBrowserImageToClipboard,
  downloadBrowserFile,
  downloadBrowserImage,
  registerWebMediaTransferCommands,
} from "./webMediaTransfer.ts";

const previous = {
  ClipboardItem: globalThis.ClipboardItem,
  createImageBitmap: globalThis.createImageBitmap,
  document: globalThis.document,
  fetch: globalThis.fetch,
  navigator: globalThis.navigator,
  window: globalThis.window,
};

const anchors = [];
const clipboardWrites = [];
const timeouts = [];

globalThis.window = {
  location: {
    href: "https://relay.example/app/",
    origin: "https://relay.example",
  },
  clearTimeout(id) {
    const timeout = timeouts.find((entry) => entry.id === id);
    if (timeout) timeout.cleared = true;
  },
  setTimeout(callback, delay) {
    const id = timeouts.length + 1;
    timeouts.push({ callback, cleared: false, delay, id });
    return id;
  },
};
globalThis.document = {
  body: { append: () => undefined },
  createElement(tag) {
    if (tag === "a") {
      const anchor = {
        click() {
          anchors.push({ download: this.download, href: this.href });
        },
        remove() {},
      };
      return anchor;
    }
    if (tag === "canvas") {
      return {
        getContext: () => ({ drawImage: () => undefined }),
        toBlob: (callback) => callback(new Blob([1], { type: "image/png" })),
      };
    }
    throw new Error(`unexpected element: ${tag}`);
  },
};
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: { clipboard: { write: async (items) => clipboardWrites.push(items) } },
});
globalThis.ClipboardItem = class ClipboardItem {
  constructor(items) {
    this.items = items;
  }
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

test("downloads authenticated relay media with sanitized browser filenames", async () => {
  installSigner();
  const requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ init, url: String(url) });
    return new Response(Uint8Array.from([1, 2, 3]), {
      headers: { "Content-Type": "application/pdf" },
    });
  };

  const result = await downloadBrowserFile({
    url: `https://relay.example/media/${"a".repeat(64)}.pdf`,
    filename: "../../report\n.pdf",
  });

  assert.equal(result, true);
  assert.equal(requests[0].init.credentials, "same-origin");
  assert.equal(requests[0].init.redirect, "manual");
  assert.match(requests[0].init.headers.Authorization, /^Nostr /);
  assert.equal(anchors.at(-1).download, "report.pdf");
});

test("image download rejects off-origin URLs before fetch or signing", async () => {
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return new Response();
  };
  await assert.rejects(
    downloadBrowserImage({
      url: `https://attacker.example/media/${"b".repeat(64)}.png`,
    }),
    /same-origin media URLs/,
  );
  assert.equal(fetched, false);
});

test("download rejects a declared response above the 50MB cap", async () => {
  installSigner();
  globalThis.fetch = async () =>
    new Response(Uint8Array.from([1]), {
      headers: {
        "Content-Length": String(50 * 1024 * 1024 + 1),
        "Content-Type": "image/png",
      },
    });
  await assert.rejects(
    downloadBrowserImage({
      url: `https://relay.example/media/${"c".repeat(64)}.png`,
    }),
    /50MB limit/,
  );
});

test("download aborts after the native 60-second timeout", async () => {
  installSigner();
  globalThis.fetch = async (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        reject(new DOMException("Aborted", "AbortError"));
      });
    });
  const download = downloadBrowserImage({
    url: `https://relay.example/media/${"e".repeat(64)}.png`,
  });
  await new Promise((resolve) => setImmediate(resolve));
  const timeout = timeouts.find((entry) => entry.delay === 60_000);
  assert.ok(timeout);
  timeout.callback();
  await assert.rejects(download, /media download timed out/);
});

test("clipboard copy decodes, bounds, and converts relay images to PNG", async () => {
  installSigner();
  let closed = false;
  globalThis.fetch = async () =>
    new Response(Uint8Array.from([1]), {
      headers: { "Content-Type": "image/webp" },
    });
  globalThis.createImageBitmap = async () => ({
    close: () => {
      closed = true;
    },
    height: 20,
    width: 30,
  });

  await copyBrowserImageToClipboard({
    url: `https://relay.example/media/${"d".repeat(64)}.webp`,
  });

  assert.equal(clipboardWrites.length, 1);
  assert.equal(clipboardWrites[0][0].items["image/png"].type, "image/png");
  assert.equal(closed, true);
});

test("native path upload is explicitly capability-off", async () => {
  registerWebMediaTransferCommands();
  await assert.rejects(
    dispatch("upload_media", { filePath: "/tmp/image.png", isTemp: true }),
    /browsers cannot read a native temporary file path/,
  );
});

test.afterEach(() => {
  anchors.length = 0;
  clipboardWrites.length = 0;
  timeouts.length = 0;
  resetRegistryForTests();
  globalThis.fetch = previous.fetch;
});

test.after(() => {
  globalThis.ClipboardItem = previous.ClipboardItem;
  globalThis.createImageBitmap = previous.createImageBitmap;
  globalThis.document = previous.document;
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: previous.navigator,
  });
  globalThis.window = previous.window;
});
