import { blossomAuthorization } from "./mediaAuth";
import { serverAuthority } from "./mediaAuthProtocol";
import { type InvokeBody, type InvokeOptions, register } from "./registry";
import { emit } from "./shims/event";

const MAX_BROWSER_UPLOAD_BYTES = 100 * 1024 * 1024;
const MAX_BROWSER_FETCH_BYTES = 50 * 1024 * 1024;
const VIDEO_AUTH_LIFETIME_SECONDS = 3600;
const DEFAULT_AUTH_LIFETIME_SECONDS = 300;
const activeUploads = new Map<string, AbortController>();

type UploadBody = {
  data?: unknown;
  filename?: unknown;
  progressId?: unknown;
};

type BlobDescriptor = {
  url: string;
  sha256: string;
  size: number;
  type: string;
  uploaded: number;
  filename?: string;
  dim?: string;
  blurhash?: string;
  thumb?: string;
  duration?: number;
  image?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function decodeRawHeader(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  return new TextDecoder().decode(
    Uint8Array.from(binary, (character) => character.charCodeAt(0)),
  );
}

function rawHeader(options: InvokeOptions | undefined, name: string) {
  const entry = Object.entries(options?.headers ?? {}).find(
    ([key]) => key.toLowerCase() === name,
  );
  return decodeRawHeader(entry?.[1]);
}

function uploadInput(body: InvokeBody, options?: InvokeOptions) {
  if (body instanceof Uint8Array) {
    return {
      bytes: Uint8Array.from(body),
      filename: rawHeader(options, "x-buzz-filename"),
      mimeType:
        rawHeader(options, "x-buzz-content-type") ?? "application/octet-stream",
      progressId: rawHeader(options, "x-buzz-progress-id"),
    };
  }
  if (body instanceof ArrayBuffer) {
    return {
      bytes: new Uint8Array(body.slice(0)),
      filename: rawHeader(options, "x-buzz-filename"),
      mimeType:
        rawHeader(options, "x-buzz-content-type") ?? "application/octet-stream",
      progressId: rawHeader(options, "x-buzz-progress-id"),
    };
  }
  if (!isRecord(body)) throw new TypeError("media upload requires bytes");

  const payload = body as UploadBody;
  if (!Array.isArray(payload.data)) {
    throw new TypeError("upload_media_bytes requires a data array");
  }
  return {
    bytes: Uint8Array.from(payload.data as number[]),
    filename:
      typeof payload.filename === "string" ? payload.filename : undefined,
    mimeType: "application/octet-stream",
    progressId:
      typeof payload.progressId === "string" ? payload.progressId : undefined,
  };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function uploadTemplate(
  sha256: string,
  mimeType: string,
  nowSeconds = Math.floor(Date.now() / 1000),
) {
  const lifetime = mimeType.startsWith("video/")
    ? VIDEO_AUTH_LIFETIME_SECONDS
    : DEFAULT_AUTH_LIFETIME_SECONDS;
  return {
    kind: 24242,
    content: "Upload buzz-media",
    createdAt: nowSeconds,
    tags: [
      ["t", "upload"],
      ["x", sha256],
      ["expiration", String(nowSeconds + lifetime)],
      ["server", serverAuthority(window.location.href)],
    ],
  };
}

async function responseError(response: Response): Promise<Error> {
  const text = (await response.text().catch(() => "")).slice(0, 512);
  return new Error(
    `media upload failed (${response.status})${text ? `: ${text}` : ""}`,
  );
}

function sameOriginMediaUrl(value: string, sha256: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.origin === window.location.origin &&
      new RegExp(`^/media/${sha256}(?:\\.[^/]+)?$`).test(url.pathname)
    );
  } catch {
    return false;
  }
}

function parseDescriptor(
  value: unknown,
  expectedSha256: string,
  expectedSize: number,
): BlobDescriptor {
  if (
    !isRecord(value) ||
    typeof value.url !== "string" ||
    value.sha256 !== expectedSha256 ||
    value.size !== expectedSize ||
    typeof value.type !== "string" ||
    typeof value.uploaded !== "number" ||
    !Number.isFinite(value.uploaded) ||
    !sameOriginMediaUrl(value.url, expectedSha256)
  ) {
    throw new Error("media upload returned a descriptor for different bytes");
  }
  return value as BlobDescriptor;
}

async function emitUploadPhase(
  progressId: string | undefined,
  phase: "preparing" | "uploading" | "finishing",
): Promise<void> {
  if (progressId) await emit("media-upload-phase", { id: progressId, phase });
}

async function emitUploadProgress(
  progressId: string | undefined,
  sent: number,
  total: number,
): Promise<void> {
  if (progressId) {
    await emit("media-upload-progress", { id: progressId, sent, total });
  }
}

async function sendUpload(
  path: string,
  bytes: Uint8Array,
  headers: Headers,
  signal: AbortSignal,
): Promise<Response> {
  return fetch(new URL(path, window.location.origin), {
    method: "PUT",
    body: Uint8Array.from(bytes),
    cache: "no-store",
    credentials: "same-origin",
    headers,
    redirect: "manual",
    signal,
  });
}

export async function uploadBrowserMedia(
  body: InvokeBody,
  options?: InvokeOptions,
): Promise<BlobDescriptor> {
  const { bytes, filename, mimeType, progressId } = uploadInput(body, options);
  if (bytes.byteLength > MAX_BROWSER_UPLOAD_BYTES) {
    throw new Error("File is too large. Maximum is 100MB.");
  }

  await emitUploadPhase(progressId, "preparing");
  const sha256 = await sha256Hex(bytes);
  const authorization = await blossomAuthorization(
    uploadTemplate(sha256, mimeType),
  );
  const headers = new Headers({
    Authorization: authorization,
    "Content-Type": mimeType,
    "X-SHA-256": sha256,
  });

  const controller = new AbortController();
  if (progressId) activeUploads.set(progressId, controller);
  try {
    await emitUploadPhase(progressId, "uploading");
    await emitUploadProgress(progressId, 0, bytes.byteLength);
    let response = await sendUpload(
      "/upload",
      bytes,
      headers,
      controller.signal,
    );
    if (response.status === 404 || response.status === 405) {
      response = await sendUpload(
        "/media/upload",
        bytes,
        headers,
        controller.signal,
      );
    }
    if (!response.ok) throw await responseError(response);
    const descriptor = parseDescriptor(
      await response.json(),
      sha256,
      bytes.byteLength,
    );
    await emitUploadProgress(progressId, bytes.byteLength, bytes.byteLength);
    await emitUploadPhase(progressId, "finishing");
    return filename ? { ...descriptor, filename } : descriptor;
  } finally {
    if (progressId && activeUploads.get(progressId) === controller) {
      activeUploads.delete(progressId);
    }
  }
}

function selectFiles(accept?: string, multiple = false): Promise<File[]> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = multiple;
    if (accept) input.accept = accept;
    input.addEventListener(
      "change",
      () => {
        resolve(Array.from(input.files ?? []));
        input.remove();
      },
      { once: true },
    );
    input.click();
  });
}

export function sniffImageMime(bytes: Uint8Array): string | null {
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return "image/png";
  }
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return "image/jpeg";
  }
  const ascii = (start: number, length: number) =>
    String.fromCharCode(...bytes.subarray(start, start + length));
  if (bytes.length >= 6 && /^GIF8[79]a$/.test(ascii(0, 6))) {
    return "image/gif";
  }
  if (bytes.length >= 12 && ascii(0, 4) === "RIFF" && ascii(8, 4) === "WEBP") {
    return "image/webp";
  }
  return null;
}

async function uploadFile(
  file: File,
  progressId?: string,
  requireImage = false,
): Promise<BlobDescriptor> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const detectedImageMime = sniffImageMime(bytes);
  if (requireImage && !detectedImageMime) {
    throw new Error("Selected file is not a supported image");
  }
  const options: InvokeOptions = {
    headers: {
      "x-buzz-filename": encodeRawHeader(file.name),
      "x-buzz-content-type": encodeRawHeader(
        detectedImageMime ?? (file.type || "application/octet-stream"),
      ),
    },
  };
  if (progressId) {
    options.headers = {
      ...options.headers,
      "x-buzz-progress-id": encodeRawHeader(progressId),
    };
  }
  return uploadBrowserMedia(bytes, options);
}

function encodeRawHeader(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function fetchMediaBytes(body: InvokeBody): Promise<ArrayBuffer> {
  if (!isRecord(body) || typeof body.url !== "string") {
    throw new TypeError("fetch_media_bytes requires a URL");
  }
  const url = new URL(body.url);
  if (
    url.origin !== window.location.origin ||
    !url.pathname.startsWith("/media/")
  ) {
    throw new Error("fetch_media_bytes only accepts same-origin media URLs");
  }
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "manual",
  });
  if (!response.ok) throw await responseError(response);
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0];
  if (!contentType?.startsWith("image/")) {
    throw new Error("fetch_media_bytes requires image content");
  }
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_BROWSER_FETCH_BYTES
  ) {
    throw new Error("media response exceeds the 50MB limit");
  }
  if (!response.body) return new ArrayBuffer(0);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BROWSER_FETCH_BYTES) {
      await reader.cancel();
      throw new Error("media response exceeds the 50MB limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes.buffer;
}

export function registerMediaCommands(): void {
  register("upload_media_bytes_raw", uploadBrowserMedia);
  register("upload_media_bytes", uploadBrowserMedia);
  register("cancel_media_upload", (body) => {
    if (!isRecord(body) || typeof body.progressId !== "string") return;
    activeUploads.get(body.progressId)?.abort();
  });
  register("pick_and_upload_media", async (body) => {
    const files = await selectFiles(undefined, true);
    const progressId =
      isRecord(body) && typeof body.progressId === "string"
        ? body.progressId
        : undefined;
    const descriptors: BlobDescriptor[] = [];
    for (const file of files) {
      descriptors.push(await uploadFile(file, progressId));
    }
    return descriptors;
  });
  register("pick_and_upload_image", async () => {
    const [file] = await selectFiles("image/*");
    return file ? uploadFile(file, undefined, true) : null;
  });
  register("fetch_media_bytes", fetchMediaBytes);
}
