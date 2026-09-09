import { blossomAuthorization } from "./mediaAuth";
import { serverAuthority } from "./mediaAuthProtocol";
import { type InvokeBody, type InvokeOptions, register } from "./registry";
import { emit } from "./shims/event";
import type { BrowserWorkspace } from "./workspace";

const MAX_BROWSER_FETCH_BYTES = 50 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES = 64 * 1024;
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
  mediaOrigin: string,
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
      ["server", serverAuthority(mediaOrigin)],
    ],
  };
}

async function readBoundedResponse(
  response: Response,
  maxBytes: number,
  limitMessage: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new Error(limitMessage);
  }
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error(limitMessage);
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function formatBinarySize(bytes: number): string {
  const mib = bytes / (1024 * 1024);
  if (mib >= 1024) return `${(mib / 1024).toFixed(1)} GiB`;
  return `${mib.toFixed(1)} MiB`;
}

/**
 * Turn the relay's 413 body into a sentence that names the limit that fired.
 * The relay sends `{ error, size, max_bytes }` for a size rejection; anything
 * else falls through to the generic upload error.
 */
export function uploadSizeLimitMessage(
  status: number,
  body: string,
): string | undefined {
  if (status !== 413) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  const max = parsed.max_bytes;
  if (typeof max !== "number" || !Number.isFinite(max) || max <= 0) {
    return typeof parsed.error === "string"
      ? `File is too large. ${parsed.error}`
      : undefined;
  }
  const size = parsed.size;
  const sizeText =
    typeof size === "number" && Number.isFinite(size) && size > 0
      ? ` (${formatBinarySize(size)})`
      : "";
  return `File is too large${sizeText}. This relay accepts up to ${formatBinarySize(max)}.`;
}

async function responseError(response: Response): Promise<Error> {
  const text = await readBoundedResponse(response, 512, "response too large")
    .then((bytes) => new TextDecoder().decode(bytes))
    .catch(() => "");
  const limit = uploadSizeLimitMessage(response.status, text);
  if (limit) return new Error(limit);
  return new Error(
    `media upload failed (${response.status})${text ? `: ${text}` : ""}`,
  );
}

function sameOriginMediaUrl(
  value: string,
  sha256: string,
  mediaOrigin: string,
): boolean {
  try {
    const url = new URL(value);
    return (
      url.origin === mediaOrigin &&
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
  mediaOrigin: string,
): BlobDescriptor {
  if (
    !isRecord(value) ||
    typeof value.url !== "string" ||
    value.sha256 !== expectedSha256 ||
    value.size !== expectedSize ||
    typeof value.type !== "string" ||
    typeof value.uploaded !== "number" ||
    !Number.isFinite(value.uploaded) ||
    !sameOriginMediaUrl(value.url, expectedSha256, mediaOrigin)
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
  mediaOrigin: string,
): Promise<Response> {
  return fetch(new URL(path, mediaOrigin), {
    method: "PUT",
    body: Uint8Array.from(bytes),
    cache: "no-store",
    credentials: "same-origin",
    headers,
    redirect: "manual",
    signal,
  });
}

async function withUploadController(
  progressId: string | undefined,
  upload: (signal: AbortSignal) => Promise<BlobDescriptor>,
  callerSignal?: AbortSignal,
): Promise<BlobDescriptor> {
  callerSignal?.throwIfAborted();
  if (progressId && activeUploads.has(progressId)) {
    throw new Error("An upload with this progress ID is already active");
  }
  const controller = new AbortController();
  if (progressId) activeUploads.set(progressId, controller);
  const onAbort = () => controller.abort();
  callerSignal?.addEventListener("abort", onAbort, { once: true });
  try {
    return await upload(controller.signal);
  } finally {
    callerSignal?.removeEventListener("abort", onAbort);
    if (progressId && activeUploads.get(progressId) === controller) {
      activeUploads.delete(progressId);
    }
  }
}

export async function uploadBrowserMedia(
  body: InvokeBody,
  options?: InvokeOptions,
  workspace?: BrowserWorkspace,
): Promise<BlobDescriptor> {
  const input = uploadInput(body, options);
  return withUploadController(
    input.progressId,
    (signal) => uploadBytes(input, signal, workspace),
    options?.signal,
  );
}

async function uploadBytes(
  { bytes, filename, mimeType, progressId }: ReturnType<typeof uploadInput>,
  signal: AbortSignal,
  workspace?: BrowserWorkspace,
): Promise<BlobDescriptor> {
  signal.throwIfAborted();
  await emitUploadPhase(progressId, "preparing");
  signal.throwIfAborted();
  const mediaOrigin = workspace
    ? new URL(workspace.httpUrl()).origin
    : window.location.origin;
  const sha256 = await sha256Hex(bytes);
  signal.throwIfAborted();
  const authorization = await blossomAuthorization(
    uploadTemplate(sha256, mimeType, mediaOrigin),
  );
  signal.throwIfAborted();
  const headers = new Headers({
    Authorization: authorization,
    "Content-Type": mimeType,
    "X-SHA-256": sha256,
  });

  await emitUploadPhase(progressId, "uploading");
  await emitUploadProgress(progressId, 0, bytes.byteLength);
  signal.throwIfAborted();
  let response = await sendUpload(
    "/upload",
    bytes,
    headers,
    signal,
    mediaOrigin,
  );
  if (response.status === 404 || response.status === 405) {
    await response.body?.cancel().catch(() => {});
    signal.throwIfAborted();
    response = await sendUpload(
      "/media/upload",
      bytes,
      headers,
      signal,
      mediaOrigin,
    );
  }
  if (!response.ok) throw await responseError(response);
  const descriptorBytes = await readBoundedResponse(
    response,
    MAX_DESCRIPTOR_BYTES,
    "media upload descriptor exceeds the 64KB limit",
  );
  signal.throwIfAborted();
  const descriptor = parseDescriptor(
    JSON.parse(new TextDecoder().decode(descriptorBytes)),
    sha256,
    bytes.byteLength,
    mediaOrigin,
  );
  await emitUploadProgress(progressId, bytes.byteLength, bytes.byteLength);
  await emitUploadPhase(progressId, "finishing");
  signal.throwIfAborted();
  return filename ? { ...descriptor, filename } : descriptor;
}

function selectFiles(accept?: string, multiple = false): Promise<File[]> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = multiple;
    if (accept) input.accept = accept;
    const finish = (files: File[]) => {
      input.removeEventListener("change", onChange);
      input.removeEventListener("cancel", onCancel);
      input.remove();
      resolve(files);
    };
    const onChange = () => finish(Array.from(input.files ?? []));
    const onCancel = () => finish([]);
    input.addEventListener("change", onChange, { once: true });
    input.addEventListener("cancel", onCancel, { once: true });
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
  workspace?: BrowserWorkspace,
): Promise<BlobDescriptor> {
  // No client-side byte cap: the relay's 413 names the real limit
  // (`uploadSizeLimitMessage`), so the picker never refuses a file the relay
  // would take.
  return withUploadController(progressId, async (signal) => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    signal.throwIfAborted();
    const detectedImageMime = sniffImageMime(bytes);
    if (requireImage && !detectedImageMime) {
      throw new Error("Selected file is not a supported image");
    }
    return uploadBytes(
      {
        bytes,
        filename: file.name,
        mimeType:
          detectedImageMime ?? (file.type || "application/octet-stream"),
        progressId,
      },
      signal,
      workspace,
    );
  });
}

async function fetchMediaBytes(
  body: InvokeBody,
  workspace?: BrowserWorkspace,
): Promise<ArrayBuffer> {
  if (!isRecord(body) || typeof body.url !== "string") {
    throw new TypeError("fetch_media_bytes requires a URL");
  }
  const url = new URL(body.url);
  const mediaOrigin = workspace
    ? new URL(workspace.httpUrl()).origin
    : window.location.origin;
  if (url.origin !== mediaOrigin || !url.pathname.startsWith("/media/")) {
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
    await response.body?.cancel().catch(() => {});
    throw new Error("fetch_media_bytes requires image content");
  }
  const bytes = await readBoundedResponse(
    response,
    MAX_BROWSER_FETCH_BYTES,
    "media response exceeds the 50MB limit",
  );
  return bytes.buffer;
}

export function registerMediaCommands(workspace: BrowserWorkspace): void {
  register("upload_media_bytes_raw", (body, options) =>
    uploadBrowserMedia(body, options, workspace),
  );
  register("upload_media_bytes", (body, options) =>
    uploadBrowserMedia(body, options, workspace),
  );
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
      descriptors.push(await uploadFile(file, progressId, false, workspace));
    }
    return descriptors;
  });
  register("pick_and_upload_image", async () => {
    const [file] = await selectFiles("image/*");
    return file ? uploadFile(file, undefined, true, workspace) : null;
  });
  register("fetch_media_bytes", (body) => fetchMediaBytes(body, workspace));
}
