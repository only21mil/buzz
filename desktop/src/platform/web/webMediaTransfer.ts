import { mediaAuthorization } from "./mediaAuth";
import { mediaHashFromUrl } from "./mediaAuthProtocol";
import {
  CapabilityUnavailableError,
  type InvokeBody,
  register,
} from "./registry";
import type { BrowserWorkspace } from "./workspace";

const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
const CLIPBOARD_PIXEL_BYTES = 4;
const DOWNLOAD_TIMEOUT_MS = 60_000;

type MediaRequest = {
  url: URL;
  filename?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function sanitizeFilename(value: string): string {
  const basename = (value.split(/[\\/]/).at(-1) ?? value).trim();
  const cleaned = Array.from(basename)
    .filter((character) => !/\p{Cc}/u.test(character))
    .slice(0, 255)
    .join("");
  return cleaned || "file";
}

function parseMediaRequest(
  command: string,
  body: InvokeBody,
  needsFilename = false,
  workspace?: BrowserWorkspace,
): MediaRequest {
  if (!isRecord(body) || typeof body.url !== "string") {
    throw new TypeError(`${command} requires a URL`);
  }
  const expectedOrigin = workspace
    ? new URL(workspace.httpUrl()).origin
    : window.location.origin;
  if (!mediaHashFromUrl(body.url, expectedOrigin)) {
    throw new Error(`${command} only accepts same-origin media URLs`);
  }
  if (needsFilename && typeof body.filename !== "string") {
    throw new TypeError(`${command} requires a filename`);
  }
  return {
    url: new URL(body.url),
    filename:
      typeof body.filename === "string"
        ? sanitizeFilename(body.filename)
        : undefined,
  };
}

async function responseError(response: Response): Promise<Error> {
  const text = (await response.text().catch(() => "")).slice(0, 512);
  return new Error(
    `media download failed (${response.status})${text ? `: ${text}` : ""}`,
  );
}

async function readBoundedBlob(response: Response): Promise<Blob> {
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_DOWNLOAD_BYTES) {
    throw new Error("media response exceeds the 50MB limit");
  }

  const contentType =
    response.headers.get("Content-Type")?.split(";", 1)[0] ?? "";
  if (!response.body) return new Blob([], { type: contentType });

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_DOWNLOAD_BYTES) {
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
  return new Blob([bytes], { type: contentType });
}

async function fetchRelayMedia(
  url: URL,
  requireImage: boolean,
  workspace?: BrowserWorkspace,
): Promise<Blob> {
  const authorization = await mediaAuthorization(url.href, workspace);
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    DOWNLOAD_TIMEOUT_MS,
  );
  try {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Authorization: authorization },
      redirect: "manual",
      signal: controller.signal,
    });
    if (!response.ok) throw await responseError(response);

    const contentType = response.headers.get("Content-Type")?.split(";", 1)[0];
    if (requireImage && !contentType?.startsWith("image/")) {
      throw new Error("media response is not an image");
    }
    return await readBoundedBlob(response);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error("media download timed out");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function triggerDownload(blob: Blob, filename: string): void {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
}

function filenameFromUrl(url: URL): string {
  const segment = url.pathname.split("/").at(-1);
  if (!segment) return "image.png";
  try {
    return sanitizeFilename(decodeURIComponent(segment));
  } catch {
    return sanitizeFilename(segment);
  }
}

export async function downloadBrowserImage(
  body: InvokeBody,
  workspace?: BrowserWorkspace,
): Promise<boolean> {
  const { url } = parseMediaRequest("download_image", body, false, workspace);
  const blob = await fetchRelayMedia(url, true, workspace);
  triggerDownload(blob, filenameFromUrl(url));
  return true;
}

export async function downloadBrowserFile(
  body: InvokeBody,
  workspace?: BrowserWorkspace,
): Promise<boolean> {
  const { url, filename } = parseMediaRequest(
    "download_file",
    body,
    true,
    workspace,
  );
  const blob = await fetchRelayMedia(url, false, workspace);
  triggerDownload(blob, filename ?? "file");
  return true;
}

function canvasToPng(canvas: HTMLCanvasElement): Promise<Blob> {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) resolve(blob);
      else reject(new Error("failed to encode image for clipboard"));
    }, "image/png");
  });
}

export async function copyBrowserImageToClipboard(
  body: InvokeBody,
  workspace?: BrowserWorkspace,
): Promise<void> {
  const { url } = parseMediaRequest(
    "copy_image_to_clipboard",
    body,
    false,
    workspace,
  );
  const source = await fetchRelayMedia(url, true, workspace);
  const image = await createImageBitmap(source).catch((error: unknown) => {
    throw new Error(
      `failed to decode image: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
  try {
    if (
      image.width * image.height * CLIPBOARD_PIXEL_BYTES >
      MAX_DOWNLOAD_BYTES
    ) {
      throw new Error("image too large to copy to clipboard");
    }
    const canvas = document.createElement("canvas");
    canvas.width = image.width;
    canvas.height = image.height;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("image clipboard conversion is unavailable");
    context.drawImage(image, 0, 0);
    const png = await canvasToPng(canvas);
    await navigator.clipboard.write([new ClipboardItem({ "image/png": png })]);
  } finally {
    image.close();
  }
}

function uploadMediaPathUnavailable(): never {
  throw new CapabilityUnavailableError(
    "upload_media",
    "Capability unavailable: browsers cannot read a native temporary file path; use upload_media_bytes instead",
  );
}

export function registerWebMediaTransferCommands(
  workspace: BrowserWorkspace,
): void {
  register("upload_media", uploadMediaPathUnavailable);
  register("download_image", (body) => downloadBrowserImage(body, workspace));
  register("download_file", (body) => downloadBrowserFile(body, workspace));
  register("copy_image_to_clipboard", (body) =>
    copyBrowserImageToClipboard(body, workspace),
  );
}
