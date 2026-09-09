import { invoke as invokeTauriRaw, isTauri } from "@tauri-apps/api/core";
import { checkBrowserUploadSize } from "../lib/browserMediaLimits";
import { type BlobDescriptor, invokeTauri } from "./tauri";

function encodeRawIpcHeader(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return window
    .btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

/** Upload a File through the platform's raw-byte transport without JSON expansion. */
export async function uploadMediaFile(
  file: File,
  progressId?: string,
  signal?: AbortSignal,
): Promise<BlobDescriptor> {
  const native = isTauri();
  if (!native) checkBrowserUploadSize(file.size);
  const headers: Record<string, string> = {
    "x-buzz-filename": encodeRawIpcHeader(file.name),
    "x-buzz-content-type": encodeRawIpcHeader(
      file.type || "application/octet-stream",
    ),
  };
  if (progressId) {
    headers["x-buzz-progress-id"] = encodeRawIpcHeader(progressId);
  }

  if (signal?.aborted) throw new Error("upload cancelled");
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (signal?.aborted) throw new Error("upload cancelled");
  // The browser PAL accepts the signal directly; native IPC keeps its contract.
  const options = { headers, ...(!native && signal ? { signal } : {}) };
  try {
    return await invokeTauriRaw<BlobDescriptor>(
      "upload_media_bytes_raw",
      bytes,
      options,
    );
  } catch (error) {
    if (error instanceof Error) throw error;
    if (typeof error === "string" && error.trim()) throw new Error(error);
    if (
      typeof error === "object" &&
      error !== null &&
      "message" in error &&
      typeof error.message === "string" &&
      error.message.trim()
    ) {
      throw new Error(error.message);
    }
    throw new Error("Media upload failed.");
  }
}

/** Stop the native HTTP request associated with a background media upload. */
export async function cancelMediaUpload(progressId: string): Promise<void> {
  await invokeTauri("cancel_media_upload", { progressId });
}

/**
 * Open a native single-file picker constrained to images and upload the
 * chosen file. Non-image files are rejected in Rust (via MIME sniffing)
 * before the bytes leave the client, so discarded/non-image selections never
 * reach the relay. Resolves to `null` when the user cancels the dialog.
 */
export async function pickAndUploadImage(): Promise<BlobDescriptor | null> {
  return invokeTauri<BlobDescriptor | null>("pick_and_upload_image", {});
}

/**
 * Fetch relay media bytes over IPC (Rust reqwest, VPN-tunneled).
 *
 * Used by the composer image editor: wrapping the bytes in a same-origin
 * `blob:` URL gives the canvas pixel access without CORS, so the media
 * proxy needs no special headers. The Rust side enforces the same URL
 * validation and size cap as the download commands.
 */
export async function fetchAudioBytes(
  url: string,
  signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  if (signal?.aborted) {
    throw new DOMException("Media fetch cancelled", "AbortError");
  }

  const requestId = signal ? crypto.randomUUID() : undefined;
  // The Rust command replies with `tauri::ipc::Response`, so the bytes
  // arrive as a raw ArrayBuffer rather than a JSON number array.
  const request = invokeTauri<ArrayBuffer>("fetch_audio_bytes", {
    requestId,
    url,
  });
  if (!signal || !requestId) return new Uint8Array(await request);

  let cancellation: Promise<unknown> | undefined;
  const onAbort = () => {
    cancellation ??= invokeTauri("cancel_media_fetch", { requestId }).catch(
      () => undefined,
    );
  };
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) onAbort();

  try {
    // Keep the scheduler slot and the cancel-before-begin token until the
    // original IPC settles. An abort race must not release native ownership.
    const bytes = await request;
    if (signal.aborted)
      throw new DOMException("Media fetch cancelled", "AbortError");
    return new Uint8Array(bytes);
  } catch (error) {
    if (signal.aborted)
      throw new DOMException("Media fetch cancelled", "AbortError");
    throw error;
  } finally {
    signal.removeEventListener("abort", onAbort);
    // A late cancel acknowledgement can recreate a token after native finish.
    await cancellation;
    await invokeTauri("release_media_fetch", { requestId }).catch(
      () => undefined,
    );
  }
}

/** Read plain text without depending on embedded-webview clipboard grants. */
export async function readTextFromSystemClipboard(): Promise<string> {
  // E2E installs Tauri's mocked IPC surface in a browser page, where the SDK's
  // `isTauri()` marker remains false. Exercise the packaged-app command path in
  // that build so tests detect accidental regressions to permission-gated DOM
  // clipboard reads.
  if (isTauri() || import.meta.env.MODE === "e2e") {
    return invokeTauri<string>("read_clipboard_text");
  }

  const clipboard = navigator.clipboard;
  if (!clipboard?.readText) {
    throw new Error("Clipboard text reading is unavailable");
  }
  return clipboard.readText();
}

/** Write text through the native clipboard after an asynchronous workflow. */
export async function copyTextToSystemClipboard(
  text: string,
  html?: string,
): Promise<void> {
  await invokeTauri("copy_text_to_clipboard", { html, text });
}

/**
 * Fetch an agent snapshot attachment in memory, verifying size, SHA-256, and
 * snapshot decode before returning the bytes.
 *
 * Inputs come directly from the message's imeta fields; validation is
 * performed on the Rust side (same-relay URL, format-specific size cap,
 * hash + size integrity, and snapshot decode). Returns the raw bytes as a
 * number array so they can be passed to the existing preview/confirm APIs.
 *
 * Throws a human-readable error string on any validation failure.
 */
export async function fetchSnapshotBytes(args: {
  url: string;
  filename: string;
  expectedSha256: string;
  expectedSize: number;
}): Promise<number[]> {
  const buffer = await invokeTauri<ArrayBuffer>("fetch_snapshot_bytes", {
    url: args.url,
    filename: args.filename,
    expectedSha256: args.expectedSha256,
    expectedSize: args.expectedSize,
  });
  return Array.from(new Uint8Array(buffer));
}

/** Fetch a validated image for the editor without widening its native content policy. */
export async function fetchMediaBytes(
  url: string,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await invokeTauri<ArrayBuffer>("fetch_media_bytes", { url }),
  );
}
