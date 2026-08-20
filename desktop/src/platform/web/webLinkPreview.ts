import { register } from "./registry";

/**
 * Browser fetch cannot preserve the native command's security contract. The
 * native implementation resolves and pins public addresses, validates every
 * redirect, bounds response bodies, and sanitizes fetched images. Returning no
 * metadata keeps links usable without exposing an unrestricted cross-origin
 * fetch from the browser PAL.
 */
export function fetchBrowserLinkPreviewMetadata(): null {
  return null;
}

export function registerLinkPreviewCommands(): void {
  register("fetch_link_preview_metadata", fetchBrowserLinkPreviewMetadata);
}
