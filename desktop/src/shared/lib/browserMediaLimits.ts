/** Enforce the browser upload cap before reading or copying file bytes. */
export function checkBrowserUploadSize(size: number): void {
  if (size > 100 * 1024 * 1024) {
    throw new Error("File is too large. Maximum is 100MB.");
  }
}
