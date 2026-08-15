export type ObjectUrlOwner = { previewUrl?: string };

export function releaseObjectUrl(
  value: string | undefined,
  released: Set<string>,
  revoke = URL.revokeObjectURL,
): void {
  if (!value?.startsWith("blob:") || released.has(value)) return;
  released.add(value);
  revoke(value);
}

export function releaseObjectUrls(
  owners: readonly ObjectUrlOwner[],
  released: Set<string>,
  revoke = URL.revokeObjectURL,
): void {
  for (const owner of owners)
    releaseObjectUrl(owner.previewUrl, released, revoke);
}

export function waitForVisiblePaint(
  visibilityState: DocumentVisibilityState,
  requestFrame: typeof requestAnimationFrame,
  timeoutMs = 50,
): Promise<void> {
  if (visibilityState === "hidden") return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve();
    };
    const timeout = setTimeout(finish, timeoutMs);
    requestFrame(finish);
  });
}
