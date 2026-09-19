import { getStorageItem, setStorageItem } from "@/shared/lib/safeStorage";

const WATERMARK_STORAGE_PREFIX = "buzz:lastReminderCheck:";
const sessionWatermarks = new Map<string, number>();

function watermarkStorageKey(scope: string, pubkey: string): string {
  return `${WATERMARK_STORAGE_PREFIX}${JSON.stringify([scope, pubkey.trim().toLowerCase()])}`;
}

/**
 * Read the persisted watermark, seeding it to `now` on first-ever launch.
 * Seeding to `now` (not 0) is deliberate: a 0 seed would replay the user's
 * entire reminder history as toasts. A reminder already due at first launch
 * fails the strict `notBefore > watermark` test and surfaces only in the
 * panel/badge, never as a toast — see the plan's behavioral note.
 */
export function readWatermark(scope: string, pubkey: string): number {
  const key = watermarkStorageKey(scope, pubkey);
  const stored = getStorageItem(key);
  if (stored !== null) {
    const parsed = Number(stored);
    if (Number.isFinite(parsed)) {
      sessionWatermarks.set(key, parsed);
      return parsed;
    }
  }
  // Preserve the missed-while-closed window across upgrades. Keep the legacy
  // baseline for communities not visited yet, but only advance scoped keys.
  const legacy = getStorageItem(
    `${WATERMARK_STORAGE_PREFIX}${pubkey.trim().toLowerCase()}`,
  );
  if (legacy !== null && Number.isFinite(Number(legacy))) {
    const watermark = Number(legacy);
    const fallback = sessionWatermarks.get(key);
    if (fallback !== undefined) return fallback;
    writeWatermark(scope, pubkey, watermark);
    return watermark;
  }
  const sessionWatermark = sessionWatermarks.get(key);
  if (sessionWatermark !== undefined) return sessionWatermark;
  const now = Math.floor(Date.now() / 1_000);
  sessionWatermarks.set(key, now);
  setStorageItem(key, String(now));
  return now;
}

/** Persist the last checked time for one community and identity. */
export function writeWatermark(
  scope: string,
  pubkey: string,
  watermark: number,
): void {
  const key = watermarkStorageKey(scope, pubkey);
  sessionWatermarks.set(key, watermark);
  setStorageItem(key, String(watermark));
}

/** Release in-memory fallbacks when leaving a community. */
export function resetReminderWatermarks(): void {
  sessionWatermarks.clear();
}
