import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const startupModules = [
  "useWebviewZoomShortcuts.ts",
  "../features/home/useFeedItemState.ts",
  "../features/notifications/use-feed-desktop-notifications.ts",
  "../features/notifications/hooks.ts",
  "../features/onboarding/hooks.ts",
  "../features/presence/hooks.ts",
  "../features/reminders/useReminderNotifications.ts",
  "../features/agents/usePreventSleep.ts",
  "../features/channels/readState/readStateManager.ts",
  "../features/channels/readState/readStateStorage.ts",
  "../shared/ui/sidebar.tsx",
];

test("app-shell startup storage uses throw-safe accessors", () => {
  for (const relativePath of startupModules) {
    const source = readFileSync(path.resolve(testDir, relativePath), "utf8");
    assert.doesNotMatch(
      source,
      /(?:window\.)?localStorage\.(?:getItem|setItem|removeItem)/,
      `${relativePath} must not access localStorage outside safeStorage`,
    );
    assert.match(
      source,
      /@\/shared\/lib\/safeStorage/,
      `${relativePath} must use safeStorage`,
    );
  }
});
