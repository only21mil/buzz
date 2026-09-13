// P01 fork contracts: welcome-everywhere banner dismissal behaviors (audit D10).
// New file. The two scenarios below are quarantined as test.fixme in
// onboarding.spec.ts because they fail on the upstream merge source. This file
// re-asserts them as active contracts against the fork so the fork run proves
// whether the defects still reproduce here or the fork already resolves them.
// Both scenarios still fail on the fork (run 2026-09-13, same signatures as the
// upstream quarantine: guidance layer count 1 after X dismiss, and chat title
// "welcome-everyone" instead of "Welcome"). Real inherited defects, so both stay
// quarantined below with the fork evidence attached. Un-quarantine when the
// onboarding owner fixes dismissal persistence and the starter-channel title.
// Service-free against the mock Tauri bridge.
import { expect, test, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import { seedActiveIdentity } from "../helpers/onboarding";

const BLANK_TYLER_IDENTITY = {
  ...TEST_IDENTITIES.tyler,
  username: "",
};

async function completeProfileOnboarding(page: Page) {
  await page.getByTestId("onboarding-next").click();
  await expect(page.getByTestId("onboarding-page-avatar")).toBeVisible();
  await page
    .getByTestId("onboarding-avatar-url")
    .fill("https://example.com/onboarding-avatar.png");
  await page.getByTestId("onboarding-next").click();
}

// QUARANTINE — reproduced on the fork 2026-09-13 in this file:
// welcome-composer-guidance-layer expected count 0, received 1 after X dismiss.
// Same defect as the upstream quarantine on block/buzz@5bf78671.
test.fixme("welcome-everywhere banner: X dismiss removes the guidance surface", async ({
  page,
}) => {
  await seedActiveIdentity(page, BLANK_TYLER_IDENTITY);
  await installMockBridge(page, undefined, { skipOnboardingSeed: true });
  await page.goto("/");

  await page.getByTestId("onboarding-display-name").fill("Morty QA");
  await completeProfileOnboarding(page);

  const banner = page.getByTestId("welcome-composer-guide-banner");
  const guidanceLayer = page.getByTestId("welcome-composer-guidance-layer");
  const dismissButton = page.getByTestId("welcome-composer-dismiss-button");

  // Banner and guidance layer are visible in the prompt state.
  await expect(banner).toBeVisible();
  await expect(guidanceLayer).toBeVisible();
  await expect(dismissButton).toBeVisible();

  await dismissButton.click();

  // After dismiss the entire guidance surface must be gone.
  await expect(banner).toHaveCount(0, { timeout: 2_000 });
  await expect(guidanceLayer).toHaveCount(0);
});

// QUARANTINE — reproduced on the fork 2026-09-13 in this file:
// chat-title expected "Welcome", received "welcome-everyone" after re-entry.
// Same defect as the upstream quarantine on block/buzz@5bf78671.
test.fixme("welcome-everywhere banner: dismiss persists after channel re-entry", async ({
  page,
}) => {
  await seedActiveIdentity(page, BLANK_TYLER_IDENTITY);
  await installMockBridge(page, undefined, { skipOnboardingSeed: true });
  await page.goto("/");

  await page.getByTestId("onboarding-display-name").fill("Morty QA");
  await completeProfileOnboarding(page);

  const banner = page.getByTestId("welcome-composer-guide-banner");

  await expect(banner).toBeVisible();
  await page.getByTestId("welcome-composer-dismiss-button").click();
  await expect(banner).toHaveCount(0, { timeout: 2_000 });

  // Leave the Welcome channel.
  await page.getByTestId("channel-general").click();
  await expect(page.getByTestId("chat-title")).toContainText("general");
  await expect(banner).toHaveCount(0);

  // Return — banner must stay hidden.
  await page.getByTestId("channel-welcome-everyone").click();
  await expect(page.getByTestId("chat-title")).toContainText("Welcome");
  await expect(banner).toHaveCount(0);
});
