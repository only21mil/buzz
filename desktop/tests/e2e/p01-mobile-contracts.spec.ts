// P01 fork contracts: phone-width scenarios for adopted mention, workflow, and
// voice-note behaviors (audit D3). New file. Browser-width coverage for the same
// behaviors lives in the p01 browser contract files. This file pins the narrow
// layout contracts: chips wrap instead of overflowing, composer controls stay
// reachable, and sends still carry exact recipients at 390px.
// All tests run service-free against the mock Tauri bridge.
import { expect, test, type Locator, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import {
  finishRecording,
  installVoiceNote,
  startRecording,
} from "../helpers/voiceNote";

const FIRST = TEST_IDENTITIES.alice.pubkey;
const SECOND = TEST_IDENTITIES.bob.pubkey;
const CHANNEL_ID = "9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50";
const THREAD_ROOT_ID = "mock-general-welcome";
const AGENT_A = "a".repeat(64);
const AGENT_B = "b".repeat(64);

test.use({ viewport: { width: 390, height: 844 } });

async function recipients(page: Page, content: string) {
  return page.evaluate((expected) => {
    const signed = (window.__BUZZ_E2E_SIGNED_EVENTS__ ?? [])
      .filter((event) => event.content === expected)
      .map((event) =>
        event.tags.filter((tag) => tag[0] === "p").map((tag) => tag[1]),
      );
    if (signed.length > 0) return signed;
    return (window.__BUZZ_E2E_COMMAND_LOG__ ?? [])
      .filter((call) => call.command === "send_channel_message")
      .map(
        (call) =>
          call.payload as { content?: string; mentionPubkeys?: string[] },
      )
      .filter((payload) => payload.content === expected)
      .map((payload) => payload.mentionPubkeys ?? []);
  }, content);
}

async function expectNoHorizontalOverflow(host: Locator) {
  const overflow = await host.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
}

test("exact-key mention chips wrap without horizontal overflow in a narrow composer", async ({
  page,
}) => {
  await installMockBridge(page, {
    searchProfiles: [FIRST, SECOND].map((pubkey) => ({
      pubkey,
      displayName: "Scout",
    })),
  });
  await page.goto(`/#/channels/${CHANNEL_ID}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("chat-title")).toHaveText("general");

  const input = page.getByTestId("message-input");
  await input.fill("@Scout");
  await page.getByTestId(`mention-suggestion-${FIRST}`).click();
  await page.keyboard.type("@Scout");
  await page.getByTestId(`mention-suggestion-${SECOND}`).click();
  await page.keyboard.type("layout journey");
  const content = `@Scout @Scout (${SECOND}) layout journey`;
  await expect(input).toHaveText(content);

  const chips = input.locator(".mention-chip");
  expect(await chips.count()).toBeGreaterThanOrEqual(2);
  for (const chip of await chips.all()) {
    await expect
      .poll(() => chip.evaluate((el) => getComputedStyle(el).overflowWrap))
      .toBe("anywhere");
  }
  await expectNoHorizontalOverflow(input);
  const inputBox = await input.boundingBox();
  for (const chip of await chips.all()) {
    const box = await chip.boundingBox();
    expect(box?.x).toBeGreaterThanOrEqual((inputBox?.x ?? 0) - 1);
    expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(
      (inputBox?.x ?? 0) + (inputBox?.width ?? 0) + 1,
    );
  }

  await page.getByTestId("send-message").click();
  await expect.poll(() => recipients(page, content)).toEqual([[FIRST, SECOND]]);
});

test("mention-button placement fits the narrow thread composer", async ({
  page,
}) => {
  await installMockBridge(page, {
    managedAgents: [
      {
        pubkey: AGENT_A,
        name: "Morgarita",
        status: "running",
        channelNames: ["general"],
      },
      {
        pubkey: AGENT_B,
        name: "Vogue",
        status: "running",
        channelNames: ["general"],
      },
    ],
  });
  await page.goto(
    `/#/channels/${CHANNEL_ID}?messageId=${THREAD_ROOT_ID}&thread=${THREAD_ROOT_ID}`,
    { waitUntil: "domcontentloaded" },
  );
  await expect(page.getByTestId("message-thread-panel")).toBeVisible();

  const overlay = page.getByTestId("thread-composer-overlay");
  for (const name of ["Morgarita", "Vogue"]) {
    await overlay.locator("[data-mention-picker-trigger]").click();
    await overlay
      .getByTestId("mention-autocomplete")
      .getByRole("button", { name: `Automatically mention ${name}` })
      .click();
    await overlay.locator("[data-mention-picker-trigger]").click();
  }
  await expect(overlay.getByTestId("composer-address-locks")).toBeVisible();
  await expect(
    overlay.getByRole("button", { name: "Manage mentions" }),
  ).toBeVisible();
  await expectNoHorizontalOverflow(overlay.getByTestId("message-composer"));
});

test("workflow library stays usable at phone width", async ({ page }) => {
  await installMockBridge(page);
  await page.goto("/#/workflows");
  await expect(page.getByTestId("workflows-view")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Create Workflow" }),
  ).toBeVisible();

  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
});

test("voice-note composer card fits phone width and sends", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto(`/#/channels/${CHANNEL_ID}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("chat-title")).toHaveText("general");

  await startRecording(page);
  await finishRecording(page);
  const card = page.getByTestId("composer-voice-note-card");
  await expect(card).toBeVisible();
  const box = await card.boundingBox();
  expect(box?.x).toBeGreaterThanOrEqual(-1);
  expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(390 + 1);

  await page.getByTestId("send-message").click();
  await expect(card).toHaveCount(0);
  await expect(page.getByTestId("audio-message-attachment")).toBeVisible();
});

test("thread audience send works at phone width", async ({ page }) => {
  await installMockBridge(page, {
    managedAgents: [
      {
        pubkey: AGENT_A,
        name: "Morgarita",
        status: "running",
        channelNames: ["general"],
      },
    ],
  });
  await page.goto(
    `/#/channels/${CHANNEL_ID}?messageId=${THREAD_ROOT_ID}&thread=${THREAD_ROOT_ID}`,
    { waitUntil: "domcontentloaded" },
  );
  await expect(page.getByTestId("message-thread-panel")).toBeVisible();

  const input = page
    .getByTestId("thread-composer-overlay")
    .getByTestId("message-input");
  await input.fill("@Mor");
  await expect(
    page
      .getByTestId("thread-composer-overlay")
      .getByTestId("mention-autocomplete"),
  ).toBeVisible();
  await input.press("Tab");
  await expect(input).toHaveText("@Morgarita ");
  await input.pressSequentially("narrow hello");
  await input.press("Enter");
  await expect
    .poll(() => recipients(page, "@Morgarita narrow hello"))
    .toEqual([[AGENT_A]]);
});
