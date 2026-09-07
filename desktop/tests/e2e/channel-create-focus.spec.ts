import { expect, test, type Page } from "@playwright/test";

import { installMockBridge, openCreateChannelDialog } from "../helpers/bridge";

type FocusTimerWindow = Window & {
  __focusTimers: Map<number, () => void>;
};

test.beforeEach(async ({ page }) => {
  await installMockBridge(page);
  await page.addInitScript(() => {
    const timers = new Map<number, () => void>();
    (window as FocusTimerWindow).__focusTimers = timers;
    const schedule = window.setTimeout.bind(window);
    const cancel = window.clearTimeout.bind(window);
    let nextId = -1;
    // Hold only the actual create-form autofocus callback. Animation and
    // Radix timers keep running normally, including menu focus and dismissal.
    window.setTimeout = (callback, delay, ...args) => {
      if (
        delay === 50 &&
        typeof callback === "function" &&
        callback.toString().includes("#create-channel-form")
      ) {
        const id = nextId--;
        timers.set(id, () => callback(...args));
        return id;
      }
      return schedule(callback, delay, ...args);
    };
    window.clearTimeout = (id) => {
      timers.delete(id ?? 0);
      cancel(id);
    };
  });
  await page.goto("/");
});

async function pendingCount(page: Page) {
  return page.evaluate(() => (window as FocusTimerWindow).__focusTimers.size);
}

async function releaseAutofocus(page: Page) {
  await page.evaluate(() => {
    for (const [id, callback] of (window as FocusTimerWindow).__focusTimers) {
      (window as FocusTimerWindow).__focusTimers.delete(id);
      callback();
    }
  });
}

test("delayed create autofocus preserves the portalled channel type menu", async ({
  page,
}) => {
  await openCreateChannelDialog(page);
  await expect.poll(() => pendingCount(page)).toBe(1);
  await page.getByTestId("create-channel-channel-type").click();
  const temporary = page.getByRole("menuitemradio", {
    name: "Temporary channel",
  });
  await temporary.focus();
  await expect(temporary).toBeFocused();
  expect(
    await temporary.evaluate((el) => el.closest("#create-channel-form")),
  ).toBeNull();
  await releaseAutofocus(page);
  await expect(temporary).toBeFocused();
  await expect(page.getByRole("menu")).toBeVisible();
  await temporary.click();
  await expect(page.getByTestId("create-channel-channel-type")).toContainText(
    "Temporary",
  );
  await expect(page.getByRole("menu")).toHaveCount(0);
});

test("delayed create autofocus focuses Name and preserves later field interaction", async ({
  page,
}) => {
  await openCreateChannelDialog(page);
  await expect.poll(() => pendingCount(page)).toBe(1);
  await releaseAutofocus(page);
  const name = page.getByTestId("create-channel-name");
  await expect(name).toBeFocused();
  expect(await name.evaluate((el: HTMLInputElement) => el.selectionStart)).toBe(
    0,
  );
  await page.keyboard.press("Escape");
  await openCreateChannelDialog(page);
  await expect.poll(() => pendingCount(page)).toBe(1);
  const description = page.getByTestId("create-channel-description");
  await description.fill("Keep my focus");
  await releaseAutofocus(page);
  await expect(description).toBeFocused();
});

test("closing create cancels autofocus and reopening schedules a fresh callback", async ({
  page,
}) => {
  await openCreateChannelDialog(page);
  await expect.poll(() => pendingCount(page)).toBe(1);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("create-channel-dialog")).toHaveCount(0);
  await expect.poll(() => pendingCount(page)).toBe(0);
  await releaseAutofocus(page);
  await openCreateChannelDialog(page);
  await expect.poll(() => pendingCount(page)).toBe(1);
  await releaseAutofocus(page);
  await expect(page.getByTestId("create-channel-name")).toBeFocused();
});
