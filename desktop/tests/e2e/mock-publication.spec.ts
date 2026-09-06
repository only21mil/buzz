import { expect, test } from "@playwright/test";
import { installMockBridge } from "../helpers/bridge";

test("default mock Tauri installation binds native publication before signing", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  expect(
    await page.evaluate(
      () => (window as Window & { isTauri?: boolean }).isTauri,
    ),
  ).toBe(true);

  const content = "Native mock publication contract";
  const input = page.getByTestId("message-input");
  await input.fill(content);
  await page.getByTestId("send-message").click();
  await expect(input).toBeEmpty();
  await expect(page.getByText(content, { exact: true })).toBeVisible();

  const publication = await page.evaluate((content) => {
    const entries = window.__BUZZ_E2E_COMMAND_LOG__ ?? [];
    const signedIndex = entries.findIndex(
      ({ command, payload }) =>
        command === "sign_event" &&
        (payload as { content?: string })?.content === content,
    );
    const payload = entries[signedIndex]?.payload as
      | {
          expectedScope?: {
            pubkey: string;
            relayUrl: string;
            nativeEpoch?: number;
          };
        }
      | undefined;
    return {
      capturedIndex: entries.findIndex(
        ({ command }) => command === "get_message_publication_scope",
      ),
      signedIndex,
      expectedScope: payload?.expectedScope,
    };
  }, content);
  expect(publication.capturedIndex).toBeGreaterThanOrEqual(0);
  expect(publication.signedIndex).toBeGreaterThan(publication.capturedIndex);
  expect(publication.expectedScope?.pubkey).toBe("deadbeef".repeat(8));
  expect(publication.expectedScope?.nativeEpoch).toBe(0);
  expect(publication.expectedScope?.relayUrl).toMatch(/^ws:\/\/localhost:\d+$/);
});
