import { expect, test } from "@playwright/test";
import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import {
  copyBody,
  expectPrivateIdentity,
  LABEL,
  NAMESAKE,
  paste,
  SELECTED,
  sentEvents,
} from "../helpers/mentionClipboard";

for (const source of ["timeline", "thread", "forum", "composer"] as const) {
  for (const destination of ["channel", "forum"] as const) {
    test(`${source} copy to ${destination} sends only the selected same-name identity`, async ({
      page,
    }) => {
      await installMockBridge(page, {
        searchProfiles: [SELECTED, NAMESAKE].map((pubkey) => ({
          pubkey,
          displayName: LABEL,
        })),
      });
      await page.goto("/");
      await page.getByTestId("channel-general").click();
      await expect
        .poll(() =>
          page.evaluate(() =>
            window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
              channelName: "general",
            }),
          ),
        )
        .toBe(true);
      const content = `@${LABEL} ${source} to ${destination}`;
      const event = await page.evaluate(
        ({ source, content, selected, author }) => {
          const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
          if (!emit) throw new Error("Mock emitter missing");
          return emit({
            channelName: source === "forum" ? "watercooler" : "general",
            content,
            kind: source === "forum" ? 45001 : undefined,
            mentionPubkeys: [selected],
            pubkey: author,
            parentEventId:
              source === "thread" ? "mock-general-welcome" : undefined,
          });
        },
        {
          source,
          content,
          selected: SELECTED,
          author: TEST_IDENTITIES.alice.pubkey,
        },
      );
      if (source === "forum")
        await page.getByTestId("channel-watercooler").click();
      if (source === "thread") {
        await page.getByTestId("message-thread-summary").first().click();
        await expect(page.getByTestId("message-thread-panel")).toBeVisible();
      }
      let body =
        source === "forum"
          ? page
              .locator(".message-markdown")
              .filter({ hasText: `${source} to ${destination}` })
          : page.locator(`[data-message-id="${event.id}"] .message-markdown`);
      await expect(
        body.locator(`[data-mention-pubkey="${SELECTED}"]`),
      ).toHaveText(LABEL);
      await expect(page.locator("[data-render-pending]")).toHaveCount(0);
      if (source === "composer") {
        const flavors = await copyBody(body);
        expectPrivateIdentity(flavors);
        const input = page.getByTestId("message-input");
        await paste(input, flavors);
        await expect(input.locator(".mention-chip")).toHaveText(LABEL);
        await input.press("ControlOrMeta+A");
        body = input;
      }
      const flavors = await copyBody(body);
      expectPrivateIdentity(flavors);
      expect(flavors.text.trim()).toBe(content);
      if (source === "thread")
        await page.getByTestId("auxiliary-panel-close").click();
      // Switching away clears the source selection and uses a different composer.
      await page
        .getByTestId(
          destination === "forum"
            ? "channel-watercooler"
            : "channel-engineering",
        )
        .click();
      if (destination === "forum")
        await page.getByRole("button", { name: "Start a new post..." }).click();
      const input = page.getByTestId("message-input");
      await paste(input, flavors);
      await expect(input.locator(".mention-chip")).toHaveText(LABEL);
      await page.getByTestId("send-message").click();
      if (destination === "forum") await expect(input).toHaveCount(0);
      else await expect(input).toHaveText("");
      await expect
        .poll(async () =>
          (await sentEvents(page, content)).map((event) =>
            event.tags.filter((tag) => tag[0] === "p").map((tag) => tag[1]),
          ),
        )
        .toEqual([[SELECTED]]);
    });
  }
}

test("partial chip copy cannot acquire the whole mention identity", async ({
  page,
}) => {
  await installMockBridge(page, {
    searchProfiles: [{ pubkey: SELECTED, displayName: LABEL }],
  });
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
          channelName: "general",
        }),
      ),
    )
    .toBe(true);
  await page.evaluate(
    ({ selected, author }) =>
      window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__?.({
        channelName: "general",
        content: "@John Smith partial",
        mentionPubkeys: [selected],
        pubkey: author,
      }),
    { selected: SELECTED, author: TEST_IDENTITIES.alice.pubkey },
  );
  const body = page
    .locator(".message-markdown")
    .filter({ hasText: "John Smith partial" });
  await expect(body.locator("[data-mention-pubkey]")).toHaveText(LABEL);
  const flavors = await copyBody(body, true);
  expect(flavors.text).toBe("John");
  expect(flavors.html).not.toContain(SELECTED);
  expect(flavors.text).not.toMatch(/[0-9a-f]{64}/i);
  const input = page.getByTestId("message-input");
  await paste(input, flavors);
  await expect(input.locator(".mention-chip")).toHaveCount(0);
  await page.getByTestId("send-message").click();
  await expect
    .poll(async () =>
      (await sentEvents(page, "John")).map((event) =>
        event.tags.filter((tag) => tag[0] === "p"),
      ),
    )
    .toEqual([[]]);
});
