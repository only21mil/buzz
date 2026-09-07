import { expect, test } from "@playwright/test";
import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import { LABEL, paste, sentEvents } from "../helpers/mentionClipboard";

for (const destination of ["channel", "forum"]) {
  test(`ambiguous typed name preserves the ${destination} draft without sending`, async ({
    page,
  }) => {
    const pubkeys =
      destination === "forum"
        ? ["a".repeat(64), "b".repeat(64)]
        : [TEST_IDENTITIES.alice.pubkey, TEST_IDENTITIES.bob.pubkey];
    await installMockBridge(page, {
      managedAgents:
        destination === "forum"
          ? pubkeys.map((pubkey) => ({
              pubkey,
              name: "Scout",
              status: "running",
              channelNames: ["watercooler"],
            }))
          : [],
      searchProfiles: pubkeys.map((pubkey) => ({
        pubkey,
        displayName: "Scout",
      })),
    });
    await page.goto("/");
    await page
      .getByTestId(
        destination === "forum" ? "channel-watercooler" : "channel-general",
      )
      .click();
    if (destination === "forum")
      await page.getByRole("button", { name: "Start a new post..." }).click();
    const content = "@Scout ambiguous";
    const input = page.getByTestId("message-input");
    await input.fill(content);
    await input.press("Escape");
    await page.getByTestId("send-message").click();
    await expect(
      page.getByText("The mention @Scout is ambiguous.", { exact: false }),
    ).toBeVisible();
    await expect(input).toHaveText(content);
    expect(await sentEvents(page, content)).toEqual([]);
  });
}

test("foreign clipboard identity is verified and rejected before sending plain text", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  const input = page.getByTestId("message-input");
  const content = `@${LABEL} foreign clipboard`;
  const foreign = "1f".repeat(32);
  await paste(input, {
    text: content,
    html: `<span data-buzz-copy="markdown"><span data-mention="" data-mention-pubkey="${foreign}" data-mention-label="${LABEL}">@${LABEL}</span> foreign clipboard</span>`,
  });
  await expect(input).toHaveText(content);
  await expect
    .poll(() =>
      page.evaluate(
        (selected) =>
          (window.__BUZZ_E2E_COMMAND_LOG__ ?? []).some(
            (entry) =>
              entry.command === "get_users_batch" &&
              (entry.payload as { pubkeys?: string[] }).pubkeys?.includes(
                selected,
              ),
          ),
        foreign,
      ),
    )
    .toBe(true);
  await page.getByTestId("send-message").click();
  await expect(input).toHaveText("");
  await expect
    .poll(async () =>
      (await sentEvents(page, content)).map((event) =>
        event.tags.filter((tag) => tag[0] === "p"),
      ),
    )
    .toEqual([[]]);
});
