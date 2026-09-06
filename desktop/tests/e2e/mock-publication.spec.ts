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

test("mock agent revalidation returns only requested keys with existing policy and membership", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await expect(page.getByTestId("app-sidebar")).toBeVisible();
  const evidence = await page.evaluate(async () => {
    const invoke = window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__;
    if (!invoke) throw new Error("Mock command bridge is unavailable");
    const directory = (await invoke("list_relay_agents")) as Array<{
      pubkey: string;
      name: string;
      channel_ids: string[];
    }>;
    const alice = directory.find((agent) => agent.name === "alice");
    if (!alice) throw new Error("Seeded alice is unavailable");
    const selected = await invoke("revalidate_relay_agents", {
      pubkeys: [alice.pubkey.toUpperCase(), "unknown-key"],
      channelId: alice.channel_ids[0],
    });
    const excluded = await invoke("revalidate_relay_agents", {
      pubkeys: [alice.pubkey],
      channelId: "unjoined-destination",
    });
    return { alice, selected, excluded };
  });
  expect(evidence.selected).toEqual([evidence.alice]);
  expect(evidence.excluded).toEqual([]);
});
