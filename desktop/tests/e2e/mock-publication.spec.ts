import { expect, test } from "@playwright/test";
import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

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

test("native notification capture preserves targets and shares browser click indices", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();

  const target = {
    channelId: "1c7e1c02-87bb-5e88-b2da-5a7a9432d0c9",
    channelName: "engineering",
    content: "Native notification body",
    createdAt: 1_788_700_000,
    eventId: "native-notification-event",
    kind: 9,
    pubkey: TEST_IDENTITIES.bob.pubkey,
    threadRootId: "native-notification-thread",
  };
  const evidence = await page.evaluate(async (target) => {
    const win = window as Window & {
      __BUZZ_E2E_CLICK_NOTIFICATION__?: (index: number) => boolean;
      __BUZZ_E2E_NOTIFICATIONS__?: Array<{
        title: string;
        body: string | null;
      }>;
    };
    const invoke = win.__BUZZ_E2E_INVOKE_MOCK_COMMAND__;
    const click = win.__BUZZ_E2E_CLICK_NOTIFICATION__;
    if (!invoke || !click)
      throw new Error("Notification bridge is unavailable");
    const actions: unknown[] = [];
    let resolveAction: (target: unknown) => void = () => {};
    const activation = new Promise((resolve) => {
      resolveAction = resolve;
    });
    window.addEventListener("buzz:desktop-notification-action", (event) => {
      actions.push((event as CustomEvent).detail);
      resolveAction((event as CustomEvent).detail);
    });
    await invoke("show_native_notification", {
      title: "Native title",
      body: target.content,
      target,
    });
    target.content = "Changed after delivery";
    let browserHandlers = 0;
    let browserListeners = 0;
    const browser = new Notification("Browser title", { body: "Browser body" });
    browser.onclick = () => {
      browserHandlers += 1;
    };
    browser.addEventListener("click", () => {
      browserListeners += 1;
    });
    const browserClicked = click(1);
    const nativeActionsBeforeClick = actions.length;
    const nativeClicked = click(0);
    const activated = await activation;
    return {
      native: win.__BUZZ_E2E_NATIVE_NOTIFICATIONS__,
      all: win.__BUZZ_E2E_NOTIFICATIONS__,
      browserClicked,
      nativeClicked,
      activated,
      actions,
      browserHandlers,
      browserListeners,
      nativeActionsBeforeClick,
      invalidIndex: click(-1),
      absentIndex: click(2),
    };
  }, target);
  expect(evidence).toEqual({
    native: [{ title: "Native title", body: target.content, target }],
    all: [
      { title: "Native title", body: target.content },
      { title: "Browser title", body: "Browser body" },
    ],
    browserClicked: true,
    nativeClicked: true,
    activated: target,
    actions: [target],
    browserHandlers: 1,
    browserListeners: 1,
    nativeActionsBeforeClick: 0,
    invalidIndex: false,
    absentIndex: false,
  });
});
