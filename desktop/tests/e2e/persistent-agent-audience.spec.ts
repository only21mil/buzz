import { expect, test, type Page } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";
import { sentEvents } from "../helpers/mentionClipboard";

const SHOTS = "test-results/persistent-agent-audience";
const CHANNEL_ID = "9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50";
const AGENT_A = "a".repeat(64);
const AGENT_B = "b".repeat(64);
const THREAD_ROOT_ID = "mock-general-welcome";
const seededAudiences = new WeakMap<Page, string[]>();

async function seedAudience(page: Page, pubkeys: string[], theme = "buzz") {
  seededAudiences.set(page, pubkeys);
  await page.addInitScript((selectedTheme) => {
    window.localStorage.setItem(
      "buzz.messages.keepMentionedAgentsPinned",
      "true",
    );
    window.localStorage.setItem("buzz-theme", selectedTheme);
  }, theme);
}

async function expectRecipients(
  page: Page,
  content: string,
  pubkeys: string[],
) {
  await expect
    .poll(async () =>
      (await sentEvents(page, content)).map((event) =>
        event.tags.filter((tag) => tag[0] === "p").map((tag) => tag[1]),
      ),
    )
    .toEqual([pubkeys]);
}

async function openGeneral(page: Page) {
  await page.goto(`/#/channels/${CHANNEL_ID}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("chat-title")).toHaveText("general");
}

async function openThread(page: Page, threadRootId = THREAD_ROOT_ID) {
  await page.goto(
    `/#/channels/${CHANNEL_ID}?messageId=${threadRootId}&thread=${threadRootId}`,
    { waitUntil: "domcontentloaded" },
  );
  await expect(page.getByTestId("message-thread-panel")).toBeVisible();
  // Audience choices are session state. Make the actual pin selections rather
  // than hydrating the retired durable audience-storage format.
  const composer = threadComposer(page);
  const input = composer.getByTestId("message-input");
  // Each pin prepends its automatic prefix. Select in reverse display order.
  for (const pubkey of [...(seededAudiences.get(page) ?? [])].reverse()) {
    const name = pubkey === AGENT_A ? "Morgarita" : "Vogue";
    await input.pressSequentially(`@${name}`);
    await composer.getByTestId(`mention-always-address-${pubkey}`).click();
    await input.press("Escape");
    await input.press("End");
  }
}

async function emitRootMessage(
  page: Page,
  content: string,
  mentionPubkeys: string[],
) {
  const event = await page.evaluate(
    ({ message, pubkeys }) =>
      (
        window as Window & {
          __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (input: {
            channelName: string;
            content: string;
            mentionPubkeys: string[];
          }) => { id: string };
        }
      ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__?.({
        channelName: "general",
        content: message,
        mentionPubkeys: pubkeys,
      }),
    { message: content, pubkeys: mentionPubkeys },
  );
  if (!event) throw new Error("Mock message emitter is not installed");
  return event;
}

function channelComposer(page: Page) {
  return page.getByTestId("channel-composer-overlay");
}

function threadComposer(page: Page) {
  return page.getByTestId("thread-composer-overlay");
}

async function installAudienceFixtures(
  page: Page,
  options: { sendMessageDelayMs?: number } = {},
) {
  await installMockBridge(page, {
    ...options,
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
}

test("first thread open inherits explicit agent identities in protocol tag order", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem(
      "buzz.messages.keepMentionedAgentsPinned",
      "true",
    );
  });
  await installAudienceFixtures(page);
  await openGeneral(page);
  const root = await emitRootMessage(
    page,
    "@Vogue please pair with @Morgarita",
    // Protocol recipient order deliberately opposes display-name order.
    [AGENT_A, AGENT_B],
  );

  await openThread(page, root.id);

  const input = threadComposer(page).getByTestId("message-input");
  await expect(input).toHaveText("@Morgarita @Vogue ");
  await expect(input.locator(".agent-mention-highlight")).toHaveCount(2);
  await input.pressSequentially("inherited recipients");
  await input.press("Enter");
  await expectRecipients(page, "@Morgarita @Vogue inherited recipients", [
    AGENT_A,
    AGENT_B,
  ]);
  expect(
    await page.evaluate(() =>
      localStorage.getItem("buzz:persistent-agent-audiences:v2"),
    ),
  ).toBeNull();
});

test("thread inheritance stays off until the user enables automatic mentions", async ({
  page,
}) => {
  await installAudienceFixtures(page);
  await openGeneral(page);
  const root = await emitRootMessage(page, "@Vogue please reply", [AGENT_B]);
  await openThread(page, root.id);
  const composer = threadComposer(page);
  const input = composer.getByTestId("message-input");
  await expect(input).toBeEmpty();
  await input.fill("@");
  const preference = composer.getByTestId("mention-keep-agents-pinned-toggle");
  await expect(preference).not.toBeChecked();
  await preference.click();
  await expect(preference).toBeChecked();
  await input.press("Escape");
  await input.press("End");
  await input.press("Backspace");
  await expect(input).toHaveText("@Vogue ");
  await input.pressSequentially("opted-in reply");
  await expect(input).toHaveText("@Vogue opted-in reply");
  await input.press("Enter");
  await expectRecipients(page, "@Vogue opted-in reply", [AGENT_B]);
});

test("persistent agents transition atomically before Enter-send resolves", async ({
  page,
}) => {
  await seedAudience(page, [AGENT_A]);
  await installAudienceFixtures(page, { sendMessageDelayMs: 1_500 });
  await openThread(page);

  const composer = threadComposer(page);
  const input = composer.getByTestId("message-input");
  const send = composer.getByTestId("send-message");
  await input.fill("@Morgarita hello");
  await input.press("Enter");

  // The network send is still pending, so this is the first observable
  // post-submit editor state rather than the later success hydration pass.
  await expect(input).toHaveText("@Morgarita ", { timeout: 500 });
  await expect(input.locator(".agent-mention-highlight")).toHaveCount(1, {
    timeout: 500,
  });
  await expect(input).toBeFocused();
  await page.waitForTimeout(200);
  await expect(composer.getByTestId("mention-autocomplete")).toHaveCount(0);

  await expect(send).toBeEnabled();
  await expect
    .poll(() =>
      input.evaluate((element) => {
        const selection = window.getSelection();
        const viewDesc = (
          element as HTMLElement & {
            pmViewDesc?: {
              posFromDOM: (node: Node, offset: number, bias: number) => number;
              size: number;
            };
          }
        ).pmViewDesc;
        if (!selection?.anchorNode || !viewDesc) return null;
        const position = viewDesc.posFromDOM(
          selection.anchorNode,
          selection.anchorOffset,
          1,
        );
        // The root view desc includes the document's two boundary tokens,
        // while posFromDOM is relative to the editable root. Converting both
        // to ProseMirror coordinates proves selection.from/to === doc.content.size.
        return {
          empty: selection.isCollapsed,
          atDocumentEnd: position + 1 === viewDesc.size - 2,
        };
      }),
    )
    .toEqual({ empty: true, atDocumentEnd: true });
});

test("timeline agent send remains one-shot and returns to the placeholder", async ({
  page,
}) => {
  await seedAudience(page, [AGENT_A]);
  await installAudienceFixtures(page, { sendMessageDelayMs: 1_500 });
  await openGeneral(page);

  const composer = channelComposer(page);
  const input = composer.getByTestId("message-input");
  await input.fill("@Mor");
  await composer
    .getByTestId("mention-autocomplete")
    .getByText("Morgarita", { exact: true })
    .click();
  await input.pressSequentially("hello");
  await expect(input).toHaveText("@Morgarita hello");
  await input.press("Enter");

  await expect(input).toHaveText("", { timeout: 500 });
  await expect(input.locator("[data-placeholder]").first()).toHaveAttribute(
    "data-placeholder",
    "Message #general",
    { timeout: 500 },
  );
  await expect(input).toBeFocused();
  await expect
    .poll(() =>
      input.evaluate((element) => {
        const selection = window.getSelection();
        return {
          collapsed: selection?.isCollapsed ?? false,
          inside: Boolean(
            selection?.anchorNode && element.contains(selection.anchorNode),
          ),
        };
      }),
    )
    .toEqual({ collapsed: true, inside: true });
});

test("persistent agents restore through the native inline mention UI", async ({
  page,
}) => {
  await seedAudience(page, [AGENT_B, AGENT_A]);
  await installAudienceFixtures(page);
  await openThread(page);

  const composer = threadComposer(page);
  const input = composer.getByTestId("message-input");
  await expect(input).toHaveText("@Vogue @Morgarita ");
  await expect(page.getByText("Talking to", { exact: true })).toHaveCount(0);
  await expect(input.locator(".agent-mention-highlight")).toHaveCount(2);

  await input.fill("@Morgarita hello");

  await composer.getByTestId("send-message").click();
  await expect(input).toContainText("@Morgarita");
  await expect(input).not.toContainText("@Vogue");
  await expect(input.locator(".agent-mention-highlight")).toHaveCount(1);
  await expectRecipients(page, "@Morgarita hello", [AGENT_A]);
  // Explicit pins must not survive a new application session, even though the
  // user's opt-in preference does. This root has no inherited recipients.
  await page.reload();
  await expect(threadComposer(page).getByTestId("message-input")).toBeEmpty();
  expect(
    await page.evaluate(() =>
      localStorage.getItem("buzz:persistent-agent-audiences:v2"),
    ),
  ).toBeNull();
});

for (const theme of ["buzz", "buzz-dark"]) {
  test(`captures native persistent mentions in ${theme}`, async ({ page }) => {
    await seedAudience(page, [AGENT_A, AGENT_B], theme);
    await installAudienceFixtures(page);
    await openThread(page);
    const overlay = threadComposer(page);
    const composer = overlay.getByTestId("message-composer");
    await expect(overlay.getByTestId("message-input")).toHaveText(
      "@Morgarita @Vogue ",
    );
    await overlay.getByTestId("message-input").focus();
    await waitForAnimations(page);
    await composer.screenshot({
      path: `${SHOTS}/${theme}-native-mentions.png`,
    });
  });
}

test("native persistent mentions fit the narrow composer", async ({ page }) => {
  await page.setViewportSize({ width: 700, height: 760 });
  await seedAudience(page, [AGENT_A, AGENT_B]);
  await installAudienceFixtures(page);
  await openThread(page);
  const overlay = threadComposer(page);
  const composer = overlay.getByTestId("message-composer");
  await expect(overlay.getByTestId("message-input")).toContainText(
    "@Morgarita",
  );
  await waitForAnimations(page);
  await composer.screenshot({ path: `${SHOTS}/narrow-native-mentions.png` });
});
