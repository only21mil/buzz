import { expect, test, type Page } from "@playwright/test";
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

// A pasted mention whose pubkey is not a member is verified against the relay
// and then blocks the send: the draft stays put and no event leaves the
// composer until the author picks a real recipient or drops the sigil.
test("foreign clipboard identity is verified and blocks the send", async ({
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
  await expect(
    page.getByText("That @mention is not linked to a member.", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(input).toHaveText(content);
  expect(await sentEvents(page, content)).toEqual([]);
});

// ── Restored upstream regression coverage ─────────────────────────────
// Ports from block/buzz@4cd82f51 desktop/tests/e2e/mention-recipients.spec.ts
// (audit D3), verbatim. The ambiguous-draft cases above already cover the two
// ambiguous typed-name tests. Not ported: duplicate-label reopen, longer-member
// edit (fork edit_message payloads carry mentionPubkeys, not mentionTags),
// narrow-composer chip-wrap styling, historical/absent-roster thread repair, and
// qualified/abbreviated copy-paste — the fork renders hex qualifiers, not npub
// (Scout (bb22a529…f260)), and blocks unresolvable sends instead of sending
// unbound. Those are fork contract differences, not missing coverage.

const FIRST = TEST_IDENTITIES.alice.pubkey;
const SECOND = TEST_IDENTITIES.bob.pubkey;
const AMBIGUOUS =
  "The mention @Scout is ambiguous. Choose a recipient from the mention picker.";

async function install(page: Page, channel = "general", agents = false) {
  await installMockBridge(page, {
    managedAgents:
      channel === "watercooler"
        ? ["a".repeat(64), "b".repeat(64)].map((pubkey) => ({
            pubkey,
            name: "Scout",
            status: "running",
            channelNames: ["watercooler"],
          }))
        : agents
          ? [FIRST, SECOND].map((pubkey) => ({
              pubkey,
              name: "Scout",
              status: "running",
              channelNames: [channel],
            }))
          : [],
    searchProfiles: [FIRST, SECOND].map((pubkey) => ({
      pubkey,
      displayName: "Scout",
      isAgent: agents,
    })),
  });
  await page.goto("/");
  await page.getByTestId(`channel-${channel}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(channel);
  if (channel === "watercooler")
    await page.getByRole("button", { name: "Start a new post..." }).click();
}

async function recipients(page: Page, content: string) {
  return page.evaluate((content) => {
    const signed = (window.__BUZZ_E2E_SIGNED_EVENTS__ ?? [])
      .filter((event) => event.content === content)
      .map((event) =>
        event.tags.filter((tag) => tag[0] === "p").map((tag) => tag[1]),
      );
    if (signed.length > 0) return signed;
    // Thread sends use native IPC in the mock bridge, not signed capture.
    return (window.__BUZZ_E2E_COMMAND_LOG__ ?? [])
      .filter((call) => call.command === "send_channel_message")
      .map(
        (call) =>
          call.payload as { content?: string; mentionPubkeys?: string[] },
      )
      .filter((payload) => payload.content === content)
      .map((payload) => payload.mentionPubkeys ?? []);
  }, content);
}

test("two selected same-name members send both exact identities", async ({
  page,
}) => {
  await install(page);
  const input = page.getByTestId("message-input");
  await input.fill("@Scout");
  await page.getByTestId(`mention-suggestion-${FIRST}`).click();
  await page.keyboard.type("and @Scout");
  await page.getByTestId(`mention-suggestion-${SECOND}`).click();
  await page.keyboard.type("hello");
  const content = `@Scout and @Scout (${SECOND}) hello`;
  await expect(input).toHaveText(content);
  await page.getByTestId("send-message").click();
  await expect.poll(() => recipients(page, content)).toEqual([[FIRST, SECOND]]);
});

test("ambiguous added mention blocks editing before clearing the draft", async ({
  page,
}) => {
  await install(page);
  const input = page.getByTestId("message-input");
  await input.fill("original message for ambiguity edit");
  await input.press("Enter");
  const row = page
    .getByTestId("message-timeline")
    .getByTestId("message-row")
    .last();
  await expect(row).toContainText("original message for ambiguity edit");
  await row.hover();
  await row.getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: "Edit message" }).click();
  await expect(page.getByTestId("edit-target")).toBeVisible();
  await expect(input).toHaveText("original message for ambiguity edit");
  await input.fill("edited @Scout hello");
  await page.getByTestId("send-message").click();
  await expect(page.getByText(AMBIGUOUS, { exact: false })).toBeVisible();
  await expect(input).toHaveText("edited @Scout hello");
  await expect(page.getByTestId("edit-target")).toBeVisible();
  expect(await recipients(page, "edited @Scout hello")).toEqual([]);
});

test("same-name teammates unfurl into distinct exact-key recipients", async ({
  page,
}) => {
  const pubkeys = ["a".repeat(64), "b".repeat(64)];
  await installMockBridge(page, {
    personas: pubkeys.map((_, i) => ({
      id: `scout-${i}`,
      displayName: "Scout",
      systemPrompt: "Help.",
    })),
    managedAgents: pubkeys.map((pubkey, i) => ({
      pubkey,
      personaId: `scout-${i}`,
      name: "Scout",
      status: "running",
      channelNames: ["general"],
    })),
    teams: [
      { id: "scouts", name: "Scouts", personaIds: ["scout-0", "scout-1"] },
    ],
  });
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  const input = page.getByTestId("message-input");
  await input.fill("@Scouts");
  await page.getByTestId("mention-suggestion-team-scouts").click();
  await page.keyboard.type("hello");
  const content = `Scouts(@Scout @Scout (${pubkeys[1]})) hello`;
  await expect(input).toHaveText(content);
  await page.getByTestId("send-message").click();
  await expect.poll(() => recipients(page, content)).toEqual([pubkeys]);
});

for (const removal of ["delete", "audience-remove", "audience-unpin"]) {
  test(`same-name automatic recipients: ${removal} A preserves exact remaining recipients`, async ({
    page,
  }) => {
    const [a, b] = ["a".repeat(64), "b".repeat(64)];
    await page.addInitScript(() =>
      localStorage.setItem("buzz.messages.keepMentionedAgentsPinned", "true"),
    );
    await installMockBridge(page, {
      managedAgents: [a, b].map((pubkey) => ({
        pubkey,
        name: "Scout",
        status: "running",
        channelNames: ["general"],
      })),
    });
    // Main retains automatic audiences only in threads, never root posts.
    await page.goto(
      "/#/channels/9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50?messageId=mock-general-welcome&thread=mock-general-welcome",
    );
    const composer = page.getByTestId("thread-composer-overlay");
    await expect(composer).toBeVisible();
    const input = composer.getByTestId("message-input");
    await input.fill("@Scout");
    await composer.getByTestId(`mention-suggestion-${a}`).click();
    await page.keyboard.type("@Scout");
    await composer.getByTestId(`mention-suggestion-${b}`).click();
    await page.keyboard.type("hello");
    await expect(input).toHaveText(`@Scout @Scout (${b}) hello`);
    await expect(
      composer.getByTestId(`composer-address-lock-${a}`),
    ).toBeVisible();
    await expect(
      composer.getByTestId(`composer-address-lock-${b}`),
    ).toBeVisible();
    if (removal === "delete") {
      // Select the literal prefix through the browser DOM, then use the real
      // editor delete path. Do not replace draft state or mock the composer.
      await input.evaluate((element) => {
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
        const range = document.createRange();
        let remaining = "@Scout ".length;
        let node = walker.nextNode();
        if (!node) throw new Error("Missing editor text");
        range.setStart(node, 0);
        while (node) {
          const length = node.textContent?.length ?? 0;
          if (remaining <= length) {
            range.setEnd(node, remaining);
            break;
          }
          remaining -= length;
          node = walker.nextNode();
        }
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
        element.dispatchEvent(new Event("focus"));
      });
      await input.press("Backspace");
    } else if (removal === "audience-remove") {
      await composer.getByTestId(`composer-address-lock-remove-${a}`).click();
    } else {
      await composer.locator("[data-mention-picker-trigger]").click();
      await composer.getByTestId(`mention-always-address-${a}`).click();
      await input.press("Escape");
    }
    // The tray unpins without deleting an authored mention; removal deletes it.
    const content = `${removal === "audience-unpin" ? "@Scout " : ""}@Scout (${b}) hello`;
    await expect(input).toHaveText(content);
    await expect(
      composer.getByTestId(`composer-address-lock-${a}`),
    ).toHaveCount(0);
    await expect(
      composer.getByTestId(`composer-address-lock-${b}`),
    ).toBeVisible();
    await composer.getByTestId("send-message").click();
    await expect
      .poll(() => recipients(page, content))
      .toEqual([removal === "audience-unpin" ? [a, b] : [b]]);
  });
}

test("edit focus transfers after menu exit; Escape still restores the trigger", async ({
  page,
}) => {
  await install(page);
  const input = page.getByTestId("message-input");
  await input.fill("menu focus handoff");
  await input.press("Enter");
  const row = page
    .getByTestId("message-timeline")
    .getByTestId("message-row")
    .last();
  await expect(row).toContainText("menu focus handoff");
  await row.hover();
  const trigger = row.getByRole("button", { name: "More actions" });
  await trigger.click();
  await page.getByRole("menu").press("Escape");
  await expect(trigger).toBeFocused();

  // Hold the real Radix exit lifecycle, rather than sleeping until the race
  // happens to pass. No composer state or focus handlers are mocked.
  await page.addStyleTag({
    content: `@keyframes held-menu-exit { from { opacity: 1; } to { opacity: 0; } }
      [data-radix-menu-content][data-state="closed"] {
        animation: held-menu-exit 1s linear paused !important;
      }`,
  });
  await trigger.click();
  await page.getByRole("menuitem", { name: "Edit message" }).click();
  const closingMenu = page.locator(
    '[data-radix-menu-content][data-state="closed"]',
  );
  await expect(closingMenu).toHaveCount(1);
  await expect(page.getByTestId("edit-target")).toHaveCount(0);
  await expect(input).toHaveText("");
  // Leave the closing menu while its exit is held. Radix can still process
  // pointer-leave here; it must not own focus after the edit handoff.
  await input.hover();
  await expect(page.getByTestId("edit-target")).toHaveCount(0);
  await closingMenu.evaluate((element) => {
    const animations = element.getAnimations();
    if (!animations.length)
      throw new Error("Expected held menu exit animation");
    for (const animation of animations) animation.finish();
  });
  await expect(closingMenu).toHaveCount(0);
  await expect(input).toHaveText("menu focus handoff");
  await expect(input).toBeFocused();
  await page.keyboard.type(" edited");
  await expect(input).toHaveText("menu focus handoff edited");
});

for (const selection of ["picker", "automatic"]) {
  test(`qualified ${selection} selection retires a pending paste of the original label`, async ({
    page,
  }) => {
    const [a, b, pasted] = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
    await page.addInitScript(() =>
      localStorage.setItem("buzz.messages.keepMentionedAgentsPinned", "true"),
    );
    await installMockBridge(page, {
      managedAgents: [a, b].map((pubkey) => ({
        pubkey,
        name: "Scout",
        status: "running",
        channelNames: ["general"],
      })),
      searchProfiles: [{ pubkey: pasted, displayName: "Scout" }],
    });
    await page.goto(
      "/#/channels/9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50?messageId=mock-general-welcome&thread=mock-general-welcome",
    );
    const composer = page.getByTestId("thread-composer-overlay");
    const input = composer.getByTestId("message-input");
    await input.fill("@Scout");
    await composer.getByTestId(`mention-suggestion-${a}`).click();
    await page.evaluate(() => window.__BUZZ_E2E_HOLD_USERS_BATCH__?.(true));
    await input.evaluate((element, pubkey) => {
      const clipboardData = new DataTransfer();
      clipboardData.setData("text/plain", "@Scout pasted ");
      clipboardData.setData(
        "text/html",
        `<span data-buzz-copy="markdown"><span data-mention="" data-mention-label="Scout" data-mention-pubkey="${pubkey}">@Scout</span> pasted </span>`,
      );
      element.dispatchEvent(
        new ClipboardEvent("paste", {
          bubbles: true,
          cancelable: true,
          clipboardData,
        }),
      );
    }, pasted);
    await expect(input).toHaveText("@Scout @Scout pasted ");
    await expect
      .poll(() =>
        page.evaluate(() => window.__BUZZ_E2E_USERS_BATCH_PENDING__?.() ?? 0),
      )
      .toBeGreaterThan(0);
    if (selection === "picker") {
      await page.keyboard.type("@Scout");
      await composer.getByTestId(`mention-suggestion-${b}`).click();
    } else {
      await composer.locator("[data-mention-picker-trigger]").click();
      await composer.getByTestId(`mention-always-address-${b}`).click();
      await input.press("Escape");
    }
    await expect(input).toContainText(`@Scout (${b})`);
    const content = (await input.innerText()).trim();
    expect(
      await page.evaluate(
        () => window.__BUZZ_E2E_HOLD_USERS_BATCH__?.(false) ?? 0,
      ),
    ).toBeGreaterThan(0);
    await composer.getByTestId("send-message").click();
    await expect(input).toHaveText(`@Scout @Scout (${b}) `);
    await expect.poll(() => recipients(page, content)).toEqual([[a, b]]);
  });
}
