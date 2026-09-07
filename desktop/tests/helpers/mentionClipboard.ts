import { expect, type Locator, type Page } from "@playwright/test";

export const SELECTED =
  "bb22a5299220cad76ffd46190ccbeede8ab5dc260faa28b6e5a2cb31b9aff260";
export const NAMESAKE =
  "5e2c9b710f4a836d2b5c0e7d8a1f4c63b9d0725e1a8c3f6407d9b2e5c8a1f403";
export const LABEL = "John Smith";
export type Flavors = {
  html: string;
  text: string;
  defaultPrevented?: boolean;
};

// A DOM clipboard event exercises the production handlers without touching the
// host clipboard. The returned text/plain is what an external text app receives.
export async function copyBody(
  body: Locator,
  partial = false,
): Promise<Flavors> {
  return body.evaluate((element, partial) => {
    const selection = window.getSelection();
    if (!selection) throw new Error("Selection API missing");
    const range = document.createRange();
    if (partial) {
      const chip = element.querySelector("[data-mention-pubkey]");
      if (!chip) throw new Error("Mention chip missing");
      const text = document
        .createTreeWalker(chip, NodeFilter.SHOW_TEXT)
        .nextNode();
      if (!text?.textContent?.startsWith("John"))
        throw new Error("Unexpected chip text");
      range.setStart(text, 0);
      range.setEnd(text, 4);
    } else range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
    const clipboardData = new DataTransfer();
    const event = new ClipboardEvent("copy", {
      bubbles: true,
      cancelable: true,
      clipboardData,
    });
    element.dispatchEvent(event);
    // Unhandled partial selections use the browser's default plain selection.
    return {
      html: clipboardData.getData("text/html"),
      text: event.defaultPrevented
        ? clipboardData.getData("text/plain")
        : selection.toString(),
      defaultPrevented: event.defaultPrevented,
    };
  }, partial);
}

export async function paste(input: Locator, flavors: Flavors) {
  await input.focus();
  await input.evaluate((element, flavors) => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/plain", flavors.text);
    clipboardData.setData("text/html", flavors.html);
    element.dispatchEvent(
      new ClipboardEvent("paste", {
        bubbles: true,
        cancelable: true,
        clipboardData,
      }),
    );
  }, flavors);
}

export function expectPrivateIdentity(flavors: Flavors) {
  expect(flavors.defaultPrevented).toBe(true);
  expect(flavors.text).toContain(`@${LABEL}`);
  expect(flavors.text).not.toMatch(/[0-9a-f]{64}/i);
  expect(flavors.html).toContain(`data-mention-pubkey="${SELECTED}"`);
  expect(flavors.html).not.toContain(NAMESAKE);
}

export async function sentEvents(page: Page, content: string) {
  return page.evaluate((content) => {
    const events: Array<{ content: string; tags: string[][] }> = [];
    for (const entry of window.__BUZZ_E2E_COMMAND_LOG__ ?? []) {
      if (entry.command === "send_channel_message") {
        const payload = entry.payload as {
          content?: string;
          mentionPubkeys?: string[];
          channelId: string;
        };
        if (payload.content === content)
          events.push({
            content,
            tags: [
              ["h", payload.channelId],
              ...(payload.mentionPubkeys ?? []).map((key) => ["p", key]),
            ],
          });
        continue;
      }
      if (entry.command !== "plugin:websocket|send") continue;
      const data = (entry.payload as { message?: { data?: string } })?.message
        ?.data;
      if (!data) continue;
      const frame = JSON.parse(data) as [
        string,
        { content: string; tags: string[][] },
      ];
      if (frame[0] === "EVENT" && frame[1].content === content)
        events.push(frame[1]);
    }
    return events;
  }, content);
}
