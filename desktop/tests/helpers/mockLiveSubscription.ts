import { expect, type Page } from "@playwright/test";

/**
 * Wait until the mock bridge reports a live subscription for `channelName`
 * (optionally narrowed to one event `kind`). Specs call this after opening a
 * channel so that emitted mock messages have a subscriber to reach.
 */
export async function waitForMockLiveSubscription(
  page: Page,
  channelName: string,
  kind?: number,
): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(
        ({ channelName: name, kind: eventKind }) =>
          (
            window as Window & {
              __BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?: (input: {
                channelName: string;
                kind?: number;
              }) => boolean;
            }
          ).__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
            channelName: name,
            kind: eventKind,
          }) ?? false,
        { channelName, kind },
      ),
    )
    .toBe(true);
}
