import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";

/**
 * Cold-channel-switch longtask harness.
 *
 * This spec samples the main-thread blocking cost of the FIRST switch into a
 * deep channel. The mock store contains 600 messages, but the channel-window
 * query loads only the newest 50. The acceptance gate checks that channel depth
 * cannot expand the mounted DOM beyond that loaded window and verifies that
 * switching away releases those rows. A focused unit test separately proves a
 * deeply cached timeline contributes only a bounded 50-item tail to Virtua.
 *
 * WHY LONGTASKS, NOT LAYOUT METRICS: the felt jank is the main thread being
 * blocked past the ~50ms frame-budget wall during the mount. PerformanceObserver
 * `longtask` entries are exactly the >50ms main-thread tasks the browser itself
 * flags. We report the
 * LONGEST single longtask (the worst freeze) and the TOTAL longtask time across
 * the switch window because many medium tasks can hide the same total cost a
 * single long one would show.
 *
 * WHY LONGTASKS ARE DIAGNOSTIC ONLY: 4x CPU throttle makes changes easy to
 * compare on the same machine, but absolute longtask duration varies too much
 * across hosted runners to be a release gate. The deterministic gate is the
 * mounted-row bound. Longtask samples remain in the log for before/after runs.
 *
 * COLD here means a fresh timeline mount, not an uncached data query. Each run
 * visits `general` first so the deep-history virtualizer and row tree unmount,
 * then measures their next mount. Later runs may reuse query and markdown data,
 * which keeps the gate focused on mounting the virtualized UI.
 *
 * SCOPE LIMIT: this measures Chromium main-thread longtasks under throttle. It
 * does NOT measure the WKWebView compositor feel on the shipped Tauri shell.
 * That needs a separate real-wheel pass.
 *
 * Run it:
 *   pnpm build:e2e && pnpm exec playwright test --config=playwright.perf.config.ts \
 *     cold-switch-longtask.perf.ts
 */

const RUNS = 5;
const THROTTLE_RATE = 4;
const SEEDED_DEEP_HISTORY_ROWS = 600;
const LOADED_CHANNEL_WINDOW_ROWS = 50;

type RunResult = { longest: number; total: number; count: number };

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

test("cold switch mounts only the loaded deep-history window", async ({
  page,
}) => {
  test.setTimeout(120_000);
  await installMockBridge(page, {
    deepHistoryMessageCount: SEEDED_DEEP_HISTORY_ROWS,
  });
  await page.goto("/");
  await page.waitForFunction(
    () => typeof window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__ === "function",
  );

  // Arm a longtask observer that buffers into a window array we can read and
  // reset per run. `buffered: true` catches tasks queued before the read.
  await page.addInitScript(() => {
    const store = window as unknown as { __LONGTASKS__?: number[] };
    store.__LONGTASKS__ = [];
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        store.__LONGTASKS__?.push(entry.duration);
      }
    }).observe({ type: "longtask", buffered: true });
  });
  // addInitScript only applies on the next navigation, so reload to arm it.
  await page.reload();
  await page.waitForFunction(
    () =>
      typeof window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__ === "function" &&
      Array.isArray(
        (window as unknown as { __LONGTASKS__?: number[] }).__LONGTASKS__,
      ),
  );

  const client = await page.context().newCDPSession(page);
  await client.send("Emulation.setCPUThrottlingRate", { rate: THROTTLE_RATE });

  const timeline = page.getByTestId("message-timeline");
  const mountedRows = timeline.locator("[data-message-id]");
  const deepHistoryRows = timeline.locator(
    '[data-message-id^="mock-deep-history-"]',
  );
  const results: RunResult[] = [];

  for (let run = 0; run < RUNS; run += 1) {
    // Warm `general` so the deep-history switch that follows is a cold first
    // entry, not a warm re-render of cached state.
    await page.getByTestId("channel-general").click();
    await expect(page.getByTestId("chat-title")).toHaveText("general");
    await expect(mountedRows.first()).toBeVisible();
    await expect(deepHistoryRows).toHaveCount(0);

    // Clear the buffer immediately before the cold switch so only the switch's
    // longtasks are attributed to this run.
    await page.evaluate(() => {
      (window as unknown as { __LONGTASKS__: number[] }).__LONGTASKS__ = [];
    });

    // The backing store has 600 rows, while the initial channel-window request
    // loads 50. Channel depth must not expand the mounted DOM beyond that
    // production query bound.
    await page.getByTestId("channel-deep-history").click();
    await expect(page.getByTestId("chat-title")).toHaveText("deep-history");
    await expect(deepHistoryRows.first()).toBeVisible();
    await expect(deepHistoryRows).toHaveCount(LOADED_CHANNEL_WINDOW_ROWS);
    await expect(mountedRows).toHaveCount(LOADED_CHANNEL_WINDOW_ROWS);
    // Let any post-mount longtasks (anchor settle, sticky handoff) flush before
    // reading — they are part of the switch cost.
    await page.waitForTimeout(300);

    const tasks = await page.evaluate(
      () =>
        (window as unknown as { __LONGTASKS__: number[] }).__LONGTASKS__ ?? [],
    );
    results.push({
      longest: tasks.length ? Math.max(...tasks) : 0,
      total: tasks.reduce((sum, d) => sum + d, 0),
      count: tasks.length,
    });
  }

  await client.send("Emulation.setCPUThrottlingRate", { rate: 1 });

  const longests = results.map((r) => r.longest);
  const totals = results.map((r) => r.total);
  const medianLongest = median(longests);
  const minLongest = Math.min(...longests);
  const maxLongest = Math.max(...longests);
  const spread = maxLongest - minLongest;
  const medianTotal = median(totals);

  /* eslint-disable no-console */
  console.log("\n=== COLD-SWITCH LONGTASK SAMPLE (deep-history) ===");
  console.log(`CPU throttle:                  ${THROTTLE_RATE}x`);
  console.log(`runs:                          ${RUNS}`);
  console.log(`fixture rows:                  ${SEEDED_DEEP_HISTORY_ROWS}`);
  console.log(`mounted rows per entry:        ${LOADED_CHANNEL_WINDOW_ROWS}`);
  console.log(
    `per-run longest-longtask (ms): [${longests.map((v) => v.toFixed(1)).join(", ")}]`,
  );
  console.log(
    `per-run total-longtask (ms):   [${totals.map((v) => v.toFixed(1)).join(", ")}]`,
  );
  console.log(
    `per-run longtask count:        [${results.map((r) => r.count).join(", ")}]`,
  );
  console.log(`MEDIAN longest-longtask:       ${medianLongest.toFixed(1)}ms`);
  console.log(
    `  spread (max - min):          ${spread.toFixed(1)}ms (min ${minLongest.toFixed(1)}, max ${maxLongest.toFixed(1)})`,
  );
  console.log(`MEDIAN total-longtask-in-window: ${medianTotal.toFixed(1)}ms`);
  console.log("(>50ms single task is a dropped-frame freeze the user feels)");
  console.log(
    "=================================================================\n",
  );
  /* eslint-enable no-console */

  // Timing is intentionally not asserted. Hosted-runner CPU contention can
  // move these samples by hundreds of milliseconds. The per-run DOM checks
  // above gate the behavior that keeps cold mount work bounded.
});
