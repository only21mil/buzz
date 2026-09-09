import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";

/**
 * Idle-foreground quiescence sample.
 *
 * The lag/fan reports (Buzz issue c45203d3...) describe a desktop that sits on
 * a channel with agents running and still keeps the CPU busy. This spec parks
 * the mocked app on `general` with two running managed agents, keeps the
 * window focused, and counts what the renderer does on its own over fixed
 * idle windows:
 *
 *   - Tauri `invoke` calls per command (every React Query poll and every
 *     backend read shows up here; the mock bridge answers from memory so the
 *     count is deterministic per window length),
 *   - `setInterval` and `setTimeout` callback fires bucketed by delay,
 *   - `requestAnimationFrame` fires,
 *   - PerformanceObserver `longtask` entries,
 *   - CDP `Performance.getMetrics` deltas (TaskDuration, ScriptDuration,
 *     LayoutDuration, RecalcStyleDuration), which is main-thread busy time.
 *
 * Deterministic gate: the invoke count for the busiest command must stay under
 * the documented budget for the window. Durations are diagnostic only; they
 * vary by host and are printed for before/after comparison on one machine.
 *
 * Relay traffic is not modelled by the mock bridge, so relay-driven
 * invalidation churn is out of scope here.
 *
 * Run it:
 *   pnpm build:e2e && pnpm exec playwright test --config=playwright.perf.config.ts \
 *     idle-quiescence.perf.ts
 *
 * Env: IDLE_WINDOW_MS (default 60000), IDLE_TRIALS (default 2),
 * IDLE_SETTLE_MS (default 15000).
 */

const WINDOW_MS = Number(process.env.IDLE_WINDOW_MS ?? 60_000);
const TRIALS = Number(process.env.IDLE_TRIALS ?? 2);
const SETTLE_MS = Number(process.env.IDLE_SETTLE_MS ?? 15_000);
/** Budget for the busiest single command per 60 s idle window. */
const MAX_INVOKES_PER_COMMAND_PER_MINUTE = 20;

const RUNNING_AGENT_A = "a1".repeat(32);
const RUNNING_AGENT_B = "b2".repeat(32);

type Counters = {
  invokes: Record<string, number>;
  intervalFires: Record<string, number>;
  timeoutFires: Record<string, number>;
  rafFires: number;
  longtasks: number[];
};

type Snapshot = Counters & {
  hasFocus: boolean;
  visibility: string;
  metrics: Record<string, number>;
};

declare global {
  interface Window {
    __IDLE_COUNTERS__?: Counters;
  }
}

function diffRecord(
  before: Record<string, number>,
  after: Record<string, number>,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(after)) {
    const delta = value - (before[key] ?? 0);
    if (delta !== 0) out[key] = delta;
  }
  return out;
}

function sortedDesc(record: Record<string, number>): Array<[string, number]> {
  return Object.entries(record).sort((a, b) => b[1] - a[1]);
}

test("idle foreground window stays within the invoke budget", async ({
  page,
}) => {
  test.setTimeout(SETTLE_MS + TRIALS * WINDOW_MS + 120_000);
  await installMockBridge(page, {
    managedAgents: [
      {
        pubkey: RUNNING_AGENT_A,
        name: "Idle Runner A",
        status: "running",
        channelNames: ["general"],
      },
      {
        pubkey: RUNNING_AGENT_B,
        name: "Idle Runner B",
        status: "running",
        channelNames: ["general"],
      },
    ],
  });

  // Timer instrumentation must exist before app code schedules anything, so
  // it is an init script and the page is (re)loaded after arming it.
  await page.addInitScript(() => {
    const counters: Counters = {
      invokes: {},
      intervalFires: {},
      timeoutFires: {},
      rafFires: 0,
      longtasks: [],
    };
    window.__IDLE_COUNTERS__ = counters;
    const bump = (bucket: Record<string, number>, key: string) => {
      bucket[key] = (bucket[key] ?? 0) + 1;
    };
    const originalSetInterval = window.setInterval.bind(window);
    window.setInterval = ((
      handler: TimerHandler,
      delay?: number,
      ...args: unknown[]
    ) => {
      const key = String(delay ?? 0);
      const wrapped =
        typeof handler === "function"
          ? (...callArgs: unknown[]) => {
              bump(counters.intervalFires, key);
              return handler(...callArgs);
            }
          : handler;
      return originalSetInterval(wrapped, delay, ...args);
    }) as typeof window.setInterval;
    const originalSetTimeout = window.setTimeout.bind(window);
    window.setTimeout = ((
      handler: TimerHandler,
      delay?: number,
      ...args: unknown[]
    ) => {
      const key = String(delay ?? 0);
      const wrapped =
        typeof handler === "function"
          ? (...callArgs: unknown[]) => {
              bump(counters.timeoutFires, key);
              return handler(...callArgs);
            }
          : handler;
      return originalSetTimeout(wrapped, delay, ...args);
    }) as typeof window.setTimeout;
    const originalRaf = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = (callback: FrameRequestCallback) =>
      originalRaf((time) => {
        counters.rafFires += 1;
        callback(time);
      });
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        counters.longtasks.push(entry.duration);
      }
    }).observe({ type: "longtask", buffered: true });
  });
  await page.goto("/");
  await page.waitForFunction(
    () =>
      typeof window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__ === "function" &&
      window.__IDLE_COUNTERS__ !== undefined,
  );

  // Count invokes through the mocked Tauri IPC surface installed by the bridge.
  await page.evaluate(() => {
    const internals = (
      window as unknown as {
        __TAURI_INTERNALS__: {
          invoke: (command: string, ...rest: unknown[]) => Promise<unknown>;
        };
      }
    ).__TAURI_INTERNALS__;
    const original = internals.invoke.bind(internals);
    internals.invoke = (command: string, ...rest: unknown[]) => {
      const counters = window.__IDLE_COUNTERS__;
      if (counters) {
        counters.invokes[command] = (counters.invokes[command] ?? 0) + 1;
      }
      return original(command, ...rest);
    };
  });

  await page.getByTestId("channel-general").click();
  await expect(page.getByTestId("chat-title")).toHaveText("general");
  await expect(
    page.getByTestId("message-timeline").locator("[data-message-id]").first(),
  ).toBeVisible();

  const client = await page.context().newCDPSession(page);
  await client.send("Performance.enable");
  await client.send("Emulation.setFocusEmulationEnabled", { enabled: true });

  const snapshot = async (): Promise<Snapshot> => {
    const { metrics } = (await client.send("Performance.getMetrics")) as {
      metrics: Array<{ name: string; value: number }>;
    };
    const page_ = await page.evaluate(() => {
      const counters = window.__IDLE_COUNTERS__ as Counters;
      return {
        invokes: { ...counters.invokes },
        intervalFires: { ...counters.intervalFires },
        timeoutFires: { ...counters.timeoutFires },
        rafFires: counters.rafFires,
        longtasks: [...counters.longtasks],
        hasFocus: document.hasFocus(),
        visibility: document.visibilityState,
      };
    });
    return {
      ...page_,
      metrics: Object.fromEntries(metrics.map((m) => [m.name, m.value])),
    };
  };

  await page.waitForTimeout(SETTLE_MS);

  const trials: Array<Record<string, unknown>> = [];
  for (let trial = 1; trial <= TRIALS; trial += 1) {
    const before = await snapshot();
    await page.waitForTimeout(WINDOW_MS);
    const after = await snapshot();
    const invokes = diffRecord(before.invokes, after.invokes);
    const longtasks = after.longtasks.slice(before.longtasks.length);
    const durations = Object.fromEntries(
      [
        "TaskDuration",
        "ScriptDuration",
        "LayoutDuration",
        "RecalcStyleDuration",
      ].map((name) => [
        name,
        Number(
          ((after.metrics[name] ?? 0) - (before.metrics[name] ?? 0)).toFixed(3),
        ),
      ]),
    );
    const result = {
      trial,
      windowMs: WINDOW_MS,
      hasFocus: after.hasFocus,
      visibility: after.visibility,
      invokeTotal: Object.values(invokes).reduce((sum, n) => sum + n, 0),
      invokes: Object.fromEntries(sortedDesc(invokes)),
      intervalFires: Object.fromEntries(
        sortedDesc(diffRecord(before.intervalFires, after.intervalFires)),
      ),
      timeoutFires: Object.fromEntries(
        sortedDesc(diffRecord(before.timeoutFires, after.timeoutFires)),
      ),
      rafFires: after.rafFires - before.rafFires,
      longtasks: {
        count: longtasks.length,
        totalMs: Number(longtasks.reduce((sum, d) => sum + d, 0).toFixed(1)),
      },
      durationsSeconds: durations,
      jsHeapUsedMb: Number(
        ((after.metrics.JSHeapUsedSize ?? 0) / 1_048_576).toFixed(1),
      ),
      domNodes: after.metrics.Nodes,
    };
    trials.push(result);
    console.log(`IDLE_TRIAL ${JSON.stringify(result)}`);
  }

  for (const trial of trials) {
    expect(trial.hasFocus, "focus emulation must hold").toBe(true);
    const busiest = sortedDesc(trial.invokes as Record<string, number>)[0];
    if (busiest) {
      const perMinute = (busiest[1] * 60_000) / WINDOW_MS;
      expect(
        perMinute,
        `busiest command ${busiest[0]} fired ${busiest[1]} times in ${WINDOW_MS} ms`,
      ).toBeLessThanOrEqual(MAX_INVOKES_PER_COMMAND_PER_MINUTE);
    }
  }
});
