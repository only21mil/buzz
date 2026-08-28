import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";

const GENERAL_CHANNEL_ID = "9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50";
const AGENTS_CHANNEL_ID = "94a444a4-c0a3-5966-ab05-530c6ddc2301";

const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 390, height: 844 },
  { name: "pixel-fold-unfolded", width: 852, height: 883 },
] as const;

test("hosted shell is secure, installable, responsive, and keyboard reachable", async ({
  page,
}) => {
  await page.goto("/app/");

  const csp = page.locator('meta[http-equiv="Content-Security-Policy"]');
  await expect(csp).toHaveAttribute("content", /script-src 'self'/);
  await expect(csp).toHaveAttribute("content", /object-src 'none'/);
  await expect(csp).toHaveAttribute("content", /connect-src 'self'(?:;|$)/);
  await expect(csp).not.toHaveAttribute(
    "content",
    /connect-src[^;]*(?:ws:|wss:)/,
  );
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute(
    "href",
    "/app/manifest.webmanifest",
  );
  await expect(page.locator("#root")).not.toBeEmpty();

  for (const viewport of VIEWPORTS) {
    await test.step(viewport.name, async () => {
      await page.setViewportSize(viewport);
      await expect
        .poll(() =>
          page.evaluate(
            () => document.documentElement.scrollWidth - window.innerWidth,
          ),
        )
        .toBeLessThanOrEqual(1);
    });
  }

  await page.keyboard.press("Tab");
  const focused = page.locator(":focus-visible");
  await expect(focused).toBeVisible();
  await expect(focused).not.toHaveAttribute("aria-hidden", "true");
});

test("hosted shell has no automated WCAG A or AA violations", async ({
  page,
}) => {
  await page.goto("/app/");
  await expect(page.locator("#root")).not.toBeEmpty();
  await expect(page.getByTestId("boot-splash-overlay")).toHaveCount(0);

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  expect(results.violations).toEqual([]);
});

test("skip link focuses the real shell without changing hash history", async ({
  page,
}) => {
  await page.goto(
    `http://127.0.0.1:4175/app/?e2e=mock#/channels/${GENERAL_CHANNEL_ID}`,
  );
  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  await expect(skipLink).toBeAttached();
  const initialHash = await page.evaluate(() => window.location.hash);
  await page.evaluate((channelId) => {
    window.location.hash = `/channels/${channelId}`;
  }, AGENTS_CHANNEL_ID);
  await expect
    .poll(() => page.evaluate(() => window.location.hash))
    .toBe(`#/channels/${AGENTS_CHANNEL_ID}`);

  const routeBeforeSkip = page.url();
  await skipLink.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  expect(page.url()).toBe(routeBeforeSkip);

  await page.goBack();
  await expect
    .poll(() => page.evaluate(() => window.location.hash))
    .toBe(initialHash);
});

test("pull request checks isolate partial failures, drift, and discovery truncation", async ({
  page,
}) => {
  const owner = "deadbeef".repeat(8);
  const repoAddress = `30617:${owner}:buzz`;
  const pullRequestId = "c".repeat(64);
  const runIds = Array.from(
    { length: 22 },
    (_, index) =>
      `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  );
  const runId = runIds.at(-1) as string;
  const now = Math.floor(Date.now() / 1_000);
  const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 97);
  const actor = getPublicKey(secret);
  const validRequests = runIds.map((candidateRunId, index) =>
    finalizeEvent(
      {
        created_at: now + index,
        kind: 46_100,
        tags: [
          ["h", GENERAL_CHANNEL_ID],
          ["a", repoAddress],
          ["run", candidateRunId],
          ["workflow", "ci"],
          ["c", "1".repeat(40)],
          ["attempt", "1"],
        ],
        content: JSON.stringify({
          schema_version: 1,
          request_type: "run",
          target_repo_a: repoAddress,
          pr_root_event_id: pullRequestId,
          source_clone_url: "https://relay.example/git/repo",
          immutable_source_ref: "refs/nostr/source",
          tip_oid: "1".repeat(40),
          source_branch: "feature/browser-ci",
          base_ref: "refs/heads/main",
          base_oid: "2".repeat(40),
          workflow_id: "ci",
          workflow_digest: "3".repeat(64),
          job_ids: ["test"],
          run_id: candidateRunId,
          attempt: 1,
          trigger_event_id: pullRequestId,
          actor,
          timeout_seconds: 300,
          idempotency_key: `browser-ci-request-${index}`,
          issued_at: now,
          expires_at: now + 300,
        }),
      },
      secret,
    ),
  );
  const request = validRequests[0];
  const driftedRequest = {
    ...request,
    id: "f".repeat(64),
    content: JSON.stringify({
      ...JSON.parse(request.content),
      unexpected: "blocked",
    }),
  };
  await page.addInitScript(
    ({
      ownerPubkey,
      repo,
      prId,
      channelId,
      createdAt,
      validRequests: seededRequests,
      invalidRequest,
    }) => {
      window.localStorage.setItem(
        "buzz-feature-overrides-v1",
        JSON.stringify({ projects: true }),
      );
      window.__BUZZ_E2E_EXTRA_PROJECT_EVENTS__ = [
        {
          id: prId,
          kind: 1618,
          pubkey: ownerPubkey,
          created_at: createdAt,
          content: "Browser CI trust test",
          tags: [
            ["a", repo],
            ["subject", "Browser CI trust test"],
            ["c", "1".repeat(40)],
            ["h", channelId],
            ["branch-name", "feature/browser-ci"],
            ["clone", "https://relay.example/git/repo"],
          ],
        },
        invalidRequest,
        ...seededRequests,
      ];
    },
    {
      ownerPubkey: owner,
      repo: repoAddress,
      prId: pullRequestId,
      channelId: GENERAL_CHANNEL_ID,
      createdAt: now,
      validRequests,
      invalidRequest: driftedRequest,
    },
  );
  await page.route("**/ci/runs/*/status**", async (route) => {
    const requestedRunId = new URL(route.request().url()).pathname
      .split("/")
      .at(-2);
    if (requestedRunId !== runId) {
      await route.fulfill({ status: 503 });
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      status: 200,
      body: JSON.stringify({
        schema_version: 1,
        authority: {
          source: "relay_startup_config",
          status_signer_pubkeys: ["a".repeat(64)],
        },
        rejected: {
          count: 1,
          malformed_count: 0,
          unexpected_request_count: 0,
          untrusted_count: 1,
          untrusted_status_signer_pubkeys: ["b".repeat(64)],
          provenance_truncated: false,
        },
        status: {
          run_id: runId,
          state: "pending",
          reduction: {
            run_id: runId,
            sha: "1".repeat(40),
            attempt: 1,
            state: "pending",
            jobs: [
              {
                job_id: "test",
                name: "Tests",
                state: "queued",
                required: true,
                attempt: 1,
              },
            ],
            jobs_terminal: 0,
            jobs_total: 1,
            required_failing: [],
          },
        },
      }),
    });
  });

  await page.goto(
    `http://127.0.0.1:4175/app/?e2e=mock#/projects/${repoAddress}?pullRequestId=${pullRequestId}`,
    { waitUntil: "domcontentloaded" },
  );
  await page.getByRole("tab", { name: "Pull Request" }).click();
  await expect(page.getByText("Browser CI trust test").first()).toBeVisible({
    timeout: 10_000,
  });
  await page.getByText("Browser CI trust test").first().click();
  await page.getByRole("tab", { name: /Checks/ }).click();

  await expect(
    page.getByRole("alert").filter({
      hasText: "1 malformed CI request event was ignored.",
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("alert").filter({
      hasText: "Status signer not trusted by browser configuration.",
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("alert").filter({
      hasText: "CI status authority is unavailable (503).",
    }),
  ).toHaveCount(19);
  await expect(
    page.getByRole("status").filter({
      hasText:
        "Showing the 20 newest CI runs. 2 older runs were omitted by the browser limit.",
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("status").filter({ hasText: "pending" }),
  ).toBeVisible();
});

test("pull request checks distinguish a saturated discovery window from no checks", async ({
  page,
}) => {
  const owner = "deadbeef".repeat(8);
  const repoAddress = `30617:${owner}:buzz`;
  const pullRequestId = "c".repeat(64);
  const unrelatedPullRequestId = "e".repeat(64);
  const now = Math.floor(Date.now() / 1_000);
  const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 97);
  const actor = getPublicKey(secret);
  const requestEvent = (
    runId: string,
    prRootEventId: string,
    createdAt: number,
  ) =>
    finalizeEvent(
      {
        created_at: createdAt,
        kind: 46_100,
        tags: [
          ["h", GENERAL_CHANNEL_ID],
          ["a", repoAddress],
          ["run", runId],
          ["workflow", "ci"],
          ["c", "1".repeat(40)],
          ["attempt", "1"],
        ],
        content: JSON.stringify({
          schema_version: 1,
          request_type: "run",
          target_repo_a: repoAddress,
          pr_root_event_id: prRootEventId,
          source_clone_url: "https://relay.example/git/repo",
          immutable_source_ref: "refs/nostr/source",
          tip_oid: "1".repeat(40),
          source_branch: "feature/browser-ci",
          base_ref: "refs/heads/main",
          base_oid: "2".repeat(40),
          workflow_id: "ci",
          workflow_digest: "3".repeat(64),
          job_ids: ["test"],
          run_id: runId,
          attempt: 1,
          trigger_event_id: prRootEventId,
          actor,
          timeout_seconds: 300,
          idempotency_key: `browser-ci-request-${runId}`,
          issued_at: createdAt,
          expires_at: createdAt + 300,
        }),
      },
      secret,
    );
  const relevantOlderRequest = requestEvent(
    "20000000-0000-4000-8000-000000000001",
    pullRequestId,
    now,
  );
  const unrelatedNewerRequests = Array.from({ length: 100 }, (_, index) =>
    requestEvent(
      `30000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      unrelatedPullRequestId,
      now + index + 1,
    ),
  );

  await page.addInitScript(
    ({ ownerPubkey, repo, prId, channelId, createdAt, ciRequests }) => {
      window.localStorage.setItem(
        "buzz-feature-overrides-v1",
        JSON.stringify({ projects: true }),
      );
      window.__BUZZ_E2E_EXTRA_PROJECT_EVENTS__ = [
        {
          id: prId,
          kind: 1618,
          pubkey: ownerPubkey,
          created_at: createdAt,
          content: "Browser CI saturation test",
          tags: [
            ["a", repo],
            ["subject", "Browser CI saturation test"],
            ["c", "1".repeat(40)],
            ["h", channelId],
            ["branch-name", "feature/browser-ci-saturation"],
            ["clone", "https://relay.example/git/repo"],
          ],
        },
        ...ciRequests,
      ];
    },
    {
      ownerPubkey: owner,
      repo: repoAddress,
      prId: pullRequestId,
      channelId: GENERAL_CHANNEL_ID,
      createdAt: now,
      ciRequests: [relevantOlderRequest, ...unrelatedNewerRequests],
    },
  );

  await page.goto(
    `http://127.0.0.1:4175/app/?e2e=mock#/projects/${repoAddress}?pullRequestId=${pullRequestId}`,
    { waitUntil: "domcontentloaded" },
  );
  await page.getByRole("tab", { name: "Pull Request" }).click();
  await expect(
    page.getByText("Browser CI saturation test").first(),
  ).toBeVisible({
    timeout: 10_000,
  });
  await page.getByText("Browser CI saturation test").first().click();
  await page.getByRole("tab", { name: /Checks/ }).click();

  await expect(
    page.getByRole("status").filter({
      hasText:
        "The CI discovery window is saturated. Older runs for this pull request may be omitted.",
    }),
  ).toBeVisible();
  await expect(
    page.getByText("No checks have been reported for this pull request yet."),
  ).toHaveCount(0);
  await expect(
    page.getByText(/older runs were omitted by the browser limit/),
  ).toHaveCount(0);
  const ciDiscoveryLimits = await page.evaluate(
    ({ repo, channelId }) =>
      (window.__BUZZ_E2E_PROJECT_QUERY_FILTERS__ ?? [])
        .filter(
          (filter) =>
            filter.kinds?.includes(46_100) &&
            filter["#a"]?.includes(repo) &&
            filter["#h"]?.includes(channelId),
        )
        .map((filter) => filter.limit),
    { repo: repoAddress, channelId: GENERAL_CHANNEL_ID },
  );
  expect(ciDiscoveryLimits).toContain(100);
});
