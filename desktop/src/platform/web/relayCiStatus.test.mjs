import assert from "node:assert/strict";
import test from "node:test";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";

import {
  ciRunIdForPullRequest,
  discoverPullRequestCiRunIds,
  fetchCiRunStatuses,
  parseCiStatusResponse,
} from "./relayCiStatus.ts";
import { nip98Fetch } from "./nip98.ts";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174000";
const CHANNEL_ID = "123e4567-e89b-42d3-a456-426614174001";
const PR_ID = "c".repeat(64);
const REPO = `30617:${"d".repeat(64)}:buzz`;
const REQUEST_SECRET = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 97,
);
const REQUEST_PUBKEY = getPublicKey(REQUEST_SECRET);

function response(overrides = {}) {
  return {
    schema_version: 1,
    authority: {
      source: "relay_startup_config",
      status_signer_pubkeys: ["a".repeat(64)],
    },
    rejected: {
      count: 0,
      malformed_count: 0,
      unexpected_request_count: 0,
      untrusted_count: 0,
      untrusted_status_signer_pubkeys: [],
      provenance_truncated: false,
    },
    status: {
      run_id: RUN_ID,
      state: "green",
      reduction: {
        run_id: RUN_ID,
        sha: "b".repeat(40),
        attempt: 1,
        state: "green",
        jobs: [
          {
            job_id: "test",
            name: "Tests",
            state: "success",
            required: true,
            started_at: 100,
            finished_at: 110,
            attempt: 1,
          },
        ],
        jobs_terminal: 1,
        jobs_total: 1,
        required_failing: [],
      },
    },
    ...overrides,
  };
}

function responseForRun(runId) {
  const value = response();
  value.status.run_id = runId;
  value.status.reduction.run_id = runId;
  return value;
}

function requestEvent(runId, prRootEventId = PR_ID, createdAt = 100) {
  return finalizeEvent(
    {
      created_at: createdAt,
      kind: 46100,
      tags: [
        ["h", CHANNEL_ID],
        ["a", REPO],
        ["run", runId],
        ["workflow", "ci"],
        ["c", "1".repeat(40)],
        ["attempt", "1"],
      ],
      content: JSON.stringify({
        schema_version: 1,
        request_type: "run",
        target_repo_a: REPO,
        pr_root_event_id: prRootEventId,
        source_clone_url: "https://relay.example/git/repo",
        immutable_source_ref: "refs/nostr/source",
        tip_oid: "1".repeat(40),
        source_branch: "feature",
        base_ref: "refs/heads/main",
        base_oid: "2".repeat(40),
        workflow_id: "ci",
        workflow_digest: "3".repeat(64),
        job_ids: ["test"],
        run_id: runId,
        attempt: 1,
        trigger_event_id: prRootEventId,
        actor: REQUEST_PUBKEY,
        timeout_seconds: 300,
        idempotency_key: `request-${runId}`,
        issued_at: 10,
        expires_at: 20,
      }),
    },
    REQUEST_SECRET,
  );
}

test("CI status parser accepts the native reduction with config provenance", () => {
  assert.deepEqual(parseCiStatusResponse(response()).reduction.jobs[0], {
    job_id: "test",
    name: "Tests",
    state: "success",
    required: true,
    started_at: 100,
    finished_at: 110,
    attempt: 1,
  });
});

test("CI status parser rejects response-selected or empty authority", () => {
  assert.throws(
    () =>
      parseCiStatusResponse(
        response({
          authority: {
            source: "relay_response",
            status_signer_pubkeys: ["a".repeat(64)],
          },
        }),
      ),
    /untrusted authority provenance/,
  );
  assert.throws(
    () =>
      parseCiStatusResponse(
        response({
          authority: {
            source: "relay_startup_config",
            status_signer_pubkeys: [],
          },
        }),
      ),
    /untrusted authority provenance/,
  );
});

test("CI status parser fails closed on schema drift and state mismatch", () => {
  const drifted = response();
  drifted.status.reduction.debug = "private";
  assert.throws(
    () => parseCiStatusResponse(drifted),
    /unexpected reduction field/,
  );

  const mismatch = response();
  mismatch.status.reduction.state = "pending";
  assert.throws(() => parseCiStatusResponse(mismatch), /malformed reduction/);
});

test("CI status parser accepts bounded rejected signer provenance", () => {
  const parsed = parseCiStatusResponse(
    response({
      rejected: {
        count: 3,
        malformed_count: 1,
        unexpected_request_count: 1,
        untrusted_count: 1,
        untrusted_status_signer_pubkeys: ["b".repeat(64)],
        provenance_truncated: false,
      },
    }),
  );
  assert.equal(parsed.rejected.untrusted_count, 1);
  assert.deepEqual(parsed.rejected.untrusted_status_signer_pubkeys, [
    "b".repeat(64),
  ]);

  assert.throws(
    () =>
      parseCiStatusResponse(
        response({
          rejected: {
            count: 1,
            malformed_count: 0,
            unexpected_request_count: 0,
            untrusted_count: 0,
            untrusted_status_signer_pubkeys: ["b".repeat(64)],
            provenance_truncated: false,
          },
        }),
      ),
    /malformed rejected provenance/,
  );
});

test("CI request discovery is PR/channel/repository bound and rejects drift", () => {
  const event = finalizeEvent(
    {
      created_at: 100,
      kind: 46100,
      tags: [
        ["h", CHANNEL_ID],
        ["a", REPO],
        ["run", RUN_ID],
        ["workflow", "ci"],
        ["c", "1".repeat(40)],
        ["attempt", "1"],
      ],
      content: JSON.stringify({
        schema_version: 1,
        request_type: "run",
        target_repo_a: REPO,
        pr_root_event_id: PR_ID,
        source_clone_url: "https://relay.example/git/repo",
        immutable_source_ref: "refs/nostr/source",
        tip_oid: "1".repeat(40),
        source_branch: "feature",
        base_ref: "refs/heads/main",
        base_oid: "2".repeat(40),
        workflow_id: "ci",
        workflow_digest: "3".repeat(64),
        job_ids: ["test"],
        run_id: RUN_ID,
        attempt: 1,
        trigger_event_id: PR_ID,
        actor: REQUEST_PUBKEY,
        timeout_seconds: 300,
        idempotency_key: "request-1",
        issued_at: 10,
        expires_at: 20,
      }),
    },
    REQUEST_SECRET,
  );
  assert.equal(ciRunIdForPullRequest(event, REPO, CHANNEL_ID, PR_ID), RUN_ID);
  event.content = JSON.stringify({
    ...JSON.parse(event.content),
    secret: "no",
  });
  assert.throws(
    () => ciRunIdForPullRequest(event, REPO, CHANNEL_ID, PR_ID),
    /unexpected CI request field/,
  );
});

test("CI request discovery isolates drifted events and keeps valid runs", () => {
  const valid = requestEvent(RUN_ID);
  const drifted = requestEvent("223e4567-e89b-42d3-a456-426614174000");
  drifted.content = JSON.stringify({
    ...JSON.parse(drifted.content),
    unexpected: true,
  });
  const otherPullRequest = requestEvent("323e4567-e89b-42d3-a456-426614174000");
  otherPullRequest.content = JSON.stringify({
    ...JSON.parse(otherPullRequest.content),
    pr_root_event_id: "e".repeat(64),
    unexpected: true,
  });

  assert.deepEqual(
    discoverPullRequestCiRunIds(
      [drifted, valid, otherPullRequest],
      REPO,
      CHANNEL_ID,
      PR_ID,
    ),
    {
      runIds: [RUN_ID],
      rejectedRequestCount: 1,
      truncatedRunCount: 0,
      runDiscoveryTruncated: false,
      discoveryWindowSaturated: false,
    },
  );
});

test("CI request discovery reports bounded run truncation", () => {
  const events = Array.from({ length: 22 }, (_, index) =>
    requestEvent(
      `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      PR_ID,
      100 + index,
    ),
  );
  const discovered = discoverPullRequestCiRunIds(
    events,
    REPO,
    CHANNEL_ID,
    PR_ID,
  );
  assert.equal(discovered.runIds.length, 20);
  assert.equal(discovered.truncatedRunCount, 2);
  assert.equal(discovered.runDiscoveryTruncated, true);
  assert.equal(discovered.discoveryWindowSaturated, false);
  assert.equal(discovered.rejectedRequestCount, 0);
  assert.deepEqual(discovered.runIds.slice(0, 2), [
    "00000000-0000-4000-8000-000000000022",
    "00000000-0000-4000-8000-000000000021",
  ]);
  assert.equal(
    discovered.runIds.at(-1),
    "00000000-0000-4000-8000-000000000003",
  );
});

test("CI request discovery reports an unknown omission when its bounded window is saturated", () => {
  const unrelatedPullRequestId = "e".repeat(64);
  const events = Array.from({ length: 100 }, (_, index) =>
    requestEvent(
      `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      unrelatedPullRequestId,
      200 + index,
    ),
  );
  const discovered = discoverPullRequestCiRunIds(
    events,
    REPO,
    CHANNEL_ID,
    PR_ID,
  );

  assert.deepEqual(discovered, {
    runIds: [],
    rejectedRequestCount: 0,
    truncatedRunCount: null,
    runDiscoveryTruncated: true,
    discoveryWindowSaturated: true,
  });
});

test("CI run status reads use bounded request batches", async () => {
  const runIds = Array.from(
    { length: 9 },
    (_, index) =>
      `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  );
  let active = 0;
  let maxActive = 0;
  const result = await fetchCiRunStatuses(
    { runIds, channelId: CHANNEL_ID, relayHttpUrl: "https://relay.example" },
    async ({ url }) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      const runId = new URL(url).pathname.split("/").at(-2);
      return new Response(JSON.stringify(responseForRun(runId)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    },
  );
  assert.equal(result.failures.length, 0);
  assert.equal(result.statuses.length, runIds.length);
  assert.equal(maxActive, 4);
});

test("CI run status reads isolate per-run HTTP, transport, and parse failures", async () => {
  const runIds = [
    RUN_ID,
    "223e4567-e89b-42d3-a456-426614174000",
    "323e4567-e89b-42d3-a456-426614174000",
    "423e4567-e89b-42d3-a456-426614174000",
    "523e4567-e89b-42d3-a456-426614174000",
  ];
  const result = await fetchCiRunStatuses(
    {
      runIds,
      channelId: CHANNEL_ID,
      relayHttpUrl: "https://relay.example",
    },
    async ({ url }) => {
      const runId = new URL(url).pathname.split("/").at(-2);
      if (runId === runIds[1]) return new Response(null, { status: 409 });
      if (runId === runIds[2]) return new Response(null, { status: 503 });
      if (runId === runIds[3]) throw new Error("offline");
      if (runId === runIds[4]) return new Response("{", { status: 200 });
      return new Response(JSON.stringify(responseForRun(runId)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    },
  );

  assert.deepEqual(
    result.statuses.map((status) => status.run_id),
    [RUN_ID],
  );
  assert.deepEqual(
    result.failures.map((failure) => [
      failure.run_id,
      failure.kind,
      failure.http_status,
    ]),
    [
      [runIds[1], "conflict", 409],
      [runIds[2], "unavailable", 503],
      [runIds[3], "transport", undefined],
      [runIds[4], "unparseable", undefined],
    ],
  );
});

test("CI run status NIP-98 binds the exact channel_id query URL", async () => {
  const signedTemplates = [];
  const fetchedUrls = [];
  const relayHttpUrl = "https://relay.example";
  const expectedUrl = `${relayHttpUrl}/ci/runs/${RUN_ID}/status?channel_id=${CHANNEL_ID}`;
  const result = await fetchCiRunStatuses(
    { runIds: [RUN_ID], channelId: CHANNEL_ID, relayHttpUrl },
    (request) =>
      nip98Fetch(request, {
        nonce: () => "fixed-nonce",
        signEvent: async (template) => {
          signedTemplates.push(template);
          return finalizeEvent(
            { ...template, created_at: 100 },
            REQUEST_SECRET,
          );
        },
        fetch: async (url) => {
          fetchedUrls.push(String(url));
          return new Response(JSON.stringify(responseForRun(RUN_ID)), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
      }),
  );

  assert.equal(result.failures.length, 0);
  assert.deepEqual(fetchedUrls, [expectedUrl]);
  assert.deepEqual(
    signedTemplates[0].tags.filter(
      (tag) => tag[0] === "u" || tag[0] === "method",
    ),
    [
      ["u", expectedUrl],
      ["method", "GET"],
    ],
  );
});
