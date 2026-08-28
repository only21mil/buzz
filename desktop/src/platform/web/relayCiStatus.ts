import { relayClient } from "@/shared/api/relayClient";
import type { RelayEvent } from "@/shared/api/types";
import { verifyEvent } from "nostr-tools/pure";
import { nip98Fetch } from "./nip98";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const STATES = new Set(["pending", "green", "red", "infrastructure_failure"]);
const JOB_STATES = new Set([
  "queued",
  "running",
  "success",
  "failure",
  "cancelled",
  "timed_out",
  "skipped",
]);
const REQUEST_KEYS = new Set([
  "schema_version",
  "request_type",
  "target_repo_a",
  "pr_root_event_id",
  "pr_update_event_id",
  "source_clone_url",
  "immutable_source_ref",
  "tip_oid",
  "source_branch",
  "base_ref",
  "base_oid",
  "workflow_id",
  "workflow_digest",
  "job_ids",
  "run_id",
  "attempt",
  "parent_attempt",
  "parent_run_id",
  "trigger_event_id",
  "actor",
  "timeout_seconds",
  "idempotency_key",
  "issued_at",
  "expires_at",
]);
const CI_STATUS_BATCH_SIZE = 4;
const CI_REQUEST_DISCOVERY_LIMIT = 100;

export type BrowserCiJob = {
  job_id: string;
  name?: string;
  state?: string;
  required?: boolean;
  started_at?: number;
  finished_at?: number;
  attempt: number;
};

export type BrowserCiStatus = {
  run_id: string;
  state: string;
  rejected: {
    count: number;
    malformed_count: number;
    unexpected_request_count: number;
    untrusted_count: number;
    untrusted_status_signer_pubkeys: string[];
    provenance_truncated: boolean;
  };
  reduction: {
    run_id: string;
    sha: string;
    attempt: number;
    state: string;
    jobs: BrowserCiJob[];
    jobs_terminal: number;
    jobs_total: number;
    required_failing: string[];
    reason?: string;
  };
};

export type BrowserCiRunFailure = {
  run_id: string;
  kind: "conflict" | "unavailable" | "http" | "transport" | "unparseable";
  http_status?: number;
  message: string;
};

type CiStatusFetch = (
  request: Parameters<typeof nip98Fetch>[0],
) => Promise<Response>;

type CiStatusOutcome =
  | { status: BrowserCiStatus }
  | { failure: BrowserCiRunFailure };

function exactKeys(
  value: Record<string, unknown>,
  keys: ReadonlySet<string>,
  label: string,
): void {
  if (Object.keys(value).some((key) => !keys.has(key))) {
    throw new Error(`Invalid CI status schema: unexpected ${label} field`);
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid CI status schema: ${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function parseJob(value: unknown): BrowserCiJob {
  const job = record(value, "job");
  exactKeys(
    job,
    new Set([
      "job_id",
      "name",
      "state",
      "required",
      "started_at",
      "finished_at",
      "attempt",
    ]),
    "job",
  );
  if (
    typeof job.job_id !== "string" ||
    job.job_id.length === 0 ||
    !safeInteger(job.attempt) ||
    Number(job.attempt) < 1 ||
    (job.name !== undefined && typeof job.name !== "string") ||
    (job.state !== undefined &&
      (typeof job.state !== "string" || !JOB_STATES.has(job.state))) ||
    (job.required !== undefined && typeof job.required !== "boolean") ||
    (job.started_at !== undefined && !safeInteger(job.started_at)) ||
    (job.finished_at !== undefined && !safeInteger(job.finished_at))
  ) {
    throw new Error("Invalid CI status schema: malformed job");
  }
  return job as BrowserCiJob;
}

export function parseCiStatusResponse(value: unknown): BrowserCiStatus {
  const root = record(value, "response");
  exactKeys(
    root,
    new Set(["schema_version", "authority", "rejected", "status"]),
    "response",
  );
  const authority = record(root.authority, "authority");
  exactKeys(
    authority,
    new Set(["source", "status_signer_pubkeys"]),
    "authority",
  );
  const signers = authority.status_signer_pubkeys;
  if (
    root.schema_version !== 1 ||
    authority.source !== "relay_startup_config" ||
    !Array.isArray(signers) ||
    signers.length === 0 ||
    signers.some(
      (signer) => typeof signer !== "string" || !HEX_64.test(signer),
    ) ||
    new Set(signers).size !== signers.length ||
    [...signers].sort().some((signer, index) => signer !== signers[index])
  ) {
    throw new Error("Invalid CI status schema: untrusted authority provenance");
  }
  const rejected = record(root.rejected, "rejected events");
  exactKeys(
    rejected,
    new Set([
      "count",
      "malformed_count",
      "unexpected_request_count",
      "untrusted_count",
      "untrusted_status_signer_pubkeys",
      "provenance_truncated",
    ]),
    "rejected events",
  );
  const rejectedSigners = rejected.untrusted_status_signer_pubkeys;
  if (
    !safeInteger(rejected.count) ||
    Number(rejected.count) > 1_000 ||
    !safeInteger(rejected.malformed_count) ||
    !safeInteger(rejected.unexpected_request_count) ||
    !safeInteger(rejected.untrusted_count) ||
    Number(rejected.count) !==
      Number(rejected.malformed_count) +
        Number(rejected.unexpected_request_count) +
        Number(rejected.untrusted_count) ||
    !Array.isArray(rejectedSigners) ||
    rejectedSigners.length > 20 ||
    rejectedSigners.length > Number(rejected.untrusted_count) ||
    rejectedSigners.some(
      (signer) => typeof signer !== "string" || !HEX_64.test(signer),
    ) ||
    new Set(rejectedSigners).size !== rejectedSigners.length ||
    [...rejectedSigners]
      .sort()
      .some((signer, index) => signer !== rejectedSigners[index]) ||
    typeof rejected.provenance_truncated !== "boolean" ||
    (rejected.provenance_truncated && rejectedSigners.length !== 20)
  ) {
    throw new Error("Invalid CI status schema: malformed rejected provenance");
  }
  const status = record(root.status, "status");
  exactKeys(status, new Set(["run_id", "state", "reduction"]), "status");
  const reduction = record(status.reduction, "reduction");
  exactKeys(
    reduction,
    new Set([
      "run_id",
      "sha",
      "attempt",
      "state",
      "jobs",
      "jobs_terminal",
      "jobs_total",
      "required_failing",
      "reason",
    ]),
    "reduction",
  );
  if (
    typeof status.run_id !== "string" ||
    !UUID.test(status.run_id) ||
    typeof status.state !== "string" ||
    !STATES.has(status.state) ||
    reduction.run_id !== status.run_id ||
    reduction.state !== status.state ||
    typeof reduction.sha !== "string" ||
    !OID.test(reduction.sha) ||
    !safeInteger(reduction.attempt) ||
    Number(reduction.attempt) < 1 ||
    !Array.isArray(reduction.jobs) ||
    !safeInteger(reduction.jobs_terminal) ||
    !safeInteger(reduction.jobs_total) ||
    Number(reduction.jobs_terminal) > Number(reduction.jobs_total) ||
    !Array.isArray(reduction.required_failing) ||
    reduction.required_failing.some((job) => typeof job !== "string") ||
    (reduction.reason !== undefined && typeof reduction.reason !== "string")
  ) {
    throw new Error("Invalid CI status schema: malformed reduction");
  }
  return {
    run_id: status.run_id,
    state: status.state,
    rejected: rejected as BrowserCiStatus["rejected"],
    reduction: {
      ...(reduction as BrowserCiStatus["reduction"]),
      jobs: reduction.jobs.map(parseJob),
    },
  };
}

export function ciRunIdForPullRequest(
  event: RelayEvent,
  targetRepoA: string,
  channelId: string,
  pullRequestId: string,
): string | null {
  let content: unknown;
  try {
    content = JSON.parse(event.content) as unknown;
  } catch {
    throw new Error("Invalid CI request schema: content is not JSON");
  }
  const value = record(content, "CI request");
  const runId = value.run_id;
  if (
    event.kind !== 46100 ||
    value.target_repo_a !== targetRepoA ||
    value.pr_root_event_id !== pullRequestId ||
    !event.tags.some((tag) => tag[0] === "h" && tag[1] === channelId) ||
    !event.tags.some((tag) => tag[0] === "a" && tag[1] === targetRepoA)
  ) {
    return null;
  }
  exactKeys(value, REQUEST_KEYS, "CI request");
  if (
    !verifyEvent(event) ||
    value.schema_version !== 1 ||
    value.request_type !== "run" ||
    typeof runId !== "string" ||
    !UUID.test(runId) ||
    value.actor !== event.pubkey ||
    typeof value.tip_oid !== "string" ||
    !OID.test(value.tip_oid) ||
    typeof value.workflow_digest !== "string" ||
    !HEX_64.test(value.workflow_digest) ||
    !Array.isArray(value.job_ids) ||
    value.job_ids.length === 0 ||
    value.job_ids.some((job) => typeof job !== "string" || job.length === 0) ||
    !event.tags.some((tag) => tag[0] === "run" && tag[1] === runId) ||
    !event.tags.some((tag) => tag[0] === "attempt" && tag[1] === "1")
  ) {
    throw new Error("Invalid CI request schema: malformed request");
  }
  return runId;
}

export function discoverPullRequestCiRunIds(
  events: RelayEvent[],
  targetRepoA: string,
  channelId: string,
  pullRequestId: string,
): {
  runIds: string[];
  rejectedRequestCount: number;
  truncatedRunCount: number | null;
  runDiscoveryTruncated: boolean;
  discoveryWindowSaturated: boolean;
} {
  const runIds = new Map<string, { createdAt: number; eventId: string }>();
  let rejectedRequestCount = 0;
  for (const event of events) {
    try {
      const runId = ciRunIdForPullRequest(
        event,
        targetRepoA,
        channelId,
        pullRequestId,
      );
      if (runId) {
        const prior = runIds.get(runId);
        if (
          !prior ||
          event.created_at > prior.createdAt ||
          (event.created_at === prior.createdAt && event.id > prior.eventId)
        ) {
          runIds.set(runId, {
            createdAt: event.created_at,
            eventId: event.id,
          });
        }
      }
    } catch {
      rejectedRequestCount = Math.min(100, rejectedRequestCount + 1);
    }
  }
  const discoveredRunIds = [...runIds.entries()]
    .sort(
      ([leftRunId, left], [rightRunId, right]) =>
        right.createdAt - left.createdAt ||
        right.eventId.localeCompare(left.eventId) ||
        rightRunId.localeCompare(leftRunId),
    )
    .map(([runId]) => runId);
  const discoveryWindowSaturated = events.length >= CI_REQUEST_DISCOVERY_LIMIT;
  const knownTruncatedRunCount = Math.min(
    CI_REQUEST_DISCOVERY_LIMIT,
    Math.max(0, discoveredRunIds.length - 20),
  );
  return {
    runIds: discoveredRunIds.slice(0, 20),
    rejectedRequestCount,
    truncatedRunCount: discoveryWindowSaturated ? null : knownTruncatedRunCount,
    runDiscoveryTruncated:
      discoveryWindowSaturated || knownTruncatedRunCount > 0,
    discoveryWindowSaturated,
  };
}

export async function fetchCiRunStatuses(
  input: {
    runIds: string[];
    channelId: string;
    relayHttpUrl: string;
  },
  fetchStatus: CiStatusFetch = nip98Fetch,
): Promise<{
  statuses: BrowserCiStatus[];
  failures: BrowserCiRunFailure[];
}> {
  const outcomes: PromiseSettledResult<CiStatusOutcome>[] = [];
  for (
    let offset = 0;
    offset < input.runIds.length;
    offset += CI_STATUS_BATCH_SIZE
  ) {
    const batch = input.runIds.slice(offset, offset + CI_STATUS_BATCH_SIZE);
    outcomes.push(
      ...(await Promise.allSettled(
        batch.map(async (runId): Promise<CiStatusOutcome> => {
          const url = new URL(
            `ci/runs/${encodeURIComponent(runId)}/status`,
            `${input.relayHttpUrl.replace(/\/$/, "")}/`,
          );
          url.searchParams.set("channel_id", input.channelId);

          let response: Response;
          try {
            response = await fetchStatus({
              url: url.toString(),
              method: "GET",
              headers: { Accept: "application/json" },
            });
          } catch {
            return {
              failure: {
                run_id: runId,
                kind: "transport",
                message: "CI status request could not reach the relay.",
              } satisfies BrowserCiRunFailure,
            };
          }

          if (!response.ok) {
            const kind =
              response.status === 409
                ? "conflict"
                : response.status === 503
                  ? "unavailable"
                  : "http";
            const message =
              response.status === 409
                ? "CI status is structurally ambiguous (409)."
                : response.status === 503
                  ? "CI status authority is unavailable (503)."
                  : `CI status request failed (${response.status}).`;
            return {
              failure: {
                run_id: runId,
                kind,
                http_status: response.status,
                message,
              } satisfies BrowserCiRunFailure,
            };
          }

          try {
            const status = parseCiStatusResponse(await response.json());
            if (status.run_id !== runId) {
              throw new Error("CI status response run does not match request");
            }
            return { status };
          } catch {
            return {
              failure: {
                run_id: runId,
                kind: "unparseable",
                message: "CI status response was invalid or unparseable.",
              } satisfies BrowserCiRunFailure,
            };
          }
        }),
      )),
    );
  }
  const statuses: BrowserCiStatus[] = [];
  const failures: BrowserCiRunFailure[] = [];
  for (const [index, outcome] of outcomes.entries()) {
    if (outcome.status === "rejected") {
      failures.push({
        run_id: input.runIds[index],
        kind: "transport",
        message: "CI status request could not reach the relay.",
      });
    } else if ("status" in outcome.value) {
      statuses.push(outcome.value.status);
    } else {
      failures.push(outcome.value.failure);
    }
  }
  return { statuses, failures };
}

export async function getPullRequestCiStatuses(input: {
  targetRepoA: string;
  channelId: string;
  pullRequestId: string;
}): Promise<{
  statuses: BrowserCiStatus[];
  failures: BrowserCiRunFailure[];
  rejectedRequestCount: number;
  truncatedRunCount: number | null;
  runDiscoveryTruncated: boolean;
  discoveryWindowSaturated: boolean;
}> {
  const { targetRepoA, channelId, pullRequestId } = input;
  if (!UUID.test(channelId) || !HEX_64.test(pullRequestId)) {
    throw new TypeError(
      "CI status requires a channel UUID and pull request event ID",
    );
  }
  const events = await relayClient.fetchEvents({
    kinds: [46100],
    "#h": [channelId],
    "#a": [targetRepoA],
    limit: CI_REQUEST_DISCOVERY_LIMIT,
  });
  const discovery = discoverPullRequestCiRunIds(
    events,
    targetRepoA,
    channelId,
    pullRequestId,
  );
  const relayHttpUrl = window.location.origin;
  const settled = await fetchCiRunStatuses({
    runIds: discovery.runIds,
    channelId,
    relayHttpUrl,
  });
  return {
    ...settled,
    rejectedRequestCount: discovery.rejectedRequestCount,
    truncatedRunCount: discovery.truncatedRunCount,
    runDiscoveryTruncated: discovery.runDiscoveryTruncated,
    discoveryWindowSaturated: discovery.discoveryWindowSaturated,
  };
}
