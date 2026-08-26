# Buzz CI control service design

Status: C3 contract milestone, 2026-08-26

This document defines `buzz-ci-controld`, the keyholding service that assigns accepted kind-46100 requests, drives the key-free runner, and publishes signed kinds 46101 through 46106. It builds on `BUZZ_CI_PROTOCOL_CONTRACT.md` and `BUZZ_CI_RELAY_API_CONTRACT.md`. Those contracts remain authoritative for event validation, sequencing, signer authority, and verdict reduction.

## 1. Controld to runner contract

This section is the coordination contract for the C4 runner daemon. Changes to it require the C3 and C4 owners to agree on a new `schema_version` before either implementation changes.

### 1.1 Socket and activation

The runner listens on the systemd-owned Unix stream socket `/run/buzzci/runner-control.sock`. The service accepts only one inherited listener on file descriptor 3 with `LISTEN_FDS=1` and `LISTEN_FDNAMES=buzz-ci-runner-control`. It rejects a listener that is not an accepting `AF_UNIX` `SOCK_STREAM` socket at that exact path.

The socket unit owns path creation and mode. It grants connect access only to the dedicated controld account. The runner checks `SO_PEERCRED` before reading request bytes and requires the configured controld UID. It does not accept a caller-selected path, TCP listener, inherited signing key, or socket path from an environment variable.

Each connection carries one dispatch. Frames are a four-byte unsigned big-endian length followed by one UTF-8 JSON object. A frame body is at most 1 MiB. Unknown `schema_version`, unknown message `type`, duplicate JSON keys, trailing bytes, oversized frames, invalid UTF-8, and read or write timeout close the connection without execution. Writers use deterministic struct field order and omit absent optional fields instead of writing `null`.

The runner sends one receipt frame at a time and waits for the write to complete. The connection closes after one terminal `attempt_finished` or `refused` receipt. A disconnect does not prove cancellation. Controld reconciles the dispatch by its durable `dispatch_id` and the runner must return the same prior receipts or a typed in-progress response after restart.

### 1.2 Execute request

Controld sends exactly one `execute_attempt` object:

```json
{
  "schema_version": 1,
  "type": "execute_attempt",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "request_event": {},
  "signed_request_digest": "64-lowerhex",
  "assigned_at": 0,
  "deadline_at": 0,
  "jobs": [
    {
      "job_id": "static job ID",
      "attempt": 1,
      "parent_attempt": 0,
      "workflow_path": ".github/workflows/ci.yml",
      "job_manifest": "canonical signed-manifest JSON",
      "job_manifest_digest": "64-lowerhex",
      "audience_digest": "64-lowerhex",
      "isolation_profile_digest": "64-lowerhex"
    }
  ]
}
```

`request_event` is data, not authority by itself. Before broker admission, the runner verifies the event ID, signature, kind, actor binding, channel scope supplied by its trusted policy source, request expiry, exact `request_event_id`, and exact `signed_request_digest`. It also verifies every job is selected by the accepted request and that all manifest digests match trusted broker output. Jobs are non-empty and unique. `deadline_at` cannot exceed the accepted request timeout or expiry.

The request contains no signer secret, relay bearer credential, repository credential, raw environment map, executable path, socket path, or host-unit name. Controld cannot ask the runner to weaken its fixed execution policy.

### 1.3 Ordered receipts

Every receipt repeats `schema_version`, `dispatch_id`, `request_event_id`, `run_id`, and `attempt`. Receipt-local `receipt_sequence` starts at 1 and increases without gaps. Controld persists the last accepted sequence before acting on a receipt. A different body at an already accepted sequence is equivocation and ends the run as `infrastructure_failure`.

The first receipt is one of:

```json
{
  "schema_version": 1,
  "type": "accepted",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "run_id": "UUID",
  "attempt": 1,
  "receipt_sequence": 1,
  "accepted_at": 0
}
```

The version-1 refusal reasons are `invalid_request`, `unauthorized`, `expired`, `invalid_manifest`, `deadline_exceeded`, `backend_unavailable`, `broker_refused`, and `reconciliation_failed`. Human detail stays in local bounded diagnostics and is not part of the wire receipt.

```json
{
  "schema_version": 1,
  "type": "refused",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "run_id": "UUID",
  "attempt": 1,
  "receipt_sequence": 1,
  "reason": "closed machine-readable reason"
}
```

After `accepted`, the runner emits `job_started` and one `job_finished` for each selected job. Timestamps are Unix seconds no greater than `2^53-1`.

```json
{
  "schema_version": 1,
  "type": "job_started",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "run_id": "UUID",
  "attempt": 1,
  "receipt_sequence": 2,
  "job_id": "job",
  "job_attempt": 1,
  "started_at": 0
}
```

```json
{
  "schema_version": 1,
  "type": "job_finished",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "run_id": "UUID",
  "attempt": 1,
  "receipt_sequence": 3,
  "job_id": "job",
  "job_attempt": 1,
  "state": "success",
  "started_at": 0,
  "finished_at": 0,
  "log": {
    "relative_path": "UUID/job/attempt-1.log",
    "sha256": "64-lowerhex",
    "byte_length": 0,
    "cap_bytes": 0,
    "truncated": false
  },
  "artifacts": []
}
```

The wire encoder omits `reason` when absent. `state` uses the protocol's terminal job states. A finished receipt with `truncated=true`, a missing scrubbed log, or evidence outside the configured spool is not publishable evidence and causes infrastructure failure. Artifacts use the same relative-path, SHA-256, byte-length, media-type, and logical-name binding.

The runner's last receipt is:

```json
{
  "schema_version": 1,
  "type": "attempt_finished",
  "dispatch_id": "UUID",
  "request_event_id": "64-lowerhex",
  "run_id": "UUID",
  "attempt": 1,
  "receipt_sequence": 4,
  "outcome": "completed",
  "finished_at": 0,
  "selected_job_attempts": [{"job_id":"job","attempt":1}],
  "teardown_attestation": {"schema_version":1},
  "receipt_set_digest": "64-lowerhex"
}
```

`outcome` is `completed` or `infrastructure_failure`. `completed` requires `teardown_attestation` and forbids `reason`. `infrastructure_failure` requires one of `backend_unavailable`, `execution_failed`, `evidence_invalid`, `deadline_exceeded`, `teardown_unproven`, or `reconciliation_failed`; it includes `teardown_attestation` only when teardown was still proven. Controld fails closed if an accepted dispatch ends without this terminal receipt.

`teardown_attestation` is the complete unsigned `CiTeardownAttestationEnvelope` produced by `buzz_ci_runner::build_teardown_attestation`. Controld verifies the envelope against the request and reducer-selected job attempts, signs it as kind 46106, and publishes it. The runner never signs or transmits Nostr events. `receipt_set_digest` is SHA-256 over the domain `buzz-ci-runner:receipt-set:v1\0` followed by each prior frame's four-byte length and exact JSON body in receipt-sequence order.

### 1.4 Evidence spool

The configured shared spool root is `/var/lib/buzzci/runner-output`. Receipt paths are relative UTF-8 paths with no empty, dot, parent, absolute, or symbolic-link component. The runner creates regular files with mode 0600 beneath a directory named by `dispatch_id`, closes them before sending `job_finished`, and never rewrites them afterward.

Controld opens each component without following links, verifies the expected owner, mode, regular-file type, byte bound, length, and SHA-256, then uploads scrubbed logs to the relay's authenticated `PUT /ci/logs/{request_event_id}/{run_id}/{job_id}/{attempt}/{log_sha256}` route. It signs kind 46103 only after the PUT response binds the same path and digest. Artifact publication follows the kind-46104 quarantine contract. Controld removes a dispatch spool only after durable evidence publication and kind 46106 acceptance, using the same descriptor-safe constraints.

## 2. Service placement

`buzz-ci-controld` is a separate service, not a relay module. It is the only process in this design that holds the dedicated CI status signing key. The relay remains an event validator and store; the runner and execd remain key-free.

Separation limits key exposure to a small process that does not execute workflow code. It also lets relay restarts, runner restarts, and controld restarts reconcile independently. A durable assignment lease keyed by `(request_event_id, run_id, attempt)` makes controld the single writer for each run. A second instance may take over only after the first lease expires and a compare-and-swap store update succeeds.

## 3. Accepted-request input and ordering

Controld consumes only stored, relay-accepted kind-46100 events from channels configured for CI. The preferred input is an authenticated channel-scoped relay subscription with bounded polling fallback. It never treats a client publication acknowledgment as assignment authority.

The relay's `ci_runs` row provides the unique `run_id` to initial-request mapping. `ci_run_events.watch_cursor` is the durable acceptance order within that run. Controld stores a per-channel input cursor and processes `(watch_cursor, event_id)` without using event `created_at` as order. On reconnect it resumes after the last committed cursor, suppresses the same cursor and event pair, and requests bounded replay for a gap. A cursor conflict or request identity conflict fails closed.

Before assignment, controld reloads the complete request through `GET /ci/runs/{run_id}/request`, validates its signature and immutable coordinates, confirms the signer grant, and obtains the trusted broker manifest. The service is repository-agnostic. Every lookup, lease, receipt, event, log path, and signer authorization stays bound to the request's `target_repo_a`; there is no configured default repository.

## 4. Run lifecycle and publication order

The durable lifecycle is:

```text
accepted request
  -> publish 46101 queued, sequence 1
  -> runner accepted
  -> publish 46101 running and 46102 job running
  -> verify and deposit scrubbed logs, publish 46103
  -> quarantine and publish artifact references as 46104
  -> publish terminal 46102 job statuses with bound references
  -> publish 46105 evidence-finalized
  -> verify runner teardown envelope, sign and publish 46106
  -> publish exactly one terminal 46101
```

Publishing kind 46100 is not success. The CLI receives success only after the authorized, request-linked kind-46101 `queued` event at sequence 1 is stored. Controld stores the canonical event body and resulting event ID before advancing its state, so restart republication is byte-identical.

Run and job sequences are separate, begin at 1, and increase without gaps. Controld derives them from durable stream state, never timestamps. Job code failure becomes run `failure`; runner, controld, materialization, evidence, teardown, or liveness failure becomes `infrastructure_failure`. A terminal event ID is committed with a compare-and-swap transition. Any later terminal proposal for the same run attempt is rejected.

## 5. Key custody

Controld uses one dedicated CI signer key with no repository fetch, deploy, release, or general relay authority. The key file lives under the host secrets directory in a mode-0700 parent and is a mode-0600 regular file. Controld opens it without following links, reads it once into memory, never accepts key bytes through argv, and never includes the key or derived secret in environment dumps, logs, receipts, crash reports, or the runner socket.

The signer pubkey must be authorized by non-empty owner configuration in `BUZZ_CI_STATUS_SIGNER_PUBKEYS` or by a repository-scoped kind-46107 grant for the request's `target_repo_a`. Rotation records the authority interval used for each run attempt. A signer that is absent, expired, ambiguous, or outside the repository grant prevents queued acknowledgment and assignment.

## 6. Crash recovery and liveness

Every externally visible action uses a durable intent and a stable idempotency key. After a crash, controld reloads the run record, accepted event IDs, runner receipt sequence, and publication intents. It republishes only the same canonical event and accepts an `Existing` result only when the returned event ID matches. A conflicting event, sequence, or receipt marks the run `infrastructure_failure`.

Controld records a liveness deadline when it publishes queued and refreshes it only from a valid runner receipt or a successful runner reconciliation response. If no valid progress arrives inside the configured liveness window, probe P-v requires controld to publish terminal `infrastructure_failure`. It does not leave a run queued or running indefinitely. Loss of a socket connection alone does not establish failure before the bounded reconciliation attempt finishes.

Terminal publication uses a stored compare-and-swap guard over `(run_id, attempt, terminal_event_id)`. Exactly one terminal verdict can win. Terminal states never transition, and a late runner receipt cannot replace or soften an infrastructure failure. Evidence-finalized and teardown facts must already be accepted before run `success`; publication acceptance alone is never treated as durable success.

## 7. Initial implementation boundary

The first `buzz-ci-controld` crate contains configuration, a typed run state machine, and a persistence trait with optimistic sequencing. It contains no relay client, socket client, signing implementation, process execution, or service wiring. Those pieces follow only after this contract and the C4 daemon agree on the version-1 frames.
