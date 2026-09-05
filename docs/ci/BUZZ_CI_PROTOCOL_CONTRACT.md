# BUZZ_CI_PROTOCOL_CONTRACT.md — Phase-1 signed envelopes and CLI wire contract

Status: **CORRECTED ENVELOPES + RELAY/API BINDING CANDIDATE v1.4 (2026-08-20)**

Inputs:

- `PLANS/BUZZ_CI_DESIGN.md` v1.2, SHA-256 `094b9a66036d9763bdb433942fca21a78a3bb7619c5285271ee2d68be596c8ab`
- `PLANS/BUZZ_CI_AGENT_LOOP.md` v1.6, SHA-256 `306a9631a374ce4fe3d326311aecc48abe35feacd07c84c8dc07bd2852e2a4d2`
- `docs/ci/BUZZ_CI_RELAY_API_CONTRACT.md` v1.1, SHA-256 `48b7eee19c63f219e3d0016d48745d5cd3f71962dae0c1209ec7a66adaf3dc56`
- `/home/victor/work/alpheus/Agent-Shared/PLANS/BUZZ_CI_THREAT_MODEL.md`, SHA-256 `2f127ef24dfe4b89a88e5b1d406287d7fb4e3de64c029c0c5aa127ce55a118be`
- product source baseline `660f83c55de5190b0ec2fcb3d6bca43715c8cdbf`

## 1. Dedicated event kinds

Repository-wide collision audit at the source baseline found `46100–46104` unused. They are dedicated to CI and do not reuse workflow lifecycle `46001–46007`, workflow approval `46010–46012`, workflow trigger `46020`, or approval commands `46030–46031`.

```text
46100 KIND_CI_REQUEST
46101 KIND_CI_RUN_STATUS
46102 KIND_CI_JOB_STATUS
46103 KIND_CI_LOG_REFERENCE
46104 KIND_CI_ARTIFACT_REFERENCE
46105 KIND_CI_EVIDENCE_FINALIZED
46106 KIND_CI_TEARDOWN_ATTESTATION
```

All seven are stored, signed, channel-scoped regular events. They are append-only facts, not NIP-33 replaceable heads.

## 2. Encoding and common invariants

Event `content` is one JSON object encoded from the typed envelope. Every envelope contains `schema_version: 1` and rejects unknown schema versions. Readers may ignore unknown fields within a known version, but writers do not emit them. Signed writers use deterministic struct field order; absent optional fields are omitted rather than emitted as `null`. Every integer-valued wire field is a non-negative JSON number no greater than `2^53-1`.

Required index tags:

```text
["h", <channel UUID>]
["a", <target_repo_a>]
["run", <run UUID>]
["workflow", <workflow_id>]
["c", <full tip OID>]
["attempt", <decimal u32>]
```

Job/log/artifact events also carry `["job", <job_id>]`. Status/reference events carry `["e", <request_event_id>, "", "request"]`. Log and artifact events carry `["x", <sha256>]`. Every duplicated tag value must equal its content field byte-for-byte; mismatch, duplicate singleton tag, malformed value, or missing required tag is rejected before storage.

All OIDs are lowercase full-length 40-hex SHA-1 or 64-hex SHA-256. Event IDs, pubkeys, workflow digests, adaptation digests, and content SHA-256 values are lowercase 64-hex. IDs are UUID strings unless explicitly identified as Nostr IDs. Timestamps are Unix seconds UTC. Attempt numbers begin at 1. Sequence numbers begin at 1.

The request signer must equal `actor`. Status/reference signers must be authorized runner/control-plane identities; the signer is the authoritative `relay_signer` and content may not override it.

For each status stream, `sequence` is strictly increasing:

- run stream key: `(run_id, attempt)`
- job stream key: `(run_id, job_id, attempt)`

Readers select within a status stream by sequence, never `created_at`. A gap leaves state pending reconciliation. Two different events for the same stream key and sequence are equivocation and fail the run closed as `infrastructure_failure`. State transitions must follow the closed transition table in §7. Global accepted-event order comes from the relay's durable `watch_cursor`; same-second event timestamps do not break ties or establish causality.

## 3. CI request envelope — kind 46100

```text
{
  schema_version,
  request_type,                 // "run" | "rerun"
  target_repo_a,
  pr_root_event_id,
  pr_update_event_id?,
  source_clone_url,
  immutable_source_ref,
  tip_oid,
  source_branch,
  base_ref,
  base_oid,
  workflow_id,
  workflow_digest,
  job_ids,                      // non-empty, unique static IDs
  run_id,
  attempt,
  parent_attempt?,
  parent_run_id?,
  trigger_event_id,
  actor,
  timeout_seconds,
  idempotency_key,
  issued_at,
  expires_at
}
```

`request_type="run"` is the one initial request for a `run_id`. It requires `attempt=1` and forbids `parent_attempt`/`parent_run_id`. `request_type="rerun"` appends a distinct kind-46100 request event to that run's lineage. It requires exactly one requested `job_id`, the same `run_id`, and both `parent_attempt` and `parent_run_id`; dependency fan-out is broker-computed and returned as `also_reruns`, never hidden in the request. A rerun is eligible only when the selected parent job is `failure`. Non-terminal `queued|running` returns `job_not_terminal`; terminal `success|skipped|cancelled|timed_out` returns `job_not_failed`. A terminal run-status `failure` does not by itself close the lineage, but acceptance of either terminal provenance fact, kind 46105 or kind 46106, does.

A rerun copies the original accepted request's complete immutable source/workflow tuple byte-for-byte: `target_repo_a`, PR event IDs, clone URL, immutable source ref, `tip_oid`, source branch, base ref/OID, workflow ID/digest, and trigger event ID. It never resolves current refs or current workflow state. Only request identity, exactly one selected `job_id`, attempt lineage, actor, timeout/expiry, and idempotency fields may change.

`idempotency_key` is unique in the actor/repository scope. Re-delivery of byte-identical accepted content returns the existing attempt; conflicting reuse is rejected. `expires_at` must be later than `issued_at` and inside broker policy. Signature proves authorship, not authorization: repository/channel role, source trust class, job allowlist, rate, concurrency, nonce, and expiry are independently enforced.

## 4. Run-status envelope — kind 46101

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  base_oid,
  attempt,
  sequence,
  state,
  conclusion?,
  reason?,
  started_at?,
  finished_at?,
  job_ids,
  relay_signer
}
```

Closed run states:

```text
queued | running | success | failure | cancelled | timed_out | infrastructure_failure
```

`queued` and `running` are non-terminal. All others are terminal. `infrastructure_failure` is emitted only for runner/control-plane/materialization/teardown/evidence failures and is never synthesized from a job exit code.

## 5. Job-status envelope — kind 46102

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  base_oid,
  job_id,
  name,
  attempt,
  parent_attempt?,
  sequence,
  state,
  conclusion?,
  reason?,
  required,
  skip_policy,
  selected_job_instance,
  also_reruns,
  started_at?,
  finished_at?,
  log_ref?,
  artifact_refs,
  relay_signer
}
```

Closed job states:

```text
queued | running | success | failure | cancelled | timed_out | skipped
```

`queued` and `running` are non-terminal. All others are terminal. `required`, `skip_policy`, matrix selection, and dependency fan-out are copied from signed broker manifest state; job-controlled output cannot change them.

`skip_policy` is the closed string enum `"forbid" | "allow"`. A skipped required job is terminal-good only with `"allow"`; `"forbid"` makes it red. Unknown values fail closed. Optional jobs still carry the signed policy so all readers interpret one grammar.

## 6. Evidence-reference envelopes

### Log reference — kind 46103

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  job_id,
  attempt,
  log_sha256,
  byte_length,
  cap_bytes,
  truncated,
  url?,
  inline?,
  created_at,
  relay_signer
}
```

Exactly one of `url` or `inline` is present. `inline` is canonical padded RFC 4648 base64 using the standard alphabet. `byte_length` and `log_sha256` are computed over the decoded scrubbed bytes, never the base64 text. Non-canonical base64, decoded length/hash mismatch, `byte_length > cap_bytes`, or `truncated=true` is a refusal. Identity binds the scrubbed bytes to `{request_event_id, run_id, tip_oid, job_id, attempt, byte_length, truncated}`. Scrub/encode/truncate occurs before hashing and before durable or channel-member-readable persistence. Overflow terminates the job; silent truncation is forbidden.

A `url` is accepted only when it has the HTTP(S) origin corresponding to the active relay (`wss` maps to `https`, `ws` maps to `http`), contains no credentials/query/fragment, and its exact path is `/ci/logs/{request_event_id}/{run_id}/{job_id}/{attempt}/{log_sha256}`. `GET` and `HEAD` require fresh NIP-98 authentication for the exact method and URL before the relay performs any request, event, or object lookup. A caller must be a current member of the repository's bound channel. Missing evidence and evidence requested by a non-member have the same response, so the route does not expose an existence oracle. The relay requires one authorized log-reference event and a terminal job-status event that names it, with exact repository, channel, request, run, workflow, tip, job, attempt, URL, byte length, cap, and digest bindings. It then verifies stored size and SHA-256 before responding. The decoded-byte ceiling is 32 MiB. The route supports one RFC 9110 byte range and returns `Accept-Ranges`, `Content-Range`, `Content-Length`, and `Digest`; `HEAD` returns the corresponding verified headers with no body. It never redirects and storage keys are built only from validated, fixed-grammar coordinates.

The capacity-one acceptance adapter deliberately exercises a narrower client
surface than this public route: full-body `GET` with an exact `200` response,
no `HEAD`, `Range`, or redirect, and a per-object bound equal to the signed
expected byte length with an independent 16 MiB ceiling. Its URL `attempt` is
the canonical positive decimal `u32` attempt number, not the broker's 16-byte
attempt ID rendered as 32 lowercase hex characters. These adapter restrictions
do not remove the public route's `GET`, `HEAD`, range, or 32 MiB contract.

The CLI uses a redirect-disabled client, buffers no more than the signed `cap_bytes`, and rejects a changed final URL. `logs --raw` verifies authorized signer, exactly one location, canonical decoding when inline, cap, exact decoded byte length, SHA-256, and `truncated=false` before writing any byte to stdout.

### Artifact reference — kind 46104

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  job_id,
  attempt,
  artifact_id,
  name,
  media_type,
  sha256,
  byte_length,
  url,
  created_at,
  relay_signer
}
```

Only allowlisted, quarantined, safely extracted, scanned, sanitized artifacts may receive a durable reference. No terminal green state may be signed before durable evidence publication and successful teardown. Kinds 46105 and 46106 are the explicit signed evidence-finalized and lease-empty facts defined by the companion relay/API contract; terminal run `success` alone is insufficient for green. Kind 46106 binds the complete selected per-job attempt graph rather than one run-wide lease.

## 7. State transitions and verdict

Allowed job transitions:

```text
queued -> running | cancelled
running -> success | failure | cancelled | timed_out | skipped
```

Allowed run transitions:

```text
queued -> running | cancelled | infrastructure_failure
running -> success | failure | cancelled | timed_out | infrastructure_failure
```

Terminal states never transition within their `(run_id, attempt)` or `(run_id, job_id, attempt)` stream. An eligible rerun after a failed job, including after terminal run-status `failure`, creates new run-status and job-status attempt streams. It never mutates prior attempts. Unknown states or illegal transitions fail closed.

Verdict is green only when the requested `expect_sha` equals `tip_oid`, all signed-manifest required jobs are terminal-good at their selected attempt lineage, each required skip is permitted by signed `skip_policy`, and the reducer independently verifies the authorized kind-46105 evidence-finalized fact and kind-46106 exact selected-job lease-set fact before terminal run success. Any non-terminal required job is pending. Required `failure`, `cancelled`, or `timed_out` is red. Infrastructure failure is separately reported and never presented as a code failure. Mixed-attempt selection, next-attempt derivation, transport routes, unique run lookup, signer authority, and watch replay/order are bound by `BUZZ_CI_RELAY_API_CONTRACT.md` v1.1.

## 8. Frozen CLI contract

```text
buzz ci run     --repo-owner <hex> --repo-id <d-tag> --sha <full-oid> [--workflow <id-or-digest>] [--jobs <ids>]
buzz ci status  --run <run-id>
buzz ci logs    --run <run-id> --job <job-id> [--attempt <n>] [--raw]
buzz ci rerun   --run <run-id> --job <job-id>
buzz ci verdict --run <run-id> --expect-sha <full-oid>
buzz ci watch   --run <run-id> --timeout-seconds <fixed-bound>
```

Success output is one JSON object on stdout, except `logs --raw` (raw scrubbed bytes) and `watch` (one JSON object per transition, then exit on run-terminal). Diagnostics and machine-readable error objects go to stderr; stdout is empty on failure except the explicitly typed infrastructure verdict below. Exit codes remain `0` success, `1` usage/validation/refusal, `2` network/relay, `3` auth, `4` infrastructure/other.

Exact success shapes:

```text
run:
{run_id, sha, workflow_digest, jobs:[{job_id,name}], attempt:1, state:"queued"}

status:
{run_id, sha, attempt, state, jobs:[{job_id,name,state,required,started_at,finished_at,attempt}]}

logs (default):
{run_id, sha, job_id, attempt, log_sha256, size, cap_bytes, truncated, url_or_inline}

rerun:
{run_id, sha, job_id, attempt, state:"queued", parent_attempt, also_reruns:[]}

verdict:
{run_id, sha, attempt, verdict:"green"|"red"|"pending", jobs_terminal, jobs_total, required_failing:[]}

infrastructure verdict (stdout, exit 4):
{run_id, sha, attempt, verdict:"infrastructure_failure", jobs_terminal, jobs_total, required_failing:[], reason}

watch transition:
{run_id, sha, attempt, sequence, scope:"run"|"job", job_id?, state, timestamp}
```

Required machine errors include:

```text
{error:"sha_mismatch",requested,resolved}
{error:"job_not_terminal",run_id,job_id,attempt,state}
{error:"job_not_failed",run_id,job_id,attempt,state}
{error:"attempt_limit",run_id,job_id,limit}
{error:"unknown_state",run_id,state}
{error:"state_equivocation",run_id,job_id?,attempt,sequence}
{error:"unauthorized"}
{error:"infrastructure_failure",run_id,reason}
```

Every state-bearing response echoes `{run_id, sha, attempt}`. CLI retries are bounded; exhaustion is nonzero. Read commands are headless and available only to authenticated members of the repository channel. Trigger/rerun events are signed by the requesting identity. No command prints or requires a signing/deploy credential beyond existing Buzz headless signing input.

## 9. v1.2 CLI resolution and acknowledgment binding

The compact `buzz ci run` grammar is unchanged. Before signing kind `46100`, the CLI performs an authenticated, read-only preflight from `{target_repo_a, requested tip_oid, workflow selector?, requested job_ids?}` and validates the complete immutable tuple locally. The broker never appends or rewrites a signed request field.

Source resolution is fail-closed and deterministic:

1. Query authorized, CI-eligible PR snapshots for the repository whose effective full `c` tag equals the requested `--sha`.
2. Resolve each snapshot as its kind `1618` root plus latest authorized kind `1619` update. Require exactly one effective snapshot; zero returns `source_not_found`, and more than one returns `source_ambiguous` rather than selecting by timestamp.
3. Copy `pr_root_event_id`, optional `pr_update_event_id`, `source_clone_url`, advertised `immutable_source_ref`, `source_branch`, `base_ref`, and full `base_oid` from that validated snapshot/repository state. `trigger_event_id` is the effective source event ID: `pr_update_event_id` when present, otherwise `pr_root_event_id`.
4. Resolve `--workflow` against workflow definitions authorized for the repository at the trusted full `base_oid`, never the PR source tip. An ID selects exactly one `workflow_id`; a 64-hex digest selects exactly one `workflow_digest`; omission requires exactly one eligible workflow. The CLI reads the canonical workflow bytes from the immutable `base_oid`, hashes them independently, and requires equality with the resolved digest before signing. Tip-divergent workflow bytes are never executed. The materializer independently fetches the same `base_oid` workflow bytes and refuses a digest mismatch. Zero matches return `workflow_not_found`; multiple matches return `workflow_ambiguous`.
5. Resolve omitted jobs to the workflow's complete signed static job set. Explicit `--jobs` must be a non-empty unique subset of that set. The CLI signs the resolved `job_ids`.

The preflight response is untrusted input despite authenticated transport. Before signing, the CLI requires the resolved `tip_oid` to equal the caller's exact `--sha` and the independently hashed trusted-base workflow bytes to equal the signed `workflow_digest`; mismatch refuses before signing.

Preflight HTTP or response-decoding failures produce empty stdout and one stderr JSON object with exactly `error`, `message`, and `retryable`. The message begins `CI preflight failed before request signing for <request-json>: `, where `<request-json>` is the compact request object in wire field order: `target_repo_a`, `requested_tip_oid`, then optional `workflow_selector` and `requested_job_ids`. This stage marker means no kind `46100` has been signed or submitted by that invocation; the read-only preflight itself uses NIP-98 authentication signing.

A nonempty HTTP 404 response retains its complete body as `relay error 404: <body>` after that prefix, with exit `2`, category `relay_error`, and `retryable:false`. This includes `source_not_found` and `workflow_not_found`; a 404 alone does not imply that the endpoint is absent. Only an empty HTTP 404 gets exit `4`, category `error`, and the cause `relay returned an empty HTTP 404 for /ci/preflight; the endpoint may be unavailable`. A failed body read remains a network error. Other HTTP, network, and decoding failures retain their existing exit/category/retryability with the same preflight prefix. Existing local validation errors keep their validation contract. Submission and acknowledgment errors never gain this preflight marker.

An operator checking a selector refusal must bind the exact effective PR tip, repository, selector, requested jobs, and trusted-base workflow cause, and require the entire expected stderr object and exit code. A missing PR snapshot, empty or malformed body, different status, retryable failure, or later-stage error is a different outcome.

The preflight also returns the broker policy bounds needed for a valid request. The CLI generates a fresh `run_id` and `idempotency_key` for each user invocation, derives `actor` from the active signer, sets `attempt=1`, chooses `timeout_seconds` within the returned policy, and sets `issued_at`/`expires_at` inside the returned expiry window. Retries within that one invocation reuse the byte-identical signed event and idempotency key; a new invocation generates new values, preserving the A3 requirement that identical SHA/workflow triggers create distinct runs.

Publishing kind `46100` is not itself success. `run` waits for a bounded broker-policy interval for an authorized, request-linked kind `46101` with matching immutable coordinates, `attempt=1`, `sequence=1`, and `state="queued"`. `rerun` waits for an authorized, request-linked kind `46102` for the selected job with matching immutable coordinates, requested attempt/parent lineage, `sequence=1`, and `state="queued"`; its signed `also_reruns` is the authoritative fan-out. A missing acknowledgment, wrong signer/linkage/sequence/state, or timeout exits nonzero with empty stdout. The CLI never invents queued state from publication acceptance.

For `buzz ci logs`, omitted `--attempt` means the greatest known attempt number for the named job, not the latest attempt that happens to have a log. If that selected attempt is non-terminal or has no finalized durable log reference, the command fails rather than returning stale evidence from an older attempt. An explicit `--attempt` always selects exactly that attempt.

Additional machine errors frozen by this binding are:

```text
{error:"source_not_found",requested}
{error:"source_ambiguous",requested,candidates}
{error:"workflow_not_found",selector?}
{error:"workflow_ambiguous",selector?,candidates}
{error:"log_unavailable",run_id,job_id,attempt}
```

`isolation_profile` remains the signed manifest object defined by the core design. Lease-local fields named `limits`, `egress_policy`, and `netns` do not collide with the common event tags or envelope fields, but they are only part of `isolation_profile`; they must not redefine it as that triple. The complete profile also binds the digest-pinned runner image, engine kind/version, architecture, network policy, and service requirements from `BUZZ_CI_DESIGN.md` §4.
