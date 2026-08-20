# BUZZ_CI_RELAY_API_CONTRACT.md — Phase-1 relay/API and reducer contract

Status: **CORRECTED TERMINAL-ATTESTATION BINDING v1.1 (2026-08-20)**

Companion to `BUZZ_CI_PROTOCOL_CONTRACT.md` v1.4. This artifact freezes the context-aware transport, trust, indexing, replay, attempt-selection, and terminal-attestation rules that the typed envelopes alone cannot enforce.

## 1. Authority and authentication

Both endpoints use the relay's existing host-derived community boundary and NIP-98 authentication. The authenticated pubkey must be a current member of the repository's bound channel. Transport authentication does not make response fields trusted.

The authorized CI status/control-plane signer set is owner-configured state loaded by the relay and CLI from the same administrative configuration source. It is never accepted from a preflight, lookup, status, log, artifact, or other relay response field. Configuration must be non-empty before CI can acknowledge a request. Rotation is explicit and audited; events are accepted only when their signer was authorized for the event's recorded run/attempt.

## 2. `POST /ci/preflight`

Request:

```text
{
  target_repo_a,
  requested_tip_oid,
  workflow_selector?,
  requested_job_ids?
}
```

Response:

```text
{
  target_repo_a,
  pr_root_event_id,
  pr_update_event_id?,
  trigger_event_id,
  source_clone_url,
  immutable_source_ref,
  tip_oid,
  source_branch,
  base_ref,
  base_oid,
  workflow_id,
  workflow_path,
  workflow_digest,
  canonical_workflow_base64,
  jobs:[{job_id,name,required,skip_policy,needs}],
  selected_job_ids,
  policy:{
    min_timeout_seconds,
    max_timeout_seconds,
    max_expiry_seconds,
    acknowledgement_timeout_seconds,
    max_attempts
  }
}
```

The relay resolves exactly one authorized effective PR snapshot whose full `tip_oid` equals `requested_tip_oid`; `trigger_event_id` equals `pr_update_event_id` when present and otherwise `pr_root_event_id`. The workflow is resolved only from canonical bytes at the trusted full `base_oid`. Jobs are static IDs using `^[A-Za-z0-9_]{1,64}$`, non-empty and unique.

Before signing kind 46100, the CLI independently requires: exact repository/tip equality; exact effective-trigger equality; a safe credential-free clone URL; a non-empty advertised immutable ref; SHA-256 of decoded `canonical_workflow_base64` equals `workflow_digest`; and selected jobs are a non-empty unique subset of the returned static set. Preflight fields never supply or extend the authorized signer set.

## 3. `GET /ci/runs/{run_id}/request`

Response:

```text
{
  run_id,
  request_event_id,
  request_event
}
```

`request_event` is the complete canonical signed kind-46100 event. The relay maintains a unique transactional index `run_id -> request_event_id`. A conflicting second accepted request for one `run_id` is rejected; byte-identical redelivery returns the existing mapping. The CLI verifies event ID/signature, kind, actor binding, exact tags, channel membership scope, and content `run_id` before using the response. Subsequent event reads use exact `e=request_event_id` and `h=channel_id` filters.

## 4. Context-aware event acceptance

For every CI event, the relay verifies event ID and Schnorr signature, exact kind-to-content type, schema version, all required tags, absence of forbidden reserved tags, and content/tag byte equality.

Kind 46100 requires `event.pubkey == actor`. Kinds 46101–46106 require `event.pubkey == relay_signer` and membership in the owner-configured signer set. Rerun acceptance loads the original accepted request and the selected failed parent job, requires byte-for-byte immutable tuple equality, one-based contiguous lineage, and state-routed eligibility:

- `queued|running` -> `job_not_terminal`
- terminal non-failure -> `job_not_failed`
- `failure` -> eligible

Status acceptance enforces signed-manifest equality for required/skip/matrix/fan-out policy; strictly increasing stream sequence without gaps; no equivocation; legal transitions; and `finished_at >= started_at`.

## 5. Explicit terminal facts

Two additional append-only signed kinds are allocated after repository-wide collision audit:

```text
46105 KIND_CI_EVIDENCE_FINALIZED
46106 KIND_CI_TEARDOWN_ATTESTATION
```

Kind 46105 content:

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  attempt,
  finalized_job_attempts:[{job_id,attempt,log_ref,artifact_refs}],
  finalized_at,
  relay_signer
}
```

Every required selected job attempt appears exactly once. `log_ref` and every artifact reference are unique 64-lowerhex event IDs that resolve to already stored, signer-authorized, run/job/attempt-bound durable evidence events. `finalized_at` is after those events.

Kind 46106 content:

```text
{
  schema_version,
  request_event_id,
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,
  base_oid,
  workflow_digest,
  attempt,
  leases:[{job_id,attempt,lease_id}],
  lease_empty:true,
  teardown_at,
  relay_signer
}
```

`leases` is a non-empty set encoded in strict ascending `(job_id,attempt,lease_id)` order. Job IDs use the static job grammar, attempts are one-based, every `{job_id,attempt}` occurs once, and every non-empty `lease_id` occurs once. The top-level `attempt` equals the maximum selected job attempt. The reducer derives the complete selected `{job_id,attempt}` graph from the accepted request and gap-free status lineage and requires exact set equality and cardinality: no missing, extra, duplicated, or stale lease can satisfy green.

The context-aware validator resolves `request_event_id` to the accepted kind-46100 request and requires exact equality of `run_id`, repository `a`, `tip_oid`, `base_oid`, `workflow_id`, and `workflow_digest`; `tip_oid` and `base_oid` must use the same supported OID width. The attestation is emitted only after the isolation substrate proves every listed per-job lease has no surviving workspace, process, mount, namespace, network rule, secret material, or writable state across its dedicated materializer, executor, and runtime principals. `lease_empty=false` is invalid and cannot satisfy teardown.

A terminal run `success` event alone is never green. The reducer independently verifies one authorized evidence-finalized event and one authorized exact-selected-graph lease-empty teardown event, both stored before the terminal success event. Missing, malformed, unauthorized, conflicting, or out-of-order facts produce `pending` while facts may still arrive, or `infrastructure_failure` once the run is terminal/fact deadline expires; they never produce green.

## 6. Mixed attempts and reruns

Each job's selected attempt is the greatest accepted attempt in its contiguous lineage. Untouched jobs remain selected at their prior attempt. The top-level status/verdict `attempt` is the maximum selected job attempt, not an assertion that every job ran at that number. `jobs[*].attempt` is authoritative per job.

The next rerun attempt for a selected failed job is `selected_job_attempt + 1`; `parent_attempt` is exactly the selected failed attempt. Global maximum attempts are checked against the new attempt. Hidden whole-run restarts are forbidden; signed `also_reruns` enumerates every dependency fan-out job and each receives the same new attempt with its own contiguous parent.

## 7. Watch ordering and replay

Per-envelope `sequence` remains stream-local and is never presented as a global order. On accepted CI event insertion, the relay transactionally assigns a durable, strictly increasing `watch_cursor` within the run's unique request index. The cursor orders storage acceptance, not event `created_at`.

`buzz ci watch --run <run_id>` first resolves the request, then requests events after an optional cursor. Each output record is:

```text
{
  run_id,
  sha,
  attempt,
  watch_cursor,
  event_id,
  scope:"run"|"job"|"evidence"|"teardown",
  job_id?,
  state?,
  timestamp
}
```

Replay is inclusive only when explicitly requested; the default `after=<cursor>` is exclusive. Reconnect resumes from the last fully emitted cursor. Duplicate cursor/event pairs are suppressed; a cursor gap triggers bounded replay and remains pending if unreconciled. The stream exits only after the terminal run event and both required terminal facts have been emitted or after a typed infrastructure failure.

## 8. Canonical wire encoding

Signed envelope writers use deterministic struct field order and canonical JSON bytes. Absent optional fields are omitted, never serialized as `null`. Exactly one of log `url|inline` means the other key is absent. All integer-valued wire fields are non-negative JSON numbers no greater than `2^53-1`; out-of-range values are rejected. Exact serialized bytes for every envelope kind are pinned in tests.

Inline base64 encoded length is bounded from `cap_bytes` before allocation or decode, then canonical padded RFC-4648 form, decoded length, SHA-256, and truncation are verified.

## 9. Reducer green rule

Green requires one immutable request identity, exact expected tip, legal and gap-free status histories, all signed-manifest required jobs terminal-good at their selected attempts, authorized durable evidence references, one valid kind-46105 fact, one valid kind-46106 fact whose lease tuples exactly equal the selected job-attempt graph, and terminal run success ordered after both facts. Any equivocation, signer failure, immutable-coordinate mismatch, evidence failure, teardown failure, or terminal missing-fact deadline becomes `infrastructure_failure`; required code/test failure remains red; non-terminal work remains pending.
