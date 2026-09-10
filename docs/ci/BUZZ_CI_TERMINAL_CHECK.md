# Buzz CI terminal check, cancellation, deadlines, rerun and concurrency

Status: implemented on the native CI plane for Spine B step 4 (Buzz issue
`913b7058dfb60d4e68b43be0e9a07bf721dfd06d70e8cc4c4f9c81c3627369cf`, under
GitHub #184). Companion to `BUZZ_CI_PROTOCOL_CONTRACT.md` v1.4, which this
document extends with one event kind. It changes no GitHub ruleset and no
required check; that cutover is a separate owner decision, described at the
end.

## 1. Terminal check, kind 46108

```text
46108 KIND_CI_CHECK
```

One signed, stored, channel-scoped regular event per run attempt, published by
the control plane after the terminal kind-46101 run status is durable. It is
the one event a merge gate reads: it carries the conclusion, the exact head
SHA, the run and attempt identifiers, and the IDs of the stored events it
summarises. It is a summary of already accepted facts. It never replaces the
reducer's evidence checks, and a reader that wants proof follows the event IDs
it names.

Content:

```text
{
  schema_version,                  // 1
  request_event_id,                // accepted kind 46100 this attempt executed
  run_id,
  workflow_id,
  target_repo_a,
  tip_oid,                         // exact head object ID
  base_oid,
  attempt,                         // one-based
  conclusion,                      // success | failure | cancelled | timed_out | infrastructure_failure
  reason?,                         // copied from the terminal run status
  run_status_event_id,             // the terminal kind 46101 event
  evidence_finalized_event_id?,    // kind 46105, present exactly when conclusion is success
  teardown_attestation_event_id?,  // kind 46106, present exactly when conclusion is success
  concurrency_group,               // see section 5
  published_at,
  relay_signer
}
```

Tags are the standard index set: `h`, `a`, `run`, `workflow`, `c`, `attempt`,
and `["e", <request_event_id>, "", "request"]`. Signer rules are the kind
46101 to 46106 rules: `event.pubkey == relay_signer`, and the signer must be in
the owner-configured status signer set or hold an active kind-46107 grant. The
relay admits the kind through the same CI ingest gate and stores it in the run
history; `GET /ci/runs/{run_id}/events` returns it in acceptance order.

The keyholder signs kind 46108 with the ci-event key. Kind 46107 stays
owner-signed; the signable set is 46101 to 46106 plus 46108, not a range.

Validation (`CiCheckEnvelope::validate`): terminal conclusion only; both
terminal fact IDs present when and only when the conclusion is success; 64-hex
event IDs; non-empty concurrency group. `validate_context` binds the check to
its request: same run, workflow, repository, tip, base, attempt, and the group
key derived from the request.

Relay storage (`buzz_db::ci::store_ci_event`, migration
`0041_ci_check_storage`) cross-checks the facts a check names before it is
indexed: `run_status_event_id` must be a stored kind 46101 for the same
request and attempt, terminal, with the same state and reason as the check;
`evidence_finalized_event_id` and `teardown_attestation_event_id`, when
present, must be stored kinds 46105 and 46106 for the same request and
attempt. One check per request: a byte-identical replay returns the stored
event, a different second check for the same request is refused, and a
partial unique index on `(community_id, request_event_id)` for kind 46108
holds the same rule under concurrent writers.

### Reader rules

`buzz ci status` reports the check under `check` (or `null`). The reducer
selects the check whose `request_event_id` is the final accepted request in
the lineage, so the latest attempt decides; checks for earlier attempts are
history. The selected check must name the accepted terminal run status for
that request by event ID, follow it in relay acceptance order, and carry the
same conclusion. Two different checks for one request, or a check that
contradicts its run status, reduce to `infrastructure_failure`. A missing
check never changes the verdict; the verdict still comes from the reducer's
own evidence rules.

Control plane binding: the durable run record stores `check_event_id` next to
`terminal_event_id`. Restart republishes a missing check through the same
durable publication intent as every other event, so one attempt has one check.

## 2. Cancellation

controld's runner v2 executor now reconciles an admitted attempt in a loop
that takes one stop decision between broker reads, in this order:

1. a queued `AttemptCommand::Cancel` on the executor's command channel;
2. the caller's watch, which the production handler uses for concurrency
   supersession (section 5);
3. the wall deadline (section 3).

A decision sends one exact broker `CancelAttempt` (reason `UserRequest` for 1
and 2, `SignedPolicy` for 3) and the loop keeps reading until execd records
the terminal binding. The stop is proven by the runner's terminal state, never
by a local flag. execd kills the job's process group (`SIGTERM`, then
`SIGKILL`) and reaps it before it answers.

Recorded state: job `cancelled` with reason `cancelled_by_request` or
`concurrency_superseded_by:<event id>`; run `cancelled`; check conclusion
`cancelled`.

Proof: `production_v2::tests::process_tests::cancel_command_kills_the_running_job_process_group_and_records_cancelled`
runs a real `sh -c 'sleep 300 & exec sleep 300'` in its own process group
behind a fake broker; after the cancel the group answers `ESRCH`.
`normal_backend::executor_handoff::tests::cancel_frame_kills_a_real_process_group_before_reporting_exited`
proves the same for execd's production kill path.

## 3. Wall-clock deadlines

Per job: the admission's `wall_timeout_seconds` (the request's
`timeout_seconds`), judged from the broker's admission time. execd expires the
lease at the same deadline. If controld reaches the deadline first it sends a
`SignedPolicy` cancellation and records the job `timed_out` with reason
`wall_deadline_exceeded`. If neither a terminal state nor an accepted
cancellation arrives within ten seconds past the deadline the attempt is an
`infrastructure_failure`.

Per run: `timeout_seconds` measured from the moment the request was queued
(`issued_at`) bounds the whole attempt, evidence sealing included. An attempt
whose `finished_at` passes that bound is recorded `timed_out` with reason
`run_deadline_exceeded`, and no terminal facts are published for it. With one
job per run the two deadlines coincide in practice; they are enforced at
different layers so a multi-job run keeps a run-level ceiling.

Before this change a deadline reached at controld became
`infrastructure_failure` with reason `runner_or_evidence_provider_failure`.

## 4. Rerun semantics

A rerun is a new attempt bound to the same source commit. controld validates
lineage against its own durable store before executing: `parent_run_id` equals
`run_id`, `attempt == parent_attempt + 1`, a stored parent attempt exists,
is terminal, and has the same `tip_oid`, `workflow_id`, and `target_repo_a`.
A rerun that fails these checks is recorded `infrastructure_failure` with
reason `rerun_lineage_mismatch:<detail>` and never reaches the executor. The
relay enforces the same lineage; controld fails closed on its own record
rather than trust it.

Prior attempts stay immutable: each attempt has its own run record, run
status stream, job status stream, and check. The latest attempt decides: the
reducer selects the final request's check and the greatest contiguous attempt
per job.

## 5. Concurrency groups

Key shape follows the GitHub `CI` workflow's
`ci-${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.sha }}`.
On a `pull_request` event `github.ref` is `refs/pull/<N>/merge`, one group per
pull request, not per branch name. The Buzz equivalent of that ref is the PR
root event, scoped by the repository coordinate because one channel can serve
more than one repository:

- `ci-<workflow_id>-<target_repo_a>-<pr_root_event_id>-<source_branch>` for
  a pull-request request (every kind 46100 request carries its PR root
  event), with `cancel_in_progress = true`;
- `ci-<workflow_id>-<target_repo_a>-<tip_oid>` otherwise, with
  `cancel_in_progress = false`.

`source_branch` is requester-signed and never checked against the pull
request, so it names the ref but never identifies the group on its own: two
forks pushing the same branch name, or two repositories on one channel, are
different groups and never cancel each other.

The key is recorded on the check as `concurrency_group`.

Behaviour at capacity one:

- Queued head: when the channel head is a PR request and a later accepted
  initial request for a different run shares its group (look-ahead of eight),
  the head is recorded `cancelled` with reason
  `concurrency_superseded_by:<event id>` without executing, its terminal
  status and check are published, and the cursor moves on.
- Running attempt: every fifth reconciliation tick the handler reads the
  same look-ahead window of eight accepted requests after the running one;
  a same-group initial request anywhere in that window cancels the running
  job through the watch seam in section 2, so an unrelated request accepted
  right after the running one does not hide a later same-group request.
- A rerun of the same run never supersedes its own lineage. Acceptance-bound
  polls (`poll_once_bound`) never look ahead.

## 6. What a ruleset cutover would still need

Nothing here touches GitHub. For Buzz results to hold merge authority the
owner would have to decide and do the following, in order:

1. Choose the authority path. Either (a) a bridge that turns each accepted
   kind-46108 event into a GitHub check run (`POST
   /repos/{owner}/{repo}/check-runs` with `head_sha = tip_oid`, a fixed
   `name` such as `buzz-ci`, `conclusion` mapped from the check, and
   `details_url` pointing at the run), or (b) a Buzz-side merge gate that
   reads kind 46108 directly and performs the merge. Path (a) needs a GitHub
   App credential with `checks:write`, kept in the keyholder's custody rules;
   path (b) needs the relay's merge path to consult the reducer. Neither
   exists today; this change deliberately builds no Checks bridge.
2. Configure the authorized signer set for production: the controld ci-event
   key must be in `ci_status_signer_pubkeys` or hold an active kind-46107
   grant for the channel and repository, or the relay refuses kind 46108.
3. Run the native plane at nonzero capacity for the `CI` workflow's required
   jobs (Spine A) and prove parity against
   `docs/ci/workflow-inventory.required-checks.json` for a sample of merged
   pull requests: every required context listed there must have a native
   job whose check conclusion agrees with GitHub's, or an accepted
   disposition in `workflow-inventory.dispositions.json`.
4. Only then edit the `main` ruleset (Victor's decision): add the bridged
   context `buzz-ci` as a required check while the GitHub contexts remain
   required; observe; then drop GitHub contexts in the reviewed reversible
   order the inventory's exit conditions describe. `desktop-build-macos` and
   `validate` have no native producer and stay on GitHub until they do.
5. Keep the receipt path: `scripts/protected-ci-receipt.py` must learn the
   bridged context, and `scripts/pre-freeze.sh` must accept a kind-46108
   check as evidence alongside the GitHub receipt.

Until step 4 lands, GitHub keeps the gate and this change only makes the Buzz
side able to publish a terminal result a ruleset could later require.

## 7. Relay merge gate (authority path b)

The relay's pre-receive policy callback can require a green kind-46108 check
before a protected ref moves. Design: `BUZZ_MERGE_GATE_DESIGN.md`. Code:
`crates/buzz-relay/src/api/git/merge_gate.rs`, `hook.rs`, `policy.rs`, and
the publish fence in `transport.rs`. Storage: migration `0042_ci_merge_gate`.

### Configuration

| Variable | Values | Default |
|----------|--------|---------|
| `BUZZ_MERGE_GATE_MODE` | `off`, `shadow`, `enforce`; any other value fails config load | `off` |
| `BUZZ_MERGE_GATE_CHECK_MAX_AGE_SECONDS` | 1 to 604800; longest age of the selected check by relay `accepted_at` | 86400 |
| `BUZZ_MERGE_GATE_DECISION_WINDOW_SECONDS` | 1 to 900; longest gap between the hook decision and the publish fence | 300 |

`off` evaluates nothing and logs each gated ref as skipped. `shadow`
evaluates every gated ref, writes the decision record, logs
`merge_gate decision=<allow|refuse> code=<code>`, and never refuses.
`enforce` refuses on every refusal code and fails closed on its own errors.

### Scope: the `require-check` rule

A repository opts in through its kind-30617 announcement:

```text
["buzz-protect", "refs/heads/main", "no-force-push", "no-delete",
 "require-check:ci:backend-integration+dead-token-guard+desktop+desktop-e2e-integration+desktop-e2e-relay+mobile+relay-e2e+rust-lint+security+unit-tests+web"]
```

`require-check:<workflow_id>:<job_id>[+<job_id>...]` names the workflow whose
terminal check is required and pins the job ids that must be green. Two
values for one workflow merge their job ids; two workflow ids require both.
The pinned set lives in the owner-signed announcement, never in the
candidate tree. A malformed value is a malformed protection rule and denies
every push to the repository, like a bad `push:<role>`.

### What the gate requires

For a fast-forward (`parents == [old]`) the candidate is the new commit;
for a landing merge (`parents == [old, candidate]`, candidate contains
`old`, merge tree equals the candidate tree) the candidate is the second
parent. The hook computes these facts in git's quarantine and binds them
into the HMAC payload. The gate then takes the latest `ci_runs` row for
`(repository, candidate, workflow_id)` whose `base_oid` is the ref's current
tip and whose `workflow_digest` equals the digest of
`.github/workflows/ci.yml` at that tip, reads only that run's events,
validates each against the live signer union (`ci_status_signer_pubkeys`
plus active kind-46107 grants), reduces them with the shared reducer, and
requires `green` with every pinned job requested, `required: true` and
successful. The selected check must conclude `success`, name the candidate
and base, be signed by the union, and have been accepted by the relay inside
`BUZZ_MERGE_GATE_CHECK_MAX_AGE_SECONDS`; `published_at` is never consulted.

### Kind 46109, owner bypass

`KIND_CI_MERGE_BYPASS = 46109` is signed by the repository owner (the
kind-30617 author, who must also hold the channel owner or admin role) with
content `{schema_version, target_repo_a, ref_name, old_oid, new_oid, reason,
issued_at, expires_at}` and the `h` and `a` index tags. The window is at
most one hour. The gate keys the lookup on the coordinate it resolved from
the pushed repository's own announcement, accepts a bypass only for exactly
`(ref_name, old_oid, new_oid)` inside its window and unconsumed, and records
it on the decision. Consumption (`ci_merge_bypasses.consumed_by`, the
allowing decision row) happens only after the publish CAS wins, so a bypass
evaluated in `shadow` or on a push that lost the CAS race stays usable.

### Decision record and publish fence

Every evaluation appends one `git_merge_gate_decisions` row (repository,
ref, old, new, candidate, classification, run, check, signer, code, mode,
pusher, bypass, `decided_at`). In `enforce` mode `finalize_push` requires an
`allow` row for exactly `(ref, old, new, pusher)` decided inside
`BUZZ_MERGE_GATE_DECISION_WINDOW_SECONDS` before it publishes a gated ref.

### Refusal codes

The pusher sees `remote: error: push denied by policy (HTTP 403)` with a
JSON denial whose reason reads `merge gate: <code>: <detail>`, identifiers
shortened to 12 hex (the relay log keeps them complete):

| Code | Meaning |
|------|---------|
| `no_check` | No run for the candidate, or the run has no accepted kind-46108 yet |
| `check_pending` | The selected run's latest attempt is still running |
| `check_not_success` | The run reduced red, or the check concludes other than `success` |
| `reducer_disagrees` | The history is inconsistent, or the check disagrees with the reduction |
| `base_moved` | The run or check names another base than the ref's current tip |
| `not_descendant` | The merge's second parent does not contain the base |
| `parent_shape` | Not a fast-forward and not a two-parent merge whose first parent is the base |
| `tree_mismatch` | The merge tree differs from the candidate tree |
| `workflow_digest_mismatch` | The run was digested against another workflow than the one at the base |
| `required_jobs_missing` | A pinned job was not requested, not required, or not successful |
| `signer_unauthorized` | A run event or the check is signed outside the live signer union |
| `check_expired` | The check's relay `accepted_at` is older than the configured age |
| `bypass_invalid` | The only bypass for this update is consumed, outside its window, or not the owner's |
| `gate_misconfigured` | The gate could not decide: hydration, database, workflow, signer union, or an over-long history |
