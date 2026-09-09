# Buzz merge gate and native landing verifier

Status: design for authority path (b) of `BUZZ_CI_TERMINAL_CHECK.md` section 6
(Victor, 2026-09-09: Buzz holds merge authority for `main`; GitHub is a mirror).
Nothing here changes a GitHub ruleset; the gate ships default off. Line
references are against main `4064707215afad1e912e31df852cf32a17607645`.

## 1. Merge gate on the relay

### 1.1 Where it runs

The gate is a new step in the existing pre-receive callback
`hook_policy_check` (`crates/buzz-relay/src/api/git/policy.rs`), after step 9
`evaluate_push` allows the push, in a new module
`crates/buzz-relay/src/api/git/merge_gate.rs`. The receive-pack flow in
`transport.rs` (`receive_pack`, lines 1121 to 1233) is unchanged; a gate
refusal is a hook decline, so `finalize_push` publishes nothing (line 1836).

The hook must supply commit facts the relay cannot read, because pushed
objects sit in git's quarantine. The hook script (`hook.rs`,
`PRE_RECEIVE_HOOK`) adds, per ref update whose `new_oid` is not zero, five
fields computed with the inherited quarantine environment:

- `parents`: ordered parent OIDs of `new_oid` (`git rev-list --parents -n 1`).
- `tree`: `git rev-parse <new_oid>^{tree}`.
- `parent_trees`: `git rev-parse <parent>^{tree}` for each parent, in order.
- `old_in_second_parent`: `git merge-base --is-ancestor <old_oid> <parents[1]>`
  when there are two parents, else false. Exit 128 counts as false.
- `workflow_blob`: `git rev-parse <old_oid>:<DEFAULT_WORKFLOW_PATH>` (the path
  preflight resolves, `api/ci.rs` line 115), empty when absent. The gate
  digests the bytes itself with `git cat-file blob` on the hydrated
  workspace, since `old_oid` is published and outside quarantine.

`HookRefUpdate` gains the same fields. The HMAC payload (`compute_hmac`,
`policy.rs` line 142, and its bash mirror) appends
`len(parents):p1p2...|tree|len(parent_trees):t1t2...|old_in_second_parent|workflow_blob`
after `is_ancestor` for every ref; the `bash_hmac_matches_rust_hmac` fixtures
change together. Create and delete send empty values and false.

### 1.2 Scope selection

A repository opts in through its own kind 30617 announcement. A new
`buzz-protect` rule `require-check:<workflow_id>:<job_id>[+<job_id>...]`
(parsed in `buzz_core::git_perms::parse_protection_tag_with_warnings`, next to
`no-force-push`) marks a ref pattern as gated, names the workflow whose
terminal check is required, and pins the job ids that must be green:

```text
["buzz-protect", "refs/heads/main", "no-force-push", "no-delete",
 "require-check:ci:backend-integration+dead-token-guard+desktop+desktop-e2e-integration+desktop-e2e-relay+mobile+relay-e2e+rust-lint+security+unit-tests+web"]
```

The pinned set lives in the owner-signed announcement, never in the candidate
tree, because kind-46100 `job_ids` and `workflow_digest` are requester-signed
(`buzz-core/src/ci.rs` lines 164 to 168) and the reducer reduces over
`request.job_ids`. `EffectiveRules::for_ref` (`git_perms.rs` line 474) unions
matching patterns: two values for one ref merge into one requirement per
workflow with the union of job ids; two workflow ids require both. Job ids
use the static grammar `^[A-Za-z_][A-Za-z0-9_-]{0,63}$`.

The relay honours the rule only when `BUZZ_MERGE_GATE_MODE` is `shadow` or
`enforce`; in `off` it is logged as skipped like an unknown rule today
(`policy.rs` line 320), so the announcement can carry it before the relay
deploys. The owner declares refs, workflow, and jobs; the operator decides
whether the relay acts.

### 1.3 Candidate and what the gate requires

For every gated ref update the gate classifies the push:

- Fast-forward: `is_ancestor` true and `parents == [old_oid]`. The candidate
  is `new_oid`, the base is `old_oid`.
- Merge landing: exactly `parents == [old_oid, candidate]`,
  `old_in_second_parent` true (the candidate already contains main, so the
  merge cannot revert anything landed since the run's base), and
  `tree == parent_trees[1]` (the rule `protected-ci-landing.py` enforces
  today). The candidate is the second parent, the base is `old_oid`.
- Anything else is refused `parent_shape`, `not_descendant`, or
  `tree_mismatch`. Create and delete of a gated ref stay with the existing
  `no-delete` and role rules.

Then the gate resolves the run. A new `buzz_db::ci::list_runs_for_tip` uses
`idx_ci_runs_repo_tip` (`migrations/0032_ci_event_storage.sql`) to return every
`ci_runs` row for `(community, target_repo_a = 30617:<repo_owner>:<repo_id>,
tip_oid = candidate, workflow_id = <rule value>)` by `created_at DESC`. The
latest run decides, as in today's provider chronology rule, and must satisfy:

1. `base_oid` of the run equals `old_oid`, else `base_moved`. Ancestry is
   proven by the hook facts above; a requester-signed `base_oid` never is.
2. `ci_runs.workflow_digest` equals the SHA-256 of the workflow blob at
   `old_oid` named by the hook's `workflow_blob`, else
   `workflow_digest_mismatch`: a candidate that edits the workflow file, or a
   run built on another base's bytes, cannot pass. A missing blob at
   `old_oid` is `gate_misconfigured`.
3. Its accepted events, read with `list_ci_run_events(after_cursor = 0)` in
   pages until short (the cursor is exclusive), reduce to `Green` under the
   shared reducer with `expected_sha = candidate`; else `check_pending`
   (`Pending`), `check_not_success` (`Red`), or `reducer_disagrees`
   (`InfrastructureFailure`, or a `success` check while the reducer is not
   green). `load_ci_reducer_events` is not widened; it feeds the relay's own
   selected-graph reducer.
4. The reduced green set covers the pinned job ids: each appears in
   `request.job_ids`, is `required: true` in its signed manifest, and is
   terminal-good at its selected attempt; else `required_jobs_missing`, even
   for a green run over a subset.
5. The reduction's selected kind-46108 check has conclusion `success`,
   `tip_oid == candidate`, `base_oid == old_oid`; none yet is `no_check`.
   `CiReducedCheck` carries no envelope, so a new
   `buzz_db::ci::load_ci_check(community, run_id, check_event_id)` returns
   the stored event by id with its `accepted_at`, and the gate re-validates
   it with `validate_signed_ci_event`. The reducer selects the final accepted
   request's check, so attempt 2 supersedes attempt 1.
6. `check.relay_signer` is in the union of `config.ci_status_signer_pubkeys`
   and `get_active_ci_signers(now)` for the repository channel, the union
   `api/ci.rs` line 1681 builds, so a revoked signer's old checks stop
   counting; else `signer_unauthorized`.
7. Fresh by the relay clock: `now - ci_run_events.accepted_at <=
   BUZZ_MERGE_GATE_MAX_CHECK_AGE_SECONDS` (`buzz-db/src/ci.rs` line 355);
   `published_at` and `created_at` are signer-chosen and never consulted.
   Default 86400, the landing verifier's `MAX_AGE`; else `check_expired`.

Reducer reuse: move `crates/buzz-cli/src/commands/ci/reducer.rs` to
`crates/buzz-core/src/ci/reducer.rs` (it depends only on `buzz_core::ci`,
`serde`, `thiserror`) and re-export it from the CLI. The one visibility
change: `validate_accepted_run` goes from `pub(super)` (line 146, used by
`dispatch.rs`) to `pub`; every rule, output shape, and test is preserved. The
relay validates each stored event with `validate_signed_ci_event` against the
signer union and builds `AcceptedCiEnvelope { event_id, watch_cursor,
envelope }` exactly as `dispatch::fetch_ci_run_snapshot` does.

### 1.4 Refusal the pusher sees

The callback answers 403 with the existing `HookCallbackResponse` shape; the
hook prints the body to stderr, which git relays over sideband, so the pusher
sees `remote: error: push denied by policy (HTTP 403)`, the JSON denial, and
`! [remote rejected] main -> main (pre-receive hook declined)`. Reason
grammar: `merge gate: <code>: <detail>`, codes `no_check`, `check_pending`,
`check_not_success`, `reducer_disagrees`, `base_moved`, `not_descendant`,
`parent_shape`, `tree_mismatch`, `workflow_digest_mismatch`,
`required_jobs_missing`, `signer_unauthorized`, `check_expired`,
`bypass_invalid`, `gate_misconfigured`. Detail names candidate, base, check
and run ids (12 hex in the message, complete in the log record).

### 1.5 Owner override

A new owner-signed kind `46109 KIND_CI_MERGE_BYPASS`, stored through the CI
ingest gate like kind 46107 (`handlers/ingest.rs` line 2867), with content
`{schema_version: 1, target_repo_a, ref_name, old_oid, new_oid, reason,
issued_at, expires_at}`.
Acceptance: `event.pubkey` is the kind-30617 author and holds the channel
Owner role; `expires_at - issued_at <= 3600`; `reason` non-empty; the `a` and
`h` tags match. `is_ci_event_kind` (`ingest.rs` line 57) admits the kind, and
`required_scope_for_kind` maps it to `JobsWrite` like kind 46107. Storage is a
new table `ci_merge_bypasses` (migration 0042) keyed by `(community,
event_id)`, indexed on `(community, target_repo_a, ref_name, old_oid,
new_oid)`; it is not a run event, so migration 0041's `ci_run_events` CHECK
is untouched. The gate accepts a bypass only when `ref_name`, `old_oid`, and
`new_oid` equal the push exactly, the event is inside its window, and it is
unconsumed. Consumption happens in `finalize_push` after `cas_publish` returns
`Won`, never at hook time, so a bypass evaluated in `shadow` or on a push
that loses the CAS race (409) stays usable until it expires; the consuming
publish writes the bypass event id into the decision record (1.7) under a
unique index. Role implies no bypass; the owner signs one exact merge commit.

### 1.6 Configuration and failure modes

- `BUZZ_MERGE_GATE_MODE`: `off` (default), `shadow`, `enforce`. Any other
  value fails config load and the relay does not start.
- `BUZZ_MERGE_GATE_MAX_CHECK_AGE_SECONDS`: default 86400, ceiling 604800.
- `BUZZ_MERGE_GATE_DECISION_WINDOW_SECONDS`: default 300, the value of
  `PACK_OPS_TIMEOUT` (`transport.rs` line 45), ceiling 900. See 1.7.

`shadow` evaluates everything, writes the decision record, logs
`merge_gate decision=<allow|refuse> code=...`, and never refuses. `enforce`
fails closed: a database error, an empty signer union, a rule naming no
workflow or job, a callback missing the new fields, or a reducer panic guard
all answer 403 `gate_misconfigured`.

### 1.7 Decision record and the finalize fence

Every evaluation inserts one append-only row in a new table
`git_merge_gate_decisions` (migration 0042): community, repo coordinate, ref,
old, new, candidate, classification, run id, check event id, signer, code,
mode, pusher, bypass event id (unique when present), decided_at. In `enforce`
mode `finalize_push` adds a second fence before `cas_publish`: every gated
ref that changed in the workspace needs an `allow` row for exactly `(ref,
old, new, pusher)` with `decided_at` within
`BUZZ_MERGE_GATE_DECISION_WINDOW_SECONDS` of now (measured from the hook
decision; the default equals the pack subprocess timeout). Otherwise the push
is refused 403 `gate_misconfigured`, which closes the case where the hook did
not run at all.

### 1.8 Concurrency, reruns, mirror

Two pushes racing: both hydrate the same parent state and both hooks may
pass. `cas_publish` lets one win; the loser gets 409 (`transport.rs` line
1894) and retries with the winner's head as `old_oid`, so the run's
`base_oid` no longer matches and the gate answers `base_moved`. The loser
needs a fresh candidate and a new run: strict by design, equal to the
"require branches to be up to date" rule the ruleset enforces today. Main
moving between check publication and push takes the same path, because the
gate compares only against the `old_oid` git reports. Rerun lineage comes
from the reducer's final-request selection: a running attempt 2 reduces to
`Pending` and the candidate is refused `check_pending`. Mirror:
`buzz-github-mirror.timer` (host unit, every two minutes) keeps force-syncing
all heads and tags; a refused push publishes no pointer, so the mirror sees
nothing, and the gate reads no GitHub state.

## 2. Buzz-native landing verifier

### 2.1 Choice: `buzz ci landing`

A Rust subcommand in `crates/buzz-cli/src/commands/ci/landing.rs`, not a
Python script: the CLI already has NIP-98 signing, `validate_signed_ci_event`,
the signer set, the reducer, `ls-remote` helpers in `repo_sync.rs`, and GitHub
reads in `repos/reconcile.rs`. Python would need a second Schnorr verifier and
a second reducer, and two reducers drift.

```text
buzz ci landing --repo-owner <hex> --repo-id <d-tag> --candidate <oid> --base <oid> \
  --landed <oid> --checkout <path> --output <absolute receipt path> [--github-mirror owner/repo]
```

### 2.2 What it proves

1. Relay main: `git ls-remote --refs <relay git url> refs/heads/main` equals
   `--landed`, read twice with the announcement's hosted refs in between
   (`reconcile.rs` line 245: hosted refs and git main must agree).
2. Parents, ancestry, trees: `git -C <checkout> rev-list --parents -n 1
   <landed>` is `[base, candidate]` or, for a fast-forward, `[base]` with
   `landed == candidate`; `git merge-base --is-ancestor <base> <candidate>`
   succeeds; `landed^{tree} == candidate^{tree}`. Objects come from the relay
   remote, never GitHub.
3. New relay route `GET /ci/checks?target_repo_a=<a>&tip_oid=<candidate>`
   (membership-authenticated like the run routes) lists runs for the tip in
   `created_at DESC` order with `workflow_id`, `workflow_digest`, and stored
   kind-46108 events with `accepted_at`. The verifier reads the rule from the
   announcement, takes the latest run for that workflow, fetches its history
   from `after=0`, validates every event, reduces with `expected_sha =
   candidate`, and applies rules 2 to 7 of 1.3 (pinned jobs, digest of `git
   show <base>:.github/workflows/ci.yml`, `success` check bound to candidate
   and base, `accepted_at` freshness), following the named run status and
   terminal fact ids to stored events in the same history.
4. Signer: `check.relay_signer` is in `BUZZ_CI_STATUS_SIGNERS`; the verifier
   reads no grants, so a granted key is listed in the environment.
5. Gate decision: `GET /ci/merge-gate/decisions?target_repo_a=&ref=refs/heads/main&new_oid=<landed>`
   returns the allow record from 1.7 (Owner or Admin members only). No allow
   record, or one recorded in `shadow`, is refused unless `--allow-shadow` is
   passed during the mixed period.
6. GitHub mirror parity, non-gating: `gh api /repos/{mirror}/git/ref/heads/main`
   when `--github-mirror` is set; the receipt records `mirror: {sha, agrees,
   read_at}` and disagreement is a stderr warning only (the timer lags).
7. Desktop identity: verify the checkout's `scripts/desktop_release.py` bytes
   equal `git show <landed>:scripts/desktop_release.py`, run `verify-main
   --commit <landed> --repo only21mil/buzz` as a subprocess, and record it as
   `protected-ci-landing.py` line 439 does.

### 2.3 Receipt

`policy: "buzz-native-landing-v1"`, `schema_version: 1`, landed, candidate,
base, classification, relay main reads, run id, workflow digest, pinned jobs,
check event id and `accepted_at`, signer, verdict, `retained_events:
[{event_id, watch_cursor, sha256, base64}]` for the complete run history,
gate decision, mirror, landing checks, timestamp. `validate --offline`
replays the retained bodies through the reducer and recomputes every hash;
`--reverify` repeats steps 1, 3, 5 live. Publication copies `safe_publish`
from `protected-ci-receipt.py` line 1297 (caller-owned 0700 parent,
`O_CREAT|O_EXCL|O_NOFOLLOW` 0600 temporary, `renameat2(RENAME_NOREPLACE)`,
existing destination refused, 4 MiB cap); reads follow `safe_read_receipt`.

### 2.4 What today's verifier proves that this one cannot

- GitHub's independent chronology (`run_started_at`). Replaced by relay
  `watch_cursor` order and the latest-run rule; a mirror has no second clock.
- The live ruleset, bypass actors, and `BUZZ_CI_REUSE_EPOCH`. Replaced by the
  owner-signed rule and the relay mode; native runs never reuse results.
- Runner image, OS package inventory, service and compiler image ids, and the
  RustSec advisory revision from the `qualification-*` artifacts. The
  executor captures no such inventory today; that affects reproducibility
  claims, not merge authority. The receipt records it as not captured.

## 3. Required-check parity

Of the 15 required contexts in `workflow-inventory.required-checks.json`, 11
have disposition native with one `ci` job each (the 11 ids in the 1.2
example). The gate needs one kind-46108 for workflow `ci` whose reduced green
set covers those pinned ids. `scripts/ci-workflow-inventory.py --check` gains
one assertion: the pinned list in the live announcement equals the native job
ids of every required native context. That check runs inside candidate CI
and only catches drift; the owner-signed rule is what the gate trusts.

During the mixed period the gate requires the native set while the GitHub
ruleset still requires all 15, so `protected-ci-receipt.py acquire-main` and
`buzz ci landing` both run and both must pass; `docs/delivery-lifecycle.md`
names both until the last GitHub context is dropped, and `scripts/pre-freeze.sh`
accepts the new receipt. The four retained contexts and their exits:

- Detect Changed Paths: native runs every required job without path
  filtering. Exit: gate in `enforce` and one `buzz ci landing` receipt.
- Desktop Release Candidate: `buzz ci landing` runs `verify-main` itself (2.2
  step 7). Exit: first receipt with `landing_checks` executed.
- relay_e2e_canary: tests only its own workflow. Exit: native `relay-e2e`
  pinned and green on three consecutive verified landings; then retire
  `scripts/test-relay-e2e-canary-contract.sh` or point it at a native request.
- Desktop Build (macOS): no native producer. Stays required on GitHub, with
  that one job and today's PR receipt, until #185 or Victor removes it.

## 4. Cutover sequence

Every step touching relay config, systemd, keys, the announcement, or the
ruleset waits for Victor's approval. Code lands first through the ordinary
GitHub-CI PR path, which is still the gate.

1. Land the code: gate, rule, hook v2, migration 0042, reducer move, kind
   46109, `buzz ci landing`, routes, tests. Rollback: revert; flag off.
2. Signer set (keys gate): read the ci-event public key from
   `/etc/buzzci/keyholder-v2.json` with sudo (print only the pubkey), confirm
   it is in `BUZZ_CI_STATUS_SIGNER_PUBKEYS` or publish a kind-46107 grant.
   Rollback: remove the key or let the grant expire.
3. Relay config and restart (config gate): `BUZZ_MERGE_GATE_MODE=shadow`,
   age 86400, window 300; confirm the mode in the journal. Rollback: unset.
4. Announcement (owner signature): republish kind 30617 for `buzz` with the
   pinned rule on `refs/heads/main`, every other tag byte-for-byte.
   Rollback: republish without the rule.
5. Shadow observation: three real landings, each with one `decision=allow`
   row for the landed `(old, new)`; a `refuse` on a landing GitHub accepted
   is a bug to fix before step 6.
6. Enforce (config gate): `BUZZ_MERGE_GATE_MODE=enforce`, restart; the next
   landing runs both verifiers. Rollback: `shadow`, restart.
7. Ruleset edit one (ruleset gate): drop Detect Changed Paths, Desktop Release
   Candidate, relay_e2e_canary per section 3. Rollback: re-add from
   `workflow-inventory.required-checks.json`.
8. Ruleset edit two (ruleset gate): drop the 11 native-covered contexts after
   three enforced landings. Rollback: same source.
9. Desktop Build (macOS): Victor's decision (section 6). Rollback: re-add.
10. GitHub CI disable (workflow gate): `gh workflow disable` for `ci.yml` and
    the canary, or edit triggers if the macOS job stays. Rollback: enable.

## 5. Test plan

Relay unit tests (`merge_gate.rs`, no database): classification of
fast-forward, two-parent merge, three parents, wrong first parent,
`old_in_second_parent` false, tree mismatch; each refusal code from a
synthetic history built with the reducer's `green_events` fixtures (moved
with the reducer behind `cfg(test)` helpers), including a green run over a
subset of the pinned jobs (`required_jobs_missing`), a `workflow_digest`
matching the candidate tree's workflow but not the blob at `old_oid`
(`workflow_digest_mismatch`), `accepted_at` one second past the window
(`check_expired`) while a later `published_at` is ignored, signer not in the
union, bypass exact-match, expired, reused, and not consumed in `shadow`,
`shadow` never refusing, `enforce` with an empty union
(`gate_misconfigured`). `policy.rs`: HMAC v2 tampering of each new field,
bash parity. `config.rs`: mode parsing, ceilings. `git_perms`: rule parse,
job grammar, two rules union into one requirement.

Database tests (`ci_ingest_storage.rs` style, scratch Postgres):
`list_runs_for_tip` ordering with a newer red run, `load_ci_check` by id with
`accepted_at`, decision row uniqueness on bypass id, kind-46109 ingest
refusing a non-owner and a window over one hour, a bypass left unconsumed
after a simulated CAS loss.

Git transport integration. No existing test drives the hook:
`run_test_receive_pack` (`transport.rs` line 2117) runs git without the
relay, the Postgres tests there cover read and ban gates, and
`buzz-test-client/tests/e2e_git.rs` never exercises a decline. The hook calls
back `http://127.0.0.1:{bind_addr.port()}`, so the harness binds a real
server: bind a `TcpListener` on `127.0.0.1:0`, set `config.bind_addr` to that
port, build `AppState` with `policy_test_state` (`policy.rs` line 926), serve
`git_router` plus the internal policy route with `axum::serve` on a task, and
drive it with a real `git push` from a temp clone through the NIP-98
credential helper `e2e_git.rs` line 35 uses. Fixtures: a repo announced with
the pinned rule and a green run seeded with `store_success_chain` from
`ci_ingest_storage.rs` (extracted to `tests/fixtures/ci_history.rs`) whose
`workflow_digest` is the digest of the workflow blob at the seeded main.
Cases: `ok refs/heads/main` when everything matches; `ng base_moved` after
advancing main; `ng not_descendant` for a candidate branched from an older
main whose merge tree equals the candidate; `ng tree_mismatch` for a
conflict-resolving merge; `ng required_jobs_missing` for a green one-job run;
`ng workflow_digest_mismatch` for a candidate that edited `ci.yml`; `ng
check_pending` while attempt 2 runs; allow after a valid bypass and `ng
bypass_invalid` on reuse; the 409 race with two concurrent pushes; the
finalize fence refusing a missing or stale decision row.

Verifier tests (`landing.rs` tests and `crates/buzz-cli/tests/ci_contract.rs`):
the in-process `TcpListener` relay stub from `dispatch.rs` tests (line 508)
serves `/ci/checks`, run routes, and decisions; a bare temp repository plays
the relay git remote. Cases: main differs, parents reversed, base not an
ancestor of the candidate, tree differs, newer red run, pinned job missing
from a green run, workflow digest from the candidate tree, `accepted_at`
expired, signer absent, shadow record without `--allow-shadow`, mirror
disagreement exits 0, receipt refuses an existing destination and a 0755
parent, offline validate fails after one retained byte changes, `verify-main`
stub failure exits 1. `test-ci-workflow-inventory.py` gains the parity check.

## 6. Open question for Victor

Desktop Build (macOS) has no native producer. Until #185 lands: keep it on
GitHub with both verifiers, or drop it and prove macOS builds only at release
time. Step 9 waits on this.
