# Buzz merge gate and native landing verifier

Status: design for authority path (b) of `BUZZ_CI_TERMINAL_CHECK.md` section 6
(Victor, 2026-09-09: Buzz holds merge authority for `main`; GitHub is a mirror).
Companion to the CI contracts in this directory and `docs/delivery-lifecycle.md`.
Nothing here changes a GitHub ruleset; the gate ships default off. Line
references are against main `4064707215afad1e912e31df852cf32a17607645`.

## 1. Merge gate on the relay

### 1.1 Where it runs

The gate is a new step in the existing pre-receive callback
`hook_policy_check` (`crates/buzz-relay/src/api/git/policy.rs`), after step 9
`evaluate_push` allows the push and before the 200 response. It lives in a new
module `crates/buzz-relay/src/api/git/merge_gate.rs`. The receive-pack flow in
`transport.rs` (`receive_pack`, lines 1121 to 1233) is unchanged: hydrate,
`install_hook`, run `receive-pack --stateless-rpc`, `finalize_push`. A gate
refusal is a hook decline, so `finalize_push` publishes nothing and the CAS
pointer never moves (the fence at line 1836).

The hook must supply commit facts the gate cannot read from the relay process,
because the pushed objects are in git's quarantine inside the tempdir. The hook
script (`hook.rs`, `PRE_RECEIVE_HOOK`) adds, per ref update whose `new_oid` is
not zero, three fields computed with the inherited quarantine environment:

- `parents`: ordered parent OIDs of `new_oid` (`git rev-list --parents -n 1`).
- `tree`: `git rev-parse <new_oid>^{tree}`.
- `parent_trees`: `git rev-parse <parent>^{tree}` for each parent, in order.

`HookRefUpdate` gains the same three fields. The HMAC payload (`compute_hmac`,
`policy.rs` line 142, and the bash mirror in the hook) appends
`len(parents):p1p2...|tree|len(parent_trees):t1t2...` after `is_ancestor` for
every ref. Both the Rust and bash `bash_hmac_matches_rust_hmac` fixtures change
together. Create and delete updates send empty lists and an empty tree.

### 1.2 Scope selection

A repository opts in through its own kind 30617 announcement. A new
`buzz-protect` rule `require-check:<workflow_id>` (parsed in
`buzz_core::git_perms::parse_protection_tag_with_warnings`, next to
`no-force-push`) marks a ref pattern as gated and names the workflow whose
terminal check is required, for example:

```text
["buzz-protect", "refs/heads/main", "no-force-push", "no-delete", "require-check:ci"]
```

The relay honours the rule only when `BUZZ_MERGE_GATE_MODE` is `shadow` or
`enforce`. In `off` the rule is logged as skipped, as an unknown rule is today
(`policy.rs` line 320), so the announcement can carry it before the relay
deploys. Two switches on purpose: the owner declares refs and workflow, the
operator decides whether the relay acts.

### 1.3 Candidate and what the gate requires

For every gated ref update the gate classifies the push:

- Fast-forward: `is_ancestor` true and `parents == [old_oid]`. The candidate
  is `new_oid`, the base is `old_oid`.
- Merge landing: `parents == [old_oid, candidate]`, exactly two parents, and
  `tree == parent_trees[1]` (the merge commit's tree equals the candidate's
  tree, the rule `protected-ci-landing.py` enforces today). The candidate is
  the second parent, the base is `old_oid`.
- Anything else (zero, three or more parents, first parent not `old_oid`, a
  non-fast-forward with one parent, a tree that differs from the candidate's)
  is refused with `parent_shape` or `tree_mismatch`. Create and delete of a
  gated ref stay with the existing `no-delete` and role rules.

Then the gate resolves the run. A new `buzz_db::ci::list_runs_for_tip` uses
`idx_ci_runs_repo_tip` (`migrations/0032_ci_event_storage.sql`) to return every
`ci_runs` row for `(community, target_repo_a = 30617:<repo_owner>:<repo_id>,
tip_oid = candidate, workflow_id = <rule value>)` ordered by `created_at DESC`.
The latest run decides; an older green run cannot outlive a newer red one,
matching today's provider chronology rule. That run must satisfy all of:

1. `base_oid` of the run equals `old_oid`. Otherwise `base_moved`.
2. Its accepted events (`load_ci_reducer_events` widened to every stored kind,
   or `list_ci_run_events` from cursor 1 with the bounded window) reduce to
   `Green` under the shared reducer, with `expected_sha = candidate`. Otherwise
   `check_pending` (reducer `Pending`), `check_not_success` (`Red`), or
   `reducer_disagrees` (`InfrastructureFailure`, or a check whose conclusion
   is `success` while the reducer is not green).
3. The reduction's selected kind-46108 check exists, has conclusion `success`,
   `tip_oid == candidate`, `base_oid == old_oid`. The reducer already selects
   the check of the final accepted request, so attempt 2 supersedes attempt 1
   (`BUZZ_CI_TERMINAL_CHECK.md` section 1, reader rules). No check yet is
   `no_check`.
4. The check signer is authorized now: `check.relay_signer` is in the union of
   `config.ci_status_signer_pubkeys` and `get_active_ci_signers(now)` for the
   repository channel, the same union `api/ci.rs` line 1681 builds. A revoked
   signer's old checks stop counting. Otherwise `signer_unauthorized`.
5. The check is fresh: `now - check.published_at <=
   BUZZ_MERGE_GATE_MAX_CHECK_AGE_SECONDS` and the stored event `created_at`
   is inside the same window. Default 86400, the `MAX_AGE` the landing
   verifier uses. Otherwise `check_expired`.

Reducer reuse: move `crates/buzz-cli/src/commands/ci/reducer.rs` to
`crates/buzz-core/src/ci/reducer.rs` unchanged (it depends only on
`buzz_core::ci`, `serde`, and `thiserror`) and re-export it from the CLI
module. The relay validates each stored event with
`validate_signed_ci_event(event, channel_id, signer_union)` and builds
`AcceptedCiEnvelope { event_id, watch_cursor, envelope }` exactly as
`dispatch::fetch_ci_run_snapshot` does. One reducer, two callers, no
relay-side re-specification.

### 1.4 Refusal the pusher sees

The callback answers 403 with the existing `HookCallbackResponse` shape. The
hook prints the body to stderr, which git relays over sideband, so the pusher
sees:

```text
remote: error: push denied by policy (HTTP 403)
remote: {"allowed":false,"denials":[{"ref_name":"refs/heads/main","reason":"merge gate: base_moved: check 3f9c... was published against base 4064...; main is now 91ab..."}]}
 ! [remote rejected] main -> main (pre-receive hook declined)
```

Reason grammar: `merge gate: <code>: <detail>`. Codes: `no_check`,
`check_pending`, `check_not_success`, `reducer_disagrees`, `base_moved`,
`parent_shape`, `tree_mismatch`, `signer_unauthorized`, `check_expired`,
`bypass_invalid`, `gate_misconfigured`. Detail always names the candidate,
base, and (when one exists) the check event id and run id, truncated to 12 hex
in the message and complete in the log record.

### 1.5 Owner override

A new owner-signed kind `46109 KIND_CI_MERGE_BYPASS`, stored through the CI
ingest gate like kind 46107 (`handlers/ingest.rs` line 2867). Content:

```text
{ schema_version: 1, target_repo_a, ref_name, old_oid, new_oid, reason, issued_at, expires_at }
```

Acceptance: `event.pubkey` is the kind-30617 author and holds the channel
Owner role; `expires_at - issued_at <= 3600`; `reason` non-empty; the `a` and
`h` tags match. The gate accepts a bypass only when `ref_name`, `old_oid`, and
`new_oid` equal the push exactly, the event is inside its window, and no prior
gate decision consumed it. It is single use: the decision record (1.7) stores
the bypass event id under a unique index. Role implies no bypass; an Owner
without one is refused like anyone else. The `new_oid` binding means the owner
signs one exact merge commit, not a window of freedom.

### 1.6 Configuration and failure modes

- `BUZZ_MERGE_GATE_MODE`: `off` (default), `shadow`, `enforce`. Any other
  value fails config load and the relay does not start.
- `BUZZ_MERGE_GATE_MAX_CHECK_AGE_SECONDS`: default 86400, ceiling 604800.

`shadow` evaluates everything, writes the decision record, logs
`merge_gate decision=<allow|refuse> code=... ` at info, and never refuses.
`enforce` refuses. Failure is closed in `enforce`: a database error, a signer
union that is empty, a `require-check` value that names no workflow, a hook
callback missing the new fields (old hook script), or a reducer panic guard all
answer 403 `gate_misconfigured`. `shadow` logs the same code and allows.

### 1.7 Decision record and the finalize fence

Every evaluation inserts one append-only row in a new table
`git_merge_gate_decisions` (migration `0042_merge_gate_decisions.sql`):
community, repo coordinate, ref, old, new, candidate, classification, run id,
check event id, signer, code, mode, pusher, bypass event id (unique when
present), decided_at. `finalize_push` adds a second fence in `enforce` mode:
before `cas_publish`, every gated ref that changed in the workspace needs an
`allow` row for exactly `(ref, old, new, pusher)` decided within the last 60
seconds. Otherwise the push is refused 403 `gate_misconfigured` and nothing
publishes. This closes the case where the hook did not run at all.

### 1.8 Concurrency, reruns, mirror

Two pushes racing: both hydrate the same parent state, both hooks see the same
`old_oid`, both may pass the gate. `cas_publish` lets one win; the loser gets
409 (`transport.rs` line 1894) and retries. On retry `old_oid` is the winner's
head, the check's `base_oid` no longer matches, and the gate answers
`base_moved`. The loser needs a fresh candidate on the new main and a new run.
Strict by design, and equal to the "require branches to be up to date" rule
the current ruleset enforces. Main moved between check publication and push
takes the same path: the gate compares only against the `old_oid` git
reports, which is the hydrated parent state the CAS predicates on.

Rerun lineage: handled by the reducer's final-request selection. A rerun that
is still running reduces to `Pending`, so a candidate whose attempt 2 has not
finished is refused `check_pending` even though attempt 1 was green. Relay
lineage validation (`BUZZ_CI_TERMINAL_CHECK.md` section 4) is unchanged.

Mirror: `buzz-github-mirror.timer` (host unit, every two minutes,
`~/.agents/tools/buzz-github-mirror.sh`) keeps force-syncing all
`refs/heads/*` and `refs/tags/*` from the relay. A refused push publishes no
pointer, so the mirror sees nothing. No GitHub state is read by the gate.

## 2. Buzz-native landing verifier

### 2.1 Choice: `buzz ci landing`

A Rust subcommand in `crates/buzz-cli/src/commands/ci/landing.rs`, not a
Python script. The CLI already has NIP-98 signing, `validate_signed_ci_event`,
the signer set from `BUZZ_CI_STATUS_SIGNERS`, the reducer, `ls-remote` helpers
in `repo_sync.rs`, and GitHub reads in `repos/reconcile.rs`. A Python verifier
would need a second Schnorr verifier and a second reducer, and two reducers
drift. The frozen CLI contract gives one JSON object on stdout, exit 0/1/2/3/4.

```text
buzz ci landing --repo-owner <hex> --repo-id <d-tag> --candidate <oid> --base <oid> \
  --landed <oid> --checkout <path> --output <absolute receipt path> [--github-mirror owner/repo]
```

### 2.2 What it proves

1. Relay main: `git ls-remote --refs <relay git url> refs/heads/main` equals
   `--landed`, read twice with the announcement's hosted refs in between
   (the `reconcile.rs` pattern, line 245: hosted refs and git main must agree).
2. Ordered parents and trees: `git -C <checkout> rev-list --parents -n 1
   <landed>` is `[base, candidate]` or, for a fast-forward, `[base]` with
   `landed == candidate`; `landed^{tree} == candidate^{tree}`. The checkout must
   contain all three objects fetched from the relay remote, never from GitHub.
3. New relay route `GET /ci/checks?target_repo_a=<a>&tip_oid=<candidate>`
   (membership-authenticated like `GET /ci/runs/{run_id}/events`) lists runs
   for the tip in `created_at DESC` order with their stored kind-46108 events.
   The verifier takes the latest run for the workflow named by the repo's
   `require-check` rule, fetches its full event history through the existing
   run routes, validates every event, and reduces with `expected_sha =
   candidate`. It requires `Green`, a selected check with conclusion `success`,
   `tip_oid == candidate`, `base_oid == base`, and follows the named
   `run_status_event_id`, `evidence_finalized_event_id`, and
   `teardown_attestation_event_id` to stored events in the same history.
4. Signer: `check.relay_signer` is in `BUZZ_CI_STATUS_SIGNERS`. The verifier
   does not read grants; an operator who relies on a kind-46107 grant lists
   the granted key in the environment, as every `buzz ci` read command
   already requires.
5. Gate decision: `GET /ci/merge-gate/decisions?target_repo_a=&ref=refs/heads/main&new_oid=<landed>`
   returns the allow record from section 1.7 (Owner or Admin members only).
   A landing with no allow record, or one recorded in `shadow`, is reported in
   the receipt as `gate_mode` and refused unless `--allow-shadow` is passed
   during the mixed period (section 3).
6. GitHub mirror parity, non-gating: `GET /repos/{mirror}/git/ref/heads/main`
   through `gh api` when `--github-mirror` is set. The receipt records
   `mirror: {sha, agrees: bool, read_at}`; disagreement is a warning on stderr
   and never changes the exit code, because the timer can lag two minutes.
7. Desktop identity: verify the checkout's `scripts/desktop_release.py` bytes
   equal `git show <landed>:scripts/desktop_release.py`, then run
   `python3 scripts/desktop_release.py verify-main --commit <landed> --repo
   only21mil/buzz` as a subprocess and record `{mode: "executed", check:
   "desktop_release.py verify-main", head_sha}` exactly as
   `protected-ci-landing.py` line 439 does.

### 2.3 Receipt

`policy: "buzz-native-landing-v1"`, `schema_version: 1`, `landed`, `candidate`,
`base`, `classification`, `relay: {git_url, main_reads: [...]}`, `run_id`,
`check_event_id`, `signer`, `verdict`, `retained_events: [{event_id,
watch_cursor, sha256, base64}]` for the complete run history, `gate_decision`,
`mirror`, `landing_checks`, `timestamp`. Retained bodies are the canonical
signed event JSON; `validate --offline` replays them through the reducer and
recomputes every hash, so a hand-edited receipt fails without network.
Publication copies `safe_publish` semantics from `protected-ci-receipt.py`
line 1297: absolute path, parent a caller-owned 0700 directory, temporary file
`O_CREAT|O_EXCL|O_NOFOLLOW` mode 0600, `renameat2(RENAME_NOREPLACE)`, refuse
when the destination exists, size cap 4 MiB. `buzz ci landing validate
--receipt <path> [--reverify]` reads with the `safe_read_receipt` rules (0600,
one link, caller owned) and `--reverify` repeats steps 1, 3, 5 live.

### 2.4 What today's verifier proves that this one cannot

- GitHub's independent chronology (`run_started_at`, attempt ordering across
  workflow runs). Replaced by relay `watch_cursor` order and the latest-run
  rule. With GitHub a mirror there is no second clock; the relay's order is
  the authority the gate itself used, so this does not matter.
- The live ruleset, bypass actors, and `BUZZ_CI_REUSE_EPOCH`. Replaced by the
  owner-signed `require-check` rule and the relay mode. Native runs never
  reuse prior results, so the epoch has no equivalent.
- Runner image revision, OS package inventory, service and compiler image
  ids, and the RustSec advisory revision from the `qualification-*`
  artifacts. Native logs and artifacts are sha256-bound (kinds 46103 to
  46105) but the executor captures no such inventory today. That matters for
  reproducibility claims, not merge authority. The receipt records
  `toolchain_inventory: "not captured"` until the executor adds it.

## 3. Required-check parity

Of the 15 required contexts in `workflow-inventory.required-checks.json`, 11
have disposition native and one native `ci` workflow job each: Backend
Integration (relay e2e), Dead Token Reference Guard, Desktop, Desktop E2E
Integration, Desktop E2E Relay, Mobile, Relay E2E, Rust Lint, Security, Unit
Tests, Web. The gate needs one kind-46108 for workflow `ci` whose signed
manifest marks all 11 jobs `required: true`; it never inspects job names.
`scripts/ci-workflow-inventory.py --check` gains one assertion: every required
context with disposition native maps to a job id that the native `ci`
workflow's static job set marks required. A drift fails CI before the gate
can be fooled by a manifest that quietly dropped a job.

The four retained contexts during the mixed period, where the gate requires
the native set and the GitHub ruleset still requires all 15:

- Detect Changed Paths (`ci.yml:changes`): native runs every required job
  without path filtering. Exit: gate in `enforce` and one landing verified by
  `buzz ci landing`. Drop first.
- Desktop Release Candidate (`desktop-release-candidate.yml:validate`):
  `buzz ci landing` executes `verify-main` itself (2.2 step 7). Exit: first
  receipt with `landing_checks` executed. Drop with the previous one.
- relay_e2e_canary: tests only its own workflow attempt. Exit: native
  `relay-e2e` required and green on three consecutive verified landings; then
  retire `scripts/test-relay-e2e-canary-contract.sh` or point it at a native
  request.
- Desktop Build (macOS): no native producer (Linux executor). Stays required
  on GitHub until an apple executor exists (#185) or Victor removes it. While
  it stays, GitHub CI keeps running for this one job and the landing procedure
  keeps acquiring today's PR receipt for it.

Mixed period procedure: run both `protected-ci-receipt.py acquire-main` and
`buzz ci landing`; both must pass. `docs/delivery-lifecycle.md` names both
until the last GitHub context is dropped, then only `buzz ci landing`, and
`scripts/pre-freeze.sh` accepts the new receipt.

## 4. Cutover sequence

Every step below that touches relay config, systemd, keys, the announcement,
or the ruleset waits for Victor's explicit approval. Code lands first through
the ordinary GitHub-CI PR path, which is still the gate.

1. Land the code: gate, `require-check` rule, hook v2, migration 0042, reducer
   move, `buzz ci landing`, routes, tests. Rollback: revert the PR; the flag is
   off and the rule is skipped, so nothing behaves differently.
2. Signer set (keys gate). Read the ci-event public key from
   `/etc/buzzci/keyholder-v2.json` with sudo, print only the pubkey, and
   confirm it is in the relay's `BUZZ_CI_STATUS_SIGNER_PUBKEYS`, or publish a
   kind-46107 grant for the repository channel. Rollback: remove the key or
   let the grant expire.
3. Relay config and restart (config gate): `BUZZ_MERGE_GATE_MODE=shadow`,
   `BUZZ_MERGE_GATE_MAX_CHECK_AGE_SECONDS=86400`; restart the relay unit;
   confirm `merge_gate mode=shadow` in the journal. Rollback: unset, restart.
4. Announcement (owner signature): republish kind 30617 for `buzz` with
   `require-check:ci` on `refs/heads/main`, keeping every existing tag
   byte-for-byte. Rollback: republish without the rule.
5. Shadow observation: three real landings. Each must show one
   `decision=allow` row for the landed `(old, new)` and no `allow` for a push
   that GitHub refused. Any `refuse` on a landing that GitHub accepted is a
   bug to fix before step 6. Rollback: none needed.
6. Enforce (config gate): `BUZZ_MERGE_GATE_MODE=enforce`, restart. First
   landing after this runs both verifiers (section 3). Rollback: `shadow`,
   restart; a landing refused in between needs a fresh run, nothing else.
7. Ruleset edit one (ruleset gate): drop Detect Changed Paths, Desktop Release
   Candidate, relay_e2e_canary per section 3 exits. Rollback: re-add from the
   contexts in `workflow-inventory.required-checks.json`.
8. Ruleset edit two (ruleset gate): drop the 11 native-covered contexts after
   three enforced landings. Rollback: same source.
9. Desktop Build (macOS): Victor's decision (section 6). Rollback: re-add.
10. GitHub CI disable (workflow gate): `gh workflow disable ci.yml` and the
    canary in only21mil/buzz once no required context remains, or edit the
    triggers if the macOS job stays. Rollback: `gh workflow enable`.

## 5. Test plan

Relay unit tests (`merge_gate.rs`, no database): classification of
fast-forward, two-parent merge, three parents, wrong first parent, tree
mismatch; each refusal code from a synthetic run history built with the
reducer's `green_events` fixtures (moved to `buzz_core::ci::reducer::tests`
and exported behind `cfg(test)` helpers); expiry at the boundary; signer not
in the union; bypass exact-match, expired, and reused; `shadow` never refuses;
`enforce` with an empty union refuses `gate_misconfigured`. `policy.rs`: HMAC
v2 tampering of `parents`, `tree`, `parent_trees`; bash parity. `config.rs`:
mode parsing rejects unknown values, age ceiling. `git_perms`: `require-check`
parse, missing workflow value is malformed.

Database tests (`crates/buzz-relay/tests/ci_ingest_storage.rs` style, scratch
Postgres via `BUZZ_TEST_DATABASE_URL`): `list_runs_for_tip` ordering, two runs
for one tip where the newer is red, decision row uniqueness on bypass id,
kind-46109 ingest refuses a non-owner and a window over one hour.

Git transport integration (`transport.rs` tests module, `policy_test_state` at
`policy.rs` line 926 plus `owner_push_response` at line 972): announce a repo
with `require-check:ci`, seed a green run with the `store_success_chain`
fixture from `ci_ingest_storage.rs` (extract it to
`crates/buzz-relay/tests/fixtures/ci_history.rs`), build a real merge commit
in a temp clone, post a pkt-line receive-pack body like
`run_test_receive_pack` (line 2117) to `/git/{owner}/{repo}/git-receive-pack`
and assert: `ok refs/heads/main` when the check matches; `ng` with the
`base_moved` reason after advancing main; `ng` `tree_mismatch` for a merge
that resolved a conflict; `ng` `check_pending` while attempt 2 is running;
allow after a valid bypass and `ng bypass_invalid` on its reuse; the 409 race
with two concurrent pushes through `git_router`; the finalize fence refuses
when the decision row is missing.

Verifier tests (`crates/buzz-cli/src/commands/ci/landing.rs` tests and
`crates/buzz-cli/tests/ci_contract.rs`): the in-process `TcpListener` relay
stub from `dispatch.rs` tests (line 508) serves `/ci/checks`, run routes, and
decisions; a bare temp repository plays the relay git remote. Cases: landed
equals main, main differs, parents reversed, tree differs, latest run red
while older green, signer absent, shadow record refused without
`--allow-shadow`, mirror disagreement exits 0 with a warning, receipt refuses
an existing destination and a 0755 parent, offline validate fails after one
retained byte changes, `verify-main` stub failure exits 1. Python:
`scripts/test-ci-workflow-inventory.py` gains the parity assertion.

## 6. Open question for Victor

Desktop Build (macOS) is the one required context with no native producer.
Until an apple executor lands (#185): keep it required on GitHub and keep both
verifiers indefinitely, or drop it from the ruleset and prove macOS desktop
builds only at release time. Step 9 of the cutover waits on this answer.
