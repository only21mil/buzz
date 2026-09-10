# Buzz delivery lifecycle

This document is the normative lifecycle for changes to `only21mil/buzz`. The
repository scripts own executable behavior. If this document and a script
disagree, stop delivery, fix the disagreement, and re-run the affected gate.

## Invariants

- Track planned work, review, CI, landing, deployment, and follow-ups in the
  applicable Buzz issue or pull request. Record full commit IDs.
- Develop on a non-default branch in an isolated worktree. Preserve unrelated
  edits and never promote a dirty checkout.
- Bind every gate to one full 40-character commit. A branch name, abbreviated
  commit, local image tag, or passing run for another commit is not evidence.
- Protected exact-head CI, required Tier 2 review, and approval are separate
  gates. One never substitutes for another. A passing review does not authorize
  a production action, and approval does not waive CI or required review.
- The Buzz relay repository is authoritative. GitHub is the CI mirror. Landing
  is incomplete until the authoritative branch and mirror branch resolve to the
  same merge commit and the expected feature ref state is confirmed.

## Retained evidence

Every retained evidence file follows one path contract: the pre-freeze
receipt, the protected-CI receipts, the promotion evidence bundle, the
acceptance verdict and records, the collection manifest, and the readiness
receipt. `scripts/protected-ci-receipt.py` owns the rule in
`validate_evidence_root`, `safe_read_receipt`, and `safe_publish`;
`scripts/pre-freeze.sh`, `scripts/ci-promotion-readiness.py`, and
`deploy/compose/deploy-local.sh` call those helpers and keep no path rules of
their own.

- The file's immediate parent is an evidence root: an absolute, canonical,
  non-symlink directory owned by the caller with mode `0700`, outside the
  checkout. `BUZZ_EVIDENCE_ROOT` names the operator's evidence root and is the
  default parent for generated receipts; an explicit path is checked against
  the same rule.
- The file is a caller-owned regular mode-`0600` file with one link, at most
  4 MiB. The promotion bundle alone may reach 64 MiB.
- Publication is create-only. The writer creates a mode-`0600` temporary file
  beside the destination, so the rename stays on one filesystem, and renames
  it with `RENAME_NOREPLACE`. An existing file is refused, never replaced;
  choose a fresh path to run a producer again.
- No generated receipt sits inside a checkout, and no clean-tree gate exempts
  a receipt file name.

```bash
mkdir -m 700 -p "$HOME/work/buzz-evidence"
export BUZZ_EVIDENCE_ROOT="$HOME/work/buzz-evidence"
```

## Freeze and review

1. Resolve the candidate and its base to full commits. Confirm the base is an
   ancestor of the candidate and the candidate worktree is clean.
2. Run `scripts/pre-freeze.sh` with the intended base and `BUZZ_EVIDENCE_ROOT`
   exported. Use `--full` and `--test` when the change or verification tier
   requires workspace-wide coverage. The script publishes
   `$BUZZ_EVIDENCE_ROOT/pre-freeze-receipt-<UTC stamp>.json` (or the
   `--receipt` path, whose parent must be an evidence root) at mode `0600`,
   prints `Receipt: <path>`, and writes nothing inside the checkout. Export
   that path as `BUZZ_PRE_FREEZE_RECEIPT`. A receipt path inside the checkout
   or an existing file at the destination is refused.
3. Acquire the pull-request receipt for the exact candidate with
   `scripts/protected-ci-receipt.py acquire`. The receipt is operator-acquired
   evidence: it retains the exact GitHub REST bodies for the repository, the
   `main` ref, the pull request, the branch rules, the rulesets, and the check
   runs, hash-bound and replayed on every validation. GitHub does not sign
   those responses, so the receipt is trusted only after `validate --reverify`
   finds the live authority unchanged, including the pull request itself: it
   must still be open, non-draft, at the receipt head, based on `main`, with
   its base SHA and the live `main` head equal to the recorded base. The output
   parent must be an evidence root; the tool publishes a new mode-`0600` file
   and refuses replacement. Validate it with literal scope `pull-request` and
   `--reverify` before supplying it to the promotion gate:

   ```bash
   evidence_dir=$BUZZ_EVIDENCE_ROOT
   scripts/protected-ci-receipt.py acquire \
     --repository only21mil/buzz --pull-request PR_NUMBER \
     --head FULL_40_CHARACTER_CANDIDATE --base main \
     --output "$evidence_dir/protected-ci-pr.json"
   scripts/protected-ci-receipt.py validate \
     --receipt "$evidence_dir/protected-ci-pr.json" \
     --repository only21mil/buzz --head FULL_40_CHARACTER_CANDIDATE \
     --scope pull-request --max-age-seconds 86400 --reverify
   ```

   Supply GitHub authentication through `GH_TOKEN` in the environment. Never
   place a token in the command line or receipt. Legacy JSON that merely
   asserts `protected: true` or `full_exact_head: true` is not evidence and is
   refused, and so is a receipt whose retained bodies no longer reproduce its
   recorded hashes, whose binding live GitHub no longer backs, or whose
   commit is no longer the head of an open pull request against the current
   `main`.
4. Apply the current risk classifier. When Tier 2 is required, close review on
   the exact candidate before promotion. A review of an ancestor, tree-equivalent
   reconstruction, or later amended commit does not close the gate.
5. Obtain explicit approval for any merge, production deployment, migration,
   external publication, or other approval-gated action.

`scripts/ci-promotion-readiness.py` validates a supplied promotion evidence
bundle when that broader gate applies. It accepts only the canonical
`pull-request` receipt, and after every offline invariant passes it re-verifies
that receipt against live GitHub through the pinned `gh` and `GH_TOKEN`,
including the live pull request and `main` head. It also requires a separate
root-installed native authority context and rechecks the three native runs with
the pinned `buzz ci verdict` command. The context binds repository, channel,
relay origin, current signers and workflow policy; the evidence bundle cannot
choose this authority. See [the promotion runbook](ci/PROMOTION_ACCEPTANCE_RUNBOOK.md)
for installation and historical reuse requirements. These readbacks do not
create approval or replace protected CI.

Both readiness and `deploy-local.sh` require all six mandatory pre-freeze checks
(`clean-tree`, `rust-format`, `rust-clippy`, `base-lineage`, `native-ci-python`,
`postgres-discovery`), unique nonempty names, PASS status and integer zero exit
codes for every check. The producer reports PASS only after the whole requested
run completes, including `--test`. HUP, INT and TERM produce a nonzero exit and
FAIL evidence; SIGKILL cannot publish a receipt. Consumers require the explicit
receipt path and never substitute an older PASS when that file is absent.

## Landing

Merge only the reviewed and CI-qualified candidate. Read back all of the
following before calling the landing complete:

- pull-request state, base, head, merge commit, ordered parents, and tree;
- authoritative relay default branch at the merge commit;
- GitHub mirror default branch at the same commit;
- intended feature-branch retention or deletion; and
- the operator's exact landed qualification receipt, including the maintained
  `desktop_release.py verify-main` identity check on the actual merge commit.

The relay merge gate (`docs/ci/BUZZ_CI_TERMINAL_CHECK.md` section 7) applies
when the announcement carries a `require-check` rule and
`BUZZ_MERGE_GATE_MODE` is `shadow` or `enforce`. In `enforce` the push to
`main` lands only as a fast-forward or a two-parent merge of a candidate whose
latest run at the current base reduced green, with every pinned job
successful and a kind-46108 `success` check accepted by the relay inside
`BUZZ_MERGE_GATE_CHECK_MAX_AGE_SECONDS`. A refusal reads
`merge gate: <code>: <detail>`; the codes are `no_check`, `check_pending`,
`check_not_success`, `reducer_disagrees`, `base_moved`, `not_descendant`,
`parent_shape`, `tree_mismatch`, `workflow_digest_mismatch`,
`required_jobs_missing`, `signer_unauthorized`, `check_expired`,
`bypass_invalid` and `gate_misconfigured`. A refused push publishes nothing:
rerun or re-request CI for the candidate, or rebase on the new base. The
owner can sign a kind-46109 bypass for one exact `(ref, old, new)` update,
valid for at most one hour and consumed once by the publish it covered.

A merge does not launch CI, a desktop candidate workflow, chart validation,
image builds or rolling Sprig builds. Protected PRs qualify the full ordinary
suite once, including both cross-target link builds. Explicit release tags,
release-PR tagging and authorized manual release actions remain separate.

## Verified landed qualification

Before merging, retain the canonical version-1 protected pull-request receipt
and acquire/live-reverify it normally. Every required check remains enforced;
no ruleset, bypass actor or required context changes for this transition.
Each successful CI job also uploads an immutable
`qualification-<job-attempt>-<job>` artifact. The capture runs after all of that
job's check commands. Missing capture fails the source job. The old six-job
`ci-reuse` artifacts alone do not cover this complete qualification.

Before merging, prove complete source coverage (without inventing a landed
identity):

```bash
scripts/protected-ci-receipt.py verify-source \
  --repository only21mil/buzz --head FULL_REVIEWED_CANDIDATE_SHA \
  --base FULL_REVIEWED_BASE_SHA --receipt "$evidence_dir/protected-ci-pr.json" \
  --output "$evidence_dir/candidate-qualification.json"
```

After merging, use the reviewed checkout's operator verifier:

```bash
scripts/protected-ci-receipt.py acquire-main \
  --repository only21mil/buzz --branch main --head FULL_LANDED_SHA \
  --reuse-source "$evidence_dir/protected-ci-pr.json" \
  --candidate FULL_REVIEWED_CANDIDATE_SHA --base FULL_REVIEWED_BASE_SHA \
  --output "$evidence_dir/protected-ci-main.json"
scripts/protected-ci-receipt.py validate \
  --receipt "$evidence_dir/protected-ci-main.json" \
  --repository only21mil/buzz --head FULL_LANDED_SHA \
  --scope main --max-age-seconds 86400 --reverify
```

The version-2 main receipt keeps the original source receipt bytes unchanged.
`head_sha` identifies the actual landing, while each `source_check.head_sha`
continues to identify the tested candidate. It sets `full_exact_head: false`
and `full_verified_landing: true`, records every source run/job/attempt, and
records the freshly executed desktop metadata check separately. Version-1
receipts keep their existing meaning and validation; relabeling one is refused.
Delivery consumers continue to call the maintained validator with `--reverify`.
The entrypoint verifies the new helper's exact committed bytes before loading it.

`protected-ci-landing.py` verifies all of the following independently:

- Live GitHub and canonical Buzz main name the actual landed commit. The merged
  internal PR names the reviewed candidate, and GitHub Git objects prove the
  exact ordered base/candidate parents and equal candidate/tested/landed trees.
  The operator supplies the independently reviewed candidate and base; this
  verifier does not grant review or merge approval.
- Every current app-bound required source check succeeds under the original
  strict ruleset and bypass authority. The latest expected workflow run and
  its latest attempt succeed. Cross-run chronology uses the provider's
  `run_started_at`, which resets on rerun; an older run ID cannot hide a newer
  failed attempt. Missing/tied chronology and overlapping attempts are refused.
  The selected job's latest positive attempt must
  succeed too; failed, skipped, cancelled, pending, ambiguous or stale work
  cannot fall back to an earlier pass. A failed-jobs rerun does not keep a
  retained job on its own attempt: GitHub copies each job it did not
  re-execute into the new attempt's listing with a new job id, the new
  `run_attempt` and the original `started_at`/`completed_at`, while the
  job's artifact keeps the attempt that executed it. The verifier treats the
  selected entry as fresh when `qualification-<selected attempt>-<job>`
  exists. Otherwise it reads `/actions/runs/{id}/attempts/{n}/jobs` for
  every earlier attempt `n` that has a `qualification-<n>-<job>` artifact and
  accepts exactly one whose job is a completed success of the same run and
  head with identical `started_at`/`completed_at`; that `n` is recorded as
  `executed_attempt` beside the selected job. A timestamp match against an
  unsuccessful origin, no match, or two matches refuses. Only a success can
  be retained this way: a retained copy of a failed execution carries
  `conclusion: failure` and `selected_job` refuses it before any artifact is
  read, and a re-executed job gets new timestamps and its own artifact. In
  the receipt, `checks[].source_job_attempt` records the listing attempt of
  the selected entry, while `jobs[].executed_attempt` records the attempt
  that executed the job; readers wanting the execution consult `jobs[]`.
  `protected-ci-reuse.py` applies the same rule to its `ci-reuse-<n>-<job>`
  artifacts and records `executed_attempt` in its reuse proof.
  Source execution and receipts expire after 24 hours.
- Immutable source artifacts belong to that CI run and each selected job's
  executed attempt, and their provider archive digests verify. The provider independently
  resolves the tested Git objects. Workflow/action pins, verifier policy,
  toolchain manifests and dependency lockfiles match the landed Git objects.
  Capture retains actual tool versions, runner image revision, OS package
  inventory digest, service image IDs and the Android runtime dependency digest.
  Relay E2E and both integration lanes retain Postgres, Redis, MinIO and the
  MinIO setup container image IDs. Each server cross build resolves its compiler
  image once, forces cross to use that immutable registry digest, and retains
  both the digest reference and local image ID. Missing image evidence refuses
  qualification.
- Qualification uses the same immutable source execution snapshot for the
  landed tree. It does not claim to have rebuilt outputs with the new commit
  SHA or to have executed on a new runner. Cache writes, checkout paths and the
  new SHA do not change this source-qualification claim. Commit-stamped
  binaries, signed packages, deployed services and release outputs require their
  own actual-source gates. Source snapshots do not assert that later mutable
  dependency resolution would return identical versions.
- The live non-secret `BUZZ_CI_REUSE_EPOCH` equals the captured value; change it
  when an external relevant qualification input is invalidated. The captured
  value may be empty only when the variable is empty or its exact GitHub 404
  response is followed by independent repository-admin confirmation. Other
  HTTP, transport, authentication and malformed-response failures refuse.
  The captured RustSec advisory revision must also equal its live authority. A changed
  advisory database refuses Security reuse. Current checks, jobs, workflow
  attempts, epoch and main are read again before a receipt can pass.
- The actual landed desktop identity runs through the existing
  `desktop_release.py verify-main` gate locally. Unchanged mode checks the first
  parent's candidate bytes and manifests; release mode validates the immutable
  candidate from the internal version-bump PR. No build or test suite runs.

The relay canary tests only its workflow attempt. Its candidate attempt-one
failure and successful attempt two remain separate provider evidence. An
identical reviewed workflow and successful candidate attempt two satisfy this
qualification; merging is not a reason to dispatch the canary again.

If a relevant input changes or equivalence is unproven, refuse qualification
and rerun the affected source job deliberately. A successful retry can provide
new immutable evidence without rewriting the retained original receipt.
Rerun the full suite only when the uncertainty covers the suite. No automatic
fallback launches postmerge CI. Retain the source artifacts before their
seven-day provider retention expires.

For the first adoption, review this verifier and run the corrected candidate
CI once to create the complete source artifacts. Acquire the existing protected
PR receipt before merging. After canonical-first landing and mirror parity,
run only the operator command above. Historical six-job proofs cannot bootstrap
missing whole-job coverage, and an old verifier cannot consume a version-2
receipt. No ruleset relaxation or blanket main run is part of bootstrap.

## Buzz-native landing verifier (not yet authoritative)

`buzz ci landing` is the future replacement for `protected-ci-receipt.py
acquire-main` and `protected-ci-landing.py`. It reads the Buzz relay and a
local checkout, never GitHub Actions, and follows
`docs/ci/BUZZ_MERGE_GATE_DESIGN.md` section 2. Until the cutover step in
`docs/ci/BUZZ_CI_TERMINAL_CHECK.md` section 6 names it as the landing gate,
its receipt is evidence next to the GitHub-backed receipts above, not a
substitute for them. Running it changes nothing on the relay.

```bash
export BUZZ_CI_CHANNEL=<repository channel UUID>
export BUZZ_CI_STATUS_SIGNERS=<comma-separated control-plane signer pubkeys>
buzz ci landing \
  --repo-owner 73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812 \
  --repo-id buzz --checkout "$reviewed_checkout" \
  --candidate FULL_REVIEWED_CANDIDATE_SHA --base FULL_REVIEWED_BASE_SHA \
  --landed FULL_LANDED_SHA --github-mirror only21mil/buzz \
  --output "$evidence_dir/buzz-native-landing.json"
buzz ci landing validate --receipt "$evidence_dir/buzz-native-landing.json" --reverify
```

Every proof is a named check in the receipt with a refusal code; the verdict
is `PASS` only when every gating check passes, and a refusal exits 1 after
the receipt is still published. Per-workflow checks carry `:<workflow_id>`.

| Check | Refusal codes | What it proves |
|-------|---------------|----------------|
| `relay_main` | `relay_main_mismatch`, `relay_main_unavailable` | `git ls-remote` of the relay's `refs/heads/main` names `--landed`, read before and after the relay reads. |
| `objects_present`, `parent_shape` | `object_missing`, `parent_shape` | The landed commit's parents are exactly `[base, candidate]` (`merge`) or `[base]` with `landed == candidate` (`fast_forward`). |
| `tree_match` | `tree_mismatch` | `landed^{tree}` equals `candidate^{tree}`. |
| `base_ancestry` | `not_descendant` | `git merge-base --is-ancestor base candidate`. |
| `require_check_rule` | `gate_misconfigured` | The owner-signed kind-30617 announcement carries a `require-check:<workflow>:<jobs>` rule for `refs/heads/main`. |
| `run_selected`, `run_base`, `workflow_digest` | `no_check`, `base_moved`, `workflow_digest_mismatch`, `gate_misconfigured` | The latest run for `(repo, candidate, workflow)` names the reviewed base and the digest of `.github/workflows/ci.yml` at that base. |
| `run_history` | `check_pending`, `check_not_success`, `reducer_disagrees`, `history_unavailable` | The complete signed run history reduces to Green for the candidate under the shared reducer. |
| `required_jobs` | `required_jobs_missing` | Every pinned job is requested, required, and terminal-good at its selected attempt. |
| `check_bound`, `check_listed` | `no_check`, `check_not_success`, `base_moved`, `reducer_disagrees` | The selected kind-46108 check is a success for the candidate on the base and is stored with the same `accepted_at` the run listing reports. |
| `check_signer` | `signer_unauthorized` | The check's signer is in `BUZZ_CI_STATUS_SIGNERS`. |
| `check_fresh` | `check_expired` | The relay clock's `accepted_at` is within `--max-age-seconds` (default 86400, the relay's `BUZZ_MERGE_GATE_CHECK_MAX_AGE_SECONDS` default). Signer-chosen `published_at` is recorded and never consulted. |
| `gate_decision` | `no_decision`, `gate_shadow`, any gate refusal code, `relay_route_unavailable` | The merge gate's decision row for `(refs/heads/main, base, landed)` is `allow`, with a bypass recorded when one applied. Non-gating while the relay's mode is `off`; a `shadow` allow needs `--allow-shadow`. |
| `github_mirror` | `mirror_lag`, `mirror_unavailable` (warning only) | `gh api` reads the mirror's `main`; disagreement is recorded, not gating, because the mirror timer lags. |
| `desktop_verify_main` | `desktop_verifier_source_differs`, `desktop_release_repo_unset`, `desktop_verify_main_failed` | The checkout's `scripts/desktop_release.py` equals the landed tree's, and `verify-main --commit <landed>` passes as an isolated `python3 -I` subprocess; a changed desktop identity needs `--github-mirror`. |

The receipt (`policy: buzz-native-landing-v1`, `schema_version: 1`) retains
the complete run history as base64 bodies with per-event SHA-256 values and a
history digest, records the relay `main` reads, the rule, the trusted signer
set, the reduction, the bound check with its `accepted_at`, the decision rows,
the mirror read, and every check. It is published create-only under a
caller-owned mode-0700 parent as a mode-0600 file, like the other receipts.
`buzz ci landing validate` re-hashes and re-validates the retained bodies,
replays the reducer and the history rules offline, and with `--reverify`
repeats the relay `main`, run listing, and decision reads. The relay serves
the two reads behind it, `GET /ci/checks` (any member) and
`GET /ci/merge-gate/decisions` (owner or admin), NIP-98 authenticated and
keyed on the announcement coordinate the verifier resolved.

The receipt is unsigned, so the replay anchors the receipt's recorded
channel and signer set to something outside the file. The `trusted_context`
check reports the anchor as `trust` in the output. With `BUZZ_CI_CHANNEL`
and `BUZZ_CI_STATUS_SIGNERS` exported (`trust: environment`), the receipt's
channel must equal the exported channel and its signers must be a subset of
the exported set, else `trusted_context_mismatch` refuses. With both unset
and `--reverify` (`trust: relay`), the live run listing proves the relay
stored the recorded check under its own signer authority, and the check only
warns. With both unset and no `--reverify` (`trust: unanchored`), the replay
refuses `trusted_context_unanchored`: a self-consistent receipt built under
an attacker's signer set would otherwise pass, so an offline PASS is only
meaningful inside the operator's exported context. Setting one variable
without the other is a usage error.

`desktop_verify_main` runs `python3 -I` so nothing in the checkout's
`scripts/` shadows the standard library. When the landed commit's
`.release/desktop-candidate.json` blob differs from its first parent's, the
maintained gate is in release mode and needs the pull request from the
GitHub repository named by `--github-mirror`; without the flag the verifier
refuses `desktop_release_repo_unset` instead of letting `desktop_release.py`
query its default repository.

What this verifier cannot prove today, per the design's section 2.4: the
provider's independent chronology, the live GitHub ruleset, and the runner
image and dependency inventory the `qualification-*` artifacts capture. Those
stay with the scripts above until the cutover step retires them.

## Deployment preflight

Production deployment is approval-gated. Run it only from a clean checkout of
the landed commit. Fetch the authoritative default branch immediately before
preflight and verify the local source ref resolves to that commit.

The operator supplies a non-secret Compose settings file, the existing
mode-`0600` secret file under a mode-`0700` directory, and fresh receipts:

```bash
evidence_dir=$BUZZ_EVIDENCE_ROOT
# Acquire the verified-landing receipt with --reuse-source as shown above.
scripts/protected-ci-receipt.py validate \
  --receipt "$evidence_dir/protected-ci-main.json" \
  --repository only21mil/buzz --head FULL_40_CHARACTER_LANDED_COMMIT \
  --scope main --max-age-seconds 86400 --reverify
export BUZZ_COMPOSE_ENV_FILE=/absolute/path/to/compose.env
export BUZZ_SECRET_ENV_FILE="$HOME/.config/sats/secrets.env"
# The path scripts/pre-freeze.sh printed for the landed commit's freeze run.
export BUZZ_PRE_FREEZE_RECEIPT="$evidence_dir/pre-freeze-receipt-20260908T101112Z.json"
export BUZZ_PROTECTED_CI_RECEIPT="$evidence_dir/protected-ci-main.json"
export BUZZ_DEPLOY_SOURCE_REF=refs/remotes/buzz/main
deploy/compose/deploy-local.sh --check FULL_40_CHARACTER_LANDED_COMMIT
deploy/compose/deploy-local.sh FULL_40_CHARACTER_LANDED_COMMIT
```

`BUZZ_DEPLOY_SOURCE_REF` may be omitted only when its default,
`refs/remotes/origin/main`, is the freshly fetched authoritative branch. Do not
set it to a raw commit merely to bypass the branch readback. `GH_TOKEN` must be
present in the environment, loaded from the secret file without output, because
the deploy re-verifies the protected-CI receipt against GitHub.

`deploy/compose/deploy-local.sh` refuses unless:

- its argument, checkout `HEAD`, and configured source ref resolve to the same
  full commit;
- the checkout is clean; no generated receipt file name is exempt;
- `BUZZ_PRE_FREEZE_RECEIPT` and `BUZZ_PROTECTED_CI_RECEIPT` are explicit
  absolute paths, both receipts satisfy the retained-evidence contract (a
  mode-`0600` file whose parent is an evidence root outside the checkout),
  both are fresh, exact-commit PASS receipts from `only21mil/buzz`, and the
  pre-freeze base is an ancestor;
- the explicitly supplied protected-CI receipt is canonical `main`-scope
  evidence for the landed commit, fresh, with complete verified source qualification
  or historical exact-head coverage, whose retained bodies reproduce the binding and whose
  binding live GitHub still backs (`validate --reverify` through the pinned
  `gh` with `GH_TOKEN`), with the live `refs/heads/main` head equal to the
  landed commit; the local remote-tracking ref alone does not establish that
  the commit landed. A pull-request-scoped, legacy self-asserted,
  hand-edited, no-longer-backed, or not-yet-landed receipt is refused;
- the Compose runner, both Compose files, the non-secret settings file, the
  secret file, and their relevant parent directories have the required regular
  file or directory type, ownership, mode, and no-symlink state. The non-secret
  Compose settings file is owner-writable mode `0640`; the secret file is mode
  `0600` under its mode-`0700` parent. The secret
  file contains every required variable name with a nonempty assignment, but
  the preflight never prints or passes secret values in command arguments;
- the deployment tools, minimum free disk, root-owned `docker` group socket,
  direct Docker access, and Compose plugin are available. `DOCKER_HOST` and
  `DOCKER_CONTEXT` must be unset; every preflight Docker call is explicitly
  bound to the validated Unix socket;
- build and receipt/log roots are absolute canonical non-root paths with no
  symlinked existing ancestor, safe deployment-user ownership and modes, and a
  safe writable nearest parent. Neither root may overlap the other or be an
  ancestor or descendant of the source repository. These gates bind every
  later `mkdir`, `chmod`, log, temporary worktree, and receipt write to an
  approved descendant;
- Compose resolves exactly one healthy production relay, healthy PostgreSQL,
  Redis, and MinIO services, and a successfully completed MinIO initializer;
- the running relay's configured image ref, manifest descriptor digest,
  platform, OCI revision, required-migration label, and streamed relay-binary
  SHA-256 are readable and mutually consistent; and
- the running relay, prior image evidence, database state, and required
  migration labels are readable and internally consistent. The database read
  also requires zero failed migration rows. The candidate migration is derived
  directly from the requested commit's Git tree, not from a temporary checkout
  or a newly built image.

`--check` and the real deploy call the same fail-closed preflight function. Run
the check immediately before requesting the production action. Check mode is
strictly read-only: it creates no directory, log, temporary file, worktree,
image, container, tag, dump, or receipt; it does not invoke `sudo`, build or
copy an image, run a one-shot container, migrate the database, recreate a
service, or change service state. Its Docker operations are limited to daemon,
Compose, container, descriptor, network, and binary-stream metadata readbacks;
it never uses `docker exec` or Compose `exec`. It never sources the secret file.
Compose schema resolution uses fixed non-secret sentinels. Relay readiness and
NIP-11 are fetched by trusted host `curl` from the inspected container network
endpoint with all ambient HTTP(S)/all-proxy variables cleared and
curl startup configuration disabled before any other option, with
`--noproxy '*'` enforced. Database checks use trusted host `psql` against the inspected
PostgreSQL endpoint with `default_transaction_read_only=on`, bounded timeouts,
including both libpq `connect_timeout` and an outer process deadline, and an
explicit `BEGIN TRANSACTION READ ONLY`/`ROLLBACK` envelope. A strict
non-evaluating parser supplies the database password only through `PGPASSWORD`;
all ambient `PG*` variables are removed before the script installs only
`PGPASSWORD`, `PGOPTIONS`, and `PGCONNECT_TIMEOUT`, and the value is never
printed or placed in command arguments. If host `psql`, the
network endpoint, or the strictly parseable connection inputs are unavailable,
preflight refuses. A Docker Engine archive stream carries the running relay
binary directly to trusted host Python for exact tar-shape validation and
SHA-256; neither container code nor `docker cp` is a hash trust anchor. The
runner is always the clean commit-bound `deploy/compose/run-local.sh`; an
operator path override is refused. Independent static blockers are reported
together; identity-dependent live checks stop at the first broken prerequisite
instead of guessing through missing or ambiguous state.
The real deploy completes this same preflight before its first filesystem write
and repeats it after the candidate build before rollback capture or backup, so
live-state drift during the build fails closed.

`protected-ci-receipt.py` records the pinned client identity, every request's
metadata and body hash, and the exact response bodies for the repository, the
`main` ref, the pull request (pull-request scope), the branch rules, the
rulesets, and the check runs. Those retained bodies count toward the 4 MiB
receipt cap; acquisition refuses to publish anything larger. Every `validate`
recomputes the body hashes and replays the bodies through the scope's
acquisition sequence, so a hand-edited receipt fails offline. GitHub does not
sign REST responses, so a receipt fabricated without contacting GitHub can
still be internally consistent; `validate --reverify` closes that gap by
requiring the live rulesets, required contexts, and exact-head check runs to
match the receipt binding, and by re-reading the scope authority: a `main`
receipt needs the live `refs/heads/main` head at the receipt head; a
`pull-request` receipt needs the live pull request open, non-draft, at the
receipt head, based on `main`, with its base SHA and the live `main` head
equal to the recorded base. Passing checks on a commit are not enough on
their own. `deploy-local.sh` always validates with `--reverify`, which is its
only GitHub contact, and requires explicit absolute `BUZZ_PRE_FREEZE_RECEIPT`
and `BUZZ_PROTECTED_CI_RECEIPT` paths; repository-root defaults are
intentionally absent because a checkout is never an evidence root.
Reacquire after a rerun, ruleset change, or landing.

Never use `run-local.sh up` as an upgrade path. The deploy script is the only
path that binds the build, backup, migration gate, swap, health checks, and
rollback evidence. It passes the pinned image through `sudo env`; do not rely on
the caller's environment surviving `sudo`. Migration commands override the
relay image entry point with `/usr/local/bin/buzz-admin`.

## Backup, migration, and rollback

The deploy script builds `localhost/buzz-relay:<full-commit>` in a detached,
clean worktree and labels it with the source revision and highest numbered SQL
migration. Before any migration or relay swap, it:

1. records the running container image ID, configured image reference, OCI
   revision, required migration, and relay binary SHA-256;
2. preserves a unique rollback tag;
3. binds the rollback source to the running container's exact platform image ID
   and matches its revision, migration evidence, and binary; and
4. writes a non-empty Postgres custom-format dump.

Some Docker image stores expose a running container's manifest-list or index ID
separately from its runnable platform image ID. The script resolves and records
the configured image reference's exact platform image ID, preserves the
historical container image ID as evidence, and tags the exact platform image ID
as the rollback source. Missing platform resolution or a failed exact-ID tag
stops the deployment. It creates, but never starts, a temporary container from
the retained tag with `--pull=never`; the temporary container's `.Image` must
equal the recorded platform image ID. The script copies
`/usr/local/bin/buzz-relay` out of that stopped container and hashes it with the
trusted host `sha256sum`, then checks the OCI revision and available migration
label. It removes the stopped container and its anonymous volumes on success
and during exit cleanup.

The current Compose files do not set a relay platform, so verification uses
Docker's same no-platform default with `DOCKER_DEFAULT_PLATFORM` unset. If a
Compose platform is added, the script passes that exact platform to the stopped
container. A caller platform override, invalid platform, or platform resolution
whose `.Image` differs from the running platform image fails closed. Bare refs
that imply `latest`, literal `main` or `latest` tags, leading-option forms, and
malformed refs are rejected. An ordinary mutable tag can identify only its
current local resolution; the stopped-container `.Image` equality is the
authority. Missing or mismatched evidence stops before the database dump,
migration, or swap. The retained rollback tag undergoes the same stopped-
container exact-ID binding immediately before any Compose rollback starts.

If the running image lacks a trustworthy required-migration label, an operator
may set `BUZZ_PRIOR_MIGRATION_OVERRIDE` only to the exact binding
`<prior-image-id>@<current-database-migration>` printed by the refusal. This is
a high-risk assertion that the exact prior binary is compatible with that
current schema; it is not a general override, does not relax image identity,
and does not authorize automatic rollback after the database advances. The
script refuses the override when the running image has a valid required-
migration label; an override cannot replace, raise, or lower valid image
metadata. A successful image inspection that returns an absent or malformed
label is the only override-eligible state. If the inspection command itself
fails, rollback compatibility is unreadable and the deployment stops before
backup, migration, or swap; an override cannot bypass that failure.

The database must have a successful latest migration no newer than the
candidate's requirement. If it is behind, the candidate image runs migrations
before the relay swap and the script rechecks the exact required version with a
true success value. A failed query, empty result, malformed table-presence
marker, or malformed latest-migration row is not treated as an empty migration
history. It stops the deployment or automatic rollback, whichever is active.

The retained rollback image must also pass exact-ID verification and the
stopped verifier container and its anonymous volumes must be removed before
Compose may restart the prior image. A verifier cleanup failure is reported
separately from an identity failure and conservatively stops automatic rollback.

Automatic image rollback is allowed only while the database migration is no
newer than the prior image's recorded requirement. If the candidate advances
the database beyond that requirement, the script refuses to restore the prior
binary. This is intentional. The operator must keep the pre-swap dump, stop
automatic recovery attempts, and choose one approved recovery path:

- restore the pre-swap dump, then restore the prior image and verify it; or
- roll forward with a corrected image compatible with the advanced schema.

Do not mark a migration as reversible merely because its SQL looks additive.
Migration 35 is not automatically reversible to a binary whose declared
requirement is 34.

## Post-deploy proof

The deploy is complete only after all of these readbacks match the landed
commit:

- the running container uses one of the built image IDs and its OCI revision is
  the landed commit;
- the relay binary SHA-256 is recorded;
- the database is at the candidate's required migration with success true;
- bounded readiness on port 8080 and NIP-11 on port 3000 pass;
- the deploy log reports `DEPLOY SUCCEEDED`; and
- the deploy directory retains the pre-swap dump, prior identity, rollback
  source and tag, new container and image IDs, migration numbers, and binary
  hashes.

Re-read the authoritative relay branch and GitHub mirror after deployment.
Update the Buzz issue or pull request with the deployed commit, image ID,
binary hash, database migration, deploy receipt path, health result, and any
recovery limits or follow-ups. A deployment is not complete while this tracking
record is missing or inaccurate.
