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

## Freeze and review

1. Resolve the candidate and its base to full commits. Confirm the base is an
   ancestor of the candidate and the candidate worktree is clean.
2. Run `scripts/pre-freeze.sh` with the intended base. Use `--full` and
   `--test` when the change or verification tier requires workspace-wide
   coverage. The script writes `pre-freeze-receipt.json` into the repository
   root. Move that file into the private mode-`0700` evidence directory at mode
   `0600` before exporting `BUZZ_PRE_FREEZE_RECEIPT`.
3. Acquire the pull-request receipt for the exact candidate with
   `scripts/protected-ci-receipt.py acquire`. The receipt is operator-acquired
   evidence: it retains the exact GitHub REST bodies for the repository, the
   `main` ref, the pull request, the branch rules, the rulesets, and the check
   runs, hash-bound and replayed on every validation. GitHub does not sign
   those responses, so the receipt is trusted only after `validate --reverify`
   finds the live authority unchanged, including the pull request itself: it
   must still be open, non-draft, at the receipt head, based on `main`, with
   its base SHA and the live `main` head equal to the recorded base. The output parent
   must be an absolute, canonical, caller-owned mode-`0700` directory; the tool
   publishes a new mode-`0600` file and refuses replacement. Validate it with
   literal scope `pull-request` and `--reverify` before supplying it to the
   promotion gate:

   ```bash
   evidence_dir=/absolute/private/evidence-directory
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
including the live pull request and `main` head. That is its only network
call; it does not acquire evidence or create approval.

## Landing

Merge only the reviewed and CI-qualified candidate. Read back all of the
following before calling the landing complete:

- pull-request state, base, head, merge commit, ordered parents, and tree;
- authoritative relay default branch at the merge commit;
- GitHub mirror default branch at the same commit;
- intended feature-branch retention or deletion; and
- terminal post-merge CI for the merge commit.

Record the merge commit and any failed, skipped, superseded, or duplicate CI
runs in the Buzz repository record. Do not describe a history containing a
failure as uniformly green. State which exact-head run is the promotion gate.

When initially adding the relay canary as a protected requirement, merge the
foundation first without that new required context. Dispatch the workflow for
the exact landed ref, record the expected first-attempt failure, rerun it once,
and require the second attempt to pass on the same landed commit. Add the
ruleset requirement only after that bootstrap evidence is complete.

## Deployment preflight

Production deployment is approval-gated. Run it only from a clean checkout of
the landed commit. Fetch the authoritative default branch immediately before
preflight and verify the local source ref resolves to that commit.

The operator supplies a non-secret Compose settings file, the existing
mode-`0600` secret file under a mode-`0700` directory, and fresh receipts:

```bash
evidence_dir=/absolute/private/evidence-directory
scripts/protected-ci-receipt.py acquire-main \
  --repository only21mil/buzz --head FULL_40_CHARACTER_LANDED_COMMIT \
  --branch main --output "$evidence_dir/protected-ci-main.json"
scripts/protected-ci-receipt.py validate \
  --receipt "$evidence_dir/protected-ci-main.json" \
  --repository only21mil/buzz --head FULL_40_CHARACTER_LANDED_COMMIT \
  --scope main --max-age-seconds 86400 --reverify
export BUZZ_COMPOSE_ENV_FILE=/absolute/path/to/compose.env
export BUZZ_SECRET_ENV_FILE="$HOME/.config/sats/secrets.env"
export BUZZ_PRE_FREEZE_RECEIPT=/absolute/path/to/pre-freeze-receipt.json
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
- the checkout is clean, apart from the two generated receipt files;
- both receipts are regular, mode-safe, fresh, exact-commit PASS receipts from
  `only21mil/buzz`, and the pre-freeze base is an ancestor;
- the explicitly supplied protected-CI receipt is canonical `main`-scope
  evidence for the landed commit, fresh, and a full exact-head protected-CI
  pass whose retained GitHub bodies reproduce every recorded hash and whose
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
only GitHub contact, and requires an explicit absolute
`BUZZ_PROTECTED_CI_RECEIPT`; a repository-root default is intentionally absent
because a normal checkout is not a private mode-`0700` evidence directory.
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
