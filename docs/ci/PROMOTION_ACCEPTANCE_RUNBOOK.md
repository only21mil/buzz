# Promotion acceptance runbook

This runbook closes a Buzz promotion only when every receipt names the same
immutable commit and the same artifacts. The verifier validates retained
evidence and emits a machine-readable receipt. It does not contact Docker, the
relay, a database, or a deployment host. Its one network call is to GitHub,
after every offline invariant passes: it re-verifies the protected-CI receipt
against the live rulesets, required contexts, and exact-head check runs through
the pinned `gh` and `GH_TOKEN`, and re-reads the receipt's scope authority: the
recorded pull request must still be open, non-draft, at the receipt head, based
on `main`, and its base SHA and the live `refs/heads/main` head must still equal
the recorded base. A receipt for a commit with passing checks that is no longer
the pull request head, or whose base has moved, is refused. The protected-CI
receipt is operator-acquired evidence with the exact GitHub REST bodies retained
and hash-bound (repository, main ref, pull request, branch rules, rulesets, and
check runs); GitHub does not sign those bodies, so a receipt is accepted only
when live GitHub still matches it. Passing the hermetic tests is not live
acceptance.

## Inputs and invariants

Use version 2 of [`promotion-evidence.schema.json`](promotion-evidence.schema.json) for the
collected input and [`promotion-readiness-receipt.schema.json`](promotion-readiness-receipt.schema.json)
for the emitted receipt. Keep evidence under the external evidence root
(`BUZZ_EVIDENCE_ROOT`; see `docs/delivery-lifecycle.md`, "Retained evidence").
The verifier reads the bundle and every `evidence_files` descriptor through the
`safe_read_receipt` helper in `scripts/protected-ci-receipt.py`: each path must
be absolute, its immediate parent a canonical, non-symlink, caller-owned
mode-0700 directory outside the candidate checkout, and the file a caller-owned,
single-link, regular mode-0600 file. The same rule applies to every descriptor.
The emitted receipt goes through the create-only `safe_publish` helper into an
evidence root as canonical JSON at mode 0600; an existing file at `--receipt`
is refused.

The bundle must bind all of these identities exactly:

- the clean candidate commit, its base and Git tree;
- the commit-tagged image, every manifest-list member, the running image ID,
  relay binary SHA-256, OCI revision and database migration;
- protected exact-head CI contexts and their conclusions;
- the final Tier 2 lineage, state digest, candidate fingerprint, reviewer
  route/model/effort, checked commit, verdict and freshness window;
- staging signer, production canary run, relay landing, authoritative mirror,
  merge commit and deliberate-red commit.

Staging, canary and deliberate-red evidence retain canonical Nostr wire events:
`id`, `pubkey`, `created_at`, `kind`, `tags`, raw `content` and `sig`. The
verifier recomputes every event ID and verifies every BIP-340 Schnorr signature.
It rejects caller-supplied verification claims. It also checks the repository
CI tag contract before it binds each stored status event to its signed request,
canonical run UUID, repository, workflow, tip, top-level base SHA, attempt and
authorized relay signer.
Each `event_evidence` object also retains the canonical HTTP(S) origin derived
from the same trusted `BUZZ_RELAY_URL` or `--relay-url` configuration used to
collect that run. Collection refuses missing configuration and never supplies a
fallback relay.

Every retained request and status event also carries the relay-assigned
`watch_cursor`. The authenticated event export includes kind 46100 requests in
the same durable acceptance sequence as kinds 46101 through 46106. A collector
splits those records into `requests` and `events` without changing their
cursors. Each array remains in strict cursor order, and the union of both arrays
must be exactly `1..N` with no duplicates or gaps. Every status or evidence
event must have been stored after the signed request it names.

Kind coverage is deduplicated. It must equal 46101 through 46106, but the
event list must contain every transition. A successful initial run therefore
has ordered `queued`, `running` and terminal `success` kind-46101 facts and the
same ordered kind-46102 history for every selected job. Sequences begin at one
and have no gaps per run-attempt or job-attempt stream. Unknown kinds, states,
fields, illegal transitions, cursor gaps and equivocation fail closed. Job
name, required status, skip policy and selected matrix instance stay immutable
through the lifecycle. Terminal state and conclusion must agree.

Every rerun has its own signed kind-46100 request. Its stable run UUID, selected
job, parent run, parent attempt and next attempt must form a contiguous lineage.
Its durable cursor must be greater than the selected parent job's terminal
failure cursor; a request accepted before that failure is not a valid rerun.
Signed kind-46102 histories must match that request exactly, including the
selected job instance and dependency fanout. The verifier decodes every retained
log body, then checks its signed byte length, cap and SHA-256.

Kind 46105 must name every selected job attempt exactly once and bind each log
and artifact event ID to the same job and attempt. Kind 46106 must carry
`lease_empty=true` and a strictly ordered lease set that exactly equals the
selected job-attempt graph. The verifier accepts terminal run success only
when both facts were stored first. Staging, canary and deliberate-red evidence
must use the same repository coordinate, workflow ID and digest, selected job
set and relay signer. These event contracts have no activation or tombstone
fact, so this runbook makes no claim about either one.

Missing evidence, a short or wrong SHA, a mismatched image or binary, a stale
review, a dirty checkout, or an unapproved rollback fails closed before the
receipt is written.

## Evidence order

1. Freeze a clean full candidate SHA. Retain its pre-freeze receipt and the
   protected exact-head CI receipt, including their SHA-256 digests. Acquire
   the CI receipt with `scripts/protected-ci-receipt.py acquire` and confirm it
   with `validate --scope pull-request --reverify`; the verifier repeats that
   live re-verification, including the pull request and base re-read, when it
   runs. Reacquire after any push to the branch or any movement of `main`.
2. Run the final Tier 2 review after exact-head CI. Its checked commit and
   fingerprint must still match the frozen candidate, and its review window
   may not exceed 5,400 seconds or be expired at verification time.
3. On approved staging infrastructure, capture the absent-policy 503 and
   configured-policy 200 paths; success, refusal, teardown, restart and
   unaccepted paths; the signed kind-46100 request; every ordered 46101 and
   46102 transition; durable 46103 and 46104 references; exact 46105 evidence
   finalization; exact 46106 lease-empty teardown; root-executor handoff;
   authenticated log denial; bounded log response; and log digest.
4. Run the 17 threat-model checks and all six named probes twice at the same
   full SHA. Retain both the canonical JSONL records and aggregate suite
   verdict. The six probes are trigger,
   assignment monitor, headless logs, bounded rerun, dropped run and bounded
   retries. Mock-suite evidence proves the harness only; live staging evidence
   remains mandatory.
5. With production-canary approval, run one accepted signed job, refuse an
   unaccepted job, retain the initial and rerun requests plus the complete
   signed event history, and prove idempotent retry results with a fresh
   workspace per attempt. The verifier checks request lineage and
   staging/canary contract parity from the retained event facts.
6. Run the deliberate-red candidate. The protected check must conclude
   failure, the merge must remain blocked, and a duplicate request must return
   the same single terminal run. Retain its canonical signed request, full
   status, log, artifact and decoded-log history. A failed run must not publish
   kind 46105 or 46106; those terminal facts are reserved for a terminal-good
   selected job graph.
7. After explicit deployment approval, record dump completion before swap,
   exact image/binary/revision/migration identities, readiness, NIP-11 and
   authenticated log results. Rehearse both rollback cases: a compatible
   prior migration may restore only its bound dump and image; an advanced
   current migration must refuse restore.
8. Record the exact merge SHA on both the relay checkout and authoritative
   mirror. Do not treat a local candidate-only bundle as a final PASS.

## Run the deterministic verifier

Choose a fixed UTC epoch for `--now`; it is part of the receipt so identical
inputs and the same epoch produce identical bytes while native authority and
freshness remain valid against the actual clock.

Populate all three signed-event sections from the relay configuration used by
the collection commands. The utility maps `ws` to `http` and `wss` to `https`,
removes a trailing slash and default port, and refuses credentials, paths,
queries, fragments or an origin that conflicts with retained evidence. It also
removes the guide-only `_usage` and `_role` template annotations recursively;
any other underscore-prefixed annotation is refused instead of silently
discarded.

Every `evidence_files` entry is an exact `{path, sha256}` descriptor. When the
collector writes a private collection-manifest sidecar, include it as the
optional `collection_manifest` descriptor so the readiness receipt binds its
digest.

```bash
: "${BUZZ_RELAY_URL:?set the trusted relay used to collect this evidence}"
python3 scripts/populate-ci-promotion-relay-origin.py \
  --input "$HOME/work/buzz-promotion-evidence/promotion-evidence.unpopulated.json" \
  --output "$HOME/work/buzz-promotion-evidence/promotion-evidence.json"
```

```bash
now=$(date -u +%s)
python3 scripts/ci-promotion-readiness.py \
  --native-context /etc/buzz/ci-promotion-authority.json \
  --candidate-dir "$HOME/work/buzz-promotion-candidate" \
  --evidence "$HOME/work/buzz-promotion-evidence/promotion-evidence.json" \
  --receipt "$HOME/work/buzz-promotion-evidence/promotion-readiness-receipt-$now.json" \
  --now "$now"
```

The native context is installed separately by the operator, after checking the
actual repository announcement, relay configuration, current signer authority,
and workflow policy. It is never generated from the bundle. The default path is
`/etc/buzz/ci-promotion-authority.json`; `--native-context` selects another
operator-installed context. Every component of its absolute canonical path and
the CLI path must be root-owned and not writable by group or other users. Files
must be regular, have one link, and contain no symlinks. This verifier does not
install policy, change credentials, or grant signing authority.

The context has exactly these fields:

| Field | Required operator binding |
| --- | --- |
| `repository` | `only21mil/buzz` |
| `target_repo_a`, `source_clone_url` | Canonical native repository address and exact source clone URL |
| `channel_id`, `relay_url` | Repository channel UUID and canonical HTTPS relay origin |
| `status_signers` | Current, nonempty authorized relay signer public keys |
| `workflow_id`, `workflow_digest`, `job_ids` | Current workflow identity, SHA-256 policy digest and complete ordered job selection |
| `cli_path`, `cli_sha256` | Independently installed CLI and its exact SHA-256 |
| `valid_from`, `valid_until` | UTC epoch interval in which this authority context is current |
| `max_evidence_age` | Positive maximum native event age in seconds; caller options may only tighten it |
| `historical_reuse` | Object mapping an explicitly approved whole-history SHA-256 to its expiry epoch; empty by default |

Each signed request must match that context and the candidate/base under review.
After local checks, the verifier supplies the context's channel and signer set
to `buzz --relay <origin> ci verdict --run <run> --expect-sha <sha>` for staging,
canary, and deliberate-red. It compares the actual run, commit, attempt, verdict
and terminal job counts. Missing access, failed authentication or an unavailable
CLI refuses qualification. Existing CLI credentials stay in the operator's
configured environment; never put a private key in a command or policy file.
The context and CLI bytes are checked again before publication so a revocation
or policy change during verification refuses the result.

Native authority validity, historical reuse expiry, and every signed event's
freshness use the actual UTC clock, checked again after live verification.
`--now` controls only non-native evidence checks. `--max-evidence-age` caps
native age at the smaller of the caller value and root-owned `max_evidence_age`;
it cannot extend the policy limit. Evidence more than 300 seconds in the future
is refused.
Old evidence requires an exact entry in `historical_reuse`: hash the canonical
JSON plus LF of the entire `event_evidence` section. Its expiry must be within
the context's validity interval and after verification time. Historical reuse
still requires the current signer/workflow bindings and a passing live readback;
it does not claim the jobs ran again. Retain original accepted scenario histories
and their approvals; a new wrapper timestamp cannot make them fresh. The output
records each history digest, `fresh` or `historical-reuse`, the live verdict
digest, and the independent authority digest.

This broader qualification is separate from `ci landing` and does not weaken or
replace its trusted-context enforcement or any GitHub protected check.

`$HOME/work/buzz-promotion-evidence` is an evidence root here: caller-owned,
mode 0700, outside the candidate checkout.

Exit status 0 means the receipt was written and printed. Exit status 2 prints
one `REFUSED:` reason and writes no receipt. Validate the input and output
against their schemas before retaining or signing them.

Re-running with the same `--receipt` path is refused with `output already
exists`, the same create-only rule `scripts/protected-ci-receipt.py acquire`
applies to `--output`. Name a fresh receipt path for each run; identical inputs
and the same `--now`, authority and live readbacks produce byte-identical receipts
at the two paths.

The hermetic contract test is safe on a development host:

```bash
TEST_TMP_ROOT="$HOME/work/buzz-promotion-readiness-tests" \
  scripts/test-ci-promotion-readiness.sh
```

It uses temporary Git repositories and synthetic evidence only. It does not
deploy, migrate, use sudo, start services, or invoke Docker.

## Live work still requiring approval

The source harness cannot perform or authorize GitHub settings or
merges, production canary traffic, live log collection, database dump or
migration, deployment, rollback, relay checkout changes, or authoritative
mirror updates. Those steps stay blocked until their named operator approvals
exist and the live evidence is retained for this exact candidate.
