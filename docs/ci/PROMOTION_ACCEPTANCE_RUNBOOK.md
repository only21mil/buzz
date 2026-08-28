# Promotion acceptance runbook

This runbook closes a Buzz promotion only when every receipt names the same
immutable commit and the same artifacts. The verifier is intentionally
source-only: it validates retained evidence and emits a machine-readable
receipt, but it does not contact GitHub, Docker, the relay, a database, or a
deployment host. Passing the hermetic tests is not live acceptance.

## Inputs and invariants

Use [`promotion-evidence.schema.json`](promotion-evidence.schema.json) for the
collected input and [`promotion-readiness-receipt.schema.json`](promotion-readiness-receipt.schema.json)
for the emitted receipt. Keep evidence outside the candidate checkout in a
mode-0700 directory; every retained file and generated receipt must be a
regular, non-symlinked mode-0600 file.

The bundle must bind all of these identities exactly:

- the clean candidate commit, its base and Git tree;
- the commit-tagged image, every manifest-list member, the running image ID,
  relay binary SHA-256, OCI revision and database migration;
- protected exact-head CI contexts and their conclusions;
- the final Tier 2 lineage, state digest, candidate fingerprint, reviewer
  route/model/effort, checked commit, verdict and freshness window;
- staging signer, production canary run, relay landing, authoritative mirror,
  merge commit and deliberate-red commit.

Missing evidence, a short or wrong SHA, a mismatched image or binary, a stale
review, a dirty checkout, or an unapproved rollback fails closed before the
receipt is written.

## Evidence order

1. Freeze a clean full candidate SHA. Retain its pre-freeze receipt and the
   protected exact-head CI receipt, including their SHA-256 digests.
2. Run the final Tier 2 review after exact-head CI. Its checked commit and
   fingerprint must still match the frozen candidate, and its review window
   may not exceed 5,400 seconds or be expired at verification time.
3. On approved staging infrastructure, capture the absent-policy 503 and
   configured-policy 200 paths; success, refusal, teardown, restart and
   unaccepted paths; immutable request; root-executor handoff; records
   46101–46106; signer; job set and conclusions; authenticated log denial;
   bounded log response; and log digest.
4. Run the 17 threat-model checks and all six named probes twice at the same
   full SHA. Retain both the canonical JSONL records and aggregate suite
   verdict. The six probes are trigger,
   assignment monitor, headless logs, bounded rerun, dropped run and bounded
   retries. Mock-suite evidence proves the harness only; live staging evidence
   remains mandatory.
5. With explicit activation approval, prove production starts at concurrency
   zero, transitions to one accepted signed job, refuses an unaccepted job,
   accepts only signed allowed kinds, and gives idempotent retry results with a
   fresh workspace per attempt.
6. Run the deliberate-red candidate. The protected check must conclude
   failure, the merge must remain blocked, and a duplicate request must return
   the same single terminal run.
7. After explicit deployment approval, record dump completion before swap,
   exact image/binary/revision/migration identities, readiness, NIP-11 and
   authenticated log results. Rehearse both rollback cases: a compatible
   prior migration may restore only its bound dump and image; an advanced
   current migration must refuse restore.
8. Record the exact merge SHA on both the relay checkout and authoritative
   mirror. Do not treat a local candidate-only bundle as a final PASS.

## Run the deterministic verifier

Choose a fixed UTC epoch for `--now`; it is part of the receipt so identical
inputs and the same epoch produce identical bytes.

```bash
now=$(date -u +%s)
python3 scripts/ci-promotion-readiness.py \
  --candidate-dir "$HOME/work/buzz-promotion-candidate" \
  --evidence "$HOME/work/buzz-promotion-evidence/promotion-evidence.json" \
  --receipt "$HOME/work/buzz-promotion-evidence/promotion-readiness-receipt.json" \
  --now "$now"
```

Exit status 0 means the receipt was written and printed. Exit status 2 prints
one `REFUSED:` reason and writes no receipt. Validate the input and output
against their schemas before retaining or signing them.

The hermetic contract test is safe on a development host:

```bash
TEST_TMP_ROOT="$HOME/work/buzz-promotion-readiness-tests" \
  scripts/test-ci-promotion-readiness.sh
```

It uses temporary Git repositories and synthetic evidence only. It does not
deploy, migrate, use sudo, start services, or invoke Docker.

## Live work still requiring approval

The source harness cannot perform or authorize activation, GitHub settings or
merges, production canary traffic, live log collection, database dump or
migration, deployment, rollback, relay checkout changes, or authoritative
mirror updates. Those steps stay blocked until their named operator approvals
exist and the live evidence is retained for this exact candidate.
