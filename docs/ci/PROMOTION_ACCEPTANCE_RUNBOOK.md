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
   protected exact-head CI receipt, including their SHA-256 digests.
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
   status history, finalization, teardown and decoded log evidence.
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

Populate all three signed-event sections from the relay configuration used by
the collection commands. The utility maps `ws` to `http` and `wss` to `https`,
removes a trailing slash and default port, and refuses credentials, paths,
queries, fragments or an origin that conflicts with retained evidence.

```bash
: "${BUZZ_RELAY_URL:?set the trusted relay used to collect this evidence}"
python3 scripts/populate-ci-promotion-relay-origin.py \
  --input "$HOME/work/buzz-promotion-evidence/promotion-evidence.unpopulated.json" \
  --output "$HOME/work/buzz-promotion-evidence/promotion-evidence.json"
```

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

The source harness cannot perform or authorize GitHub settings or
merges, production canary traffic, live log collection, database dump or
migration, deployment, rollback, relay checkout changes, or authoritative
mirror updates. Those steps stay blocked until their named operator approvals
exist and the live evidence is retained for this exact candidate.
