# Capacity-one activation acceptance

Native CI is not qualified or active merely because this harness builds or its
unit tests pass. A real acceptance run must finish with a schema-valid `pass`
receipt against the exact installed candidate. The run ends by closing
admission and returning capacity to zero.

The harness drives a fixed sequence through the installed
`/usr/libexec/buzz-ci-capacity-one-driver`. It does not contain provider URLs,
service-manager commands, credentials, or prebaked success responses. The
driver reads actual host state through the root acceptance helper, then binds
that readback into a request to controld. The harness checks the normalized
response independently.

The acceptance tree does not own or retain a deployable copy of
`buzz-ci-controld-acceptance.socket`. The controld package is its sole source
and package owner.

## What the gate proves

The 13 checks run in this order:

1. Capacity is zero, admission is closed, and no work is active.
2. Capacity becomes exactly one without starting work.
3. The exact candidate, source object, request, and manifest wait for approval.
4. The expected approver and grant are present, but no attempt starts.
5. Explicit resume starts exactly one first attempt.
6. The first attempt terminates successfully with the expected log and artifact.
7. An authenticated export returns the same evidence set and exact byte digests.
8. Rerun creates attempt two with a distinct ID and attempt one as its parent.
9. Cancellation makes attempt two terminal with a cancelled conclusion.
10. A tombstone keeps attempt two visible and folds the run back to attempt one.
11. Controller restart advances its generation without losing folded state.
12. Runner restart advances its generation without losing folded state.
13. The final durable controld snapshot is retained while capacity is prepared
    for the root-only close.

The receipt then retains two root-only phases. Sequence 14 finalizes capacity
zero and stops the controld acceptance transport. Sequence 15 independently
proves capacity zero, closed admission, and the absence of the controld service,
socket unit, and socket path. These phases are not acceptance-stage entries.

Any missing field, duplicate attempt, extra evidence object, identity mismatch,
generation regression, or ambiguous active count stops the sequence. A failed
receipt never authorizes activation.

## Inputs

Start from [scenario.template.json](scenario.template.json), then replace the
activation package digest, activation ID suffix, scenario-specific identities,
grant event, and initial systemd generations with frozen-package readback. The
candidate path is pinned to the integrated base. All five endpoint entries are
the same installed driver with an empty argument list. The schema rejects any
other executable or arguments.

The checked-in fixture runs
[`fixtures/run-fixture.sh`](fixtures/run-fixture.sh). It verifies the source
input digest, writes a byte-stable `result.json`, and emits one byte-stable log
line. [`fixtures/fixture-manifest.json`](fixtures/fixture-manifest.json) binds
the command, input, and required evidence names. Recompute all scenario digests
if any fixture byte changes.

Validate a rendered scenario before the approved run:

```bash
check-jsonschema \
  --schemafile deploy/native-ci/acceptance/scenario.schema.json \
  /protected/path/capacity-one-scenario.json
```

## Approved qualification run

This sequence changes CI capacity, submits work, writes an approval grant,
cancels an attempt, writes a tombstone, and restarts services. Obtain current
approval for those exact actions before running it. Run it only on the isolated
qualification host and only while the ordinary CI path remains closed.

```bash
. ./bin/activate-hermit
cargo build --locked --release -p buzz-ci-acceptance-ctl \
  --bin buzz-ci-capacity-one-canary \
  --bin buzz-ci-capacity-one-driver \
  --bin buzz-ci-acceptance-control

target/release/buzz-ci-capacity-one-canary \
  < /protected/path/capacity-one-scenario.json \
  > /protected/path/capacity-one-receipt.json
```

The binary returns `0` only after all 13 checks and both root-only phases pass.
It returns `1` with a failure receipt for a driver or evidence failure, and `2`
for invalid input. It copies no raw adapter output or stderr into the receipt.

Validate the receipt schema, then run the maintained semantic verifier against
the exact rendered scenario:

```bash
check-jsonschema \
  --schemafile deploy/native-ci/acceptance/receipt.schema.json \
  /protected/path/capacity-one-receipt.json

/usr/libexec/buzz-ci-verify-acceptance-receipt \
  /protected/path/capacity-one-scenario.json \
  /protected/path/capacity-one-receipt.json
```

The central activation package installs that sole verifier path with mode
`0755`. Its source is the Git-`100755` file
`deploy/native-ci/acceptance/verify-receipt.py`; restrictive checkouts may
materialize it as `0700`. Packaging must validate the tracked execute intent
and hardened file metadata through `verifier_source.py`, then install and read
back the declared `0755` mode.

The verifier reads its fixed 13-stage vector only from
`/usr/libexec/buzz-ci-acceptance-expected-stages.json`. The activation package
installs that tracked data asset as `root:root` mode `0644`; the verifier rejects
missing, linked, multiply linked, ownership- or mode-drifted, noncanonical, or
digest-drifted data. There is no argument or environment override for the path.

The verifier rejects reordered, duplicate, partial, or hash-only stage records.
It recomputes every retained driver-response and root-phase digest; binds the
scenario, activation package, candidate, run, evidence, and service generations;
and requires the sequence-15 proof to equal the retained final zero proof. Its
single JSON success line is acceptance evidence for that exact scenario. It is
not a deployment receipt and does not activate capacity. Keep capacity zero
until the separate activation decision and its approval are recorded.

## Failure and recovery

Treat every nonzero canary or verifier exit as closed. A failure after capacity
opened may retain a successful two-phase zero transition, but it never passes
the verifier. Confirm capacity zero through an independent read path before
retrying. Do not edit a failed receipt or reuse its grant, request, run, or
attempt identities. If sequence 15 cannot prove the close, stop and use the
approved service recovery procedure.
