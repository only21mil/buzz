# Capacity-one activation acceptance

Native CI is not qualified or active merely because this harness builds or its
unit tests pass. A real acceptance run must finish with a schema-valid `pass`
receipt against the exact installed candidate. The run ends by closing
admission and returning capacity to zero.

The harness drives a fixed sequence through injected commands. It does not
contain provider URLs, service-manager commands, credentials, or prebaked
success responses. Each adapter must read actual system state and return the
normalized response described in [driver-protocol.md](driver-protocol.md). The
harness checks that response independently.

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
13. Capacity returns to zero, admission closes, and durable run state remains.

Any missing field, duplicate attempt, extra evidence object, identity mismatch,
generation regression, or ambiguous active count stops the sequence. A failed
receipt never authorizes activation.

## Inputs

Start from [scenario.template.json](scenario.template.json), but replace every
identity and command with values from the frozen activation package. In
particular, replace the template candidate SHA and placeholder approval values
after the final integrated commit exists. Adapter programs must be absolute
paths. Do not put secrets in `args`.

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
cargo build --locked --release \
  -p buzz-ci-acceptance-ctl \
  --bin buzz-ci-capacity-one-canary

target/release/buzz-ci-capacity-one-canary \
  < /protected/path/capacity-one-scenario.json \
  > /protected/path/capacity-one-receipt.json
```

The binary returns `0` only after all 13 checks pass. It returns `1` with a
failure receipt for a driver or evidence failure, and `2` for invalid input.
It copies no raw adapter output or stderr into the receipt.

Validate and inspect the receipt:

```bash
check-jsonschema \
  --schemafile deploy/native-ci/acceptance/receipt.schema.json \
  /protected/path/capacity-one-receipt.json

jq -e '
  .outcome == "pass" and
  (.checks | length) == 13 and
  .checks[12].stage == "return_capacity_zero" and
  .checks[12].outcome == "pass"
' /protected/path/capacity-one-receipt.json
```

A passing receipt is acceptance evidence for its exact scenario digest and
candidate SHA. It is not a deployment receipt and does not activate capacity.
Keep capacity zero until the separate activation decision and its approval are
recorded.

## Failure and recovery

Treat every nonzero exit as closed. Confirm capacity zero through an independent
read path before retrying. Do not edit a failed receipt or reuse its grant,
request, run, or attempt identities. Fix the adapter or system, render a new
scenario, and rerun the complete sequence. If the final capacity-zero operation
cannot be proven, stop and use the approved service recovery procedure.
