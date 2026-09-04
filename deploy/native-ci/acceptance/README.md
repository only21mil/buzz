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

Both driver endpoints are systemd socket units, so the kernel reports pid 1
root as the `SO_PEERCRED` of every connection the driver opens: it names the
process that called `listen()`, not the service that accepts. Before it
connects, the driver requires the socket inode at the fixed path to be a
root-owned socket with the `buzzci-ctl` group and mode `0620`, the shape only
the installed socket unit produces under the root-owned `0711` runtime
directory. After it connects, it accepts exactly two listeners: the endpoint
service's own uid and gid, or pid 1 root. Any other root process, an
unmappable pid, and any other identity fail closed as `wrong_peer`. Controld
still authenticates the driver itself through `SO_PEERCRED`, because the
driver connects directly and the kernel reports the connecting process.

## What the gate proves

The 16 checks run in this order. Run A is the successful evidence lane; Run B
is a distinct failed-parent and rerun lane with different run and request IDs:

1. Capacity is zero, admission is closed, and no work is active.
2. Capacity becomes exactly one without starting work.
3. The exact candidate, source object, request, and manifest wait for approval.
4. The expected approver and grant are present, but no attempt starts.
5. Explicit resume starts exactly one first attempt.
6. The first attempt terminates successfully with the expected log and artifact.
7. Authenticated relay queries read back the exact signed evidence references
   and final facts, then bounded authenticated `GET`s return exactly Run A
   attempt 1 `job.log` and the declared `result` artifact (`result.json`) with
   the same evidence set, lengths, and byte digests. The returned nip98 subject
   and generation equal the frozen `export_subject` and `export_generation`.
8. The exact Run B manifest enters the granted-but-not-resumed boundary without
   starting work.
9. Explicit resume starts exactly one Run B attempt.
10. Run B attempt one terminates in failure with its exact failure log and no artifact.
11. Rerun creates Run B attempt two with a distinct ID and attempt one as its parent.
12. Cancellation makes attempt two terminal with a cancelled conclusion.
13. A tombstone keeps attempt two visible and folds Run B back to failed attempt one.
14. The root acceptance helper restarts controld. Its generation advances and
    controld recovers the folded Run B state.
15. The root acceptance helper restarts the runner. Its generation advances and
    controld retains the folded Run B state.
16. The root helper prepares staged zero first. The restarted capacity-zero
    controld then journals and returns the final durable snapshot with capacity
    zero, admission closed, no active work, and the folded Run B state intact.

The receipt then retains two root-only phases. Sequence 17 finalizes capacity
zero and stops the controld acceptance transport. Sequence 18 independently
proves capacity zero, closed admission, and the absence of the controld service,
socket unit, and socket path. These phases are not acceptance-stage entries.

The activation binding freezes five actor-signed events. The keyholder's
`describe_acceptance` response names their semantic slots as Run, Grant,
Rerun, Tombstone, FailureRun. The gate publishes them in API call order as Run,
Grant, FailureRun, Rerun, Tombstone because Run B must exist and fail before its
rerun and tombstone. Do not treat the semantic field order as publication
chronology.

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

The scenario and shared acceptance receipt contain the Run A request digest,
run ID, job ID, expected hashes, fixed object declarations, and export selector
identity; they contain no evidence URL or path list. Keyholder independently
reconstructs the one log path and one artifact path with attempt `1` and
artifact ID `result`. A third path is denied even when it has canonical syntax.

The checked-in fixture runs
[`fixtures/run-fixture.sh`](fixtures/run-fixture.sh). It verifies the source
input digest, writes a byte-stable `result.json`, and emits one byte-stable success log
line. A distinct, domain-separated UUIDv5 identifies Run B without encoding
fixture behavior in the identifier. The activation manifest freezes a public
`failure_selector` bound to Run B's job ID, run ID, and attempt 1, and hashes
that tuple separately. The controller copies it into the scenario, driver
configuration, and execd static declaration. Execd injects the resulting
`BUZZ_CI_FIXTURE_OUTCOME` only after the exact tuple matches; attempt 1 emits
the byte-stable failure log and exits nonzero without an artifact, while Run A
and Run B attempt 2 enter the normal success/hold path.
[`fixtures/fixture-manifest.json`](fixtures/fixture-manifest.json) binds
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

The binary returns `0` only after all 16 checks and both root-only phases pass.
It returns `1` with a failure receipt for a driver or evidence failure, and `2`
for invalid input. It copies no raw adapter output or stderr into the receipt.
The receipt never contains an Authorization header, encoded NIP-98 token, raw
NIP-98 event, signature, nonce, NIP-98 timestamp, credential, or evidence-object
bytes. It retains only stable public selector identity and generation facts,
sanitized request bindings and object metadata, and deterministic digests of
those values.

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

The verifier reads its fixed 16-stage vector only from
`/usr/libexec/buzz-ci-acceptance-expected-stages.json`. The activation package
installs that tracked data asset as `root:root` mode `0644`; the verifier rejects
missing, linked, multiply linked, ownership- or mode-drifted, noncanonical, or
digest-drifted data. There is no argument or environment override for the path.

The verifier rejects reordered, duplicate, partial, or hash-only stage records.
It recomputes every retained driver-response and root-phase digest; binds the
scenario, activation package, candidate, run, evidence, and service generations;
and requires the sequence-18 proof to equal the retained final zero proof. Its
single JSON success line is acceptance evidence for that exact scenario. It is
not a deployment receipt and does not activate capacity. Keep capacity zero
until the separate activation decision and its approval are recorded.

## Failure and recovery

Treat every nonzero canary or verifier exit as closed. A failure after capacity
opened may retain a successful two-phase zero transition, but it never passes
the verifier. Confirm capacity zero through an independent read path before
retrying. A stage-7 authentication, exact-event cardinality or binding,
response-cap, object-length, or digest failure stops the gate before Run B and
returns no partial export. Do not edit a failed receipt or reuse its grant,
request, run, or attempt identities. If sequence 18 cannot prove the close,
stop and use the approved service recovery procedure.
