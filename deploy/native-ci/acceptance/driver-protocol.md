# Acceptance driver protocol

Each endpoint is the manifest-bound
`/usr/libexec/buzz-ci-capacity-one-driver` with no arguments. The harness starts
it directly. No shell parses the program or arguments.
The harness writes one JSON request to stdin and accepts one JSON response from
stdout. Each driver response frame has a 1 MiB stdout limit and the scenario
timeout, capped at 300 seconds. This is not a relay-response limit. The stage-7
adapter permits at most 8 MiB for an exact-event JSON response. Each evidence
object is bounded by its signed expected byte length and by the adapter's 16 MiB
hard ceiling, even though the public relay evidence route permits up to 32 MiB.
A nonzero exit, timeout, malformed response, wrong sequence, wrong operation,
or wrong protocol version fails the gate.

The five endpoint classes are:

| Endpoint | Operations |
| --- | --- |
| `observe` | `observe_initial` |
| `control` | capacity changes, submit, approve, resume, wait, rerun, cancel, tombstone |
| `export` | `export_first_evidence` |
| `controller_process` | `restart_controller` |
| `runner_process` | `restart_runner` |

The driver first calls `/run/buzzci/acceptance-control.sock` for a fresh host
readback. That root-owned helper accepts only readback, capacity changes, and
the two fixed restart actions. It verifies the root activation receipt and an
exact `buzzci-ctl` peer. The driver then sends the operation and host readback
to `/run/buzzci/controld-acceptance.sock`. Controld owns every relay, signer,
durable-run, and evidence operation. A response synthesized from the request is
not evidence.

This is the API call order for every acceptance stage: root control first,
controld second. For ordinary relay operations, the root call is only
`observe`; the stage's semantic operation runs in controld. At sequences 14 and
15 the root helper owns the systemd restart, then the restarted controld
journals and returns its recovered snapshot. At sequence 16 the helper prepares
staged zero before the capacity-zero controld journals the final snapshot.

## Request

Every request has this shape:

```json
{
  "schema_version": "buzz-ci-capacity-one-driver/v2",
  "scenario_sha256": "64-lowercase-hex",
  "sequence": 5,
  "operation": "resume_grant",
  "fixture": {},
  "attempt_id": "optional-lowercase-32-hex-attempt-id"
}
```

`fixture` is the exact fixture object from the scenario. It includes the
activation ID and package digest, candidate, run, job, grant event and digest,
source and manifest digests, export identity, and initial service generations.
The export identity is the exact `export_subject` plus nonzero
`export_generation` of the frozen nip98 selector.
`attempt_id` appears when the operation targets an attempt already observed by
the harness. After sequence one, every request also carries the controller and
runner generations returned by the prior step. Either service rejects stale
generations and any target that differs from durable state.

## Response

Every response repeats `schema_version`, `sequence`, and `operation`, then
returns a normalized snapshot:

```json
{
  "schema_version": "buzz-ci-capacity-one-driver/v2",
  "sequence": 1,
  "operation": "observe_initial",
  "snapshot": {
    "capacity": 0,
    "admission": "closed",
    "active_run_count": 0,
    "active_attempt_count": 0,
    "controller_generation": 12,
    "runner_generation": 9
  }
}
```

Later snapshots add one `run`. The run binds `run_id`, candidate SHA, request
digest, manifest digest, source object, state, aggregate conclusion, approval,
selected attempt, and all attempts. Each attempt binds its ID, number, parent,
state, conclusion, all source identities, and terminal evidence. Attempt IDs
are 16 bytes rendered as exactly 32 lowercase hex characters. They are not the
evidence URL's `attempt` coordinate, which is a canonical positive decimal
`u32` attempt number. Digests and principals are normalized lowercase hex.

The export response also adds:

```json
{
  "export": {
    "authenticated": true,
    "subject": "64-lowercase-hex",
    "generation": 1,
    "authorization_digest": "64-lowercase-hex",
    "attempt_id": "32-lowercase-hex",
    "request_digest": "64-lowercase-hex",
    "manifest_digest": "64-lowercase-hex",
    "evidence_set_digest": "64-lowercase-hex",
    "objects": [
      {"name": "job.log", "sha256": "64-lowercase-hex", "bytes": 131},
      {"name": "result.json", "sha256": "64-lowercase-hex", "bytes": 107}
    ]
  }
}
```

The harness requires the export objects to equal the fixture log plus artifact
set, with no missing, duplicate, or extra object. It compares the export's
evidence-set digest to the terminal attempt's digest. `authorization_digest` is
a stable deterministic digest over the ordered evidence-object `GET` bindings
and the dedicated nip98 subject and generation. Exact-event `/query` proofs use
the distinct ci-event subject and generation and are validated at runtime; the
query operations and their volatile proof IDs are not part of this frozen
digest. It is never a digest of an Authorization header, bearer token,
signature, nonce, or timestamp.
The harness requires the response `subject` and `generation` to equal fixture
`export_subject` and `export_generation` exactly.

The two ordered object bindings are not supplied as URLs or a path list. They
are reconstructed from the fixture's Run A request digest, run ID, job ID,
expected hashes, fixed attempt `1`, and fixed `job.log` and `result` artifact
declaration (`result.json`). Only those two paths may be signed or read; a third
canonical evidence path fails the stage.

## Adapter rules

- Read actual controller, runner, and ledger state. Stage 7 reads the relay's
  exact signed events through `/query` and the objects at their signed evidence
  `GET` URLs; controld receives no direct object-store credential. Require one
  signature-valid event for each exact id, author, and kind, then verify every
  object's canonical path, expected length, SHA-256, and set membership. Do not
  infer a later state from an earlier successful command.
- Authenticate through the deployed service boundary. Do not place credentials
  in arguments, responses, stdout diagnostics, or receipts.
- Bind every operation to the canonical scenario digest and deterministic
  operation ID. Only a byte-identical replay may reuse an operation ID.
- Return global active counts, not counts filtered to the fixture.
- Preserve tombstoned attempts in the normalized run so folding is observable.
- Return only after the requested state is durable and readable. For wait and
  restart operations, time out and exit nonzero if that cannot be established.
- Keep the stage-7 operation identity and target fixed across recovery. A retry
  after response staging returns the stored response without another read; a
  crash before staging may repeat the idempotent reads with fresh NIP-98 tokens.
  Tokens and their volatile event IDs never enter a response or receipt.
- Keep provider-specific fields inside the adapter. The normalized contract is
  deliberately provider-neutral.
