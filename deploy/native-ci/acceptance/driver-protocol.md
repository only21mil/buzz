# Acceptance driver protocol

Each configured endpoint is an absolute executable path plus a bounded argument
list. The harness starts it directly. No shell parses the program or arguments.
The harness writes one JSON request to stdin and accepts one JSON response from
stdout. Each command has a 1 MiB output limit and the scenario timeout, capped
at 300 seconds. A nonzero exit, timeout, malformed response, wrong sequence,
wrong operation, or wrong protocol version fails the gate.

The five endpoint classes are:

| Endpoint | Operations |
| --- | --- |
| `observe` | `observe_initial` |
| `control` | capacity changes, submit, approve, resume, wait, rerun, cancel, tombstone |
| `export` | `export_first_evidence` |
| `controller_process` | `restart_controller` |
| `runner_process` | `restart_runner` |

The process endpoints must perform a real bounded restart and read back state
after recovery. A response synthesized from the request is not evidence.

## Request

Every request has this shape:

```json
{
  "schema_version": "buzz-ci-capacity-one-driver/v1",
  "sequence": 5,
  "operation": "resume_grant",
  "fixture": {},
  "attempt_id": "optional-lowercase-32-hex-attempt-id"
}
```

`fixture` is the exact fixture object from the scenario. `attempt_id` appears
when the operation targets an attempt already observed by the harness. The
adapter must reject a target that does not match its own durable state.

## Response

Every response repeats `schema_version`, `sequence`, and `operation`, then
returns a normalized snapshot:

```json
{
  "schema_version": "buzz-ci-capacity-one-driver/v1",
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
are 16-byte lowercase hex strings. Digests and principals are normalized
lowercase hex.

The export response also adds:

```json
{
  "export": {
    "authenticated": true,
    "subject": "64-lowercase-hex",
    "authorization_digest": "64-lowercase-hex",
    "attempt_id": "32-lowercase-hex",
    "request_digest": "64-lowercase-hex",
    "manifest_digest": "64-lowercase-hex",
    "evidence_set_digest": "64-lowercase-hex",
    "objects": [
      {"name": "job.log", "sha256": "64-lowercase-hex", "bytes": 131}
    ]
  }
}
```

The harness requires the export objects to equal the fixture log plus artifact
set, with no missing, duplicate, or extra object. It compares the export's
evidence-set digest to the terminal attempt's digest.

## Adapter rules

- Read actual controller, runner, ledger, and object-store state. Do not infer a
  later state from an earlier successful command.
- Authenticate through the deployed service boundary. Do not place credentials
  in arguments, responses, stdout diagnostics, or receipts.
- Return global active counts, not counts filtered to the fixture.
- Preserve tombstoned attempts in the normalized run so folding is observable.
- Return only after the requested state is durable and readable. For wait and
  restart operations, time out and exit nonzero if that cannot be established.
- Keep provider-specific fields inside the adapter. The normalized contract is
  deliberately provider-neutral.
