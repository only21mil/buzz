# Buzz CI acceptance suite

`run_suite.sh` runs the 17 security runners and the six Phase-2 probes twice.
It writes one security JSONL file, one probe JSONL file, and the aggregate
verdict for one candidate SHA.

## Real run

Use a checkout of the merged main candidate for `--candidate-dir`. Point
`--probe-bin` at the real `buzz` CLI, not at a test mock. Until the broker and
proxy changes from #55 and #56 are merged, point the runners at their checked
out crates with `BUZZ_CI_BROKER_DIR` and `BUZZ_CI_PROXY_DIR`.

```bash
candidate=$(git -C /path/to/merged-main rev-parse HEAD)
BUZZ_CI_BROKER_DIR=/path/to/broker \
BUZZ_CI_PROXY_DIR=/path/to/proxy \
ci-acceptance/suite/run_suite.sh \
  --candidate "$candidate" \
  --candidate-dir /path/to/merged-main \
  --evidence-root /path/to/acceptance-evidence \
  --probe-bin /path/to/merged-main/target/release/buzz \
  --probe-repo-owner block \
  --probe-repo-id buzz \
  --probe-workflow buzz-ci-phase2-probe-v1
```

The suite does not infer a candidate SHA from the checkout. Pass the complete
lowercase object ID explicitly. A production run must not use a path under
`ci-acceptance/fixtures`; those paths are guarded mocks for the selftest.

`--plan` calls every discovered security runner with `--plan` and records the
probe plan without executing checks. It returns a plan document even when a
runner is still missing. `--security-only` and `--probes-only` are useful for
diagnostics, but the aggregate verdict stays red until both canonical sets are
complete.

## Evidence layout

For an evidence root `/var/tmp/buzz-ci-evidence` and candidate `SHA`, the
runner writes:

```text
/var/tmp/buzz-ci-evidence/SHA/
  security.jsonl
  probe.jsonl
  verdict.json
  TM-01/
    runner.stdout
    runner.stderr
    MANIFEST.sha256
    ...runner-reported files...
  P-i/run-1.results.jsonl
  P-i/run-2.results.jsonl
  ...
  probe-run/
    results.jsonl
    summary.json
    run.stdout
    run.stderr
```

Each security `evidence_ref` is the SHA-256 of its `MANIFEST.sha256`. The
manifest contains the SHA-256 and relative path of each retained evidence
file. Each probe `evidence_ref` is the SHA-256 of that probe/run's result
slice. Raw command output stays below the candidate evidence directory.

## Security runner contract

The following contract is authoritative for every security runner:

```text
Security test runners:
- Path: ci-acceptance/suite/security/tm-NN_<slug>.sh (NN = 01..17, two digits). Executable bash, `set -euo pipefail`, shellcheck -S warning clean, self-contained (bash + coreutils + jq + the tools it tests; no shared library sourcing).
- CLI: tm-NN_<slug>.sh --candidate <full 40-hex sha> --candidate-dir <path to a checkout at that sha> --evidence-dir <writable dir> [--plan]
  Optional env: BUZZ_CI_BROKER_DIR / BUZZ_CI_PROXY_DIR (checkouts holding the broker and proxy crates while #55/#56 are unmerged; default to --candidate-dir), SUITE_SUDO (default: `sudo -n` if `sudo -n true` works, else empty), SUITE_TIMEOUT_SECONDS per runner (default 600).
- Output: exactly one JSON object on stdout (nothing else on stdout; diagnostics to stderr):
  {"test_id":"TM-NN","title":"<title from tm_tests.json>","status":"pass|fail|not_runnable|plan","pass":<bool, true only when status==pass>,"summary":"<one line>","checks":[{"name":"<snake_case>","status":"pass|fail|not_runnable|plan","detail":"<one line, no secrets>"}],"evidence_files":["<relative path under evidence-dir/TM-NN/>", ...],"preconditions":["<what must exist for the not_runnable checks>"]}
  Exit codes: 0 pass, 1 fail, 3 not_runnable, 4 usage/internal error. Overall status is pass only when every check passes; any not_runnable check makes the overall status not_runnable (nothing unrunnable counts as a pass); any failed check makes it fail (fail beats not_runnable).
- --plan: prints the same JSON with status "plan" for the runner and every check, lists preconditions, touches nothing, needs no root, never executes the checks. Must work on any machine.
- Evidence: write every raw readback/log/command output under <evidence-dir>/TM-NN/ (create it), list each file in evidence_files, never write secrets or token values, and never modify the candidate checkout. Use `timeout` on every external command. Root steps go through "$SUITE_SUDO" only; if SUITE_SUDO is empty a root-needing check is not_runnable with a clear detail.
- Truthfulness: report what the host/candidate actually shows. A check that cannot be decided yet is not_runnable with a precise precondition; never invent a pass.
```

## Exit codes

| Command | 0 | 1 | 2 | 3 | 4 |
| --- | --- | --- | --- | --- | --- |
| `run_suite.sh` | Green aggregate | Valid red aggregate | Malformed input or orchestration | - | Usage/internal error |
| `run_security.sh` | Runners recorded | - | Duplicate/canonical input error | - | Usage/internal error |
| A `tm-NN_*.sh` runner | Pass | Failed check | - | Not runnable | Usage/internal error |
| `probes_bridge.sh` | All 12 probe runs pass | A probe run fails | Mock guard or malformed probe output | - | Usage/internal error |

The aggregate script is the final authority for a normal run. It requires all
17 security records and all 12 probe/run records at one exact candidate SHA.

## Seam contract as published

The root-owned `/etc/buzzci/harness.env` file publishes these `KEY=VALUE`
entries. Runners read it with the configured `SUITE_SUDO` command and parse
the values as data. They never source it:

`BUZZ_CI_EXECD_SOCKET`, `BUZZ_CI_BROKER_UNIT`, `BUZZ_CI_LEASE_STATE_ROOT`,
`BUZZ_CI_RUNNER_CTL`, `BUZZ_CI_ACCEPTANCE_CTL`,
`BUZZ_CI_QUALIFICATION_CASE_ROOT`, `BUZZ_CI_FIXTURE_REPO`,
`BUZZ_CI_HARNESS_SIGNER`, `BUZZ_CI_GRAPH_REDUCER`, and
`BUZZ_CI_GRAPH_FIXTURE_DIR`.

TM-06, TM-07, and TM-12 through TM-17 never send synthetic control flags.
They stream exact root-authored, root:root mode `0444` case files from the
qualification case root to the no-argv acceptance controller. Missing,
mutable, symlinked, or otherwise unsafe case artifacts are `not_runnable`.

For a lease id, the published state is laid out as follows:

```text
<lease-state-root>/<lease_id>/
  materializer/receipt.json
  materializer/commands.jsonl
  proxy/decisions.jsonl
  proxy/objects/<sequence>.json
  ordering.jsonl
  teardown.json
  reconcile.json
  lease.json
```

`lease.json.lease_unit` is the exact transient unit name. It may end in
`.service` or `.scope`; consumers must use that value and the recorded
`cgroup_path`, never derive a name from the lease id. The broker also records
the resource-property readback in `lease.json`.

The TM-09 lease readback has one `dns_readback` object. All five booleans must
be true: `files_lookup_ok`, `arbitrary_getent_refused`,
`resolved_varlink_inaccessible`, `direct_53_refused`, and
`allowed_tuples_only`. The first proves lookup of the broker-pinned relay and
mirror names inside the materializer unit. The last four prove that arbitrary
DNS and egress remain blocked while approved address/port tuples work.

| Runner | Decides today | Decides after wiring |
| --- | --- | --- |
| TM-01 | Tracking records when Buzz credentials are present | Same, with the published issue history |
| TM-02 | Act, Podman, and image pin readbacks where installed | Full host/toolchain pin check |
| TM-03 | Broker source and dependency posture | Broker IPC isolation and socket readback |
| TM-04 | Materializer source hardening | Signed receipt and `commands.jsonl` readback |
| TM-05 | Proxy source, route census, and transport refusals | Recorded `decisions.jsonl` mediation |
| TM-06 | Account, subuid, cgroup, and mount posture | Live slot provisioning and quarantine |
| TM-07 | Socket and listener negative checks | Live lease socket isolation |
| TM-08 | Act implicit-config fixture checks | Live act invocation with the accepted fixture |
| TM-09 | Host nft and DNS checks where root is available | Five `dns_readback` proofs in `lease.json` |
| TM-10 | Reducer source presence and relay `ci::` tests | Signed reducer fixtures and act-side concurrency record |
| TM-11 | Proxy pre-start source checks | `proxy/objects` effective-spec records before start |
| TM-12 | Exhaustion fixture syntax and timeout markers | Cgroup, ordering, teardown, and reconciliation readback |
| TM-13 | Hostile-artifact fixture payloads | Sanitized publication and terminal ordering |
| TM-14 | Runner teardown-attestation guard | Live terminal ordering and fault refusal |
| TM-15 | Crash fixture syntax and static controls | `lease_unit`, cgroup, `reconcile.json`, and no-reuse proof |
| TM-16 | Broker protocol refusal source checks | Fresh retry, replay refusal, and capacity enforcement |
| TM-17 | Broker-protocol and runner static refusal checks | Live refusal through the runner control path |
