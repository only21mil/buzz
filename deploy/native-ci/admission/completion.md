# Operator completion for native runners

The admission example has an explicit `begin` → root runner submission →
`publish` lifecycle. It supports one initial request for `CI/dead-token-guard`
or `native-macos/desktop-build-macos-unsigned`. The fixture daemon still does
not dispatch either runner. This is an operator-submitted job, not automatic
dispatch or full workflow matrix parity.

`begin` reads the exact request from authenticated accepted intake, records it
in a dedicated durable store, and publishes a signed queued acknowledgement.
It never asserts execution has started. After root runs the admission,
`publish` validates the original manifest-signed registration, exact request
and source, protected root receipt, measured start/completion times, cleanup
and evidence bytes. It passes those facts to the existing `ProductionHandler`,
`UnixKeyholderClient`, `AuthenticatedRelay`, and `DurableControlStore`.

The ordinary handler publishes historical running and job states using the
measured timestamps, uploads real log/result bytes, and publishes terminal
run/check events. Success also requires the existing evidence-finalized and
lease-empty teardown facts. Failure, cancellation and timeout follow the
existing handler semantics: job/log/artifact/run/check without success-only
finalization and teardown events. Every outcome requires exact signed check
readback. Success additionally reuses `export_first_evidence`, which checks
authenticated event and object readback. The final stdout object names those
accepted IDs and object hashes. A local validation object is not relay evidence.

## Required live capabilities

Root must first review and install the frozen admission example and the runner
packages under the existing approval. The Mac broker changes require an updated
package inventory and corresponding lane/build identity before admission.
`desktop-build.sh` is unchanged. No new credentials or keyholder peer identities
are needed. Existing peer UID/GID 1201 supplies the control-plane socket calls.

The installed fixture controller must include intake isolation before any native
request is published. Its background poll selects only its configured fixture
actor, workflow ID and job IDs. Other requests advance only its own durable
cursor, without signed run facts or execution. An existing local run for an
unowned request closes capacity for reconciliation; upgrading does not erase or
repair facts published by an older controller. Fixture digest and execution
failures still use the ordinary failure path.

The live relay and keyholder must support the current kind 46108 check, exact
event query, and evidence upload/readback operations. The scoped status-signer
grant must be accepted and read back before `begin`. Old pre-46108 deployments
cannot complete this path; a local grant file does not activate a signer.
The genuine 1618 source pin, trusted-base workflow selection, accepted 46100,
reviewed authority file, and existing owner CLI trust configuration remain
prerequisites from the [admission guide](README.md).

## Queued acknowledgement before execution

Build the reviewed example using the admission guide. The commands below use
the installed `/usr/local/libexec/buzz-ci-native-admission` path. All public
authority/request/source files must be root:root 0444, one link, under canonical
root-owned directories without group/other writes. Retain independent SHA256s.

Each request has its own store at
`/var/lib/buzzci/native-publication/REQUEST_EVENT_ID`. Root creates the parent
root:root 0755 and the request directory UID/GID 1201, mode 0700. Never point
this operator at the fixture daemon's store. Intake scanning does not advance
the daemon's cursor.

Prepare a root query/staging watcher **before** launching `buzz ci run`.
The CLI publishes its request and waits for a bounded queued acknowledgement;
it does not print the signed request before that wait. The watcher captures the
matching signed request from authoritative accepted intake, stages it with the
permissions above, creates its store, and immediately invokes:

Install the reviewed `watch-and-begin.py` root:root 0755 as
`/usr/local/libexec/buzz-ci-native-watch-and-begin.py`. Ensure
`/var/lib/buzzci` is a root-owned protected directory. Start this command in a
foreground terminal/tool session, then start the CLI in another session after
the `native request capture ready` diagnostic appears:

```sh
sudo -n /usr/bin/python3 -I /usr/local/libexec/buzz-ci-native-watch-and-begin.py \
  /var/lib/buzzci/native-admission/ATTEMPT AUTHORITY_SHA256 \
  https://RELAY 60 /var/lib/buzzci/native-admission/ATTEMPT/queued.readback.json
```

The watcher invokes `await-request` through UID/GID 1201. That command only
returns a signature-verified request from authenticated accepted intake that
matches the reviewed authority/source and was issued at or after capture
started. It scans to the current intake head and refuses multiple matching
fresh requests. Capture is capped at 60 seconds and 10,000 intake reads; the
root wrapper enforces a subprocess deadline. No owner key is loaded and no
request is signed or submitted by the watcher. It creates the request file
and per-request store once, then runs the following acknowledgement command:

```sh
sudo -n -u '#1201' -g '#1201' /usr/local/libexec/buzz-ci-native-admission begin \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json AUTHORITY_SHA256 \
  /var/lib/buzzci/native-admission/ATTEMPT/request.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/source.event.json \
  https://RELAY
```

Only after `begin` returns accepted queued readback and the CLI returns queued
should root sign the registration and submit it through the installed Linux
supervisor or fixed Mac SSH adapter. Follow their reviewed run commands.
Do not treat a CLI acknowledgement timeout followed by later import as a
working dispatch. `begin` retries are idempotent while the attempt remains
queued. It does not advance the intake cursor or execute the runner.

## Collect actual root evidence

Create a fresh root-owned bundle directory below the public admission attempt.
Root stages all files as root:root 0444, one link, with protected ancestors:

| File | Linux origin | Mac origin |
| --- | --- | --- |
| `registration.bin` | Exact submitted 992-byte frame | Exact submitted 992-byte frame |
| `receipt.json` | Root supervisor's `supervisor.json` | Fixed SSH broker `run` or `status` JSON |
| `result.json` | Actual worker `result.json`, equal to supervisor `native_result` | Same exact broker receipt bytes as `receipt.json` |
| `stdout.log`, `stderr.log` | Actual worker retained log files | Not used |
| `job.log` | Not used | Fixed broker `log` operation |

Linux receipts are validated against exact registration/admission, profile,
source and workload projection, unit exit, invocation and independent empty
cgroup/container cleanup. The publication log contains stdout then stderr with
explicit channel headers. It makes no claim about relative timing between the
two channels. The original streams are compared with their receipt hashes and
observed byte counts before serialization.

The Mac root broker retains the first 1 MiB of combined stdout/stderr, its exact
hash/size, observed byte count, truncation flag, and actual start/completion
times. Root retrieves only the log belonging to the same retained admission:

```sh
python3 deploy/native-ci/macos/submit.py --operation log \
  --verifier /PATH/TO/REVIEWED/buzz-ci-admission-verifier \
  --policy /PATH/TO/REVIEWED/policy.json < registration.bin > job.log
```

The adapter verifies the retained frame and compares returned bytes against the
fixed broker `status` receipt. The SSH operation accepts no caller-selected
remote path. This command must run in root's already-authorized transport
context; UID 1201 does not inherit an SSH credential.

Current native-CI log envelopes reject truncated logs as durable evidence.
The operator refuses truncated or missing logs **before publication**. It never
changes the flag or substitutes metadata for unavailable log bytes. Linux keeps
32 KiB per stream; Mac keeps 1 MiB. A cap hit needs an explicit reviewed change
and a fresh attempt. Missing/unclean receipts likewise cannot become success.
The sole `result.json` artifact remains terminal metadata, maximum 32768 bytes;
it does not claim to export the unsigned `.app`.

## Bundle and publication

Create `bundle.json` with exactly these fields and retain its independent
SHA256. Hash the exact staged file bytes, without newline or JSON normalization.

```json
{
  "schema_version": 1,
  "relay_base_url": "https://RELAY",
  "profile_sha256": "REVIEWED_PROFILE_SHA256",
  "receipt_sha256": "SHA256_OF_RECEIPT_JSON",
  "result_sha256": "SHA256_OF_RESULT_JSON",
  "registration_sha256": "SHA256_OF_REGISTRATION_BIN"
}
```

Linux `profile_sha256` is the exact installed runner profile hash reported in
its receipt. Mac uses the reviewed `authority.lane.host_profile_digest`.
Compare those profile preimages and package inventories to actual host readback;
hashing a new assertion does not prove installation.

Validate the retained bundle without contacting the keyholder or relay:

```sh
/usr/local/libexec/buzz-ci-native-admission check-completion \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json AUTHORITY_SHA256 \
  /var/lib/buzzci/native-admission/ATTEMPT/request.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/source.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/bundle/bundle.json BUNDLE_SHA256
```

Then perform the already-approved publication under the existing socket peer:

```sh
sudo -n -u '#1201' -g '#1201' /usr/local/libexec/buzz-ci-native-admission publish \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json AUTHORITY_SHA256 \
  /var/lib/buzzci/native-admission/ATTEMPT/request.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/source.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/bundle/bundle.json BUNDLE_SHA256
```

Publication requires the prior accepted queued intent. It rechecks authoritative
intake rather than trusting a caller's watch cursor. Retained completions may be
published after admission expiry, but their measured execution must have started
inside the signed window. The existing whole-run timeout still determines the
final run/check conclusion. A long cleanup can therefore turn a successful job
into a timed-out run.

Keep the per-request durable store and immutable bundle after any error. Retry
the same command and inputs after the specific relay/keyholder fault is fixed.
The existing publication intents reconcile exact event acceptance and do not
rerun the native job. Review changes to authority, evidence or runner packages
as new work; do not rewrite retained facts to force a passing import.
