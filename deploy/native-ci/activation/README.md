# Buzz CI capacity-one activation package

This package moves a fully installed native CI host from dormant capacity zero
to one ordinary job at a time. The source tree stays dormant. It does not
contain a frozen package, private key, credential, relay token, or enabled unit.

The controller composes the frozen runner, controld, execd, keyholder,
qualification, and runner-executor binaries. It also installs the three frozen
capacity-one acceptance binaries and the tracked receipt verifier because no
other package owns them. The same central package installs the exact executor
binary, execd/executor unit fragments, and the three immutable fixture inputs;
they are not assumed to exist on a clean host. Every
binary has a full source commit, binary digest, and copied mode-`0400`
provenance record. The staged and active runner, execd-template, and controld
configs have separate digests. Execd's exact live configs are rendered only
after the package digest and acceptance scenario are known. The separate
keyholder package solely owns
`/etc/buzzci/keyholder-v1.json`; activation validates its exact public receipt
reference, peer operations, selectors, origin, owner, and mode but never writes
the file.

The controld package solely owns
`/etc/systemd/system/buzz-ci-controld-acceptance.socket`. Activation does not
publish or roll back that path. Its manifest binds the canonical controld
package-manifest digest and the exact controld service and acceptance-socket
bytes.

Live `stage`, `activate`, and `rollback` actions require root and use exact
`/usr/bin/systemd-sysusers`, `/usr/bin/systemd-tmpfiles`, and
`/usr/bin/systemctl` paths without a shell or sudo. Tests select the fake
systemd driver and never invoke those programs.

## Fixed principal and socket plan

The manifest freezes five distinct numeric UIDs and GIDs plus one dedicated
socket-access group:

- `buzzci-runner` owns runner state and connects to execd.
- `buzzci-controld` owns controller state and connects to the runner and
  keyholder sockets.
- `buzzci-keyholder` owns only the signer service and its private state.
- `buzzci-ctl` runs only the descriptor-bound qualification controller.
- `buzzci-job` runs the fixed unprivileged executor and has no supplementary
  groups.
- `buzzci-execd` has exactly `buzzci-runner` and `buzzci-ctl` as supplementary
  members. Membership grants socket reachability, not protocol authorization;
  execd must still authorize exact `SO_PEERCRED` UID and primary GID claims.

The generated sysusers file uses nologin shells and exact supplementary group
memberships. Socket permissions grant only the required adjacent connection:

| Endpoint | Owner | Group | Mode | Accepted peer |
| --- | --- | --- | --- | --- |
| `/run/buzzci/keyholder.sock` | `buzzci-keyholder` | `buzzci-controld` | `0620` | controld only |
| `/run/buzzci/runner-control.sock` | `buzzci-runner` | `buzzci-controld` | `0620` | controld only |
| `/run/buzzci/execd.sock` | `root` | `buzzci-execd` | `0620` | runner and qualification controller |
| `/run/buzzci/acceptance-control.sock` | `root` | `buzzci-ctl` | `0620` | qualification controller only |
| `/run/buzzci/controld-acceptance.sock` | `root` | `buzzci-ctl` | `0620` | qualification controller only |
| `/run/buzzci/executor.sock` | `root` | `root` | `0600` | execd only |

Controld cannot connect to execd. Keyholder cannot execute jobs. Execd remains
the sole privileged executor, and the runner still requires execd's UID 0 peer
credential.

## State machine

`check` starts from installed component packages and requires activation-owned
services and sockets to be inactive. A pre-existing enabled and listening execd
socket is captured as baseline state. Managed activation files must be absent or
match the staged payload exactly. The runner and controld closed configs must
already exist with their frozen staged bytes and metadata.
For all 13 lifecycle units, the controller reads both `FragmentPath` and
ordered `DropInPaths`. It independently hashes every returned fragment and
drop-in. Dormant checks allow only manifest-bound dependencies and exact
activation files captured as prior state. Every later phase rejects missing,
extra, duplicated, reordered, relocated, stale, or byte-drifted drop-ins.

1. `stage --scenario` validates the exact scenario, installs the generated
   sysusers, tmpfiles, acceptance binaries and units, target, drop-ins, and
   capacity-zero configs. After the package digest is known, it atomically
   writes the shared acceptance binding receipt, the two acceptance adapter
   configs, and the rendered capacity-zero execd-v2 config. It persists the
   truthful `staged_zero` receipt before starting any receipt-consuming staged
   service. A startup/readback failure triggers complete compensation and
   independent prior-state readback.
   It also installs the controller and its package module, then copies the
   validated package to the fixed root-owned mode-`0700`
   `/var/lib/buzzci/activation-controller/package`. Only the two acceptance
   sockets and their services remain active. Ordinary CI units and the
   capacity-one target remain inactive and disabled.
2. `activate` first starts execd with its rendered capacity-zero config while
   admission and the capacity-one target remain closed. It constructs a closed
   production-v2 qualification request from exact package, scenario, principal,
   lane, seccomp, executor, and generation bindings. Random request ID, nonce,
   time bounds, and complete compact bytes are persisted before execution and
   reused byte-for-byte on retry.
3. The descriptor-opened `/usr/libexec/buzz-ci-production-qualification`
   receives that request with no arguments. The controller clears the
   environment, applies `no_new_privs`, and runs it as the manifest-bound
   `buzzci-ctl` identity with sole `buzzci-execd` supplementary membership.
   Timeout cleanup TERM/KILLs and reaps the whole new process group. Only an
   exact `qualified_closed` production-v2 response passes. The client is frozen
   at source commit `564e41fda889f25b094b79524b3fb409121794c7`; neither the
   legacy v1 client nor the full live canary is used for this gate.
   An uncertain delivery may retry the exact persisted request at most three
   times and only while `now < expires_at`. The server has no outcome-query
   operation and rejects replay after expiry. An unresolved expiry therefore
   moves the receipt to `qualification_uncertain`, preserves the request and
   last transport error, returns to proven capacity zero, and permits only
   rollback. Restaging must change the package, fixture, controller generation,
   or runner generation before the controller creates a new request identity.
4. A passing qualification stops the temporary execd service and records
   `qualified_closed` only after the staged configs, capacity-zero units, and
   closed admission are read back. Capacity remains zero until the root helper
   invokes the separate fixed `set-capacity-one` action.
5. `set-capacity-one` verifies the immutable package, private receipt, shared
   acceptance binding, passed qualification, exact principal, candidate,
   scenario, and initial generation bindings. It stops the staged controld
   acceptance socket before controld, atomically swaps the active runner,
   rendered execd, and controld configs, reloads systemd, starts the exact
   keyholder/executor/execd/runner/controld dependency order, and enables the target only
   after config, FragmentPath, socket, process InvocationID, capacity-one, and
   open-admission readback. The executor socket and service must be active at
   their exact `/usr/lib/systemd/system` fragments before capacity one is
   reported. Acceptance-control remains alive throughout and the
   controld acceptance socket is active when the action returns for canary
   sequence 2.
6. Any failed capacity-one action attempts every stop, disable, config-restage, reload,
   and independent readback. It records `rollback_failed` unless both staged
   configs and capacity zero are proven. A proven compensation returns to
   `qualified_closed` and permits only the same request bytes and operation ID,
   at most three attempts; it never labels an unproven host safe.
7. `rollback` first validates every managed target against its prior, staged,
   or active digest. Unknown drift stops rollback before systemd or file
   mutation. A valid rollback stops and disables the activation, restores exact
   prior bytes, metadata, and exact unit active/enable state. It restores or
   removes generated acceptance configs and restores the prior controld
   acceptance ledger. Service principals remain for audit and UID stability.

The production canary closes capacity through three root-only calls to the
installed `/usr/libexec/buzz-ci-activation-controller`. Each call accepts only
its fixed hyphenated action and a compact JSON request on stdin. It accepts no
package or root path from the caller.

- `prepare-qualification-zero` verifies the immutable fixed package, restores
  and reads back the staged runner, rendered execd, and controld configs, and keeps controld plus
  both acceptance services available for the stage-13 durable snapshot.
- `finalize-qualification-zero` stops the controld acceptance socket first and
  controld second, closes the remaining capacity-one units, keeps the root
  acceptance-control service available, restores the prior controld binding,
  and records `staged_zero` only after independent file, unit, and socket-path
  readback passes.
- `prove-qualification-zero` performs the same readback without changing the
  receipt or reconnecting to controld.

The controller request and response schemas remain
`buzz-ci-activation-qualification-zero-request/v1` and
`buzz-ci-activation-qualification-zero-response/v1`. The calling root-control
protocol is separately versioned as `buzz-ci-acceptance-control-request/v2`
and `buzz-ci-acceptance-control-response/v2`. Finalize and prove return the
SHA-256 of the existing private activation receipt. The caller combines that
digest with its own fresh systemd `zero_proof`; the controller does not create
a second evidence file.

The production canary opens capacity through one separate root-only fixed call:

```text
/usr/libexec/buzz-ci-activation-controller set-capacity-one
```

It accepts no package, root, scenario, or fake-state path. Stdin is one compact
JSON object plus LF, with declaration-order fields
`schema_version,action,activation_id,activation_package_digest,scenario_sha256,initial_controller_generation,initial_runner_generation,operation_id`.
The schema is `buzz-ci-activation-capacity-one-request/v1`, the action is
`set_capacity_one`, and every value is checked against the fixed package,
private activation receipt, and shared binding. Stdout on success is one compact
JSON object plus LF with declaration-order fields
`schema_version,action,activation_id,activation_package_digest,scenario_sha256,operation_id,state,receipt_sha256`.
The response schema is `buzz-ci-activation-capacity-one-response/v1`, state is
`active_one`, and `receipt_sha256` hashes the exact bytes of the final private
receipt including its LF. Exact replay is read-only and idempotent; a different
request or operation ID is rejected.

The root-owned receipt at
`/var/lib/buzzci/activation-controller/receipt-v1.json` binds the activation ID,
package digest, source commit, previous target contents and metadata, unit
readback, qualification result, and current state. Reusing a receipt with a
different package fails closed.

The shared `/var/lib/buzzci` ancestor and this directory are `root:root` mode
`0711`; sensitive child roots remain mode `0700`. The private controller receipt
remains `root:root` mode `0600`; both controld and keyholder read only the
separate `controld-acceptance-v1.json` binding at `root:root` mode `0444`.
Its compact declaration-order JSON has no trailing newline and uses schema
`buzz-ci-activation-acceptance-binding/v1`. The frozen public acceptance
template omits the scenario digest. After the package and scenario are final,
the controller injects the independently computed digest at the receipt top
level and in the nested acceptance object, where the two values must match.
The scenario digest matches `serde_json::to_vec` field order used by the Rust
canary, not the input file's whitespace or key order.

## Freeze

Create a private mode-`0600` draft that follows
`activation-manifest.schema.json`, except use schema
`buzz-ci-capacity-one-activation-draft-v1` and omit `activation_id` and
`package_digest`. Asset names are flat `assets/...` names. Put config and
provenance inputs in a private asset directory with the exact source modes
declared by the draft. Qualification requests are never frozen assets because
they bind the final package digest and runtime validity interval.

The runner staged config is the exact runner-v2 `dormant` shape at
`/etc/buzzci/runner-v2.json`. Its active config selects `mode=v2_proxy`, binds
the root execd peer at `/run/buzzci/execd.sock`, and carries the frozen lane
authority. The package freezes closed capacity-zero and capacity-one execd-v2
templates with zero dynamic placeholders. After freezing, the controller
injects only the final package digest, canonical scenario digest, and initial
controller/runner generations, atomically installs the rendered
`/etc/buzzci/execd-v2.json`, and receipt-binds both rendered digests. The config binds protocol v2,
`RegisterJobIntent` operation 9, exact runner and qualification peers, the
`buzzci-job` executor principal, retained intent/state roots, the executor
socket, lane manifest digest, and packaged `/usr/libexec/buzz-ci-executor`
provenance. It also binds the exact `buzzci-ctl` name, manifest-selected UID and
GID, `/var/lib/buzzci/ctl` home, `/usr/sbin/nologin` shell, sole
`buzzci-execd` supplementary group, and private qualification root. Dynamic
accepted-request intent files are runtime state and are
never frozen into the activation package.

The templates also carry one closed `execution` declaration. Its digest is a
domain-separated SHA-256 over the candidate OID, final package digest, lane and
isolation digests, fixed workflow/job/artifact, the three fixture digests, and
big-endian resource limits. The freezer accepts only a zero digest placeholder;
the controller computes the nonzero declaration after the final package digest
and scenario manifest binding are known. The installed immutable sources are
`/usr/share/buzzci/execd-v2/fixture/fixture-manifest.json` and `input.txt`
root:root `0444`, plus `/usr/libexec/buzz-ci-capacity-one-fixture` root:root
`0555`. No request can select a command, environment, executable, or path.

The package also freezes the tracked Git-`100755` receipt verifier from
`deploy/native-ci/acceptance/verify-receipt.py`, records its source commit and
digest, and installs it only at
`/usr/libexec/buzz-ci-verify-acceptance-receipt` mode `0755`. A private
umask checkout may materialize that source as `0700`; the freezer checks the
Git executable class and writes the package asset and installed target at their
declared exact modes. The settled source contract is commit
`84698212017eb20891c931c645024c0e7de265f8`, SHA-256
`2d95e2a97655e40ef779804065f68450dd6745ba2b499e4ecf9218f25540c6fd`.
Its Git-`100644` expected-stage table is separately frozen at package mode
`0400` and installed root:root mode `0644` only at
`/usr/libexec/buzz-ci-acceptance-expected-stages.json`; the verifier has no
argument or environment override for that path.

The activation tmpfiles entry creates retained execd and seccomp parent
directories only. `/var/lib/buzzci`, `execd-v2`, `execd-v2/attempts`, and the
seccomp `{v1,sha256}` traversal chain are root:root `0711`; sensitive siblings
remain `0700`. Per-attempt job-owned directories and files are created by execd
with their narrower `0500`/`0400`/`0700`/`0600` contract. The execd composition package owns the immutable seccomp
profile and receipt; stage and rollback neither create nor remove those files.
Controld changes from capacity 0 to capacity 1 without changing its schema,
store root, or fixed receipt path. Its active config carries the complete relay,
runner-v2, lane, workflow, single-job, single-artifact, and keyholder public
bindings from controld commit `65f1dee3bbad485ba4f9746c839ee0b7fd385fb3`.
It contains no inline acceptance policy or scenario/package digest. The static
keyholder config exposes only the fixed shared receipt reference and
`acceptance-actor.key` credential selector; the credential bytes never enter
the activation package.

```bash
deploy/native-ci/activation/freeze_package.py \
  --source-root "$PWD" \
  --source-commit FULL_40_CHARACTER_SHA \
  --draft /private/activation-draft.json \
  --asset-root /private/activation-inputs \
  --output /private/buzz-ci-capacity-one-package
```

The freezer requires a clean activation source directory at the named commit.
An owner-held Git worktree root may be mode `2775` only when it is the exact
top-level worktree for `core.sharedRepository=all`, has setgid without sticky or
world write, and its Git directory and tracked-input parents pass the same
ownership and no-symlink checks. Tracked files still reject group/world write,
hard links, irregular files, and executable-class drift. Asset and output
directories never receive this exception.
It renders exact numeric sysusers entries, copies the reviewed systemd files,
checks all config and provenance digests, writes a canonical manifest, and
binds the activation ID to its package digest.
The draft's controld component names a mode-`0400` copy of the frozen controld
`package-manifest.json` in `--asset-root`. The freezer checks its canonical
package digest, source commit, and both controld unit entries.

Clean-host preflight permits `not-found` only for the seven fragments installed
by this package. Every external dependency unit, including the controld
acceptance socket, must already be loaded from its sole package owner. After
installation and `daemon-reload`, staging requires all 13 lifecycle units
loaded and re-reads 18 exact fragment/drop-in paths and digests before starting
any staged service.

Before using a package against `/`, transfer its root, `assets` directory,
manifest, and every asset to `root:root`. Both directories must be mode `0700`.
The manifest must be mode `0600`, provenance and config sources mode `0400`,
and every other source must retain its declared mode. `check` verifies these
conditions without changing the host.

## Controller commands

These commands describe the approved operator procedure. Do not run live
mutation actions without the separate deployment approval.

```bash
deploy/native-ci/activation/controller.py check --package /private/package
deploy/native-ci/activation/controller.py stage \
  --package /private/package \
  --scenario /private/capacity-one-scenario.json
deploy/native-ci/activation/controller.py activate --package /private/package
deploy/native-ci/activation/controller.py qualify --package /private/package
deploy/native-ci/activation/controller.py rollback --package /private/package
```

The installed canary calls these fixed commands. Operators do not pass a
package path to them:

```bash
/usr/libexec/buzz-ci-activation-controller prepare-qualification-zero
/usr/libexec/buzz-ci-activation-controller finalize-qualification-zero
/usr/libexec/buzz-ci-activation-controller prove-qualification-zero
```

Tests use a non-root filesystem and an explicit fake driver state file:

```bash
deploy/native-ci/activation/controller.py check \
  --package /private/test-package \
  --root /private/fake-root \
  --fake-systemd-state \
    /private/fake-root/var/lib/buzzci/activation-controller/fake-systemd-v1.json
```

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/activation/tests -v
python3 -m py_compile deploy/native-ci/activation/*.py
python3 -m json.tool deploy/native-ci/activation/activation-manifest.schema.json >/dev/null
systemd-analyze verify --recursive-errors=no \
  deploy/native-ci/activation/templates/buzz-ci-capacity-one.target
```

Run the collision gate against the exact five final manifests before install:

```bash
deploy/native-ci/activation/check_package_inventory.py \
  --runner /private/runner/package-manifest.json \
  --controld /private/controld/package-manifest.json \
  --keyholder /private/keyholder/package-manifest.json \
  --execd /private/execd/package-manifest.json \
  --activation /private/activation/activation-manifest.json
```

Only the byte-identical dormant runner and controld configs are modeled as
shared targets. Every other duplicate fails, even with identical bytes. A
modeled config share fails if its digest, mode, UID, or GID differs.
