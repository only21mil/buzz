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
`/etc/buzzci/keyholder-v2.json`; activation validates its exact public receipt
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

The fixed fixture child also runs as `buzzci-job`. The executor and its one
digest-pinned fixture form a single narrow trust domain. This capacity-one
package does not authorize dynamic or general workloads. Supporting those
requires distinct executor and runtime principals plus a separately reviewed,
systemd or root-controlled identity transition. The current package must not
gain setuid helpers, UID-switching capabilities, or weaker service hardening.

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
match the staged payload exactly. The controld closed config must already exist
with its frozen staged bytes and metadata. The component-owned runner-v1 config
remains in place. The runner and activation packages share the byte-identical
dormant runner-v2 config, and activation later performs the active runner-v2
swap.
For all 13 lifecycle units, the controller reads both `FragmentPath` and
ordered `DropInPaths`. It independently hashes every returned fragment and
drop-in. Dormant checks allow only manifest-bound dependencies and exact
activation files captured as prior state. Every later phase rejects missing,
extra, duplicated, reordered, relocated, stale, or byte-drifted drop-ins.

1. `stage --scenario` validates the exact scenario and atomically installs and
   reopens the complete package at the fixed root-owned mode-`0700`
   `/var/lib/buzzci/activation-controller/package` before its first receipt,
   marker, managed-file, identity, tmpfiles, or systemd mutation. It installs
   the controller first and the package module second from that durable source,
   using deterministic resumable temporary names, and reads back both before
   writing a `preparing` receipt or rollback-retirement marker. Before the
   installed controller is published, the controller asset in the exact fixed
   package is the restart command. After publication, the installed controller
   can load the fixed package's module until the module target is published.
   A later activation accepts each retained recovery target only when it matches
   the prior rolled-back manifest or the exact successor manifest. It then
   completes the remaining recovery target before advancing durable state.
   Only after this restart anchor is exact does it apply the remaining
   generated sysusers, tmpfiles, acceptance
   binaries and units, target, drop-ins, and capacity-zero configs. After the
   package digest is known, it atomically
   writes the shared acceptance binding receipt, the two acceptance adapter
   configs, and the rendered capacity-zero execd-v2 config. It persists the
   truthful `staged_zero` receipt before starting any receipt-consuming staged
   service. A startup/readback failure triggers complete compensation and
   independent prior-state readback while retaining the exact fixed package,
   package module, and controller until explicit rollback reaches its durable
   cleanup phase. Only the two acceptance
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
7. After the canary returns capacity to zero, `persist-capacity-one` accepts the
   protected scenario and the canary's pass receipt. It freezes both inputs,
   runs the installed semantic receipt verifier, requires the receipt's final
   zero-controller digest to match the current private controller receipt, and
   derives a domain-separated operation ID from those exact bytes. It then
   reconstructs the bound `set-capacity-one` request, performs the same cutover,
   and reads back configs, fragments, sockets, process generations, target
   enablement, capacity one, and open admission again before returning. The
   private receipt retains the candidate, package, scenario, acceptance receipt,
   verifier output, zero receipt, operation, and final readback digests.
8. `rollback` first validates every managed target against its prior, staged,
   or active digest. Unknown drift stops rollback before systemd or file
   mutation. A valid rollback stops and disables the activation, restores exact
   prior bytes, metadata, and exact unit active/enable state. It restores or
   removes generated acceptance configs and restores the prior controld
   acceptance ledger. Service principals remain for audit and UID stability.
   The installed activation controller and package module remain at their exact
   staged bytes as the terminal recovery command.
   If the prior execd service or socket was active, rollback stops at a safe
   capacity-zero hold before restoring prior unit state while the standalone
   execd package receipt is active. The hold retains the fixed activation
   package and installed recovery command across process restart. Run the exact
   execd package's `install.py rollback`, then retry through the installed
   controller:

   ```bash
   /usr/libexec/buzz-ci-activation-controller rollback \
     --package /var/lib/buzzci/activation-controller/package
   ```

   The retry accepts only the exact current terminal execd rollback schema. Its
   `live_target` must prove absence or bind the restored baseline's device,
   inode, digest, mode, UID, and GID to the candidate-bound install receipt.
   The controller independently reads the live name and requires that exact
   proof before systemd may restart the prior execd unit.
   After the prior targets, generated files, ledger, and systemd state pass
   readback, the controller writes root-owned mode-`0600`
   `/var/lib/buzzci/activation-controller/rollback-cleanup-v1.json` and durably
   records `rollback_cleanup`. It then removes the fixed package with an
   idempotent closed-inventory cleanup. Every asset unlink, directory removal,
   and a missing fixed tree can resume only from that exact marker. Before the
   first marker write, the fixed path must be a real directory and the complete
   package must validate; a missing path, symlink, or other node fails closed.
   Only complete package absence permits the final `rolled_back` receipt write.
   If that write or its acknowledgement is lost, the installed controller loads
   the bound manifest from the marker, completes the receipt, and returns
   `unchanged` on an exact terminal retry. A later activation first binds the
   current marker to a root-owned retirement record. After the new `staged_zero` receipt and
   readback are durable, it archives the old marker under
   `/var/lib/buzzci/activation-controller/rollback-archive/`, then removes the
   current and retirement markers. Each archive write and marker unlink is
   independently replayable after interruption; the archive remains audit
   evidence while the new activation can create its own strictly bound marker.

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
separate `controld-acceptance-v2.json` binding at `root:root` mode `0444`.
Its compact declaration-order JSON has no trailing newline and uses schema
`buzz-ci-activation-acceptance-binding/v2`. It binds the keyholder client to
the controld identity and the acceptance client to the qualification identity.
The frozen public acceptance
template omits the scenario digest. After the package and scenario are final,
the controller injects the independently computed digest at the receipt top
level and in the nested acceptance object, where the two values must match.
The scenario digest matches `serde_json::to_vec` field order used by the Rust
canary. `render-scenario` emits that declaration order as compact JSON with no
trailing LF, so its literal file bytes hash to the same digest used by the
controller and installed verifier.

## Freeze

Create a private mode-`0600` draft that follows
`activation-manifest.schema.json`, except use schema
`buzz-ci-capacity-one-activation-draft-v2` and omit `activation_id` and
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
GID, `/var/lib/buzzci/principals/ctl` home, `/usr/sbin/nologin` shell, sole
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
declared exact modes. The freezer binds the verifier to the exact candidate
OID and computes its source digest from those tracked bytes at freeze time;
the package manifest records both values.
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

## Package bootstrap sequence

Use one full candidate SHA for every step. This order removes the former cycle
between the execd and activation packages:

1. Freeze and verify the final runner, controld, and keyholder packages. The
   controld freezer's config entry is the canonical staged
   `/etc/buzzci/controld-v2.json`: capacity zero plus the fixed public
   acceptance receipt path. Use those exact bytes and digest as the activation
   draft's staged controld config. Draft validation and final inventory reject
   any missing, substituted, or divergent config.
2. Run `deploy/native-ci/execd/freeze_package.py prepare-input` against the exact
   execd release binary and its canonical provenance. Keep those bytes fixed.
3. Run `render_inputs/generate_checked_templates.py activation-draft` against
   the complete validated draft. This production generator replaces only the
   candidate, public actor, ready-package component evidence, execd
   pre-activation evidence, and controld package bindings.
4. Run `render_inputs.py render-draft`. Its descriptor names the three ready
   manifests and the pre-activation execd input. It does not name an execd
   package manifest.
5. Freeze the activation package from that rendered draft and the exact asset
   directory.
6. Run `deploy/native-ci/execd/freeze_package.py freeze-package` with the same
   binary, provenance, and pre-activation input plus the final activation
   package. Any changed or replayed tuple fails.
7. Generate the checked scenario template from the maintained production
   scenario, then run `render-scenario` and `render-clean-host` with all five
   final package manifests and trees. The final renderer derives the closed v3
   harness and timing bindings from the exact candidate Git object and rejects
   a renderer checkout whose harness, guest entry, or timing asset differs.
8. Run `check_package_inventory.py` against those same five manifests before
   installation.

Do not substitute a provisional execd manifest, a synthetic activation
manifest, or a fixed-point digest. The pre-activation file carries no ownership
or install claims. Only the final execd manifest binds the final activation ID,
package digest, manifest digest, and activation-owned target hashes.

Clean-host preflight permits `not-found` only for the seven fragments installed
by this package. Every external dependency unit, including the controld
acceptance socket, must already be loaded from its sole package owner. After
installation and `daemon-reload`, staging requires all 13 lifecycle units
loaded and re-reads 18 exact fragment/drop-in paths and digests before starting
any staged service.

A clean-host terminal run takes an exclusive advisory lock through a no-follow
descriptor for the prepared state's parent directory. Contention waits at most
30 seconds, then fails before state selection. The same lock remains held
through claim, VM execution, result publication, and every cleanup path. Run
ownership is first written to a recoverable pending name bound to the canonical
ownership bytes and the selected state's device, inode, and marker digest. The
harness fsyncs that complete record and atomically renames it to
`run-ownership.json`. The canonical v2 record repeats that complete state
identity. Every resume or cleanup-authority decision compares its exact bytes
with a record derived from the currently held state descriptor. An exact retry
can rewrite an empty or partial matching pending record. A differently bound
pending record, a stale canonical identity, or a legacy v1 record grants no
cleanup authority and fails closed without changing the state. Cleanup moves
the selected state to its identity-checked tombstone and fsyncs that namespace
change, then revalidates the held descriptor's state identity and exact v2
ownership authority inside that quarantine immediately before sanitization.
An ownership or state replacement remains quarantined and unmodified. A crash
after zeroing leaves no public prepared or claimed state.

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
deploy/native-ci/activation/controller.py rollback --package /private/package
```

`activate` runs the closed production qualification and stops at
`qualified_closed`. The acceptance canary then uses the fixed controller calls
above, exercises capacity one, and returns the host to proven capacity zero.
Validate its pass receipt as described in
[`../acceptance/README.md`](../acceptance/README.md). The approved keyholder then
runs the maintained persistent cutover against those exact protected files:

```bash
/usr/libexec/buzz-ci-activation-controller persist-capacity-one \
  --scenario /protected/path/capacity-one-scenario.json \
  --acceptance-receipt /protected/path/capacity-one-receipt.json
```

The command accepts no package, root, or fake-state override. Both evidence
files must be regular, singly linked, non-writable by group or other, and
root-owned on the live host. An exact repeat is read-only and returns the same
terminal receipt. Changed, stale, mismatched, or differently bound evidence
fails closed. One root-owned nonblocking operator lock serializes `stage`,
`activate`, `qualify`, `set-capacity-one`, `prepare-qualification-zero`,
`finalize-qualification-zero`, `persist-capacity-one`, and `rollback`. A
concurrent mutator fails before state mutation. `check` and
`prove-qualification-zero` remain read-only.

If cutover fails but compensation proves staged capacity zero, rerun the exact
command. It reuses the same operation ID for at most three attempts. If the
receipt reports `rollback_failed`, or if independent readback is not exact, do
not retry activation. Recover deterministically with the fixed package path:

```bash
/usr/libexec/buzz-ci-activation-controller rollback \
  --package /var/lib/buzzci/activation-controller/package
```

`qualify --package ...` remains a post-activation health probe. It is not the
persistent cutover and requires `active_one`.

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

The byte-identical dormant controld and runner-v2 configs are modeled as shared
targets. The runner and activation packages intentionally share
`/etc/buzzci/runner-v2.json`; either package may install those exact dormant
bytes before activation swaps in the active runner-v2 config. Every other
duplicate fails, even with identical bytes. A modeled config share fails if its
digest, mode, UID, or GID differs. The gate
also checks the source tree and rejects any second
`buzz-ci-controld-acceptance.socket` template. Its only source and package
owner is controld.
