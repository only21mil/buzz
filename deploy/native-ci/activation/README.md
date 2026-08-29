# Buzz CI capacity-one activation package

This package moves a fully installed native CI host from dormant capacity zero
to one ordinary job at a time. The source tree stays dormant. It does not
contain a frozen package, private key, credential, relay token, or enabled unit.

The controller composes the frozen runner, controld, execd, keyholder,
qualification, and runner-executor binaries. It also installs the three frozen
capacity-one acceptance binaries because no other package owns them. Every
binary has a full source commit, binary digest, and copied mode-`0400`
provenance record. The staged and active runner and controld configs have
separate digests. The keyholder config is secret-free; its socket ABI remains
in the manifest and systemd unit. The controller rejects fields whose names
suggest private key material, seeds, credentials, or tokens.

Live `stage`, `activate`, and `rollback` actions require root and use exact
`/usr/bin/systemd-sysusers`, `/usr/bin/systemd-tmpfiles`, and
`/usr/bin/systemctl` paths without a shell or sudo. Tests select the fake
systemd driver and never invoke those programs.

## Fixed principal and socket plan

The manifest freezes four distinct numeric UIDs and GIDs plus one dedicated
socket-access group:

- `buzzci-runner` owns runner state and connects to execd.
- `buzzci-controld` owns controller state and connects to the runner and
  keyholder sockets.
- `buzzci-keyholder` owns only the signer service and its private state.
- `buzzci-ctl` runs only the descriptor-bound qualification controller.
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

Controld cannot connect to execd. Keyholder cannot execute jobs. Execd remains
the sole privileged executor, and the runner still requires execd's UID 0 peer
credential.

## State machine

`check` starts from installed component packages and requires activation-owned
services and sockets to be inactive. A pre-existing enabled and listening execd
socket is captured as baseline state. Managed activation files must be absent or
match the staged payload exactly. The runner and controld closed configs must
already exist with their frozen staged bytes and metadata.

1. `stage --scenario` validates the exact scenario, installs the generated
   sysusers, tmpfiles, acceptance binaries and units, target, drop-ins, and
   capacity-zero configs. After the package digest is known, it atomically
   writes the controld binding receipt and the two acceptance adapter configs.
   It also installs the controller and its package module, then copies the
   validated package to the fixed root-owned mode-`0700`
   `/var/lib/buzzci/activation-controller/package`. Only the two acceptance
   sockets and their services remain active. Ordinary CI units and the
   capacity-one target remain inactive and disabled.
2. `activate` replaces only the runner and controld configs with their frozen
   active variants. It starts keyholder, execd, runner, and controld in the
   manifest's fixed order. Socket ownership and mode readback must pass.
3. The controller sends one bounded, frozen request on stdin to the
   descriptor-opened `/usr/libexec/buzz-ci-acceptance-ctl`. It passes no
   arguments, clears the environment, applies `no_new_privs` where supported,
   and runs as the manifest-bound `buzzci-ctl` UID, primary GID, and sole
   supplementary group. Timeout cleanup sends TERM and then KILL to the whole
   new process group. The exact response digest and a second health readback
   must pass before the controller enables `buzz-ci-capacity-one.target`.
4. Any failed activation attempts every stop, disable, config-restage, reload,
   and independent readback. It records `rollback_failed` unless both staged
   configs and inactive units are proven; it never labels an unproven host
   `staged_zero`.
5. `rollback` first validates every managed target against its prior, staged,
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
  and reads back the staged runner and controld configs, and keeps controld plus
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

The root-owned receipt at
`/var/lib/buzzci/activation-controller/receipt-v1.json` binds the activation ID,
package digest, source commit, previous target contents and metadata, unit
readback, qualification result, and current state. Reusing a receipt with a
different package fails closed.

The same directory is `root:buzzci-controld` mode `0710`. The private controller
receipt remains `root:root` mode `0600`; the daemon sees only the separate
`controld-acceptance-v1.json` binding at `root:buzzci-controld` mode `0440`.
The scenario digest matches `serde_json::to_vec` field order used by the Rust
canary, not the input file's whitespace or key order.

## Freeze

Create a private mode-`0600` draft that follows
`activation-manifest.schema.json`, except use schema
`buzz-ci-capacity-one-activation-draft-v1` and omit `activation_id` and
`package_digest`. Asset names are flat `assets/...` names. Put config,
provenance, and qualification request inputs in a private asset directory with
the exact source modes declared by the draft.

The runner staged config must omit `host`; its active config must add the full
host block, bind `/run/buzzci/execd.sock` to peer UID 0, and name only the
manifest-bound `/usr/libexec/buzz-ci-executor`. Controld must change from
capacity 0 to capacity 1 without changing its schema or store root. The
keyholder config is installed during staging, but the separate socket remains
inactive until activation. Its exact daemon fields are `schema_version`,
`peer`, `selectors`, and `nip98_origin`; socket and credential-descriptor
details remain in the manifest/systemd layer. The active controld config
carries the same public selectors and generations plus the exact keyholder
peer UID and GID.

```bash
deploy/native-ci/activation/freeze_package.py \
  --source-root "$PWD" \
  --source-commit FULL_40_CHARACTER_SHA \
  --draft /private/activation-draft.json \
  --asset-root /private/activation-inputs \
  --output /private/buzz-ci-capacity-one-package
```

The freezer requires a clean activation source directory at the named commit.
It renders exact numeric sysusers entries, copies the reviewed systemd files,
checks all config and provenance digests, writes a canonical manifest, and
binds the activation ID to its package digest.

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
