# Buzz CI capacity-one activation package

This package moves a fully installed native CI host from dormant capacity zero
to one ordinary job at a time. The source tree stays dormant. It does not
contain a frozen package, private key, credential, relay token, or enabled unit.

The controller composes the frozen runner, controld, execd, keyholder,
qualification, and runner-executor binaries. It does not replace their package
installers. Every binary has a full source commit, binary digest, and copied mode-`0400`
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

Controld cannot connect to execd. Keyholder cannot execute jobs. Execd remains
the sole privileged executor, and the runner still requires execd's UID 0 peer
credential.

## State machine

`check` starts from installed component packages and requires every existing
service and socket to be inactive. Managed activation files must be absent or
match the staged payload exactly. The runner and controld closed configs must
already exist with their frozen staged bytes and metadata.

1. `stage` installs the generated sysusers, tmpfiles, target, drop-ins, and
   capacity-zero configs. It provisions or verifies exact principals, reloads
   systemd, and reads back capacity zero. No unit is enabled or left active.
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
   prior bytes and metadata, and retains service principals for audit and UID
   stability.

The root-private receipt at
`/var/lib/buzzci/activation-controller/receipt-v1.json` binds the activation ID,
package digest, source commit, previous target contents and metadata, unit
readback, qualification result, and current state. Reusing a receipt with a
different package fails closed.

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
deploy/native-ci/activation/controller.py stage --package /private/package
deploy/native-ci/activation/controller.py activate --package /private/package
deploy/native-ci/activation/controller.py qualify --package /private/package
deploy/native-ci/activation/controller.py rollback --package /private/package
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
