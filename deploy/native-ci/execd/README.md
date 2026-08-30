# Buzz CI dormant execd source package

This directory packages the privileged `buzz-ci-execd` execution broker. The
checked-in files do not create accounts, install files, run
`systemd-tmpfiles`, reload systemd, or enable or start a unit.

The installed default stays closed:

- `buzz-ci-execd.service` and `buzz-ci-execd.socket` are installed but static,
  disabled, and inactive. Neither install nor rollback calls systemd.
- The broker reports `not_provisioned` with capacity `0` until a separately
  reviewed activation procedure provisions it.
- State reported as `enabled=false`, `active=false`, `provisioned=false`, and
  `capacity=0`.

## Fixed resources

The broker is socket-activated on `/run/buzzci/execd.sock` with the inherited
descriptor name `buzz-ci-execd`. The socket unit creates the socket root-owned
mode `0666`: reachability is delegated to the broker, which verifies the peer
UID before reading any request bytes and refuses every account other than the
two dedicated peers. The package installs the unit that owns that socket but
never creates or starts the runtime socket itself.

The broker runs as `root` because it executes the privileged host operations
(lease teardown, DNS activation, materializer handoff) that no unprivileged
account may perform. It resolves its peers from `/etc/passwd`:

- `buzzci-ctl`, the control-plane peer, must exist exactly once with UID and
  GID `961`, home `/var/lib/buzzci/principals/ctl`, and the
  `/usr/sbin/nologin` shell, matching the deployment contract compiled into
  the broker.
- `buzzci-runner` must exist exactly once with a nonzero UID and GID distinct
  from the control peer and the same login posture.

The installer validates exactly those identity rules and refuses a host whose
accounts drift from them. The binary, units, tmpfiles file, documentation,
and their installed directory roots are root-owned. The only managed
directory is `/usr/share/doc/buzz-ci-execd`; `/run/buzzci` is provisioned by
the packaged tmpfiles entry shared with the runner package.

## Freeze a package

Build `target/release/buzz-ci-execd` from one clean full source commit with
the pinned toolchain. The build lane writes a mode-`0600` provenance file:

```json
{
  "binary": "buzz-ci-execd",
  "profile": "release",
  "schema": "buzz-ci-binary-provenance-v1",
  "sha256": "<64 lowercase hex characters>",
  "source_commit": "<full 40-character source commit>"
}
```

Freeze it in an owner-private directory:

```bash
deploy/native-ci/execd/freeze_package.py \
  --source-root "$PWD" \
  --source-commit FULL_40_CHARACTER_SHA \
  --binary target/release/buzz-ci-execd \
  --binary-provenance /private/path/buzz-ci-execd.provenance.json \
  --output /private/path/buzz-ci-execd-package
```

The freezer binds the supplied binary digest and provenance, exact commit,
every payload and destination, mode, dormant daemon contract, and default
state. It refuses dirty package sources, links, broad modes, provenance
mismatch, and pre-existing output.

Before any install against `/`, the package root and assets directory must be
root-owned mode `0700`. Manifest and provenance files must be root-owned mode
`0600`; every asset must retain the manifest mode.

## Source-only operator modes

These commands document the lifecycle. Live install or rollback remains
approval-gated and is outside this package task.

```bash
deploy/native-ci/execd/install.py check --package /private/package
deploy/native-ci/execd/install.py dry-run --package /private/package
deploy/native-ci/execd/install.py install --package /private/package
deploy/native-ci/execd/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID \
  --dry-run
deploy/native-ci/execd/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID
```

`check` is read-only and validates the sealed package, host peer identities,
target parents, exact changed paths, and closed metadata without requiring
root. `dry-run` revalidates install ownership. `install` uses
descriptor-verified sources, atomic replacement, exact metadata readback, and
a root-private backup receipt. Rollback refuses installed-target or backup
drift before restoring prior bytes and metadata.

Neither installer action invokes systemd. Machine-readable default-state
fields describe package behavior, not live systemd observation; a separate
reviewed activation procedure owns socket enabling, unit start, and live
readback.

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/execd/tests -v
python3 -m py_compile deploy/native-ci/execd/*.py
systemd-analyze verify deploy/native-ci/execd/templates/buzz-ci-execd.service \
  deploy/native-ci/execd/templates/buzz-ci-execd.socket
```
