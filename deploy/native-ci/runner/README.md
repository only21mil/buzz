# Buzz CI runner source package

This directory packages the unprivileged `buzz-ci-runner` process. The checked-in
files do not create accounts, install files, run `systemd-tmpfiles`, reload
systemd, or enable or start a unit.

The installed default stays closed:

- `buzz-ci-runner.socket` is installed but disabled.
- `runner-v1.json` contains only `schema_version` and `controld_uid`. It has no
  `host` block.
- The runner returns `backend_unavailable` when someone starts the dormant unit
  manually. The package records `provisioned=false` and `capacity=0`.

Provisioning a host block and enabling the socket require a separate reviewed
activation package. This installer does neither.

## Fixed resources

The runner listens only on `/run/buzzci/runner-control.sock`. Systemd names its
single inherited descriptor `buzz-ci-runner-control`. The privileged broker
socket remains `/run/buzzci/execd.sock`; this package does not create or own it.

Runner-owned evidence and journal data live under `/var/lib/buzzci/runner`.
The controld handoff root remains `/var/lib/buzzci/runner-output`; this package
does not create it and the runner service cannot write it.

The host must already have these dedicated principals:

- `buzzci-runner`, the service and private state owner
- `buzzci-controld`, the group allowed to connect to the runner socket

The numeric `buzzci-runner` UID and GID and the numeric `buzzci-controld` UID
are frozen into each package. The ordinary config is mode `0600` and owned by
the runner UID and GID. The binary, units, tmpfiles file, documentation, and
their installed directory roots are root-owned.

## Freeze a package

Build `target/release/buzz-ci-runner` from a clean full source commit. The build
lane must write a mode `0600` provenance file with this exact shape:

```json
{
  "binary": "buzz-ci-runner",
  "profile": "release",
  "schema": "buzz-ci-binary-provenance-v1",
  "sha256": "<64 lowercase hex characters>",
  "source_commit": "<full 40-character source commit>"
}
```

Then freeze the package in a private directory:

```bash
deploy/native-ci/runner/freeze_package.py \
  --source-root "$PWD" \
  --source-commit FULL_40_CHARACTER_SHA \
  --binary target/release/buzz-ci-runner \
  --binary-provenance /private/path/buzz-ci-runner.provenance.json \
  --output /private/path/buzz-ci-runner-package \
  --runner-uid RUNNER_UID \
  --runner-gid RUNNER_GID \
  --controld-uid CONTROLD_UID \
  --controld-gid CONTROLD_GID
```

The freezer refuses a different checkout head, a dirty package source path, an
untracked template, a linked input, a broad source mode, a provenance mismatch,
or a pre-existing output. It copies the binary provenance into the package and
binds its digest, the full Git commit, every payload digest, every destination,
and every installed UID, GID, and mode in `package-manifest.json`.

Before an install against `/`, transfer the package root, `assets`, manifest,
provenance, and every asset to `root:root`. The two directories must be mode
`0700`; the manifest and provenance must be mode `0600`; package payload modes
must match the manifest. `install.py` checks all of this with no-follow file
descriptors.

## Source-only operator modes

These commands describe the installation lifecycle. Do not run `install` or
`rollback` on a live host without the required approval.

```bash
deploy/native-ci/runner/install.py check --package /private/package
deploy/native-ci/runner/install.py dry-run --package /private/package
deploy/native-ci/runner/install.py install --package /private/package
deploy/native-ci/runner/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID \
  --dry-run
deploy/native-ci/runner/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID
```

`check` validates an operator-owned sealed package, host identities, target
parents, and exact changed paths without writing or requiring root. `dry-run`
revalidates installation ownership before reporting the same plan. `install` uses
descriptor-verified sources, atomic replacements, exact metadata readback, and
a root-private backup receipt. Reinstalling the same package returns
`unchanged`. Rollback requires the same package and backup ID and refuses any
installed-target drift before restoring prior bytes and metadata.

Neither install nor rollback calls systemd. An operator must separately run the
reviewed reload or activation procedure. Installation alone leaves the socket
disabled and the runner unprovisioned.

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/runner/tests -v
python3 -m py_compile deploy/native-ci/runner/*.py
```
