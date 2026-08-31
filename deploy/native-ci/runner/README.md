# Buzz CI runner source package

This directory packages the unprivileged `buzz-ci-runner` process. The checked-in
files do not create accounts, install files, run `systemd-tmpfiles`, reload
systemd, or enable or start a unit.

The installed default stays closed:

- `buzz-ci-runner.socket` is installed but disabled.
- `runner-v2.json` defaults to `mode=dormant` and binds the exact controld UID
  and GID. It has no `host` block.
- The runner returns `backend_unavailable` when someone starts the dormant unit
  manually. The package records `enabled=false`, `active=false`,
  `provisioned=false`, `host_block=false`, and `capacity=0`.

The package does not enable the socket, and the production parser rejects a
`host` block. No activation package can select the removed same-UID local
executor. Broker v2
reaches execd through its separate fixed-width transport, and execd alone owns
job execution and durable evidence.

## Fixed resources

The runner listens only on `/run/buzzci/runner-control.sock`. Systemd names its
single inherited descriptor `buzz-ci-runner-control`. The socket is statically
bound to `buzzci-runner:buzzci-controld` mode `0620`: the runner owns the
listening endpoint and only the distinct controld group may connect. The sealed
package manifest and every `check`, `dry-run`, and install readback report that
identity contract together with the dormant state.

The privileged broker socket remains `/run/buzzci/execd.sock`; this package
does not create or own it. Its frozen access contract is
`root:buzzci-execd` mode `0620`, with `buzzci-runner` and `buzzci-ctl` as the
exact supplementary members. The runner service declares only its own required
membership. Broker authorization still checks the exact root `SO_PEERCRED` UID.

The runner writes only its bounded request-ID replay map under
`/var/lib/buzzci/runner`. Execd owns active v2 evidence retention.
The controld handoff root remains `/var/lib/buzzci/runner-output`; this package
does not create it and the runner service cannot write it.

The host must already have these dedicated principals:

- `buzzci-runner`, the service and private state owner
- `buzzci-controld`, the group allowed to connect to the runner socket

The numeric `buzzci-runner` UID and GID and the numeric `buzzci-controld` UID
are frozen into each package and must be numerically distinct. The ordinary
config is mode `0600` and owned by the runner UID and GID. The binary, units,
tmpfiles file, documentation, and their installed directory roots are
root-owned.

This package does not alter the execd socket or group database. The activation
package owns both. Installation here remains dormant and does not grant group
membership, start a service, or expose execution capacity.

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
revalidates installation ownership before reporting the same plan. `install`
uses descriptor-verified sources, descriptor-relative atomic replacements, and
exact metadata readback. Before it creates a managed directory or publishes a
target, it durably records a root-private `transaction.json` with the package
ID, package digest, source commit, candidate metadata, complete prior-state
inventory, backup digests, and transaction digest. Its explicit phases are
`install_prepared`, `install_publishing`, and `installed`.

Repeating `install` for an installed transaction returns the same terminal
result and backup ID. If the prior process stopped while publishing, the retry
accepts only an exact mix of recorded prior and candidate states, then finishes
the same transaction. Any third state is drift and blocks recovery. The
terminal `receipt.json` must match the transaction binding.

Rollback requires the same package and backup ID. It validates every backup,
target, and removable directory before recording `rollback_prepared`, then
records `rollback_restoring` before its first target mutation. A restart accepts
only an exact mix of candidate and recorded prior states and restores the rest.
`rolled_back` is terminal, and repeating the same rollback returns the same
result without another mutation. A receipt/transaction mismatch, package
mismatch, unexpected target state, or directory drift blocks rollback. The
installer also accepts an exact parent-era v1 receipt-only backup. A legacy
dry-run validates the receipt, package, candidate targets, unchanged package
targets, prior-state inventory, backup files, and created directories without
writing `transaction.json` or changing the receipt. A real rollback persists
the synthesized transaction first, upgrades the matching receipt to v2, and
then enters the same restartable rollback phases. An exact legacy
`installed` receipt may contain an exact candidate/prior mix left by an
interrupted v1 rollback; migration records `rollback_restoring` and continues
from that point. An exact legacy `rolled_back` receipt is an idempotent
read-only terminal retry. Missing, ambiguous, third-state, or tampered legacy
evidence is refused before migration.

The machine-readable check and install results include the exact runner-control and
broker peer policy plus the disabled, inactive, unprovisioned capacity-zero
state. Those fields describe what this package leaves unchanged; they are not a
substitute for the separate activation procedure's live systemd readback.

Neither install nor rollback calls systemd. An operator must separately run the
reviewed reload or activation procedure. Installation alone leaves the socket
disabled and the runner unprovisioned.

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/runner/tests -v
python3 -m py_compile deploy/native-ci/runner/*.py
```
