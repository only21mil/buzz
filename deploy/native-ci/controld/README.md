# Buzz CI controld source package

This directory packages the capacity-zero default and strict capacity-one
configuration contract for `buzz-ci-controld`. It accepts a supplied exact
release binary and provenance record; it does not build, fetch, or install a
binary on the live host by itself.

The checked-in package does not create accounts, run `systemd-tmpfiles`, reload
systemd, enable or start a unit, provision keys, contact a relay, connect to a
runner or broker, or grant execution capacity. The installed service sandbox
permits only the network and local sockets needed after a separate activation.

## Closed contract

The installed default remains:

- `buzz-ci-controld.service` present but static, disabled, and inactive;
- `controld-v1.json` contains only schema version 1, capacity exactly `0`, and
  absolute store root `/var/lib/buzzci/controld`;
- no relay URL, key descriptor, keyholder, runner, broker, or polling
  configuration;
- state reported as `enabled=false`, `active=false`, `provisioned=false`,
  `providers_wired=false`, and `capacity=0`.

In capacity zero the daemon opens only its owner-private durable control store,
reports the unified `parked` readiness record, and parks without polling,
dispatching, networking, or signing. An activation may add only the fixed
post-freeze `acceptance_binding` receipt path while capacity remains zero. The
root-owned, controld-group-readable receipt binds the complete fixture,
scenario and package digests, peer identity, and timeout without creating a
package self-digest cycle. Capacity one is accepted only with the complete relay authority,
channel, authenticated runner identity and bounds, exact static lane,
JobIntentV2 job and artifact declaration, keyholder selector generations, and
the same four public Run/Grant/Rerun/Tombstone acceptance templates configured
in keyholder.
The active daemon polls the authenticated accepted-request source one at a
time, signs through keyholder, admits only the exact runner-control v2 frame,
and fetches terminal logs, the declared artifact, and teardown through the
runner-forwarded bounded evidence operations. It never connects to execd or
reads an evidence filesystem.

The disabled `buzz-ci-controld-acceptance.socket` binds
`/run/buzzci/controld-acceptance.sock` as root:`buzzci-ctl` mode `0620` and names
the inherited descriptor `buzz-ci-controld-acceptance`. Installation does not
enable or start it.

The service runs as the pre-existing `buzzci-controld` account. Its config is
mode `0600` and owned by that account. Its store is mode `0700` and owned by the
same account. Static files and installed directory roots remain root-owned.

## Freeze a package

Build `target/release/buzz-ci-controld` from one clean full source commit. The
build lane writes a mode-`0600` provenance file:

```json
{
  "binary": "buzz-ci-controld",
  "profile": "release",
  "schema": "buzz-ci-binary-provenance-v1",
  "sha256": "<64 lowercase hex characters>",
  "source_commit": "<full 40-character source commit>"
}
```

Freeze it in an owner-private directory:

```bash
deploy/native-ci/controld/freeze_package.py \
  --source-root "$PWD" \
  --source-commit FULL_40_CHARACTER_SHA \
  --binary /private/path/buzz-ci-controld \
  --provenance /private/path/buzz-ci-controld.provenance.json \
  --output /private/path/buzz-ci-controld-package \
  --controld-uid CONTROLD_UID \
  --controld-gid CONTROLD_GID
```

The freezer binds the supplied binary digest and provenance, exact commit,
every payload and destination, identity, mode, capacity-zero config, daemon
contract, and default state. It refuses dirty package sources, links, broad
modes, provenance mismatch, and pre-existing output. A clean checkout may
materialize Git non-executable sources as `0600` or `0644` and executable
sources as `0700` or `0755`; the freezer preserves Git's executable class and
does not repair source modes.

Before any install against `/`, the package root and assets directory must be
root-owned mode `0700`. Manifest and provenance files must be root-owned mode
`0600`; every asset must retain the manifest mode.

## Source-only operator modes

These commands document the lifecycle. Live install or rollback remains
approval-gated and is outside this package task.

```bash
deploy/native-ci/controld/install.py check --package /private/package
deploy/native-ci/controld/install.py dry-run --package /private/package
deploy/native-ci/controld/install.py install --package /private/package
deploy/native-ci/controld/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID \
  --dry-run
deploy/native-ci/controld/install.py rollback \
  --package /private/package \
  --backup-id EXACT_BACKUP_ID
```

`check` is read-only and validates the sealed package, host identity, target
parents, exact changed paths, and closed metadata without requiring root.
`dry-run` revalidates install ownership. `install` uses descriptor-verified
sources, atomic replacement, exact metadata readback, and a root-private backup
receipt. Rollback refuses installed-target or backup drift before restoring
prior bytes and metadata.

Neither installer action invokes systemd. Machine-readable default-state fields
describe package behavior, not live systemd observation; a separate reviewed
activation procedure owns live unit readback.

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/controld/tests -v
python3 -m py_compile deploy/native-ci/controld/*.py
systemd-analyze verify deploy/native-ci/controld/templates/buzz-ci-controld.service
```
