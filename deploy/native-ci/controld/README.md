# Buzz CI controld source package

This directory packages the capacity-zero default and strict capacity-one
configuration contract for `buzz-ci-controld`. It accepts a supplied exact
release binary and provenance record; it does not build, fetch, or install a
binary on the live host by itself.

The checked-in package does not create accounts, run `systemd-tmpfiles`, reload
systemd, enable or start a unit, provision keys, contact a relay, connect to a
runner or broker, or grant execution capacity. The installed service sandbox
permits only the network and local sockets needed after a separate activation.
The unit lists `/run/buzzci` as a read-only directory rather than the keyholder
and runner socket inodes: SELinux denies `init_t` `mounton` on a `sock_file`, so
a per-socket `ReadOnlyPaths=` entry fails the service at NAMESPACE as soon as
the socket exists. Connecting through a read-only bind mount still works.

Controld authenticates the keyholder and runner listeners the way the
acceptance driver authenticates controld: the socket inode must be owned by the
service account with controld's group and mode `0620`, and `SO_PEERCRED` must
name either that account or pid 1 root, which the kernel reports for a socket
bound by a systemd socket unit because `SO_PEERCRED` names the `listen()`
caller. Any other root process, an unmappable pid, or another account fails
closed.

## Closed contract

The installed default remains:

- `buzz-ci-controld.service` present but static, disabled, and inactive;
- `controld-v2.json` contains only schema version 2, capacity exactly `0`,
  absolute store root `/var/lib/buzzci/controld`, and the fixed public
  `acceptance_binding` receipt path;
- no relay URL, key descriptor, keyholder, runner, broker, or polling
  configuration;
- state reported as `enabled=false`, `active=false`, `provisioned=false`,
  `providers_wired=false`, and `capacity=0`.

In capacity zero the daemon opens only its owner-private durable control store,
reports the unified `parked` readiness record, and parks without polling,
dispatching, networking, or signing. The frozen config always names the fixed
post-freeze `acceptance_binding` receipt path. The package remains safe on a
standalone host because both packaged units stay disabled and inactive. If an
operator starts either unit before activation creates the receipt, controld
fails closed. The central activation controller creates that receipt only after
the package and scenario digests are final. Its exact schema is
`buzz-ci-activation-acceptance-binding/v2`; the fixed path is
`/var/lib/buzzci/activation-controller/controld-acceptance-v2.json`. The compact
canonical JSON binds the activation, package, candidate, complete fixture,
scenario, distinct keyholder and acceptance peer identities, generations,
timeout, acceptance actor, and the four
public Run/Grant/Rerun/Tombstone event templates. The regular file is root:root
mode `0444`, link count one, beneath the exact root:root mode `0711` activation
controller directory. Both controld and keyholder validate this same public
receipt. The controld freezer is the sole source of the canonical staged config
bytes. The config entry digest binds those bytes into its package manifest, and
activation must freeze the same bytes for the shared installed path. Frozen
daemon configs contain only the receipt path, so neither contains a digest of
bytes that contribute to the package digest.

Capacity one is accepted only with the complete relay authority, channel,
authenticated runner identity and bounds, exact static lane, JobIntentV2 job
and artifact declaration, keyholder selector generations, and a receipt whose
authority description exactly matches keyholder. The `manifest` keyholder
selector is the one source of the admission key: controld derives
`admission_key_generation` from `keyholder_selectors.manifest.generation`, the
activation freezer requires the execd lane manifest's `admission_verifying_key`
and `admission_key_generation` to equal that selector, and the runner's static
activation coordinates copy the lane manifest. The public event templates are
issued at the package's bound time reference (`acceptance_template.time_reference`,
recorded at freeze); the freezer requires the runner's static
`acceptance_time_reference` to equal it, and the runner judges the admission
window against that reference rather than the wall clock. The freezer also
requires the active `channel_id` to equal the `h` tag channel frozen into
those templates: the acceptance path publishes the signed Run event on the
event's own channel while the daemon polls the configured one.
The active daemon polls the authenticated accepted-request source one at a
time, signs through keyholder, admits only the exact runner-control v2 frame,
and fetches terminal logs, the declared artifact, and teardown through the
runner-forwarded bounded evidence operations. It never connects to execd or
reads an evidence filesystem.

The disabled `buzz-ci-controld-acceptance.socket` binds
`/run/buzzci/controld-acceptance.sock` as root:`buzzci-ctl` mode `0620` beneath
a mode `0711` runtime directory and names the inherited descriptor
`buzz-ci-controld-acceptance`. Installation does not
enable or start it. The controld package is its sole package owner. Activation
binds the canonical controld package-manifest digest and reads back this
fragment's exact path and bytes, but never republishes or removes it.

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

The default transaction path uses the cross-installer shared parent
`/var/lib/buzzci`, which must be root-owned mode `0711`. The installer creates
an absent shared parent with that exact mode even under umask `077`; it refuses
an existing symlink or any ownership or mode drift instead of widening it.
`/var/lib/buzzci/install-backups` and the controld transaction tree remain
root-owned mode `0700`.

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
sources, descriptor-relative atomic replacement, exact metadata readback, and a
root-private transaction directory. Before it creates a managed directory or
publishes a target, it writes `state.json` with the exact package ID and digest,
full changed-target inventory, absent or present directory baseline, and prior
target metadata. Present prior targets also have digest-checked backups before
publication starts.

The transaction phases are `preparing`, `install_prepared`, `installing`,
`installed`, `rolling_back`, and `rolled_back`. Repeating `install` resumes the
single package-bound nonterminal install. Repeating `rollback` with the exact
backup ID resumes restoration and accepts only the candidate or the recorded
prior state for each target. This permits the precise mixed state created by an
interrupted operation while still refusing unrelated drift. A terminal
rollback retry returns the same result after it verifies the prior targets and
absent directory baseline. `receipt.json` is written only at an installed or
rolled-back terminal point and must match `state.json` exactly.
Rollback dry-run also validates legacy receipt-only backups, but it builds the
migration state only in memory and leaves every file, directory, and timestamp
unchanged. A real rollback persists that state only after the full rollback
preflight passes.

Neither installer action invokes systemd. Machine-readable default-state fields
describe package behavior, not live systemd observation; a separate reviewed
activation procedure owns live unit readback.

## Deterministic checks

```bash
python3 -m unittest discover -s deploy/native-ci/controld/tests -v
python3 -m py_compile deploy/native-ci/controld/*.py
systemd-analyze verify deploy/native-ci/controld/templates/buzz-ci-controld.service
```
