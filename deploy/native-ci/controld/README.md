# Buzz CI dormant controld source package

This directory packages the local-only, capacity-zero `buzz-ci-controld`
daemon. It accepts a supplied exact release binary and provenance record; it
does not build, fetch, or install a binary on the live host by itself.

The checked-in package does not create accounts, run `systemd-tmpfiles`, reload
systemd, enable or start a unit, provision keys, contact a relay, connect to a
runner or broker, or grant execution capacity.

## Closed contract

The installed default remains:

- `buzz-ci-controld.service` present but static, disabled, and inactive;
- `controld-v1.json` contains only schema version 1, capacity exactly `0`, the
  absolute store root `/var/lib/buzzci/controld`, and the fixed public
  acceptance-binding receipt path;
- `buzz-ci-controld-acceptance.socket` is packaged but remains static, disabled,
  and inactive until the activation controller explicitly starts it;
- no relay URL, key descriptor, keyholder, runner, broker, or polling
  configuration;
- state reported as `enabled=false`, `active=false`, `provisioned=false`,
  `providers_wired=false`, and `capacity=0`.

The daemon contract validated in the corresponding source lane opens only its
owner-private durable control store, reports `ready_closed` with reason
`production_providers_unwired`, and parks without polling, dispatching,
networking, or signing. This package does not add capacity-one logic.

The service runs as the pre-existing `buzzci-controld` account. Its config is
mode `0600` and owned by that account. Its store is mode `0700` and owned by the
same account. Static files and installed directory roots remain root-owned.

## CI status key provisioning

The capacity-one activation provisions one CI status key file and names it in
the key descriptor (`path`, `expected_owner_uid`, `expected_pubkey`). The key
file must be UTF-8 plaintext text of exactly 64 lowercase hex characters —
or an `nsec…` secret-key string — with surrounding whitespace tolerated. It
is never 32 raw bytes; a raw 32-byte key fails the UTF-8 hex parser by
design. Two metadata contracts are accepted, nothing else:

- a directly referenced key file must be mode `0600`, owned by the
  descriptor's `expected_owner_uid`, with exactly one link;
- a key delivered through systemd `LoadCredentialEncrypted=` mounts the
  decrypted plaintext read-only at mode `0400` under the unit's
  `$CREDENTIALS_DIRECTORY`. The loader accepts mode `0400` only for paths
  inside that directory and still enforces the same owner and link count.

The loader never follows a final symlink and binds the expected public key;
any mismatch fails closed without exposing the key material.

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
contract, and default state. It binds tracked sources to their Git executable
class: Git `100644` may materialize as `0600` or `0644`, and Git `100755` as
`0700` or `0755`; other or unsafe modes are refused. It also refuses dirty
package sources, links, provenance mismatch, and pre-existing output.

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
