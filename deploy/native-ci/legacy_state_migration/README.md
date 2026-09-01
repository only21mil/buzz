# Legacy native-CI state migration

This one-time tool clears the legacy native-CI layout that blocks the v2
execd and capacity-one installers. It is tied to the known
`framework-desktop` layout. It refuses any extra path, changed metadata,
changed content, unexpected systemd resolution, unexpected symlink, hard link, special
file, mount, swap, loop-device association, kernel lock, or process reference.

The tool never deletes legacy data. It renames every archived item into
`/var/lib/buzzci-legacy-archive/f7b2abdb-v1` on the same filesystem. The
20 GiB sparse lease image keeps its inode and allocation rather than being
copied. The archive root is root-owned mode `0700`; transaction, migration,
and rollback receipts are mode `0600`.

## Fixed live inventory

The plan accepts exactly these direct children under `/var/lib/buzzci`:

- archived: `activation`, `fixtures`, `lease01`, `lease01.img`, and `leases`;
- retained: `principals` and `seccomp`.

`principals/ctl` remains UID/GID 961 mode `0700`. The migration changes only
the shared ancestor and `seccomp/v1/sha256` traversal chain to mode `0711`.
It moves every legacy regular file away from the shared ancestor before that
mode change.

The tool also archives all three known `/etc/buzzci` entries:
`authority`, `harness.env`, and the empty `qualification-cases` directory.
It archives the legacy service, socket, host-adapter drop-in, socket enablement
link, and tmpfiles fragment:

```text
/etc/systemd/system/buzz-ci-execd.service
/etc/systemd/system/buzz-ci-execd.socket
/etc/systemd/system/buzz-ci-execd.service.d
/etc/systemd/system/sockets.target.wants/buzz-ci-execd.socket
/usr/lib/tmpfiles.d/buzzci-control.conf
```

The known four regular system fragments have these SHA-256 values. The plan
recomputes and records them before approval.

```text
681adfc8ef9756f20909b34c6acd959558455e44bc1f1a6c14c937328f39eda8  buzz-ci-execd.service
afa9e9eef2dba23689410788914ce5baa91a8bcfbe9b1dcf7d1ada4f00fabae5  buzz-ci-execd.socket
2b9497c8f942156e3ef54167380dbaccf9ddba7ebc4982ab1932fd3bb8c79e04  10-host-adapters.conf
fd5d9c4472f6fe1f4ad34d76446cbb308964587e05ae4346876e6a2f27034d42  buzzci-control.conf
```

The legacy socket must resolve to its `/etc` fragment and be active, listening,
and enabled. The service must resolve to its `/etc` fragment and be inactive,
dead, and static. The only service drop-ins allowed are the archived host
adapter and `/usr/lib/systemd/system/service.d/10-timeout-abort.conf`.

## Read-only check and plan

Run these commands from a clean checkout of the reviewed and landed commit.
They read filesystem metadata and bytes, `/proc`, `/sys`, and `systemctl show`.
They do not stop a unit or write a file. Hashing the sparse image may take a
few minutes.

```bash
sudo -- ./deploy/native-ci/legacy_state_migration/migrate.py check
sudo -- sh -c 'umask 077; exec ./deploy/native-ci/legacy_state_migration/migrate.py plan > /root/buzzci-legacy-migration-plan.json'
sudo -- sha256sum /root/buzzci-legacy-migration-plan.json
```

Review the complete plan and retain its exact SHA-256. Approval must name that
digest. A stale or edited plan cannot authorize migration.

## Approval-gated migration

Production migration requires Victor's explicit approval for the exact plan
digest. The approval token is not a general override.

```bash
sudo -- ./deploy/native-ci/legacy_state_migration/migrate.py migrate \
  --plan /root/buzzci-legacy-migration-plan.json \
  --approve-migration FULL_PLAN_SHA256
```

The command rechecks the entire plan before its first write. It then writes a
transaction record, stops the socket and service, archives each exact item,
normalizes the traversal directories, reloads systemd, proves the legacy units
are no longer loadable, and writes `receipt-v1.json`. Re-run the same command
after an interruption. It resumes only when every live or archived item still
matches the approved plan.

Do not install v2 native-CI packages until the migration receipt is retained
and checked. Do not use rollback after a v2 package has created managed state.
The rollback preflight refuses new `/var/lib/buzzci` or `/etc/buzzci` entries.

## Approval-gated rollback

Rollback also needs explicit approval for the exact migration receipt digest:

```bash
sudo -- sha256sum /var/lib/buzzci-legacy-archive/f7b2abdb-v1/receipt-v1.json
sudo -- ./deploy/native-ci/legacy_state_migration/migrate.py rollback \
  --receipt /var/lib/buzzci-legacy-archive/f7b2abdb-v1/receipt-v1.json \
  --approve-rollback FULL_RECEIPT_SHA256
```

Rollback verifies that no v2 or unknown state exists, restores the original
directory modes and every archived inode, reloads systemd, then restores the
exact unit enablement and active states. It writes `rollback-v1.json` and keeps
the archive directory and all receipts. The same command resumes safely after
an interruption.
