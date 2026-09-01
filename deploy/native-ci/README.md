# Buzz CI native deploy packages

The one-time, approval-gated migration for the legacy framework host is in
[`legacy_state_migration/`](legacy_state_migration/README.md). Run its
read-only plan and complete the migration receipt before installing v2 packages
on a host with the old direct `/var/lib/buzzci` layout.

`runner/`, `controld/`, and `execd/` hold the dormant Buzz CI source packages
and their check/dry-run/install/rollback installers. Each lane freezes a
supplied release binary and provenance record; none of them builds, fetches,
or installs a binary on a live host by itself. See each lane's README.md for
the closed contract, freeze commands, and deterministic checks.

The shared state parent `/var/lib/buzzci` is root-owned mode `0711` across all
installers and tmpfiles declarations. Runner and controld create it with an
explicit post-`mkdir` mode when absent, including under umask `077`, but refuse
to repair an existing parent whose type, ownership, or exact mode differs.
Their shared `install-backups` directory and all component-private leaves stay
root-owned mode `0700`.

## Build toolchain pin

Every packaged binary (`buzz-ci-runner`, `buzz-ci-controld`,
`buzz-ci-execd`) must be built with the exact toolchain pinned in
[`rust-toolchain.toml`](../../rust-toolchain.toml) (`1.95.0`). A host with
`rustup` honors the pin automatically; a system `cargo` ignores
`rust-toolchain.toml` and silently builds with its own version, so verify
with `rustup show active-toolchain` (or `cargo --version`) before freezing a
package. A binary built off-pin fails the provenance contract's intent and
must not be frozen.
