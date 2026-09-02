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

## Clock model

Two clocks exist, and a reviewer can verify which one a comparison uses by
grep.

Admission windows are judged against the package's bound time reference,
never the wall clock. The activation freezer records
`acceptance_template.time_reference` once, issues the frozen
Run/Grant/Rerun/Tombstone templates at it, and binds the runner's
`acceptance_time_reference` and the execd config's `acceptance_time_reference`
to the same value. The runner (`crates/buzz-ci-runner/src/proxy_v2.rs`,
`validate_window`) and execd (`crates/buzz-ci-execd/src/production_binding.rs`,
`validate_window`) require `issued_at <= reference < expires_at` for every
admission, intent registration, and cancel. A frozen package therefore admits
on any host date; the clean-host runs prove it with the reference minutes and
hours behind the guest clock.

Live bounds use the host clock, through one named helper on each side:

- controld: `runner_v2::live_bound_now` (the attempt wait, the acceptance
  command hold in `production_v2.rs`, and cancel eligibility in
  `service.rs`) compares with `BoundAttempt::deadline_at`, which is
  `accepted_at + min(wall_timeout, expires_at - issued_at)`; execd stamped
  `accepted_at` at admission on the same host clock. The window contributes
  its length only.
- execd: `production_v2::live_bound_now` polls the executor lease against the
  binding's `deadline_at`, anchored the same way (`admitted_at` is execd's
  clock at admission).
- activation controller: `controller.py` `live_unix_now` issues and expires
  the qualification request, a live request minted at activation with a
  fresh ID and nonce and a 60-second delivery validity; execd judges it on
  its own host clock. It carries no package-bound instant.

Tests pin the shape: `live_bound_now_is_the_only_wall_clock_in_the_attempt_path`
(controld), `live_bound_now_is_the_only_wall_clock_in_production_v2` (execd),
and `test_qualification_clock_is_the_named_live_bound_only` (activation).
To audit, `grep -n 'SystemTime::now()'` over `runner_v2.rs`,
`production_v2.rs`, and `service.rs` in `crates/buzz-ci-controld/src` and
over `crates/buzz-ci-execd/src/production_v2.rs` returns the two helpers
only, and `grep -n 'time.time()' deploy/native-ci/activation/controller.py`
returns `live_unix_now`. Event timestamps (keyholder `created_at`, receipt
`updated_at`) are wall-clock stamps, not bounds, and are outside this rule.
