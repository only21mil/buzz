# Buzz CI native deploy packages

`runner/`, `controld/`, and `execd/` hold the dormant Buzz CI source packages
and their check/dry-run/install/rollback installers. Each lane freezes a
supplied release binary and provenance record; none of them builds, fetches,
or installs a binary on a live host by itself. See each lane's README.md for
the closed contract, freeze commands, and deterministic checks.

## Build toolchain pin

Every packaged binary (`buzz-ci-runner`, `buzz-ci-controld`,
`buzz-ci-execd`) must be built with the exact toolchain pinned in
[`rust-toolchain.toml`](../../rust-toolchain.toml) (`1.95.0`). A host with
`rustup` honors the pin automatically; a system `cargo` ignores
`rust-toolchain.toml` and silently builds with its own version, so verify
with `rustup show active-toolchain` (or `cargo --version`) before freezing a
package. A binary built off-pin fails the provenance contract's intent and
must not be frozen.
