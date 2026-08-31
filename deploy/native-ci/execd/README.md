# Execd production-v2 package contract

This directory packages the still-dormant broker v2 composition. Activation is
possible only when `/etc/buzzci/execd-v2.json` selects protocol 2 and capacity
0 or 1, and every identity, digest, path, mode, and group membership matches.

At capacity zero, the production socket accepts only the fixed version-2
production qualification operation from the exact configured `buzzci-ctl` UID
and primary GID. Every ordinary operation returns `NotProvisioned`, and every
version-1 frame is rejected before its body is read. Qualification carries no
command, path, environment, artifact, or job input and never invokes the
executor.

`buzz-ci-execd` stays root-owned and is the only process that admits work,
persists bindings, collects terminal output, scrubs it, or writes evidence.
`buzzci-runner` only transports protocol frames. The fixed
`/usr/libexec/buzz-ci-executor` runs outside the root broker as `buzzci-job` and
accepts only the typed, binding-digest protocol over its root-only systemd
socket. The fixed fixture child inherits that same UID and GID. This is one
deliberate, narrow executor/fixture trust domain, not a principal boundary. It
cannot receive argv, environment, prior claims, or log paths.
Declared artifacts are limited to one 32 KiB text output per attempt. Execd
opens it beneath the root-owned `attempts` anchor without following links,
scrubs it, and persists the receipt once before teardown; undeclared, linked,
oversized, or metadata-drifting outputs fail closed.

Capacity one admits only the single config-declared fixture job. Its static
declaration digest binds the candidate, activation package, lane and isolation
manifests, workflow and job identities, exact artifact declaration, all three
source digests, and the fixed stdout, stderr, memory, process, and wall limits.
Execd verifies the root-owned package sources at
`/usr/share/buzzci/execd-v2/fixture/{fixture-manifest.json,input.txt}` and
`/usr/libexec/buzz-ci-capacity-one-fixture`, then create-once materializes only
those bytes beneath the attempt root. The private executor RPC carries an
attempt identifier and binding digests, never argv, environment, or a caller
path. It invokes only the materialized `run-fixture.sh artifacts` process group.
The adopted systemd listener and every accepted control stream are marked
close-on-exec before any fixture starts, so the child cannot retain the
executor endpoint.

This package must not execute dynamic or general workloads. Such workloads
require a separate executor account, a separate runtime account, and a new
root or systemd-controlled credential transition with its own review and
adversarial isolation tests. Do not add `CAP_SETUID`, a setuid helper, or relax
`NoNewPrivileges`, `RestrictSUIDSGID`, or `RestrictNamespaces` to extend this
capacity-one fixture path.

The executor drains bounded stdout and stderr without persisting raw bytes.
Exit zero with empty stderr is required. Execd scrubs the bounded stdout and
the single declared regular, single-link `result.json` before create-once
evidence. Cancellation and deadline expiry kill the live process group before
terminal state and teardown are persisted. Startup reconciliation kills any
remembered live group, or emits a bounded infrastructure-failure receipt when
the unprivileged executor lost volatile state; ambiguity never reopens
capacity as success.

Dynamic JobIntentV2 authority crosses the existing authenticated runner socket
only through protocol operation 9. Execd verifies the embedded manifest-key
signature and generation, recomputes the established intent digest, and writes
one canonical mode-`0400` record under its private intent root keyed by the
logical attempt replay coordinates. Byte-identical retries return the sealed
record; spoofed, mixed, stale, permission-drifting, or ambiguous records never
reach admission. No controller or runner receives filesystem write access.

The activation access group is `buzzci-execd`, with exactly `buzzci-runner` and
`buzzci-ctl` as members. The execd control socket is root:`buzzci-execd` mode
`0620`. Execd still authorizes the peer by exact `SO_PEERCRED` UID and primary
GID. Supplementary group membership grants filesystem access only.

The config freezes the control account and primary group as `buzzci-ctl` at
`961:961`, with home `/var/lib/buzzci/principals/ctl`, a nologin shell, and sole
supplementary group `buzzci-execd`.
Execd validates `/etc/passwd` and `/etc/group` before serving. It stores at most
16 create-once qualification receipts under
`/var/lib/buzzci/execd-v2/qualification`, root-owned mode `0600` inside a
root-owned mode-`0700` directory. Exact retries return `Existing`; frame drift
under the same package, fixture, and generation key returns `ReplayConflict`.

Package generation must replace the sysusers UID/GID placeholders, install the
two release binaries, and write canonical compact JSON. The execd config binds
the executor's full source commit, SHA-256, owner, group, mode, and fixed path.
The package remains dormant until the separate activation controller enables
the capacity-one target.

Before capacity-one dispatch opens, execd verifies the Fedora-owned
`/usr/share/containers/seccomp.json` against the compiled digest, atomically
installs or reuses the root-owned content-addressed profile under
`/var/lib/buzzci/seccomp/v1/sha256`, and freshly verifies the mode-`0600`
install receipt. The package creates only the retained state directories; it
does not bundle, replace, or remove the immutable profile bytes during package
rollback.

The job principal reaches its exact attempt and pinned seccomp profile through
execute-only directory chains. `/var/lib/buzzci`, `execd-v2`, `attempts`,
`seccomp`, `seccomp/v1`, and `seccomp/v1/sha256` are root-owned mode `0711`:
known names may be traversed but directory contents cannot be listed. Every
other execd-v2 state child remains root-owned mode `0700`; activation receipts
remain below root-owned mode-`0700` parents. Attempt children are job-owned mode
`0500` with a mode-`0700` artifact output directory and are removed after sealed
teardown. The immutable profile alone is root-owned mode `0444`.

The root execd service retains no Linux capabilities. OCI process execution
runs only in the separate unprivileged `buzzci-job` executor service. The
executor service retains no capabilities, devices, namespaces, SUID/SGID,
realtime, resource-control, or kernel mutation syscalls; systemd also pins its
memory to 128 MiB, tasks and processes to 16, file descriptors to 64, output
files to 64 KiB, and write access to the attempt root. The executor validates
the exact installed root-owned seccomp profile digest before accepting its
root-only socket. The execd
unit blocks device access, namespace creation, kernel mutation, mounts, raw I/O,
debug syscalls, reboot, and swap while retaining Unix-socket and descriptor-safe
file operations for seccomp installation, durable bindings, sealed evidence,
and executor handoff.

The shared `/var/lib/buzzci` ancestor is root:root mode `0711`: service
principals may traverse an already-known child name but cannot list the
directory. No regular file may live directly beneath that ancestor. Execd's
sensitive child roots remain root-private mode `0700`; the separate activation
package uses the same ancestor contract so either package installation order is
idempotent. The only cross-service readable state is the explicitly named,
root-owned mode-`0444` acceptance receipt beneath the separately traversable
`activation-controller` directory. The `execd-v2` and `seccomp` parents are the
only additional traverse-only children; their private descendants remain
unreadable and unlistable.

The standalone execd package owns only `/usr/libexec/buzz-ci-execd`. Before the
activation package exists, `freeze_package.py prepare-input` emits one canonical
mode-`0600` `buzz-ci-execd-preactivation-input-v1` file. It contains only the
source commit, execd binary SHA-256, and provenance-file SHA-256. It is not an
install package or manifest and claims no targets.

The central activation package owns the executor binary, all four
execd/executor units, fixture files, sysusers, tmpfiles, and their transactional
rollback. After that package freezes, `freeze-package` reopens the same execd
binary, provenance, and pre-activation input. It rejects any tuple drift, then
binds the exact pre-activation-input digest, final activation ID, package and
manifest digests, execd provenance, and eight activation-owned targets.
The installer never writes those targets. On a clean host their receipt state
is `pending`; after activation has written its central receipt, `check` requires
the exact package, source, fixed-manifest, and managed-target binding.

The standalone package does not bundle the distribution seccomp profile. It
checks `/usr/share/containers/seccomp.json` against the compiled digest and
writes a create-once root-owned mode-`0600` package receipt at
`/var/lib/buzzci/execd-v2/package/receipt-v1.json`. Execd startup remains the
only owner of the content-addressed runtime profile and runtime receipt.

Prepare the activation input, then freeze and install the final package with:

```bash
deploy/native-ci/execd/freeze_package.py prepare-input \
  --source-root . --source-commit "$SOURCE_COMMIT" \
  --binary "$EXECD_BINARY" --binary-provenance "$EXECD_PROVENANCE" \
  --output "$EXECD_PREACTIVATION_INPUT"

# Render and freeze the activation package before this command.
deploy/native-ci/execd/freeze_package.py freeze-package \
  --source-root . --source-commit "$SOURCE_COMMIT" \
  --binary "$EXECD_BINARY" --binary-provenance "$EXECD_PROVENANCE" \
  --preactivation-input "$EXECD_PREACTIVATION_INPUT" \
  --activation-package "$ACTIVATION_PACKAGE" --output "$EXECD_PACKAGE"
deploy/native-ci/execd/install.py verify-package --package "$EXECD_PACKAGE"
deploy/native-ci/execd/install.py install --package "$EXECD_PACKAGE"
```

Both freezer phases reject symbolic paths, hard links, noncanonical input,
metadata or digest drift, and source-commit replay. Final freeze also rejects a
different pre-activation tuple, overlapping ownership, and mismatched activation
bindings. Installation does not reload, enable, or start a unit.

Run the local static checks with:

```bash
python3 deploy/native-ci/execd/verify.py --source-root .
python3 -m unittest discover deploy/native-ci/execd/tests
```
