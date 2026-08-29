# Execd capacity-one package contract

This directory packages the still-dormant broker v2 composition. Activation is
possible only when `/etc/buzzci/execd-v2.json` selects protocol 2 and capacity
exactly 1, and every identity, digest, path, mode, and group membership matches.

`buzz-ci-execd` stays root-owned and is the only process that admits work,
persists bindings, collects terminal output, scrubs it, or writes evidence.
`buzzci-runner` only transports protocol frames. The fixed
`/usr/libexec/buzz-ci-executor` runs as the separate `buzzci-job` principal and
accepts only the typed, binding-digest protocol over its root-only systemd
socket. It cannot receive argv, environment, prior claims, or log paths.
Declared artifacts are limited to one 32 KiB text output per attempt. Execd
opens it beneath the root-owned `attempts` anchor without following links,
scrubs it, and persists the receipt once before teardown; undeclared, linked,
oversized, or metadata-drifting outputs fail closed.

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

The shared `/var/lib/buzzci` ancestor is root:root mode `0711`: service
principals may traverse an already-known child name but cannot list the
directory. No regular file may live directly beneath that ancestor. Execd's
sensitive child roots remain root-private mode `0700`; the separate activation
package uses the same ancestor contract so either package installation order is
idempotent. The only cross-service readable state is the explicitly named,
root-owned mode-`0444` acceptance receipt beneath the separately traversable
`activation-controller` directory.

Run the local static checks with:

```bash
python3 deploy/native-ci/execd/verify.py --source-root .
python3 -m unittest discover deploy/native-ci/execd/tests
```
