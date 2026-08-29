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

The activation access group is `buzzci-execd`, with exactly `buzzci-runner` and
`buzzci-ctl` as members. The execd control socket is root:`buzzci-execd` mode
`0620`. Execd still authorizes the peer by exact `SO_PEERCRED` UID and primary
GID. Supplementary group membership grants filesystem access only.

Package generation must replace the sysusers UID/GID placeholders, install the
two release binaries, and write canonical compact JSON. The execd config binds
the executor's full source commit, SHA-256, owner, group, mode, and fixed path.
The package remains dormant until the separate activation controller enables
the capacity-one target.

Run the local static checks with:

```bash
python3 deploy/native-ci/execd/verify.py --source-root .
python3 -m unittest discover deploy/native-ci/execd/tests
```
