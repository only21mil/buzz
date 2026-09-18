# Qualification control deployment contract

This directory defines the inactive host assets for the Buzz CI qualification
control boundary and its in-process privileged host adapters. It does not
install users, copy files into host paths, load systemd units, or enable the
socket.

The broker listens on `/run/buzzci/execd.sock`. The socket is mode `0600` and
owned by `buzzci-ctl:buzzci-ctl`. The dedicated `buzzci-ctl` account has a
nologin shell. Materializer, executor, and runtime accounts are not members of
the control group.

The former `/usr/libexec/buzz-ci-acceptance-ctl` launcher spoke broker
protocol version 1, which production execd refuses, and its `qualification_v1`
fixture lane has no server in the production composition. The manifest no
longer installs it, and no sudoers rule is shipped. The only qualification
client that production execd serves is `buzz-ci-production-qualification`
(protocol version 2, `AdmitQualification`), which is built and invoked by the
activation package rather than by this substrate.

## Host adapter composition

There is one privileged executable: `/usr/libexec/buzz-ci-execd`. Durable
authority loading, restart cleanup, DNS isolation, and seccomp installation are
typed in-process modules composed behind `ActivationDispatch`. This deployment
adds no adapter executables, services, sockets, or sudo rules.

The immutable configuration root is `/etc/buzzci/authority`, `root:root` mode
`0700`. A privileged installer renders these regular files atomically:

- `authority-v1.json`, `root:root` mode `0400`, is the versioned root authority
  record consumed by the durable loader.
- `host-adapters-v1.json`, `root:root` mode `0400`, pins every runtime, state,
  receipt, lease, qualification-case, DNS, and seccomp path. Its
  `default_capacity` is exactly zero.

The mutable durable root is `/var/lib/buzzci/activation`, `root:root` mode
`0700`. The install plan seeds `state-v1.json` as an explicitly unprovisioned
mode `0600` record bound to the authority bytes. Execd may replace it only by
atomic no-follow publication. Adapter receipts use the same root. Lease
evidence remains below `/var/lib/buzzci/leases`.
The seccomp directory chain stays `root:root` mode `0700`. The final artifact
is the fixed content-addressed `root:root` mode `0444` file named in
`host-adapters-v1.json.plan`; root execd passes the validated descriptor to the
OCI runtime without granting ordinary principals filesystem traversal.

`buzz-ci-execd.service.d/10-host-adapters.conf` orders execd after local
filesystems and `systemd-tmpfiles-setup.service`, requires mounts for every
fixed root, makes authority and qualification inputs read-only, and narrows
writes to the runtime, activation, lease, and seccomp roots. Execd must load
and validate authority, recover durable controller state, reconcile cleanup,
and obtain fresh DNS and seccomp readbacks before constructing
`ActivationDispatch`. A missing, linked, stale, wrongly owned, wrongly moded,
or malformed input keeps `ClosedDispatch` and capacity zero.

The rendered `/etc/buzzci/harness.env` keeps the two entrypoints distinct:

- `BUZZ_CI_RUNNER_CTL=/usr/libexec/buzz-ci-runner` remains the ordinary runner
  endpoint.
- `BUZZ_CI_QUALIFICATION_CASE_ROOT=/etc/buzzci/qualification-cases` names the
  root-authored case directory. The directory is `root:root` mode `0755`; each
  deployed case file must be `root:root` mode `0444`. Each `$TEST_ID`
  subdirectory is also a root:root mode `0755` real directory.
  `qualification-cases.plan` enumerates the case names the privileged installer
  must render after binding the exact candidate, host, suite, signer, permit,
  job, nonce, and expiry values. The suite scripts that stream these cases
  (TM-06, TM-07, TM-12 through TM-17) report `not_runnable` until a version 2
  fixture lane exists; there is no `BUZZ_CI_ACCEPTANCE_CTL` entry to point them
  at.

`install-manifest.tsv` declares eventual destinations, ownership, and modes.
`cargo-bin:` rows refer to compiled release artifacts. `rendered:` means the
installer must replace every `@...@` token with a validated public value before
publishing the destination. `host-paths.plan` declares runtime-created paths
and their required publication method. No installer is included here.

Run the deterministic checks with:

```bash
ci-acceptance/substrate/selftest.sh
```
