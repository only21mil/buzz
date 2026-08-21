# Qualification control deployment contract

This directory defines the inactive host assets for the Buzz CI qualification
control boundary and its in-process privileged host adapters. It does not
install users, copy files into host paths, load systemd units, or enable the
socket.

The broker listens on `/run/buzzci/execd.sock`. The socket is mode `0600` and
owned by `buzzci-ctl:buzzci-ctl`. The dedicated `buzzci-ctl` account has a
nologin shell. Materializer, executor, and runtime accounts are not members of
the control group.

`/usr/libexec/buzz-ci-acceptance-ctl` is a compiled launcher, not a shell
wrapper. The install contract makes it `root:buzzci-ctl`, mode `0750`, with no
setuid or setgid bit. Sudoers permits only root to invoke that exact path as
`buzzci-ctl`, and only with no command-line arguments. The launcher accepts one
fixed `qualification_v1` request on stdin. This root-only sudoers entry is
intentionally redundant with root's ability to change identity. It records the
qualification command and prevents the deployment assets from granting the
ordinary job accounts a control entrypoint.
The launcher reads at most 64 KiB and rejects any argv as `invalid_cli`.

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

- `BUZZ_CI_ACCEPTANCE_CTL=/usr/libexec/buzz-ci-acceptance-ctl` is the
  qualification-only stdin endpoint.
- `BUZZ_CI_RUNNER_CTL=/usr/libexec/buzz-ci-runner` remains the ordinary runner
  endpoint and must never dispatch the acceptance launcher.
- `BUZZ_CI_QUALIFICATION_CASE_ROOT=/etc/buzzci/qualification-cases` names the
  root-authored case directory. The directory is `root:root` mode `0755`; each
  deployed case file must be `root:root` mode `0444` and passed unchanged to
  the acceptance launcher on stdin. Each `$TEST_ID` subdirectory is also a
  root:root mode `0755` real directory. `qualification-cases.plan` enumerates
  the case names the privileged installer must render after binding the exact
  candidate, host, suite, signer, permit, job, nonce, and expiry values.

`install-manifest.tsv` declares eventual destinations, ownership, and modes.
`cargo-bin:` rows refer to compiled release artifacts. `rendered:` means the
installer must replace every `@...@` token with a validated public value before
publishing the destination. `host-paths.plan` declares runtime-created paths
and their required publication method. No installer is included here.

Run the deterministic checks with:

```bash
ci-acceptance/substrate/selftest.sh
```
