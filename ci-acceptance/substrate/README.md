# Qualification control deployment contract

This directory defines the inactive host assets for the Buzz CI qualification
control boundary. It does not install users, copy files into host paths, load
systemd units, or enable the socket.

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
publishing the destination. No installer is included here.

Run the deterministic checks with:

```bash
ci-acceptance/substrate/selftest.sh
```
