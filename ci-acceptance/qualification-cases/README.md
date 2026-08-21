# Qualification case fixtures

This directory is the reviewable source for every immutable case named by
`../substrate/qualification-cases.plan`. Checked-in files are deliberately
unsigned templates: every authority, host, candidate, job, nonce, and time
value is an explicit `@...@` token. They are never runnable as-is.

The privileged installer must materialize each template to:

```text
/etc/buzzci/qualification-cases/<TM-ID>/<case-name>.json
```

It must replace every token with the authenticated public binding of the
correct JSON type, obtain the root-authorized permit, validate the result
against `schema/sealed-case.schema.json`, write it atomically as root:root
mode `0444` beneath root:root mode `0755` real directories, and retain no
private signing material in the artifact. There is intentionally no renderer
or signer in this repository.

`expectations.tsv` binds every case to its expected control result and required
readback. Negative cases are explicit: unaccepted trust, external-fork binding,
and unauthorized signer must fail in the local validator; expiry, replay, rate,
and concurrency reach the service-owned `ActivationController`.

Run the deterministic catalog and hostile-fixture checks with:

```bash
ci-acceptance/qualification-cases/selftest.sh
```

See `LIVE-CANARY.md` for the gated host procedure. No command in this directory
mutates a host or starts a service.
