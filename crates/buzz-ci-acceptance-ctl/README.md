# buzz-ci-acceptance-ctl

`buzz-ci-acceptance-ctl` is a qualification-only input gate. It reads one
bounded JSON object from standard input. The object contains authenticated,
normalized permit and admission fields. The gate rejects zero values,
coordinate mismatches, non-qualification trust, invalid time bounds, unknown
fields, and malformed encodings before it calls its transport.

The binary has no flags or subcommands. In particular, it has no repository,
workflow, job, generic fault, or acceptance-case input. Its only optional
directive is `"teardown_failure"`. Ordinary `buzz-ci-runner` does not depend on
this crate or invoke the binary.

The crate also builds `buzz-ci-capacity-one-canary`. That binary owns the
activation acceptance sequence. It reads a scenario from standard input,
invokes absolute provider adapter and process-control commands without a
shell, validates 13 ordered system snapshots, and writes a receipt. Driver
exit status is transport evidence only. The binary checks identities, state,
digests, byte lengths, attempt lineage, tombstone folding, restart recovery,
and final capacity zero itself.

The installed `/usr/libexec/buzz-ci-capacity-one-driver` uses two fixed local
sockets. `/run/buzzci/acceptance-control.sock` returns root-owned capacity and
service readback. `/run/buzzci/controld-acceptance.sock` performs the bound
relay, signer, run-ledger, and evidence operations. The driver checks both
server identities with `SO_PEERCRED`; each request carries the exact activation,
candidate, scenario, run, job, grant, attempt, digest, and last-seen service
generations.

`/usr/libexec/buzz-ci-acceptance-control` is the socket-activated root helper.
It accepts only capacity one, capacity zero, controller restart, runner restart,
and readback. Its protocol contains no program, unit, path, argv, credential,
or signer field. A durable operation ledger permits byte-identical replay and
rejects an operation ID reused with different bytes.

The canary is not part of the ordinary runner path. See
`deploy/native-ci/acceptance/README.md` for its operator runbook and current
activation status.

The library exposes `QualificationTransport` for deterministic zero-transport
validation tests. The installed binary maps the validated request into the
fixed `AdmitQualification` frame and exchanges it only with
`/run/buzzci/execd.sock`. Successful broker responses are JSON lines on standard
output. Input and broker refusals are stable JSON errors on standard error and
leave standard output empty.
