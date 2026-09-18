# buzz-ci-acceptance-ctl

`buzz-ci-acceptance-ctl` is the qualification-only input library and the
home of the acceptance binaries. Its `qualification_v1` validator reads one
bounded JSON object with authenticated, normalized permit and admission fields
and rejects zero values, coordinate mismatches, non-qualification trust,
invalid time bounds, unknown fields, and malformed encodings before any
transport runs. The validator's only optional directive is
`"teardown_failure"`. Ordinary `buzz-ci-runner` does not depend on this crate.

The crate no longer ships a `buzz-ci-acceptance-ctl` binary. That launcher
encoded the validated request as a broker protocol version 1
`AdmitQualification` frame, and production execd refuses version 1 at the
transport (`ControlServer::new_polling`). The version 2 qualification client is
`buzz-ci-production-qualification` below.

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
validation tests.

`/usr/libexec/buzz-ci-production-qualification` is the closed version 2
qualification probe. It reads one `buzz-ci-production-qualification-request/v2`
JSON object on stdin, encodes it with `buzz_ci_broker_protocol::v2`, exchanges
it only with `/run/buzzci/execd.sock`, and accepts only a response that echoes
every activation and host binding. Successful receipts are JSON lines on
standard output. Input and broker refusals are stable JSON errors on standard
error and leave standard output empty.
