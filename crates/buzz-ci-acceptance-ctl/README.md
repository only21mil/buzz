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

The library exposes `QualificationTransport` for deterministic zero-transport
validation tests. The installed binary maps the validated request into the
fixed `AdmitQualification` frame and exchanges it only with
`/run/buzzci/execd.sock`. Successful broker responses are JSON lines on standard
output. Input and broker refusals are stable JSON errors on standard error and
leave standard output empty.
