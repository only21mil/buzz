# Forward lease-completion acceptance

These fixtures freeze the semantic acceptance boundary for two-phase lease
completion without choosing a wire encoding. Every identity and digest remains
an explicit `@...@` installer token. The repository does not render, sign, or
authenticate a case.

A privileged installer may materialize one case only after binding every token
to the exact candidate, host, suite, signer, job, lease, generation, and root
receipt set. It must write the result atomically as root-owned mode `0444` and
retain no signing material. The live controller must authenticate those facts;
the mock reducer in `selftest.sh` proves only the closed state transitions.

This fixture layer deliberately does not choose a wire encoding. Live dispatch
coverage must bind the ratified completion operation to the opaque lease ID,
lease generation, service-authenticated signer result, advisory conclusion, and
root-receipt-set digest. These cases must never be sent over an admission,
cancel, lookup, or qualification frame.

`anchors.sha256` freezes the two v1.4 contract anchors. `relay-kinds.tsv` freezes
the allocated CI relay kinds. Completion work must not alter either surface.

Run the deterministic checks with:

```bash
ci-acceptance/completion-cases/selftest.sh
```
