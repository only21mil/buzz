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

`anchors.sha256` freezes the two contract documents. `relay-kinds.tsv` freezes
the allocated CI relay kinds. Completion work must not alter either surface.

The original v1.4 anchors from `06a37cb7c` were refreshed against `27a7b558a`
after accounting for every landed change to the documents and CI kind list:

| Commit | Contract change |
| --- | --- |
| `904595a45` | Authenticated log reads, byte ranges, size bounds, and redirect refusal. |
| `c1425b199` | Durable watch ordering and a fixed watch deadline. |
| `e76548344` | Protected GitHub delivery authority and gap-free request/event promotion evidence. |
| `8f3737973` | Rerun lineage, final-request provenance, and narrower acceptance-adapter log reads. |
| `7972bdc69` | Stable preflight failure stage and cause. |
| `c8151fdb2` | Terminal check contract and allocation of `KIND_CI_CHECK`, 46108. |
| `6f7b3fc34` | Native macOS workflow registration from a fixed trusted-base path. |
| `602c3b550` | Allocation of `KIND_CI_MERGE_BYPASS`, 46109. |

The completion fixtures and their refusal/quarantine decisions are unchanged.
Future anchor updates must explain the intervening landed contract changes;
matching the current hashes alone is not sufficient.

Run the deterministic checks with:

```bash
ci-acceptance/completion-cases/selftest.sh
```
