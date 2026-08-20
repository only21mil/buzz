# buzz-ci-policy-proxy

This crate is the fail-closed Docker API decision and bounded inherited-Unix-
transport foundation for Buzz CI's pre-start policy proxy. It implements the
closed versioned/unversioned route table,
canonical container/exec reconstruction, manifest-bound image and environment
injection, object ownership ledger, exact pre-start configuration proof, and
terminal mutation barrier.

Production installation consumes a validated protocol v1.4 lease. The proxy
refuses any mismatch in request event, repository, run, tip, base, workflow
ID/digest, job, attempt, or lease ID. The shared lease emits the exact
`{job_id,attempt,lease_id}` tuple used by kind 46106.

Pulls, builds, networks, volume mutation, Libpod endpoints, service containers,
archive access, runtime or proxy socket mounts, secret-bearing environment,
privileged configuration, and unknown routes are denied for the Phase-1
offline slice.

The transport authenticates executor and runtime Unix peer UIDs. A typed
one-shot capability supplies each broker-inherited runtime connection, so an
executor cannot choose a socket path or TCP address. The proxy bounds HTTP
framing and bodies, canonicalizes forwarded requests, projects runtime JSON
into fixed response schemas, and poisons itself after ambiguous upstream
failures.

The pinned route census is in
[`ACT_V0_2_89_ROUTE_CENSUS.md`](ACT_V0_2_89_ROUTE_CENSUS.md). The proxy answers
ping, version, info, owned container-list, and empty volume-list requests
locally. It filters manifest-pinned image inspect, owned container inspect, and
owned exec inspect responses. The runtime never controls executor-visible
headers or exposes extra inspect fields.

Archive and exec-hijack grants are types only. The transport refuses those
routes until bounded tar and hijack mediators exist. Pinned `act` 0.2.89 needs
both routes, so this crate is not act-compatible.

The root-owned broker must still deliver one-shot descriptors over an
authenticated capability channel. It must also persist poison and
reconciliation state, consume sealed mount, cgroup, network namespace, and
quota handles, and run the pinned `act` and Podman black-box census. Until those
pieces and all 17 frozen security tests pass, concurrency remains zero and no
CI job may run.
