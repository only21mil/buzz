# `act` v0.2.89 Docker route census

This census pins the proxy work to `nektos/act` tag `v0.2.89`. It describes a
minimal Linux shell job with no service containers. It is a source audit, not a
claim that the current proxy can run the job.

The machine-readable copy is
[`tests/fixtures/act-v0.2.89-minimal-shell-routes.json`](tests/fixtures/act-v0.2.89-minimal-shell-routes.json).

## Request order

1. `GET /info`
2. `GET /images/{digest}/json`
3. `GET /containers/json?all=1`
4. `GET /version`
5. `POST /containers/create?name={act-name}`
6. `POST /containers/{id}/start`
7. `POST /containers/{id}/exec` and hijacked `POST /exec/{id}/start` for
   user and group probes
8. `PUT /containers/{id}/archive?path=...` for event, environment, command,
   and script files
9. `POST /containers/{id}/exec`, hijacked `POST /exec/{id}/start`, then
   `GET /exec/{id}/json` for each shell step
10. `GET /containers/{id}/archive?path=...` for command files and step output
11. `DELETE /containers/{id}?force=true&v=true`
12. `GET /volumes`

The Docker client may issue `GET /_ping` or `HEAD /_ping` while negotiating the
API. A missing image would cause `POST /images/create`; the offline policy must
refuse that request.

## Current safe subset

The proxy answers ping, version, info, owned container-list, and empty
volume-list requests locally. It forwards only manifest-pinned image inspect,
owned container inspect, and owned exec inspect responses through fixed JSON
projections. Create and other already-admitted non-streaming operations also
receive fixed projections.

Archive transfer and exec hijack remain disabled. Their typed grants only state
what a future mediator must bind. They do not authorize forwarding. Because
both operations are mandatory in the sequence above, this crate is not yet
compatible with `act`.

## Pinned source paths

The sequence comes from these files at tag `v0.2.89`:

- [`pkg/container/docker_run.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/container/docker_run.go)
- [`pkg/runner/run_context.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/runner/run_context.go)
- [`pkg/runner/step.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/runner/step.go)
- [`pkg/runner/step_run.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/runner/step_run.go)
- [`pkg/container/docker_pull.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/container/docker_pull.go)
- [`pkg/container/docker_volume.go`](https://github.com/nektos/act/blob/v0.2.89/pkg/container/docker_volume.go)

The archive calls follow Moby's client implementation in
[`client/container_copy.go`](https://github.com/moby/moby/blob/v28.5.2/client/container_copy.go).
