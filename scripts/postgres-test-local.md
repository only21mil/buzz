# Owned PostgreSQL tests

`postgres-test-run.sh` compiles and reconciles the explicit ignored-test inventory,
then runs each admitted test through `postgres-test-local.py`. Each case receives
a new cluster and database. Desired-schema tests load `schema/schema.sql`;
migration tests start empty. Redis/live-relay/APNs fixtures remain external.
A schema override cannot admit an external fixture.

Execution and libtest discovery require Linux bubblewrap, iproute2 and util-linux.
The runner creates fresh user, network, mount and PID namespaces automatically,
drops all capabilities, sets no_new_privs and disables nested user namespaces.
Failure to establish these controls stops execution; there is no host fallback
and no CLI flag or environment variable that disables the fence.

The sandbox sees system `/usr`, a fresh `/proc` and `/dev`, synthetic `/etc`, the
runner scripts and schema, the supplied PostgreSQL tool tree and individual test
executables. Input trees containing sockets or other special files are refused.
Host `/home`, `/run`, `/var` and `/tmp` are absent. The only host writable mount is
a new private work directory. No inherited credentials, service files or URLs
enter the sandbox. Host TCP, default Unix sockets, abstract sockets and host PID
namespace handles are therefore unavailable, including to hardcoded clients.
The owned PostgreSQL cluster listens only on its private Unix socket.

```sh
python3 scripts/test-postgres-test-fence.py
scripts/postgres-test-run.sh --task-root /absolute/task --pg-bin-dir /absolute/pg/bin
```

The kernel regression first creates a controlled parent namespace with synthetic
listeners at TCP 5432 and the usual Unix socket paths. It proves that the parent
can connect, the production fence cannot connect, and user/setns escape attempts
fail. It never contacts an existing host database. Service-free runner tests are
in `test-postgres-test-local.py`; discovery checks are in
`test-postgres-test-discovery.py`.

Use `--filter NAME --exact BINARY` with `postgres-test-local.py` for a focused
compiled case. A successful invocation must execute exactly one passing test.
Both test and cleanup failures propagate as failure. Owned data is retained if
cleanup is incomplete; namespace teardown kills remaining child processes.
Neither test success nor absence of an owned cluster establishes anything about
historical tests run before the namespace fence existed.

Production URL defaults and signed CI context names are unchanged. This fence
qualifies the PostgreSQL-only inventory; it does not provide the Redis, relay,
APNs or other services required by external fixtures.

The Relay E2E invite selection also requires a live relay, Redis and MinIO. These seven
cases remain `external` in the PostgreSQL-only inventory. CI invokes
`postgres-test-ci.sh --relay-invites --relay-binary target/ci/buzz-relay
--s3-tools-dir target/invite-tools` to keep
the hosted Ubuntu admission profile alive around `relay-invite-test-local.py`.
That command compiles the `e2e_relay` target, then uses the same production fence
for complete libtest inventory reconciliation and execution. It starts owned
PostgreSQL (Unix socket only), Redis, MinIO and the relay inside that fence and passes
an explicit database URL to both relay and tests. No host relay is used.

For local reproduction with already compiled binaries:

```sh
python3 scripts/relay-invite-test-local.py --task-root /absolute/task \
  --pg-bin-dir /absolute/pg/bin --redis-binary /absolute/redis-server \
  --s3-tools-dir /absolute/minio-tools \
  --relay-binary /absolute/buzz-relay --test-binary /absolute/e2e_relay
```

Each exact selector must report one passing test. The command reaps relay and
Redis and MinIO, stops PostgreSQL, removes private data, and fails on incomplete cleanup.
Fixture logs are printed before removal. Discovery drift fails before any
service starts. `test-relay-invite-test-local.py` checks that admission behavior
without starting services.
