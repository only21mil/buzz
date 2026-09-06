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
