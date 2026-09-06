# Disposable HTML relay acceptance

`html-relay-test-local.py` runs the real relay and the ignored HTML HTTP test
against newly created PostgreSQL, Valkey and MinIO instances. It requires a
fresh Linux network namespace containing only loopback. The relay's health and
metrics exporters bind wildcard addresses, so setting `BUZZ_BIND_ADDR` alone
does not isolate every listener.

The runner uses explicit binary paths and a whitelist environment. PostgreSQL
uses a private Unix socket with TCP disabled. All data, the synthetic relay
identity, public fixture S3 credentials and the dedicated bucket are disposable.
It stops its processes and removes data on success, failure, SIGINT and SIGTERM.
Logs and binary hashes remain under `--task-root`. Do not supply production
binaries with extra startup behavior or reuse this runner outside the authorized
local fixture scope. This is a test runner, not a sandbox for untrusted binaries.

Build only the relay and focused integration test from the chosen source:

```sh
. ./bin/activate-hermit
cargo build -p buzz-relay --bin buzz-relay
cargo test -p buzz-test-client --test e2e_media_extended --no-run --message-format=json
```

Read the test executable path from Cargo's `compiler-artifact` record. Supply
an extracted PostgreSQL server/client directory and a tools directory containing
`minio`, `mc`, and `usr/bin/valkey-server`. The script never installs or downloads
tools. Binaries must be compatible with the host. This task used PostgreSQL
18.6, Valkey 9.0.6 and MinIO RELEASE.2025-09-07T16-13-09Z.

Create the namespace with ordinary task ownership inside it. Substitute absolute
paths and the intended task username; capture the original namespace before
`unshare`:

```sh
fixture_host_netns=$(readlink /proc/self/ns/net)
sudo unshare --net sh -c 'ip link set lo up; exec runuser -u victor -- "$@"' fixture \
  /usr/bin/python3 /absolute/repo/scripts/html-relay-test-local.py \
  --host-netns "$fixture_host_netns" \
  --task-root /absolute/task \
  --pg-bin-dir /absolute/task/pg-tools/usr/bin \
  --tools-dir /absolute/task/html-fixture-tools \
  --relay-binary /absolute/target/debug/buzz-relay \
  --test-binary /absolute/target/debug/deps/e2e_media_extended-HASH
```

The test receives an explicit `RELAY_HTTP_URL=http://127.0.0.1:13000`. It covers
canonical `.html` and bare-hash URLs, full 200 and range 206 responses, exact
bytes and SHA-256, authoritative HTML MIME despite advisory upload headers,
attachment disposition, nosniff, restrictive CSP, anonymous/malformed/expired
auth rejection, wrong-extension 404, hash mismatch and the media-only legacy
upload route. It does not establish browser, native save-dialog or mobile OS
handler behavior.

The runner then stops the relay, explicitly seeds two community hosts and public
synthetic key 2 as a member of both, and restarts with membership enforcement
enabled. `test_html_tenant_read_denial` uploads distinct HTML on each host and
proves both member contexts work. Hash-scoped Blossom auth is valid on both
hosts. Each owner gets exact full/range bytes while the other tenant receives
404 with exactly `{"error":"not found"}` for canonical and bare-hash paths.
The error response contains no attachment bytes. This tests the tenant sidecar
boundary even though underlying content-addressed S3 bytes are shared. It does
not test channel ACLs, quotas or audit isolation. The broader existing media
cross-tenant conformance row remains a `pending_lane` stub and is not counted as
a pass.
