# Native completion evidence reads

Standalone native keyholders deny object GET by default. The optional
`native_evidence` configuration authorizes the exact log and artifact digests
for one request, run, job and attempt during a bounded read window. It enables
no acceptance operations and grants no execution or publication authority.
The fixture renderer, fixture schema and acceptance exact-path policy remain
separate. `keyholder-native-config.schema.json` describes this native variant.

The service still enforces the peer UID/GID, operation mask, NIP-98 selector and
generation, HTTPS origin, canonical URL/path, GET without query, filter or
payload, and the normal fresh token timestamp. It checks the read window
against its own clock on every request. Configured windows cannot exceed 900
seconds; the root preparation path issues 300-second windows. Expired workload
admission is never extended. Native config must be a root-owned regular file
without group/other write permission under root-owned protected directories.
It cannot be edited by the signing service account.

## Owned sequence

One root controller owns the complete lane. It preserves the accepted request,
signed source/registration, measured completion, cleanup proof and immutable
bundle. After independent cleanup and before opening any publisher connection:

1. Install the reviewed operator and keyholder binaries through the existing
   qualified deployment procedure, retaining exact old/new bytes, hashes,
   metadata, unit/drop-in/socket state and process provenance. No other binary
   or credential changes are required by this policy.
2. Build a root-owned mode-0444 stage specification with the fields below and
   a fresh root-owned mode-0700 backup directory. Root owns every ancestor.
3. Run the pinned `stage_native_evidence.py --spec PATH --sha256 SHA256` for
   an optional dry read. Run it with `--apply` in the uninterrupted owned
   completion flow to install a fresh policy. The helper invokes the pinned
   operator's `check-completion` as root. That invokes the existing complete
   receipt verifier with protected filesystem reads and derives policy digests
   from the same `OutputDescriptor`s publication consumes. Linux combined log
   bytes and Mac retained log bytes share that implementation.
4. The helper checks every public binding, all input hashes, current config
   CAS and process hash. It refuses connected keyholder clients. Under a root
   lock, it saves immutable prior config bytes and metadata, stops the existing
   socket/service, atomically replaces the config with owner `0:1202`, mode
   `0640`, and starts the service. The unchanged service dependency starts the
   socket. It checks a new invocation, exact process binary/config hashes and
   the native four-operation Describe handshake through UID/GID 1201.
5. Only a successful helper result permits the caller to launch its existing
   publisher command. The publisher opens fresh connections and revalidates
   accepted references, actual relay bytes and hashes through the normal
   authenticated export. The helper itself signs and publishes nothing.

`check-completion` retains its original verification behavior and adds a
versioned evidence plan to stdout. It reads no operator store. The new
`describe-keyholder AUTHORITY AUTHORITY_SHA256` command performs only the
existing native handshake. The new operator may be used for plan generation
and Describe while the old reviewed publisher binary remains in use. Both
consume identical bundle and store formats; `publish` logic is unchanged.

The stage specification has exactly these fields:

```json
{
  "schema_version": 1,
  "operator": "/usr/libexec/buzz-ci-native-admission-operator",
  "operator_sha256": "<reviewed new operator SHA-256>",
  "authority": "<root mode-0444 reviewed authority path>",
  "authority_sha256": "<reviewed authority SHA-256>",
  "request": "<root mode-0444 accepted request event path>",
  "request_sha256": "<exact captured request file SHA-256>",
  "source": "<root mode-0444 source event path>",
  "source_sha256": "<exact source file SHA-256>",
  "bundle": "<root mode-0444 bundle.json path>",
  "bundle_sha256": "<exact immutable bundle SHA-256>",
  "expected_config_sha256": "<exact current native config SHA-256>",
  "keyholder_binary_sha256": "<reviewed installed keyholder SHA-256>",
  "accepted_store": null,
  "accepted_store_sha256": null,
  "backup_directory": "<fresh root mode-0700 directory>"
}
```

For already published recovery, root supplies an immutable mode-0444 snapshot
of the existing accepted operator store plus its SHA-256. The helper requires
all log/artifact publications for the bound request to be Accepted, from the
configured CI signer, with exactly the derived object paths and digests. The
snapshot is a root-pinned recovery cross-check; it is not a substitute for the
publisher's authenticated relay reads. For future jobs it is null because
completion references are published after policy installation. The request
comes from the root-owned authenticated capture and reviewed authority. The
helper never obtains authority from an unprivileged caller's arbitrary paths.

## Failure and recovery

Before replacement, any failed predicate leaves the current config unchanged.
A failure after quiescing leaves the socket/service stopped. A failed startup
or Describe also stops both. The exact candidate config and immutable backup
remain for diagnosis; there is no automatic publisher or workload retry.
An interrupted atomic update leaves either the prior complete config or the
new complete bounded config. A temporary file cannot become authority; only
the configured path is loaded. Root must diagnose, compare current bytes and
state, and prepare a fresh CAS specification and backup directory before
retrying. A stale 300-second plan is never replayed.

To roll back, the qualified runtime owner stops socket/service, restores the
retained pre-install binary and config bytes with their recorded metadata,
then reuses the existing native Describe/process-hash readback. The old
keyholder cannot parse `native_evidence`; restoring only its binary is invalid.
The old native config intentionally denies evidence GET. Restoring that pair
preserves all accepted CI events and the immutable completion/store while
leaving evidence export held. Rollback never resends accepted publications or
rewrites execution/admission timestamps.

The first migration accepts the existing exact CAS-pinned `1202:1202/0600`
standalone config and replaces it with `0:1202/0640`. Later native policies
remain root-owned. No fixture receipt, actor credential, grant, protocol
operation, socket identity, UID, selector or generation changes.
