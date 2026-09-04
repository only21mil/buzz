# Buzz CI keyholder source package

This directory contains the dormant systemd base templates and an explicit
acceptance-actor provisioning package for the local signing keyholder. The
package scripts never create accounts or credentials, read credential bytes,
reload systemd, enable the socket, or start the service. The package now owns
the exact release binary at `/usr/libexec/buzz-ci-keyholder`; activation owns
neither that path nor a second copy of the daemon.

The service accepts one bounded request per Unix connection at
`/run/buzzci/keyholder.sock`. Systemd owns the listener as
`buzzci-keyholder:buzzci-controld` mode `0620`. The keyholder authenticates both
the effective UID and GID from `SO_PEERCRED` before it reads request bytes, then
checks the operation against the exact policy in the public config.

## Public config

`/etc/buzzci/keyholder-v2.json` is owned only by this package and contains
only static public values. Its acceptance-enabled shape is:

```json
{
  "schema_version": 2,
  "peer": {
    "uid": 1201,
    "gid": 1201,
    "allowed_operations": [
      "describe",
      "sign_ci_event",
      "nip98_authorize",
      "sign_manifest",
      "describe_acceptance",
      "sign_acceptance_mutation"
    ]
  },
  "selectors": {
    "ci_event": { "public_key": "64 lowercase hex", "generation": 1 },
    "nip98": { "public_key": "64 lowercase hex", "generation": 1 },
    "manifest": { "public_key": "64 lowercase hex", "generation": 1 }
  },
  "nip98_origin": "https://relay.example.invalid",
  "acceptance": {
    "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
    "credential_selector": "acceptance-actor.key"
  }
}
```

Each operation selects one fixed key domain. A request carries only its expected
generation. It cannot provide a credential name, key path, public key, origin,
or signing algorithm. Startup fails if any loaded key does not match its public
selector. NIP-98 authorization also requires the configured HTTPS origin and a
timestamp within 60 seconds of the keyholder clock. The three selector public
keys must be distinct, so a configuration error cannot collapse the signing
domains onto one credential.

A NIP-98 request names its `signer`. The relay stores a `POST /events` only
when the event `pubkey` equals the token pubkey, so a publish token is signed
by the key that signed the event: signer `ci_event` for kinds 46101 to 46106
(the `ci-event.key` selector) and signer `acceptance_actor` for the five frozen
acceptance events (the `acceptance-actor.key` credential, only when the
activation binding is loaded and at the actor's generation). Both are accepted
for `POST {origin}/events` with a payload digest. Signer `ci_event` is also
accepted for `POST {origin}/query`, and only for the exact-event read-back:
the request carries the literal filter body (at most 512 bytes), the keyholder
derives the payload digest from those bytes itself, and the bytes must be
exactly `[{"ids":[<id>],"authors":[<ci-event key>],"kinds":[<kind>],"limit":1}]`
with one 64-character lowercase hex id, the keyholder's own ci-event public key
as the only author, one CI kind in 46100 to 46107, and limit 1. Controld uses
this exact query both to recover a refused publication and to read back the
signed evidence-reference and final-fact events required by acceptance stage
7. A response must contain exactly the requested event, whose signature, id,
author, and kind are checked before use. Any other filter, and a filter on any
other route, is denied.

Signer `nip98` (the `nip98.key` selector) is accepted for the accepted read,
the evidence `PUT` routes, and full-body `GET` of exactly two
signed-reference paths at the configured HTTPS origin:

```text
/ci/logs/{request-id}/{run-id}/{job-id}/{attempt}/{sha256}
/ci/artifacts/{request-id}/{run-id}/{job-id}/{attempt}/{artifact-id}/{sha256}
```

Those braces describe the grammar, not caller-selectable fields. At startup the
keyholder reconstructs the sole log path and sole artifact path from the public
acceptance receipt's Run A request digest, run ID, job ID, expected log and
artifact hashes, fixed attempt `1`, and fixed artifact ID `result`. The receipt
contains no evidence URL or path-list field. Even a third path that satisfies
the grammar is denied because it is absent from that two-entry derived set.

`request-id` and `sha256` are 64-character lowercase hex; `run-id` is a
canonical lowercase hyphenated UUID; `job-id` matches
`[A-Za-z_][A-Za-z0-9_-]{0,63}`; `attempt` is canonical positive decimal `u32`;
and `artifact-id` is 1 to 128 ASCII alphanumeric, dot, underscore, or hyphen
characters other than `.` or `..`. The URL must reproduce the configured
origin and canonical path byte-for-byte and contain no credentials, query,
fragment, or percent encoding. These reads carry no payload. `HEAD`, range or
generic `GET`, redirects, and object-store credentials are outside the
acceptance adapter: keyholder signs no `HEAD` or generic path, and the adapter
sends no `Range` header and follows no redirect. A `POST /events` or
`POST /query` request with signer `nip98` is denied, and the acceptance actor
never queries.

The config never contains an activation package digest, scenario digest,
acceptance actor identity, or event template. After the activation package and
scenario are frozen, the root activation controller creates one public compact
JSON receipt at the fixed path. Keyholder and controld independently read and
validate the same bytes. The receipt has this declaration-order shape:

```json
{
  "schema_version": "buzz-ci-activation-acceptance-binding/v2",
  "activation_id": "activation id",
  "activation_package_digest": "64 lowercase hex",
  "scenario_sha256": "64 lowercase hex",
  "keyholder_peer_uid": 62002,
  "keyholder_peer_gid": 62002,
  "acceptance_peer_uid": 961,
  "acceptance_peer_gid": 961,
  "timeout_millis": 1000,
  "fixture": {
    "...": "capacity-one fixture",
    "export_subject": "6666666666666666666666666666666666666666666666666666666666666666",
    "export_generation": 1,
    "export_authorization_digest": "7777777777777777777777777777777777777777777777777777777777777777",
    "expected_log": {
      "name": "job.log",
      "sha256": "64 lowercase hex",
      "bytes": 131
    },
    "expected_artifacts": [
      {
        "name": "result.json",
        "sha256": "64 lowercase hex",
        "bytes": 107
      }
    ]
  },
  "acceptance": {
    "actor": { "public_key": "64 lowercase hex", "generation": 1 },
    "scenario_sha256": "same 64 lowercase hex",
    "run_event": [0, "actor public key", 0, 46100, [], "canonical content"],
    "grant_event": [0, "actor public key", 0, 46107, [], "canonical content"],
    "rerun_event": [0, "actor public key", 0, 46100, [], "canonical content"],
    "tombstone_event": [0, "actor public key", 0, 5, [], ""],
    "failure_run_event": [0, "actor public key", 0, 46100, [], "canonical content"],
    "export_subject": "6666666666666666666666666666666666666666666666666666666666666666",
    "export_generation": 1,
    "export_authorization_digest": "7777777777777777777777777777777777777777777777777777777777777777"
  }
}
```

The receipt is root:root mode `0444`, a regular one-link file, with a root:root
mode `0711` immediate parent. It has no whitespace or trailing newline. The
daemon rejects missing, linked, replaced, noncanonical, loose-mode, or
semantically drifted receipts on every start. It verifies the fixture package,
candidate, scenario, peer, actor generation, grant identity, and all five event
templates. The fixture and nested acceptance copies of `export_subject`,
`export_generation`, and `export_authorization_digest` must be equal. The
subject and generation must also equal the loaded nip98 selector. The digest
must equal the deterministic transcript over the ordered Run A attempt 1
`job.log` and `result` artifact `GET` bindings reconstructed from the receipt;
no token or volatile proof field enters it. The daemon requires exactly the
declared `job.log` and `result.json` objects before deriving that two-path
allowlist. The actor credential must be distinct from every existing selector.

The keyholder wire codec is strict protocol v2. Its `describe_acceptance`
response carries event IDs in Run, Grant, Rerun, Tombstone, FailureRun semantic
order; the fifth ID is required tag 8. Calls publish those frozen events in Run,
Grant, FailureRun, Rerun, Tombstone order because the distinct failed run must
exist before its rerun. Protocol v1 had only the first four IDs. A v1 peer
accepted only tags 1 through 7, so the required tag 8 could not be added under
the old version. V1 and v2 peers now reject each other's frame headers.
Keyholder and controld must come from the same frozen candidate. Activation
stages and restarts those package versions together. Wire v2 does not by itself
make two policy revisions deployment-compatible: an older v2 keyholder rejects
the evidence `GET` authority required by a newer controld, which must then fail
closed, while a newer keyholder with an older controld leaves the added
authority unused. Either mixed package is unsupported. A wire-protocol mismatch
fails closed before controld completes initialization, serves, or accepts any
acceptance operation; systemd may already have opened its sockets. A same-v2
policy mismatch is detected when the exact evidence `GET` authorization is
denied and fails stage 7 without an export or passing qualification.

## Credentials

The dormant service template uses three `LoadCredentialEncrypted=` entries. Their
plaintext values never appear in the unit environment, process arguments,
config, logs, or error responses. Each decrypted credential must contain
exactly 32 raw secp256k1 secret-key bytes:

- `ci-event.key`
- `nip98.key`
- `manifest.key`

The active package adds a separate systemd drop-in with exactly:

```ini
LoadCredentialEncrypted=acceptance-actor.key:/etc/credstore.encrypted/buzzci-keyholder/acceptance-actor.key
```

A production activation therefore needs four separately provisioned,
cryptographically distinct credentials: the three selector credentials above
and `acceptance-actor.key`. The acceptance credential also contains exactly 32
raw secret bytes. Hex, `nsec`, PEM, a trailing LF, or a copied clean-host guest
credential is invalid. Provisioning all four credentials is one approval-gated
operation; generating a public binding does not provision or inspect them.

The encrypted source is an external prerequisite owned by root with mode
`0400`; it is not a package asset. The installer checks only its file metadata
and size and never opens it. Missing, linked, loose-mode, or wrongly owned
sources fail closed. The existing three credential mappings remain in the base
service and never appear in the acceptance drop-in.

The binary opens the systemd credential directory once with `O_NOFOLLOW`, then
opens these fixed names relative to that descriptor. It accepts the two shapes
systemd delivers: a directory and files owned by the service account (`0500`,
`0400`), or, as systemd 259 installs them on the clean host, `root:root` with no
world bits and read access granted to the service through an ACL (directory
`0550`, files `0440`). It rejects links, non-regular files, multiple links,
wrong lengths, world-readable objects, group- or world-writable objects,
setuid, setgid, or sticky bits, and any owner other than root or the service
account. Error messages identify only the failed class, never the credential,
path, parser detail, key bytes, request, URL, digest, public key, or signature.

The checked-in unit is not enabled. Freezing or installing a package does not
change that state. Creating the dedicated principals, creating the encrypted
credential, reloading systemd, and enabling the socket remain separate
approval-gated activation work.

## Generate a production public binding

The clean-host `prepare` binding contains disposable guest keys and is valid
only for that isolated qualification run. Do not use those public keys for a
live host. After the separately approved production provisioner has written
all four encrypted credentials directly to their fixed paths, capture its four
public readback streams in an owner-held mode-`0700` directory. Each stream
must contain only the corresponding 64-character lowercase BIP-340 x-only
public key plus one LF. Redirect only that documented public-readback stream.
Reject a provisioner that puts secret bytes in stdout, argv, logs, or a public
readback file; never decrypt a credential to obtain this input.

The generator accepts only those four public files, public relay origins,
numeric identities, and explicit generation `1`. It never reads a credential,
accepts stdin, or prints a key. The four public files must be regular,
singly-linked, owned by the caller, and mode `0400`, `0444`, `0600`, or `0644`.
The output parent must be an owner-held real mode-`0700` directory, and the
output must not exist.

```bash
PUBLIC_INPUTS=/protected/buzzci-production-public
PUBLIC_BINDING=/protected/buzzci-production-binding/public-binding.json

deploy/native-ci/keyholder/generate_public_binding.py \
  --relay-url wss://relay.example.invalid \
  --relay-http-origin https://relay.example.invalid \
  --controld-uid 1201 --controld-gid 1201 \
  --ci-event-public-key "$PUBLIC_INPUTS/ci-event.pub" \
  --ci-event-generation 1 \
  --nip98-public-key "$PUBLIC_INPUTS/nip98.pub" \
  --nip98-generation 1 \
  --manifest-public-key "$PUBLIC_INPUTS/manifest.pub" \
  --manifest-generation 1 \
  --acceptance-actor-public-key "$PUBLIC_INPUTS/acceptance-actor.pub" \
  --acceptance-actor-generation 1 \
  --output "$PUBLIC_BINDING"
```

The result is mode `0600`, canonical compact declaration-order JSON plus LF
with schema `buzz-ci-clean-host-e2e-public-binding/v3`. The schema name remains
unchanged because the keyholder freezer and activation renderers consume those
exact bytes. The generator validates that all four public keys lift to
secp256k1 points, are nonzero and distinct, that both origins name one exact
lowercase authority, and that every downstream v3 consumer accepts the result.
It does not copy any guest key or credential bytes.

## Freeze and inspect an acceptance package

For isolated qualification, use the canonical `public-binding.json` emitted by
the clean-host `prepare` step. For a live host, use only the production binding
generated from the approved production public readbacks above. The freezer requires schema
`buzz-ci-clean-host-e2e-public-binding/v3`, validates the complete closed
document in the producer's exact declaration-order compact JSON plus LF,
checks the controld UID and GID, rejects raw or private key fields, and verifies
that the acceptance actor differs from all keyholder selectors. Reordered,
pretty-printed, duplicate-key, extra-field, and truncated bindings fail closed.
It projects `keyholder_public_spec` by removing only
`peer.allowed_operations`, then validates the result as the existing lean
acceptance-public spec. The package manifest binds both the original binding
SHA-256 and the projected canonical spec SHA-256. The package retains those
exact original bytes as root package member `public-binding.json`, mode `0600`.
The installer rehashes and reprojects that member against the manifest and
runtime config. Activation rendering also requires its digest to match the
exact prepared-state binding supplied to the descriptor.

```bash
deploy/native-ci/keyholder/freeze_package.py \
  --source-root "$PWD" \
  --source-commit "$(git rev-parse HEAD)" \
  --binary /private/path/buzz-ci-keyholder \
  --binary-provenance /private/path/binary-provenance.json \
  --public-binding "$STATE/public-binding.json" \
  --output /private/path/keyholder-package \
  --keyholder-uid 1202 --keyholder-gid 1202 \
  --controld-uid 1201 --controld-gid 1201

deploy/native-ci/keyholder/install.py verify-package \
  --package /private/path/keyholder-package
```

`--public-binding` and `--public-spec` are mutually exclusive. The latter
remains available only for an explicit legacy lean acceptance-public spec. A
legacy package records `public_binding_sha256` as JSON `null` and still binds
the canonical lean spec digest. It omits `public-binding.json`; an unclaimed
artifact fails installation, and a legacy package cannot enter the
prepared-public-binding activation composition. Neither input may contain an activation
package digest, scenario, event template, arbitrary path, or secret. The
keyholder package digest therefore remains independent of the post-freeze
receipt and cannot participate in a package self-digest cycle.

`install.py check` and `install.py install --dry-run` validate the host
principals and external encrypted credential without mutation. `install`
copies the public config and static units with exact ownership and modes, but
does not call systemd. It also installs the provenance-bound release binary,
publishes every target through descriptor-relative no-follow operations, and
records one immutable receipt under `/var/lib/buzzci/keyholder-package`.
The installer locks the receipt and target directory descriptors for the full
transaction. Linux `renameat2` no-replace and exchange operations compare the
live inode and digest at publication, so a target that changes after planning
is restored without overwriting the concurrent file. Replays accept only the
exact receipt and installed bytes. Drift or another candidate is refused.
`install.py rollback` verifies every installed target and backup before
restoring the prior file or prior absence. It checkpoints each restored target
and removed install-created directory in `rollback-state-v1.json`, then writes
the create-once `rollback-v1.json` terminal marker. A restart resumes from the
last exact checkpoint. A retry after terminal marker publication returns
`unchanged`. Use `--root` only for a controlled fake root or an explicitly
approved installation.

## Targeted checks

```bash
python3 deploy/native-ci/package_source.py \
  --source-root "$PWD" \
  --source-commit "$(git rev-parse HEAD)" \
  --package-path deploy/native-ci/keyholder
cargo test -p buzz-ci-keyholder
cargo check -p buzz-ci-keyholder --all-targets
cargo clippy -p buzz-ci-keyholder --all-targets -- -D warnings
python3 -m unittest discover -s deploy/native-ci/keyholder/tests -v
```

The source check accepts Git non-executable files materialized as `0600` or
`0644`. It rejects executable-class drift, missing owner read access, ownership
drift, group or world writes, symbolic links, and hard links. It does not repair
source modes.
