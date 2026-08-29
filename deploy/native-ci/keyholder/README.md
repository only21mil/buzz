# Buzz CI keyholder source package

This directory contains dormant systemd templates for the local signing
keyholder. Nothing here installs files, creates accounts, loads credentials,
reloads systemd, enables the socket, or starts the service.

The service accepts one bounded request per Unix connection at
`/run/buzzci/keyholder.sock`. Systemd owns the listener as
`buzzci-keyholder:buzzci-controld` mode `0620`. The keyholder authenticates both
the effective UID and GID from `SO_PEERCRED` before it reads request bytes, then
checks the operation against the exact policy in the public config.

## Public config

`/etc/buzzci/keyholder-v1.json` contains only public values. It uses this closed
shape:

```json
{
  "schema_version": 1,
  "peer": {
    "uid": 1201,
    "gid": 1201,
    "allowed_operations": [
      "describe",
      "sign_ci_event",
      "nip98_authorize",
      "sign_manifest"
    ]
  },
  "selectors": {
    "ci_event": { "public_key": "64 lowercase hex", "generation": 1 },
    "nip98": { "public_key": "64 lowercase hex", "generation": 1 },
    "manifest": { "public_key": "64 lowercase hex", "generation": 1 }
  },
  "nip98_origin": "https://relay.example.invalid"
}
```

Each operation selects one fixed key domain. A request carries only its expected
generation. It cannot provide a credential name, key path, public key, origin,
or signing algorithm. Startup fails if any loaded key does not match its public
selector. NIP-98 authorization also requires the configured HTTPS origin and a
timestamp within 60 seconds of the keyholder clock. The three selector public
keys must be distinct, so a configuration error cannot collapse the signing
domains onto one credential.

## Credentials

The service template uses three `LoadCredentialEncrypted=` entries. Their
plaintext values never appear in the unit environment, process arguments,
config, logs, or error responses. Each decrypted credential must contain
exactly 32 raw secp256k1 secret-key bytes:

- `ci-event.key`
- `nip98.key`
- `manifest.key`

The binary opens the systemd credential directory once with `O_NOFOLLOW`, then
opens these fixed names relative to that descriptor. It rejects links,
non-regular files, multiple links, wrong lengths, and group- or world-writable
objects. Error messages identify only the failed class, never the credential,
path, parser detail, key bytes, request, URL, digest, public key, or signature.

The checked-in unit is not enabled. Creating the dedicated principals,
installing encrypted credentials and public config, and enabling the socket are
separate approval-gated activation work.

## Targeted checks

```bash
python3 deploy/native-ci/package_source.py \
  --source-root "$PWD" \
  --source-commit "$(git rev-parse HEAD)" \
  --package-path deploy/native-ci/keyholder
cargo test -p buzz-ci-keyholder
cargo check -p buzz-ci-keyholder --all-targets
cargo clippy -p buzz-ci-keyholder --all-targets -- -D warnings
```

The source check accepts Git non-executable files materialized as `0600` or
`0644`. It rejects executable-class drift, missing owner read access, ownership
drift, group or world writes, symbolic links, and hard links. It does not repair
source modes.
