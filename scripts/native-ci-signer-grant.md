# Scoped CI signer grant operation

`native-ci-signer-grant.mjs` publishes a reviewed kind-46107 grant or a
replacement grant with an expired window. The issuer must own the named
repository and separately hold the relay's required channel/community admin
role. The relay remains authoritative for authorization. Existing private keys
are supplied through `BUZZ_PRIVATE_KEY` in the process environment. No key is
created or stored by this tool.

The plan is caller-owned mode 0600, singly linked, regular JSON with exactly:

```json
{
  "schema": "buzz-ci-signer-grant-operation-v1",
  "operation": "grant",
  "relay": "wss://relay.example",
  "channel_id": "12345678-1234-1234-1234-123456789abc",
  "repository": "30617:<issuer-public-key>:repo",
  "issuer_public_key": "<64 lowercase hex>",
  "signer_public_key": "<64 lowercase hex>",
  "valid_until": null
}
```

A null grant expiry is an explicit standing grant. A bounded grant uses Unix
seconds strictly after execution time. For revocation, change `operation` to
`revoke`, keep `valid_until` null, and preserve all scope fields. Execution
sets the revoked window to `[now - 60, now]` while retaining the current event
creation time. The relay upserts one row by community, channel, repository,
and signer; revocation affects that row only. A static signer entry or a
different scoped grant can still authorize the same key.

```bash
node scripts/native-ci-signer-grant.mjs --dry-run /private/plan.json
# After approval/review, using the already installed nostr-tools dependency:
export BUZZ_NOSTR_TOOLS_ROOT=/absolute/directory/containing/node_modules
node scripts/native-ci-signer-grant.mjs --publish /private/plan.json \
  /absolute/external-evidence-root/grant-unique-attempt
```

The dry run loads no dependencies, reads no key, signs nothing, and opens no
connection. Publication verifies the key's public identity before signing.
It writes `.event.json` before opening a WebSocket, authenticates through
NIP-42, and sends one event. A successful `.receipt.json` requires an accepted
acknowledgement and the exact signature-verified event from a subsequent relay
query. Both files use the existing retained-evidence publisher with private,
create-only, durable publication. The evidence root must be outside the
checkout, canonical, caller-owned, mode 0700. Existing outputs are refused.

A timeout, disconnect, or failed receipt publication can leave an accepted
event with no success receipt. Query the saved event ID and exact scoped
`ci_grants` row before any retry. Do not treat an event file as acceptance,
and do not treat readback as proof the grant row remains current. Compare
`granted_by`, `valid_from`, `valid_until`, signer, repository, channel and
community with that exact event. Concurrent later grants can replace the row.
After revocation, verify that neither the scoped active row nor the static
signer set authorizes the key. No automatic retry or automatic revocation runs.

Offline tests use fake signatures and transport, with no key or network:

```bash
node --test scripts/test-native-ci-signer-grant.mjs
```
