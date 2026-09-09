# Apple release request contract v1

Status: candidate v1 (2026-09-08). Part of the program tracked in Buzz issue
`2afb782a8d8993a9a539623eea94e74bab20110dc9d186a5624b92fd953344c6`
(GitHub mirror only21mil/buzz#185).

Companion to `BUZZ_CI_PROTOCOL_CONTRACT.md` v1.4. That contract is unchanged;
this one adds a profile that rides inside its kind-46100 request. Schema:
`deploy/native-ci/apple-release/apple-release-request.schema.json`. Validator:
`crates/buzz-relay/src/api/ci/apple_release.rs`, called from the relay ingest
gate for every kind-46100 request that carries the profile.

## 1. What this contract does

An Apple build, sign, notarize, or TestFlight upload is expressed as an
ordinary Buzz CI request with one extra content object, `apple_release`. The
relay admits or refuses that request deterministically at ingest, before any
executor, credential, or App Store Connect call exists. Today every such
request is refused with `missing_capability`, because no relay advertises an
Apple executor. That refusal is the "deliberate red before credentials" done
check from the issue: the contract is enforced end to end while the executor
is still future work.

The contract does not schedule work, hold credentials, sign, notarize, upload,
or retire the hosted GitHub path in `only21mil/masons-budget`. Those are later
deliverables listed in section 7.

## 2. Envelope binding

The request is a signed kind-46100 event exactly as `BUZZ_CI_PROTOCOL_CONTRACT.md`
section 3 defines it: same tags, same immutable source tuple, same actor and
idempotency rules. `buzz_core::ci::CiRequestEnvelope` ignores unknown content
fields, so the `apple_release` object does not change core validation. The
relay validates the profile only after the envelope, tags, and actor/signer
equality pass.

Two envelope fields bind the profile:

- `tip_oid` must equal `apple_release.source_commit` byte for byte. The
  profile therefore inherits the PR-snapshot resolution, trusted-base workflow
  digest, and rerun copy rules of the base contract. A rerun copies the
  profile unchanged with the rest of the immutable tuple.
- `actor` is the requester. The relay requires the authenticated principal
  that submits the event to hold `jobs:write`, the same scope every CI kind
  already needs.

## 3. Profile fields

All strings are exact; no field may hold a credential, and refs name entries
in the executor keyholder. Vocabulary follows App Store Connect and the `asc`
CLI: app record ID, bundle identifier, team ID, build number, beta group, and
"What to Test".

| Field | Required | Shape | Meaning |
|-------|----------|-------|---------|
| `schema_version` | yes | `1` | Profile version. Unknown versions are malformed. |
| `target` | yes | `macos-notarized` or `ios-testflight` | Release outcome. |
| `executor_class` | yes | `apple-mbp` | The only executor class. Anything else is `missing_capability`. |
| `source_commit` | yes | 40 lowercase hex | Exact Buzz source. Must equal `tip_oid`. |
| `controller_commit` | no | 40 lowercase hex | Exact controller (Budget) commit when a controller drives the host. |
| `version` | yes | `X.Y.Z` decimal, no leading zeros | Marketing version. |
| `build_number` | iOS: yes | 1 to 10 digits, no leading zero | `CFBundleVersion` for the upload. |
| `bundle_identifiers` | yes | 1 to 8 unique reverse-DNS ids, 155 chars max | App bundle first, then extensions. Current values: `xyz.block.buzz.app` (macOS), `com.sats21m.buzz` plus its notification extension (iOS). |
| `team_id` | yes | 10 uppercase alphanumerics | Apple developer team. |
| `signing_identity_ref` | yes | `^[a-z0-9][a-z0-9-]{0,63}$` | Keyholder entry name for the signing identity. |
| `signing_certificate_sha256` | no | non-zero 64 lowercase hex | Expected leaf certificate fingerprint. |
| `architectures` | yes | 1 or 2 unique of `arm64`, `x86_64` | iOS must be exactly `["arm64"]`. |
| `notarization` | macOS: yes, iOS: forbidden | object | `credential_ref`, `staple` (bool), `wait_timeout_seconds` (60 to 7200). |
| `testflight` | iOS: yes, macOS: forbidden | object | `asc_app_id` (1 to 20 digits), `credential_ref`, optional `beta_group_refs` (up to 16 unique names), optional `what_to_test` (1 to 4000 chars), `wait_for_processing_seconds` (60 to 7200). |
| `approval_event_id` | yes | 64 lowercase hex | Signed approval event authorizing this release. Format only in v1; existence binding is a later deliverable. |
| `artifact_retention_days` | yes | 1 to 90 | How long the executor keeps artifacts and logs. |

Unknown fields at any level are refused. The schema encodes every shape rule
above except tip equality, the secret scan, capability coverage, and requester
scope, which only the relay can judge.

## 4. Executor capability

A target needs all of its capabilities from one advertised executor set:

| Target | Required capabilities |
|--------|-----------------------|
| `macos-notarized` | `apple-build`, `apple-codesign`, `apple-notarize` |
| `ios-testflight` | `apple-build`, `apple-codesign`, `apple-testflight-upload` |

The relay operator advertises the set with
`BUZZ_CI_APPLE_EXECUTOR_CAPABILITIES`, a comma-separated list limited to those
four names. Any other name fails relay startup. The variable defaults to empty,
so a relay without a registered Apple executor refuses every Apple request. The
variable is a statement about what the operator has deployed; it grants no
credential and no host access.

## 5. Refusal reasons

Checks run in this order and the first failure is the verdict. Details name
the failing field or bound and never echo a rejected value.

| Order | Reason | Trigger | Ingest response |
|-------|--------|---------|-----------------|
| 1 | `unauthorized_requester` | Submitting principal lacks `jobs:write`. | `restricted: apple release request refused (unauthorized_requester): ...` |
| 2 | `secret_material` | Any key at any depth containing `private_key`, `privatekey`, `password`, `passphrase`, `secret`, `token`, `api_key`, `apikey`, `p8`, `p12`, `pkcs`, or `mobileprovision` (case-insensitive, `-` treated as `_`); any string containing `-----BEGIN` or `AuthKey_`; any whitespace-free token of 80 or more base64-alphabet characters. | `invalid: apple release request refused (secret_material): <json path> ...` |
| 3 | `unknown_target` | `target` is a string outside the closed set. | `invalid: ... (unknown_target): ...` |
| 4 | `malformed_profile` | Missing or unknown field, wrong type, bound violation, or a block that does not belong to the target. | `invalid: ... (malformed_profile): <field or bound>` |
| 5 | `unpinned_commit` | `source_commit` is not 40 lowercase hex, differs from `tip_oid`, or `controller_commit` is present and not 40 lowercase hex. | `invalid: ... (unpinned_commit): ...` |
| 6 | `missing_capability` | `executor_class` is not `apple-mbp`, or the advertised set lacks one of the target's capabilities. The detail lists the missing names. | `invalid: ... (missing_capability): no advertised executor offers ...` |

Accepted profiles are typed as `AppleReleaseRequest` and the event is stored
like any other kind-46100 request. Acceptance grants nothing beyond storage.

## 6. Fixtures and tests

`deploy/native-ci/apple-release/fixtures/` holds two accepted profiles (one
per target) and four refused ones (unknown target, unpinned commit, secret
material, malformed profile). `deploy/native-ci/apple-release/tests/` checks
them with `check-jsonschema` 0.38.0 and runs in `just test-unit` and
`scripts/test-native-ci-python.sh`. The Rust unit tests in
`apple_release.rs` load the same files with `include_str!`, so an accepted
fixture is admitted by both validators and each refused fixture is refused by
both, with the Rust side asserting the reason code.

## 7. After this contract

In order:

1. Bind `approval_event_id` to a stored, signed approval event for the same
   repository and tip, and require the requester to be a channel owner or
   admin.
2. Read-only preflight: `POST /ci/apple-release/validate` returning the same
   reason codes so the CLI can refuse before signing, mirroring section 9 of
   the protocol contract.
3. Signed status kinds for scheduling, executor identity, artifact hashes,
   upload result, and cleanup, then the `apple-mbp` executor itself, which
   depends on the Buzz issue for the local isolated executor
   (`17440d4742d8...`, GitHub #188) and the keyholder custody design.
