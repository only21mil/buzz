# Apple release request profile

Schema and fixtures for the `apple_release` object carried inside a kind-46100
Buzz CI request. The contract is `docs/ci/apple-release-request.md`; the relay
validator is `crates/buzz-relay/src/api/ci/apple_release.rs`.

- `apple-release-request.schema.json`: draft 2020-12 shape of profile v1.
- `fixtures/accepted-*.json`: one admitted profile per target. Both validators
  accept them.
- `fixtures/refused-*.json`: one refused profile per shape-visible reason.
  The schema refuses each; the Rust tests assert the reason code.
- `tests/`: `check-jsonschema` 0.38.0 checks, run by `just test-unit` and
  `scripts/test-native-ci-python.sh`.

Nothing here builds, signs, notarizes, uploads, or holds a credential. Refs in
the fixtures are keyholder entry names; identifiers are public App Store
Connect values.
