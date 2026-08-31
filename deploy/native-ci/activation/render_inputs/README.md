# Activation input renderer

`render_inputs.py` turns one private, canonical descriptor into one private,
canonical output. It does not discover keys, generate secrets, operate services,
or claim protected CI or Tier 2 review.

The descriptor and every JSON input must use sorted compact JSON with one LF.
The descriptor must be mode `0600`. Every file reference supplies its relative
path, SHA-256, byte count, and mode. The renderer anchors references at the
descriptor directory, opens every component with `O_NOFOLLOW`, rejects hard
links, and detects reads that change underneath it. Outputs are new mode-`0600`
files. Existing outputs are never replaced.

## Commands

```bash
RENDER=deploy/native-ci/activation/render_inputs/render_inputs.py

python3 "$RENDER" render-draft \
  --descriptor private/draft-input.json --output activation-draft.json

python3 "$RENDER" render-scenario \
  --descriptor private/scenario-input.json --output capacity-one-scenario.json

python3 "$RENDER" render-clean-host \
  --descriptor private/clean-host-input.json --output clean-host-contract.json

python3 "$RENDER" record-residue \
  --descriptor private/residue-input.json --output residue-receipt-input.json

python3 "$RENDER" record-sealed-freeze \
  --descriptor private/sealed-freeze-input.json --output sealed-freeze-receipt-input.json
```

`--output` and every descriptor path are relative to the descriptor directory.
The clean-host contract preserves those relative paths. Run the v2 harness from
that same directory when consuming the contract.

`render-draft` consumes the four component package manifests, the ceremony's
public binding, and a checked template. `render-scenario` also requires the
frozen activation manifest. It rejects an activation manifest unless its
default state is closed capacity zero, then binds the rendered scenario to the
exact candidate, activation ID, activation package digest, and source object.
A checked template has this exact envelope:

```json
{"definitions":{},"document":{"source_commit":{"$copy":"candidate_sha"}},"kind":"activation-draft","schema_version":"buzz-ci-checked-render-template/v1"}
```

`$copy` reads only the immutable binding graph: `candidate_sha`,
`public_binding`, `packages`, their manifest file hashes, and the public-binding
file hash. `$ref` may point only below `#/definitions/`. Missing references,
unknown directives, and reference cycles fail.

`render-clean-host` computes the same path, mode, and content tree hash as the
v2 clean-host harness. It checks every package member against the package
manifest and rejects missing or extra files. It also checks the candidate HEAD,
the prepared state's exact `public-binding.json`, the scenario, seccomp source,
and execd-to-activation bindings.

The two `record-*` commands run only after the clean-host result, contract,
evidence manifest, acceptance receipt, and installed-verifier output form one
verified passing lifecycle. They bind those exact bytes. `record-residue`
requires the four absence booleans and destroyed VM state. `record-sealed-freeze`
also binds the exact public binding and five package manifests. Both outputs set
`protected_ci` and `tier2` to `false`; a later controller must supply those
independent gates.

`descriptor.schema.json` defines the five input contracts. `output.schema.json`
links the existing activation draft, scenario, clean-host v2 contract schemas
and defines the two evidence-input records.

Both schemas resolve local references without network access. Validate a
scenario descriptor and rendered output with the plain commands:

```bash
RENDER_DIR=deploy/native-ci/activation/render_inputs
check-jsonschema --schemafile "$RENDER_DIR/descriptor.schema.json" \
  private/scenario-input.json
check-jsonschema --schemafile "$RENDER_DIR/output.schema.json" \
  private/capacity-one-scenario.json
```
