# Activation input renderer

`render_inputs.py` turns one private, canonical descriptor into one private,
canonical output. It does not discover keys, generate secrets, operate services,
or claim protected CI or Tier 2 review.

The descriptor, checked templates, package manifests, and renderer-owned JSON
inputs use sorted compact JSON with one LF. The public binding uses the
declaration order emitted by the clean-host ceremony and enforced by the
keyholder package freezer. The rendered capacity-one scenario uses the exact
declaration order normalized by the shipped receipt verifier, compact JSON, and
no trailing LF; its file digest is therefore the same digest computed by the
controller, guest, and installed verifier. The v3 lifecycle result, evidence
manifest, acceptance receipt, and installed-verifier output retain the compact
declaration order emitted by the clean-host harness. The renderer rejects
pretty-printed or re-serialized lifecycle evidence because those exact bytes
are digest-bound. The descriptor must be mode `0600`. Every file reference
supplies its relative path, SHA-256, byte count, and mode. The renderer anchors
references at the descriptor directory, opens every component with
`O_NOFOLLOW`, rejects hard links, and detects reads that change underneath it.
Outputs are new mode-`0600` files. Existing outputs are never replaced.

## Commands

```bash
RENDER=deploy/native-ci/activation/render_inputs/render_inputs.py
TEMPLATES=deploy/native-ci/activation/render_inputs/generate_checked_templates.py

python3 "$TEMPLATES" activation-draft \
  --input private/validated-draft.json --output private/activation-template.json

python3 "$TEMPLATES" capacity-one-scenario \
  --input deploy/native-ci/acceptance/scenario.template.json \
  --output private/scenario-template.json

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
The clean-host contract preserves those relative paths. Run the v3 harness from
that same directory when consuming the contract.

The checked-template generator validates a complete canonical activation draft
before it replaces the candidate, public actor, ready-package component, execd
pre-activation, and controld package fields with renderer bindings. Its scenario
mode validates the maintained capacity-one scenario before it binds the four
candidate and activation fields. Both outputs use the checked envelope below;
the generator creates new private files and never replaces an output.

The generator rebinds `source_commit` for every candidate-owned component. It
also replaces runner, controld, keyholder, and execd binary provenance with the
corresponding frozen package or pre-activation evidence. The production-v2
qualification client is the sole source-commit exception: it keeps the fixed
ABI commit `564e41fda889f25b094b79524b3fb409121794c7` and its validated binary and
provenance digests.

The two generator inputs intentionally have different byte and mode contracts.
An activation draft contains release evidence, so its source must be private
mode `0600` and sorted compact canonical JSON plus LF. The maintained scenario
is a checked repository document. It must have the declaration order accepted
by the receipt verifier, may retain its checked formatting and repository mode,
and must not be writable by another identity. Both generated templates are new
mode-`0600` files with sorted compact canonical JSON plus LF.

`render-draft` consumes the three ready component package manifests, the execd
pre-activation input, the ceremony's public binding, and the generated checked
template. `render-scenario` also requires the frozen execd and activation
manifests. It rejects an activation manifest unless its default state is closed
capacity zero, then binds the rendered scenario to the exact candidate,
activation ID, activation package digest, and source object. A checked template
has this exact envelope:

```json
{"definitions":{},"document":{"source_commit":{"$copy":"candidate_sha"}},"kind":"activation-draft","schema_version":"buzz-ci-checked-render-template/v1"}
```

`$copy` reads only the immutable binding graph: `candidate_sha`,
`public_binding`, `packages`, normalized ready-package component evidence,
execd pre-activation evidence, package manifest hashes, and the public-binding
file hash. `$ref` may point only below `#/definitions/`. Missing references,
unknown directives, and reference cycles fail.

`render-clean-host` computes the same path, mode, and content tree hash as the
v3 clean-host harness. It reads the harness and timing assets from the exact
candidate Git object and places their digests and timing value in the v3
contract. It checks every package member against the package
manifest and rejects missing or extra files. For keyholder packages it also
checks every declared asset size and the retained mode-`0600`
`public-binding.json`, then cross-binds those bytes to the prepared state. It
also checks the candidate HEAD, scenario, seccomp source, and
execd-to-activation bindings.

The two `record-*` commands run only after the clean-host result, contract,
evidence manifest, acceptance receipt, and installed-verifier output form one
verified passing lifecycle. They bind those exact bytes. `record-residue`
requires the four absence booleans and destroyed VM state. `record-sealed-freeze`
also binds the exact public binding and five package manifests. Both outputs set
`protected_ci` and `tier2` to `false`; a later controller must supply those
independent gates.

The lifecycle result input is the exact JSON-plus-LF standard-output byte stream
captured from the checked clean-host harness. Redirect standard output directly
to its result file and standard error to a separate diagnostic file. Do not use
command substitution, parse the result, or reserialize it before a record
descriptor references those bytes.

`descriptor.schema.json` defines the five input contracts. `output.schema.json`
links the existing activation draft, scenario, clean-host v3 contract schemas
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
