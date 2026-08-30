# Activation input renderer

`render_inputs.py` turns one private, canonical descriptor into one private,
canonical output. It does not discover keys, generate secrets, operate services,
or claim protected CI or Tier 2 review.

The descriptor and every JSON input must use sorted compact JSON with one LF.
The descriptor must be mode `0600`. Every file reference supplies its relative
path, SHA-256, byte count, and mode. The renderer anchors references at the
descriptor directory, opens every component with `O_NOFOLLOW`, rejects hard
links, and detects reads that change underneath it. Outputs are new mode-`0600`
files. Existing outputs are never replaced. A retry may accept an existing
output only when it is the same owner-controlled mode-`0600` regular file with
the exact complete canonical bytes. The retry fsyncs the output directory again
before it succeeds; every mismatch keeps the no-clobber failure.

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
The clean-host contract preserves those relative paths. Run the v3 harness from
that same directory when consuming the contract.

`render-draft` consumes the final runner, controld, and keyholder package
manifests, the execd pre-activation input, the ceremony's public binding, and a
checked template. The execd input uses schema
`buzz-ci-execd-preactivation-input-v1`; it binds only the exact candidate,
execd binary digest, and binary-provenance digest. It is not a package manifest
and carries no package ID, package digest, activation ID, entries, or target
claims. `render-scenario` requires all five final manifests. A checked template
has this exact envelope:

```json
{"definitions":{},"document":{"source_commit":{"$copy":"candidate_sha"}},"kind":"activation-draft","schema_version":"buzz-ci-checked-render-template/v1"}
```

`$copy` reads only the immutable binding graph: `candidate_sha`,
`public_binding`, `packages`, their manifest file hashes,
`execd_preactivation`, `execd_preactivation_sha256`, and the public-binding file
hash. `$ref` may point only below `#/definitions/`. Missing references, unknown
directives, and reference cycles fail. The draft descriptor's
`execd_preactivation` file reference must name the exact mode-`0600` canonical
file emitted by `execd/freeze_package.py prepare-input`.

`render-clean-host` computes the same path, mode, and content tree hash as the
v3 clean-host harness. It checks every package member against the package
manifest and rejects missing or extra files. It reads `harness.py`,
`guest_entry.py`, and `timing-contract.json` from the exact candidate Git
object, not from caller-supplied digests. The renderer requires those blobs to
match its maintained clean-host assets. It also checks their digests against
the prepared state's mode-`0400` `state.json`, including the frozen guest-entry
asset. It then emits the harness digest, raw timing-asset digest, decoded timing
object, and harness-semantic timing digest. The renderer also checks the
candidate HEAD, exact index bytes and entries, and non-ignored worktree status.
It freezes that repository identity through every candidate-blob read and rechecks it before
output. The canonical output bytes are written, synced, and read back from a
private staging inode. At finalization, maintained Git transactions hold the
HEAD and index locks. A mode-`000` no-clobber hard link is pending, not accepted;
the renderer checks its inode identity and repository status again while those
locks remain. Successful completion of the final status read accepts that exact
pending inode. The renderer then changes its mode to `0600`, making the accepted
output readable. Drift before the pending link rejects without an output.
Drift after that link but before acceptance returns a distinct error and leaves
only an unreadable mode-`000` artifact. No failure authorizes pathname deletion,
so namespace replacement cannot cause removal of an unrelated file. The final
verification and acceptance operation includes the pending link, inode check,
and final status read before it returns. A mutation injected after the final
status read is post-acceptance.
If the no-clobber link finds an existing destination, the same Git locks remain
held while the renderer validates its exact canonical bytes, inode, owner, and
mode, performs the final candidate status read, and validates the destination
again. Only an exact match is accepted. Candidate drift or a destination
mismatch rejects and removes only the private temporary. The renderer never
overwrites, changes the mode of, or removes the pre-existing destination.
Ignored build artifacts do not change the repository identity. The renderer
also checks the
prepared state's exact `public-binding.json`, the scenario, seccomp source, and
execd-to-activation bindings. The resulting contract has
the exact closed v3 shape accepted by preflight. Missing, extra, legacy v2, or
independently drifted harness/timing fields fail before transfer or VM
execution.

The two `record-*` commands run only after the clean-host result, contract,
evidence manifest, acceptance receipt, and installed-verifier output form one
verified passing lifecycle. They require the verifier's exact real output,
`{"outcome":"pass","status":"verified"}`, and bind its digest through both the
evidence manifest and result. They derive and compare every evidence asset
digest—harness, guest entry, timing contract, local TLS relay, receipt verifier,
and expected stages—against the exact candidate Git blobs, so a self-consistent
caller rewrite cannot substitute any frozen asset. `record-residue` requires
the four absence booleans and destroyed VM state. `record-sealed-freeze` also
binds the exact public binding and five package manifests. Both outputs set
`protected_ci` and `tier2` to `false`; a later controller must supply those
independent gates. Both recorders use the same repository snapshot and
pending-link acceptance boundary as `render-clean-host`.

`descriptor.schema.json` defines the five input contracts. `output.schema.json`
links the existing activation draft, scenario, clean-host v3 contract schemas
and defines the two evidence-input records.
