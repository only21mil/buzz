# Qualification live-canary plan

This is a plan, not an executable host procedure. Keep the deployment inactive
until every gate below is satisfied.

## Freeze and render

1. Freeze one integrated candidate, broker build, host profile, suite identity,
   fixture signer, source/base pair, and exact job identities.
2. On the authorized host, render all 35 templates to a private staging
   directory. Root authority supplies the permit and fresh bounded validity
   window. The renderer must reject unknown tokens, zero values, duplicate
   nonces, and output over 64 KiB.
3. Validate exact plan coverage and `sealed-case.schema.json`; require no `@`
   token anywhere. Record SHA-256 for every case without logging case bodies.
4. Publish atomically as root:root `0444` files under root:root `0755` real
   directories. Re-read ownership, modes, hashes, candidate binding, and
   `not_before <= now < expires_at` immediately before the suite.

## Static and refusal canary

1. Run the qualification-case self-test and full suite self-test.
2. Run TM-17 `unaccepted` and `external_fork`, then TM-16
   `unauthorized_signer`. Each must exit nonzero with empty stdout and its exact
   local error (`unaccepted_trust_class` or `binding_mismatch`). Socket byte
   counters must remain unchanged.
3. Run the structurally valid expired case. It must reach the service and return
   `policy_denied`; do not claim a client-side zero-byte refusal.
4. Run replay, rate, and concurrency cases only after the controller snapshot is
   frozen. Require `replay_conflict` or `no_capacity` from `ActivationController`.

## Positive and teardown canary

1. Run one positive case and bind the returned nonzero `attempt_id` to the exact
   root-owned lease directory before reading evidence.
2. Run TM-07 and TM-12 through TM-15 in plan order. Require every documented
   lease readback; an absent response field or file is `not_runnable`, never a
   pass inferred from elapsed time.
3. Run TM-06 and TM-14 `teardown_failure` last. Require broker state
   `quarantined`, a before-reuse reconciliation record, ordinary capacity zero,
   no green conclusion, and no publish event.
4. Stop on the first stale binding, mutation, unexpected account, service-state
   drift, or missing readback. Do not rerender or retry inside the same evidence
   lineage.

## Evidence and closure

Retain case-path hashes, control stdout/stderr, broker response codes, lease
readbacks, and the exact controller snapshot identity. Never retain signing
material or case bodies. Promotion remains separately approval-gated and needs
the repository's normal Tier-2 closure.
