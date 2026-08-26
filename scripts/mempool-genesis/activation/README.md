# Mempool and Genesis activation staging

This directory builds a credential-free activation package after Buzz Desktop saves the two public identities. The generator reads no private key. The installer writes no credential, enables no unit, starts no service, and sends no relay event.

## Review order

The normal review policy has two promotion boundaries.

1. This disabled, unmerged source candidate gets parent Tier 1 readback and deterministic checks. The exact-head code candidate then gets normal Tier 2 before merge.
2. After Desktop saves two distinct public identities, both managed services must remain stopped and disabled. Freeze the final dynamic package and run a second normal Tier 2. Credential handoff, installation, and activation remain blocked until that review has terminal accepted closure.

The preflight receipt only reports readiness and records bounded evidence inputs. It cannot close either review, make the package installable, or grant install authority.

## Private staging root

```sh
ACT=/home/victor/work/prog-buzz/wave3/MGACT/.scratch/activation-wt-sats/scripts/mempool-genesis/activation
STAGE=/home/victor/work/prog-buzz/wave3/MGACT/.scratch/MGACT-staging-r3
install -d -m 0700 "$STAGE"
install -m 0600 "$ACT/input.template.json" "$STAGE/inputs.json"
```

The template contains placeholders. After Desktop save, replace only these JSON values:

- `mempool_pubkey`: 64 lowercase hex characters
- `genesis_pubkey`: 64 lowercase hex characters

The values must differ and must not reuse Victor, Rachel, Sats Codex, Sats Codex-2, or Archimedes Codex. Never read or copy Desktop private keys.

## Generate

A placeholder preview is incomplete and cannot pass installer validation:

```sh
python3 "$ACT/generate-activation-bundle.py" \
  --inputs "$STAGE/inputs.json" \
  --output "$STAGE/candidate-placeholder" \
  --allow-placeholders
```

After Desktop returns both public keys, generate the final package:

```sh
python3 "$ACT/generate-activation-bundle.py" \
  --inputs "$STAGE/inputs.json" \
  --output "$STAGE/candidate-final" \
  --replace
```

A complete package reports `input_status=complete`, `ready_for_parent_tier1=true`, and `installable=false`. It contains deterministic `metadata/review-files.json` and `metadata/tier2-evidence-inputs.json` records. Each agent's installed closure inventory has exactly 17 paths.

## Preflight receipt

```sh
python3 "$ACT/make-tier1-receipt.py" \
  --bundle "$STAGE/candidate-final" \
  --output "$STAGE/preflight-receipt.json"
```

A complete package with green checks returns `READY_FOR_PARENT_TIER1`. A placeholder package returns `BLOCKED_ON_DESKTOP_PUBKEYS`. The receipt records no review verdict and creates no installed closure. Gate selection is independent of caller `PATH`: shellcheck always uses `/home/victor/.npm-global/bin/shellcheck` during normal-user receipt creation, while installer validation only compares the recorded fixed command and never executes that user-owned tool as root.

## Normal dynamic Tier 2

The parent controller converts `metadata/tier2-evidence-inputs.json` into a private normal Tier 2 evidence bundle. The evidence bundle must use `tier2-evidence-v2` files mode and bind exactly these two package files by absolute path and SHA-256:

- `bundle-manifest.json`
- `metadata/review-files.json`

Its `fingerprints` object must bind the package digest, review-files digest, and runtime artifact fingerprint from the generated inputs. The controller owns the standard evidence validation, launch capability, independent GPT-5.6 Sol `xhigh` review, result recording, and terminal closure checks.

Keep these final artifacts under the private staging root, all mode `0600`:

- the evidence bundle
- the closure state created by `tier2_evidence.py authorize-launch`
- the `tier2-review-result-v3` result recorded by `tier2_evidence.py validate-closure`

The source candidate carries an exact reviewed snapshot of the maintained Tier 2 closure engine. The package source inventory binds that verifier by SHA-256. After package validation, the installer opens the source with `O_NOFOLLOW`, copies and hashes the exact bytes into a sealed `memfd`, and runs `/proc/self/fd/N`; replacing or modifying the user-owned source after the freeze cannot change the executed code. Under sudo the verifier drops to the authenticated artifact owner before reading the private closure files. The installer also validates the exact evidence paths, package fingerprints, state binding, result digest, reviewer identity, model, effort, verdict, and unchanged mutation check.

## Read-only installer checks

Both modes call the same preflight function and write nothing:

```sh
sudo python3 "$ACT/install-activation-bundle.py" check \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STAGE/dynamic-tier2-state.json" \
  --tier2-result "$STAGE/dynamic-tier2-result.json"

sudo python3 "$ACT/install-activation-bundle.py" dry-run \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STAGE/dynamic-tier2-state.json" \
  --tier2-result "$STAGE/dynamic-tier2-result.json"
```

The real-root gate requires `framework-desktop`, root, and both `buzz-agent@mempool.service` and `buzz-agent@genesis.service` to report exactly `inactive` and `disabled`. Private receipt, evidence, state, and result files must be owned by the authenticated sudo invoker; direct-root operation instead requires root-owned artifacts. Malformed, incomplete, or parent-process-forged `SUDO_UID` metadata fails closed. Every target must be classified `add`, `replace`, or `current`, with `writes=0`.

The staged sweep candidate has separate read-only modes. They require a later approval to use Victor's sanctioned owner credential for relay reads. Mempool and Genesis remain a fixed public-key roster. The script covers every live open channel, uses Victor's owner authority, and never reads either managed agent's private key.

```sh
"$STAGE/candidate-final/ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh" --check
"$STAGE/candidate-final/ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh" --dry-run
```

## Install and rollback

Installation is outside this lane. It needs separate Victor or Rachel approval after final normal Tier 2 closure and real-host read-only checks.

```sh
sudo python3 "$ACT/install-activation-bundle.py" install \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STAGE/dynamic-tier2-state.json" \
  --tier2-result "$STAGE/dynamic-tier2-result.json"
```

The installer derives `/etc/buzz-agents/review-closure.json` from the validated normal Tier 2 state and result. It never accepts a caller-authored installed closure. It backs up every changed target, uses same-directory temporary files with `fsync` and `os.replace`, installs the derived closure last, verifies final state, and restores applied targets on failure. An exact second run returns `ALREADY_INSTALLED writes=0` without creating another backup.

The successful install output contains one backup ID. Roll back only while both services remain stopped and disabled:

```sh
sudo python3 "$ACT/install-activation-bundle.py" rollback \
  --backup-id FULL_BACKUP_ID
```

Backups and install receipts live under `/var/lib/buzz-mgact-backups/` as mode-0700 state. The install lock uses canonical `/run/lock/buzz-mgact-install.lock`; `/var/lock` is not traversed because Fedora exposes it as a symlink to `/run/lock`. Rollback refuses any installed-file digest, owner, mode, hard-link, or symlink drift.

## Parent integration order

1. Read back and test only `scripts/mempool-genesis/activation/**`. Leave the disabled intermediate candidate at Tier 1.
2. Freeze the exact code candidate, run normal Tier 2, and merge only after terminal accepted closure.
3. Wait for Desktop to return the two public keys while both identities remain stopped. Put only those public values in `inputs.json`.
4. Generate `candidate-final` without `--allow-placeholders`, then generate the preflight receipt.
5. Freeze the final dynamic files and run the second normal Tier 2.
6. Run installer `check` and `dry-run` on the real host. Run sweep `--check` and `--dry-run` only under separate approval to use the live owner credential.
7. Seek separate approval for credential handoff, installation, and activation. Preserve the printed backup ID if installation is approved.
