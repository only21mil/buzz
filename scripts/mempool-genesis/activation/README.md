# Mempool and Genesis activation staging

This directory builds a credential-free activation package after Buzz Desktop saves the two public identities. The generator reads no private key. The installer writes no credential, enables no unit, starts no service, and sends no relay event.

## Review order

The work crosses two promotion boundaries.

1. The disabled, unmerged source candidate gets parent Tier 1 readback and deterministic checks. The exact code candidate then gets Tier 2 before merge.
2. After Desktop saves two distinct public identities, both services stay stopped and disabled. Freeze the final dynamic package and run a second Tier 2. Credential handoff, installation, and activation remain blocked until that review has a current terminal accepted closure.

This package is GPT-produced and touches credentials, signing, and production, but Victor explicitly overrode automatic escalation for this one activation on 2026-08-26. Run Tier 2 with `--producer-provider gpt` and no `--escalate`; the engine selects one independent Claude Opus 5 reviewer at `high` reasoning. This activation-specific route does not change generic fleet canon: future GPT-produced security, authentication, signing, or production-infrastructure work escalates the Claude leg to Claude Fable 5 unless Victor or Rachel explicitly overrides it.

The parent Tier 1 receipt is deterministic evidence only. It cannot close review, make the package installable, or grant install authority.

## Private staging root

The current Tier 2 engine fingerprints Git state when a candidate sits inside a repository. Keep the dynamic package and review state outside every Git worktree so the review covers only the package files.

```sh
ACT=/home/victor/work/prog-buzz/wave3/MGACT/.scratch/activation-wt-sats/scripts/mempool-genesis/activation
STAGE=/home/victor/work/mgact-activation-staging
install -d -m 0700 "$STAGE"
install -m 0600 "$ACT/input.template.json" "$STAGE/inputs.json"
```

The template contains placeholders. After Desktop save, replace only these JSON values:

- `mempool_pubkey`: 64 lowercase hex characters
- `genesis_pubkey`: 64 lowercase hex characters

The values must differ and must not reuse Victor, Rachel, Sats Codex, Sats Codex-2, or Archimedes Codex. Never read or copy Desktop private keys.

## Generate

A placeholder preview is incomplete and cannot pass installer validation.

```sh
python3 "$ACT/generate-activation-bundle.py" \
  --inputs "$STAGE/inputs.json" \
  --output "$STAGE/candidate-placeholder" \
  --allow-placeholders
```

After Desktop returns both public keys, generate the final package.

```sh
python3 "$ACT/generate-activation-bundle.py" \
  --inputs "$STAGE/inputs.json" \
  --output "$STAGE/candidate-final" \
  --replace
```

A complete package reports `input_status=complete`, `ready_for_parent_tier1=true`, and `installable=false`. The manifest records:

- producer provider `gpt`;
- activation-specific non-escalated route `claude-opus-5` at `high`;
- engine sequence `prepare`, `review`, `check`;
- the exact SHA-256 of `/home/victor/.agents/skills/codex-review/scripts/tier2`;
- candidate paths `bundle-manifest.json` and `metadata/review-files.json`.

Each agent's installed closure inventory still has exactly 17 paths.

## Tier 1 receipt and Tier 2 evidence

Run the deterministic preflight as the artifact owner, not root.

```sh
python3 "$ACT/make-tier1-receipt.py" \
  --bundle "$STAGE/candidate-final" \
  --output "$STAGE/preflight-receipt.json" \
  --tier2-bundle-output "$STAGE/dynamic-tier2-evidence.json"
```

A complete package with green checks returns `READY_FOR_PARENT_TIER1`. A placeholder package returns `BLOCKED_ON_DESKTOP_PUBKEYS` and does not create Tier 2 evidence. The receipt records no verdict and creates no installed closure.

`dynamic-tier2-evidence.json` uses the installed engine's exact `tier2-evidence-v2` contract. It names the package as `candidate_root`, lists only the two manifest-owned candidate paths, and carries the observed Tier 1 command results. The receipt binds its absolute path and SHA-256.

Shellcheck selection does not depend on caller `PATH`. Receipt generation uses `/home/victor/.npm-global/bin/shellcheck`. Installer validation compares the recorded command and never executes that user-owned tool as root. Real-root installer commands use `/usr/bin/python3` explicitly because Fedora's sudo path resolves bare `python3` through `/usr/sbin`, which would not match the recorded command path.

## Tier 2 v2

The parent controller owns this sequence. The state directory must be mode `0700`, private to the artifact owner, and outside the candidate directory and every candidate repository.

```sh
TIER2=/home/victor/.agents/skills/codex-review/scripts/tier2
STATE_DIR="$STAGE/tier2-r1"

STATE=$("$TIER2" prepare \
  --bundle "$STAGE/dynamic-tier2-evidence.json" \
  --producer-provider gpt \
  --controller sats-codex-2 \
  --state-dir "$STATE_DIR")

"$TIER2" review --state "$STATE"
"$TIER2" check --state "$STATE"
```

`prepare` freezes one candidate fingerprint and, because this invocation omits `--escalate`, selects Claude Opus 5 at `high`. `review` records the terminal result in the same `tier2-state-v2` file. There is no separate result artifact. `check` rejects failed, stale, expired, mismatched, overridden, or mutated closure state.

If revision 1 fails, follow the engine's revision 2 contract with the same reviewer identity. Do not open another review leg. The shared runbook in `Agent-Shared/adapters/sats-shared-common.md` owns retries and corrected lineages.

Keep the evidence bundle and state file under the private staging root. The launch token is single-use and the engine removes it when review claims it.

## Read-only installer checks

Both modes call the same preflight function and write nothing.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" check \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STATE"

sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" dry-run \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STATE"
```

The installer runs the installed engine's `check` subcommand every time. The package binds both the adapter source and the installed engine by SHA-256. The installer copies the adapter into a sealed `memfd`; the adapter does the same for the engine before executing `/proc/self/fd/N`. Under sudo, the adapter runs as the authenticated artifact owner before it reads private review files.

The adapter requires:

- `tier2-state-v2` with `status=closed`;
- producer `gpt` and `escalate=false`;
- route `claude`, `claude-opus-5`, `high`;
- an accepted `PASS` or `PASS WITH RISKS` result;
- the exact evidence digest and package candidate fingerprint;
- no transport override;
- a current engine `check` result of `OK`.

The real-root gate also requires `framework-desktop`, root, and both `buzz-agent@mempool.service` and `buzz-agent@genesis.service` to report exactly `inactive` and `disabled`. Private receipt, evidence, and state files must belong to the authenticated sudo invoker. Direct-root operation requires root-owned artifacts. Malformed or forged `SUDO_UID` metadata fails closed. Every target must be `add`, `replace`, or `current`, with `writes=0`.

Parent symlinks are allowed only when the link owner is trusted, the resolved directory remains inside the install root and below the same already-validated parent tree, and the normal owner and non-writable-directory checks pass. Broken, escaping, cross-tree, writable, or wrong-owner links remain blocked.

The staged sweep candidate has separate read-only modes. They need later approval to use Victor's sanctioned owner credential for relay reads. Mempool and Genesis remain a fixed public-key roster. The script covers every live open channel, uses Victor's owner authority, and never reads either managed agent's private key.

```sh
"$STAGE/candidate-final/ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh" --check
"$STAGE/candidate-final/ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh" --dry-run
```

## Install and rollback

Installation is outside this lane. It needs separate Victor or Rachel approval after terminal Tier 2 closure and real-host read-only checks.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" install \
  --bundle "$STAGE/candidate-final" \
  --receipt "$STAGE/preflight-receipt.json" \
  --tier2-evidence "$STAGE/dynamic-tier2-evidence.json" \
  --tier2-state "$STATE"
```

The installer derives `/etc/buzz-agents/review-closure.json` from the validated Tier 2 state. It never accepts a caller-authored installed closure. The installed `buzz-agent-review-closure-v2` record binds the lineage, state, evidence, verdict, runtime files, package digest, and frozen candidate fingerprint. The package-installed `verify-installed-agent` prestart gate validates that same v2 contract before either service can start.

The installer backs up every changed target, uses same-directory temporary files with `fsync` and `os.replace`, installs the derived closure last, verifies final state, and restores applied targets on failure. An exact second run returns `ALREADY_INSTALLED writes=0` without another backup.

The successful install output contains one backup ID. Roll back only while both services remain stopped and disabled.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" rollback \
  --backup-id FULL_BACKUP_ID
```

Backups and install receipts live under `/var/lib/buzz-mgact-backups/` as mode-`0700` state. The install lock is `/run/lock/buzz-mgact-install.lock`. Rollback refuses digest, owner, mode, hard-link, symlink, or content drift.

## Parent integration order

1. Read back and test `scripts/mempool-genesis/activation/**` plus `scripts/mempool-genesis/verify-installed-agent`. Leave the disabled intermediate candidate at Tier 1.
2. Freeze the exact code candidate. Run Tier 2 and merge only after terminal accepted closure.
3. Wait for Desktop to return the two public keys while both identities remain stopped. Put only those public values in `inputs.json`.
4. Generate `candidate-final`. Generate the Tier 1 receipt and current Tier 2 evidence.
5. Complete parent Tier 1 readback. Run `tier2 prepare`, `review`, and `check` on the exact dynamic package.
6. Run installer `check` and `dry-run` on the real host before the closure expires. Run sweep `--check` and `--dry-run` only with separate approval to use the live owner credential.
7. Seek separate approval for credential handoff, installation, and activation. Preserve the printed backup ID if installation is approved.
