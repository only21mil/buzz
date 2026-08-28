# Mempool and Genesis activation staging

This directory builds a credential-free activation package after Buzz Desktop saves the two public identities. The generator reads no private key. The installer writes no credential, enables no unit, starts no service, and sends no relay event.

This source is a staged parity candidate only. It packages the template unit and both effective per-instance drop-ins, installs agent EnvironmentFiles as `0600 root:root`, and binds those paths into each installed review closure. Mempool keeps only its identity-local state/runtime paths and the approved `/home/victor/work/ci-mig/a1` through `a6` lanes. Genesis has no Victor-home write path and no writable-user tool path. The package pins `codex-acp`, the Codex CLI, and Node inside `/usr/local/libexec/buzz`; `CODEX_PATH` names the Codex CLI because that is the `codex-acp` child-process contract.

GLM activation remains on hold pending its own current Tier 2 closure and separate activation approval. Nothing in this candidate authorizes a GLM runtime, installation, credential handoff, or service start.

## Review order

The work crosses two promotion boundaries.

1. The disabled, unmerged source candidate gets parent Tier 1 readback and deterministic checks. The exact code candidate then gets Tier 2 before merge.
2. After Desktop saves two distinct public identities, both services stay stopped and disabled. Freeze the final dynamic package and run a second Tier 2. Credential handoff, installation, and activation remain blocked until that review has a current terminal accepted closure.

This package is GPT-produced and touches credentials, signing, and production. Run Tier 2 with `--producer-provider gpt`; the current opposite-provider engine selects one independent Claude Opus 5 reviewer at `high` reasoning. Fable 5 is not a review or escalation route.

The parent Tier 1 receipt is deterministic evidence only. It cannot close review, make the package installable, or grant install authority.

## Private package-review worktree

Tier 2 v3 accepts only a Git-worktree root and binds its complete status inventory. Create a clean detached worktree at the source base, generate the package beneath it as the only untracked content, and keep inputs, receipts, evidence, state, and the scope ledger in separate owner-only directories outside that worktree. The preflight rejects any tracked drift, non-package status entry, or package file missing from the manifest-owned inventory.

```sh
ACT=/home/victor/work/prog-buzz/wave3/MGACT/.scratch/activation-wt-sats/scripts/mempool-genesis/activation
STAGE=/home/victor/work/mgact-activation-staging
PACKAGE_WT=/home/victor/work/mgact-activation-package-wt
PACKAGE_DIR="$PACKAGE_WT/candidate-final"
PARITY_DIR="$STAGE/capability-parity"
PREFLIGHT_RECEIPT="$STAGE/preflight-receipt.json"
TIER2_EVIDENCE="$STAGE/dynamic-tier2-evidence.json"
: "${FULL_REVIEWED_SOURCE_COMMIT:?set to the full reviewed source commit}"
if [ "${#FULL_REVIEWED_SOURCE_COMMIT}" -ne 40 ]; then
  echo "FULL_REVIEWED_SOURCE_COMMIT must be exactly 40 lowercase hex characters" >&2
  exit 1
fi
case "$FULL_REVIEWED_SOURCE_COMMIT" in
  *[!0-9a-f]*)
    echo "FULL_REVIEWED_SOURCE_COMMIT must be exactly 40 lowercase hex characters" >&2
    exit 1
    ;;
esac
git -C /home/victor/work/buzz-relay cat-file -e "${FULL_REVIEWED_SOURCE_COMMIT}^{commit}"
install -d -m 0700 "$STAGE" "$PARITY_DIR"
install -m 0600 "$ACT/input.template.json" "$STAGE/inputs.json"
if ! git -C /home/victor/work/buzz-relay worktree add --detach "$PACKAGE_WT" "$FULL_REVIEWED_SOURCE_COMMIT"; then
  echo "failed to create package worktree from FULL_REVIEWED_SOURCE_COMMIT" >&2
  exit 1
fi
if ! PACKAGE_HEAD=$(git -C "$PACKAGE_WT" rev-parse HEAD 2>/dev/null); then
  echo "failed to read package worktree HEAD" >&2
  exit 1
fi
if [ "$PACKAGE_HEAD" != "$FULL_REVIEWED_SOURCE_COMMIT" ]; then
  echo "package worktree HEAD mismatch; refusing to continue" >&2
  exit 1
fi
```

Set `FULL_REVIEWED_SOURCE_COMMIT` only to the final full commit ID whose exact source candidate received the terminal accepted review. Do not reuse an older source base or abbreviated ID.

The template is deliberately pending and contains placeholders. After Desktop saves both identities, change `identity_binding` to `desktop-saved` and replace only these JSON values:

- `mempool_pubkey`: 64 lowercase hex characters
- `genesis_pubkey`: 64 lowercase hex characters

The values must be distinct valid secp256k1 x-only public keys. Repeated-nibble placeholders, missing values, curve-invalid values, and Victor, Rachel, Sats Codex, Sats Codex-2, or Archimedes Codex identities are rejected before the generator creates its temporary output. Never read or copy Desktop private keys.

## Generate

The generator never writes a preview from pending, missing, placeholder, duplicate, reserved, or curve-invalid identity input. `--allow-placeholders` remains only to return an explicit compatibility error and does not write a package. After Desktop returns both public keys, generate the final package.

```sh
python3 "$ACT/generate-activation-bundle.py" \
  --inputs "$STAGE/inputs.json" \
  --output "$PACKAGE_DIR" \
  --replace
```

A complete package reports `input_status=complete`, `ready_for_parent_tier1=true`, and `installable=false`. The manifest records:

- producer provider `gpt`;
- current opposite-provider route `claude-opus-5` at `high`;
- profile-backed Claude authentication source, bound into the Tier 2 state route;
- engine sequence `prepare`, `review`, `check`;
- the reviewed source commit and tree plus the exact SHA-256, source commit, source tree, path, and `0755` mode of `/home/victor/.agents/skills/codex-review/scripts/tier2`;
- every manifest-owned generated package file as the candidate path inventory.

Each agent's installed closure inventory has exactly 22 paths, including its effective template fragment, manager drop-in, per-instance drop-in, capability-parity comparator, activation transaction tool, and approved-differences policy. The prestart verifier compares systemd's actual `FragmentPath` and `DropInPaths` with that closed set and rejects any extra or missing path.

The environment templates match Codex-R's reviewed response policy: `respond_to=allowlist`, `allowed_respond_to=allowlist`, and the sole responder is Victor's owner pubkey. They bind `BUZZ_ACP_STATE_DIR` to the identity-local persistent state path. Generation and prestart accept only the reviewed ASCII `KEY=VALUE` grammar: an unquoted whitespace-free value or one completely balanced double-quoted value without escapes. Blank lines, comments, leading whitespace, single quotes, embedded unquoted whitespace, control bytes, backslashes, continuations, and multiline or unbalanced quotes fail closed. The package removes the unproven `AF_NETLINK` exception and binds the template and both drop-in hashes that prove it remains absent.

## Codex-R capability parity

`capability-parity.py` captures or builds redacted `reference`, `mempool`, and `genesis` manifests and compares the set against `capability-parity-policy.json`. `capture` reads only explicitly named local sources: the effective EnvironmentFile, prompt and policy, Codex TOML, Buzz key and Codex auth files, public channel/profile/directory JSON, executable closure, and either an effective systemd fixture or a live system- or user-manager `systemctl show` property allowlist. It never asks systemd for `Environment`, never returns a credential value, and reduces the two secret-file descriptors and owner auth tag to path class, presence, owner/mode/link/inode metadata, length/character class, and a 12-character SHA-256 prefix. Command-backed public-source adapters run a fixed absolute executable with a sanitized environment, no stderr capture, and no secret-looking arguments.

The v2 policy keeps Codex-R's truthful 26-channel reference set and partitions it into 25 Mempool/Genesis-eligible channels plus one authority exclusion. The excluded channel `9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f` remains visible in the reference set because it is open, Codex-R is present as a bot, and Victor is a member rather than the required owner. It is never a membership candidate. A comparison can pass only with a fresh, package-bound live-authority receipt that observes that exact state and confirms both candidate identities are absent. Missing, stale, tampered, or drifted visibility, archive, role, reference, or candidate presence blocks parity.

The comparator also fails closed on a shared pubkey, auth-tag binding, secret path class, inode, or secret digest; shared users, homes, state, prompts, events, or receipts; response-policy drift from Codex-R; candidate drift from the reviewed 25-channel set; runtime closure drift; Rachel/Archimedes private scope; admin elevation; a directory record not authored by that agent; stale directory `channel_ids`; weakened systemd hardening; unapproved `AF_NETLINK`; or broad Victor, Sats, family, vault, browser, or secret-store access. Mempool's six existing CI migration lanes are the only host-path exceptions in the policy. Policy, authority, parity, transaction, phase, install, and rollback records bind the reference, eligible, exclusion, and live-authority digests.

All parity digests use `buzz-canonical-json-ascii-v1`: null, booleans, arrays, objects with byte-sorted printable-ASCII keys, printable-ASCII strings, and signed 64-bit integers. Floats, non-finite numbers, non-ASCII text, control bytes, DEL, and out-of-range integers fail before hashing or signature verification. Python and Rust consume the same golden fixture.

Capture Codex-R immediately before freezing the source candidate, then capture Mempool and Genesis from the same public relay snapshot and effective host state. Capture specs and command specs are owner-only JSON; outputs are newly created mode-`0600` files. The role-generic sequence is:

```sh
python3 "$ACT/capability-parity.py" capture --spec "$PARITY_DIR/reference-capture.json" --policy "$ACT/capability-parity-policy.json" --output "$PARITY_DIR/reference-manifest.json"
python3 "$ACT/capability-parity.py" capture --spec "$PARITY_DIR/mempool-capture.json" --policy "$ACT/capability-parity-policy.json" --output "$PARITY_DIR/mempool-manifest.json"
python3 "$ACT/capability-parity.py" capture --spec "$PARITY_DIR/genesis-capture.json" --policy "$ACT/capability-parity-policy.json" --output "$PARITY_DIR/genesis-manifest.json"
python3 "$ACT/capability-parity.py" compare-set --reference "$PARITY_DIR/reference-manifest.json" --mempool "$PARITY_DIR/mempool-manifest.json" --genesis "$PARITY_DIR/genesis-manifest.json" --policy "$ACT/capability-parity-policy.json" --authority-receipt "$PARITY_DIR/live-authority-receipt.json" --output "$PARITY_DIR/parity-receipt.json"
python3 "$ACT/capability-parity.py" seal-receipt --receipt "$PARITY_DIR/parity-receipt.json" --policy "$ACT/capability-parity-policy.json" --signer-command "$PARITY_DIR/signer-command.json" --verifier-command "$PARITY_DIR/verifier-command.json" --bundle-manifest "$PACKAGE_DIR/bundle-manifest.json" --output "$PARITY_DIR/sealed-parity-receipt.json"
```

Activation requires `status=PASS` and empty `unexplained_differences` for both candidates. `seal-receipt` accepts owner-only signer/verifier command specs of schema `buzz-agent-capability-command-v1` plus `--bundle-manifest`; before either executable runs, its exact path, `0700` mode, uid/gid, and SHA-256 must match the manifest's corresponding ops record. Before signing, the tool adds the exact source commit, staged source tree, package digest, runtime fingerprint, and canonical bundle-manifest digest to the receipt payload. The maintained `buzz-parity-owner-signer` reads the existing sanctioned `BUZZ_OWNER_PRIVATE_KEY` only from an absolute, single-link `0600` private file inside an owner-controlled `0700` directory and receives only `payload_sha256` through an anonymous standard-input pipe. It BIP-340 signs `SHA256("buzz-agent-capability-parity/signature/v1\\0" || payload_sha256_bytes)`, which prevents reuse as a raw Nostr event-digest signature, and emits only the public envelope. The owner verifier used while sealing accepts either the pre-seal envelope or a persisted sealed envelope, recomputes the canonical receipt and sealed-envelope digests, and verifies the owner binding and signature. At activation and every systemd prestart, `verify-sealed` validates the persisted owner-tool records against the manifest without reading owner-home executables, then opens the reviewed root-owned `buzz-agent-key-handoff` runtime target, checks its root ownership, `0755` mode, single-link status, exact manifest hash and path, copies it to a write/shrink/grow-sealed executable memfd, and invokes its verifier-only subcommand. A missing or changed manifest, receipt, policy, root runtime verifier, or binding prevents `ExecStart`. A failing verifier, wrong owner, wrong digest, malformed signature, persisted-envelope tamper, unbound executable, weak private-file metadata, or non-PASS receipt blocks sealing. Build the handoff binary and both owner tools with `cargo build --release -p buzz-agent-key-handoff --bin buzz-agent-key-handoff --bin buzz-parity-owner-signer --bin buzz-parity-owner-verifier` before generating a package; the generator records their Rust source inventory and binds runtime bytes separately from the owner-only ops tools.

## Tier 1 receipt and Tier 2 evidence

Run the deterministic preflight as the artifact owner, not root.

```sh
python3 "$ACT/make-tier1-receipt.py" \
  --bundle "$PACKAGE_DIR" \
  --output "$PREFLIGHT_RECEIPT" \
  --tier2-bundle-output "$TIER2_EVIDENCE"
```

A complete package with green checks returns `READY_FOR_PARENT_TIER1`. A placeholder package returns `BLOCKED_ON_DESKTOP_PUBKEYS` and does not create Tier 2 evidence. The receipt records no verdict and creates no installed closure.

`dynamic-tier2-evidence.json` uses the installed engine's exact `tier2-evidence-v3` contract. Its `candidate_root` is the package-review worktree root, its paths equal the complete Git status inventory, and every path must be a manifest-owned file beneath the package directory. Commands use v3 `kind=result` records. The receipt binds the evidence's absolute path, candidate root, and SHA-256.

Shellcheck selection does not depend on caller `PATH`. Receipt generation uses `/home/victor/.npm-global/bin/shellcheck`. Installer validation compares the recorded command and never executes that user-owned tool as root. Real-root installer commands use `/usr/bin/python3` explicitly because Fedora's sudo path resolves bare `python3` through `/usr/sbin`, which would not match the recorded command path.

## Tier 2 v3

The parent controller owns this sequence. The state directory must be mode `0700`, private to the artifact owner, and outside the candidate directory and every candidate repository.

```sh
TIER2=/home/victor/.agents/skills/codex-review/scripts/tier2
TIER2_STATE_DIR="$STAGE/tier2-r1"
TIER2_LEDGER_DIR="$STAGE/tier2-scope-ledgers"
SCOPE_ID=mgact-dynamic-package-20260827

install -d -m 0700 "$TIER2_STATE_DIR" "$TIER2_LEDGER_DIR"
TIER2_STATE_FILE=$("$TIER2" prepare \
  --bundle "$TIER2_EVIDENCE" \
  --producer-provider gpt \
  --claude-auth-source profile \
  --controller sats-codex-2 \
  --scope-id "$SCOPE_ID" \
  --scope-ledger-dir "$TIER2_LEDGER_DIR" \
  --state-dir "$TIER2_STATE_DIR")

"$TIER2" review --state "$TIER2_STATE_FILE"
"$TIER2" check --state "$TIER2_STATE_FILE"
```

`prepare` freezes the complete Git candidate fingerprint, binds the stable promotion/correction scope, and selects Claude Opus 5 at `high`. `review` records the terminal result in the same `tier2-state-v3` file and updates the separate controller-owned scope ledger. There is no separate result artifact. `check` rejects failed, stale, expired, mismatched, overridden, ledger-inconsistent, or mutated closure state.

If revision 1 fails, follow the engine's revision 2 contract with the same reviewer identity. Do not open another review leg. The shared runbook in `Agent-Shared/adapters/sats-shared-common.md` owns retries and corrected lineages.

Keep the evidence bundle and state file under the private staging root. The launch token is single-use and the engine removes it when review claims it.

## Read-only installer checks

Both modes call the same preflight function and write nothing.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" check \
  --bundle "$PACKAGE_DIR" \
  --receipt "$PREFLIGHT_RECEIPT" \
  --tier2-evidence "$TIER2_EVIDENCE" \
  --tier2-state "$TIER2_STATE_FILE"

sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" dry-run \
  --bundle "$PACKAGE_DIR" \
  --receipt "$PREFLIGHT_RECEIPT" \
  --tier2-evidence "$TIER2_EVIDENCE" \
  --tier2-state "$TIER2_STATE_FILE"
```

The installer runs the installed engine's `check` subcommand every time. The package binds both the adapter source and the installed engine by SHA-256. The installer copies the adapter into a sealed `memfd`; the adapter does the same for the engine before executing `/proc/self/fd/N`. Under sudo, the adapter runs as the authenticated artifact owner before it reads private review files.

The adapter requires:

- `tier2-state-v3` with `status=closed` and a matching passing scope-ledger entry;
- producer `gpt` with no retired `escalate` field;
- route `claude`, `claude-opus-5`, `high`, with `auth_source=profile`;
- an accepted `PASS` or `PASS WITH RISKS` result;
- the exact evidence digest and package candidate fingerprint;
- no transport override;
- a current engine `check` result of `OK`.

The real-root gate also requires `framework-desktop`, root, and both `buzz-agent@mempool.service` and `buzz-agent@genesis.service` to report exactly `inactive` and `disabled`. It checks each identity-local HOME state directory for exact owner, mode, and service-user read/write/search access, then resolves the root-owned `codex-acp`, Codex, and Node paths as each service identity. It does not read EnvironmentFiles or credentials. Private receipt, evidence, and state files must belong to the authenticated sudo invoker. Direct-root operation requires root-owned artifacts. Malformed or forged `SUDO_UID` metadata fails closed. Every target must be `add`, `replace`, or `current`, with `writes=0`.

Parent symlinks are allowed only when the link owner is trusted, the resolved directory remains inside the install root and below the same already-validated parent tree, and the normal owner and non-writable-directory checks pass. Broken, escaping, cross-tree, writable, or wrong-owner links remain blocked.

The staged sweep candidate has separate read-only modes. They need later approval to use Victor's sanctioned owner credential for relay reads. Mempool and Genesis remain a fixed public-key roster. The script derives its 25 candidates and one exclusion from the policy-bound package. It rechecks the exclusion immediately before reconciliation and blocks on visibility, archive, Victor-role, Codex-R, or candidate-presence drift. Generic mutable skips apply only to the legacy sweep and cannot suppress Mempool/Genesis checks. The excluded or unknown channel is never planned or written. The script skips Rachel/Archimedes private channels, enforces member role and exact owner authority for candidate writes, and never reads either managed agent's private key.

```sh
"$PACKAGE_WT/candidate-final/ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep" --check
"$PACKAGE_WT/candidate-final/ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep" --dry-run
```

The staged sweep candidate defaults to `--check`, and its service unit also passes `--check`.

The service's `[Install]` section makes it enableable under the user manager's `default.target`. Enabling is a separate live service mutation that requires its own Victor or Rachel approval; package installation or approval for one manual `--check` does not authorize it. Once enabled, the user manager runs the read-only `--check` once when `default.target` is reached for each user-manager start, and every such run loads Victor's sanctioned owner credential for relay reads. With `loginctl enable-linger`, the user manager starts at boot and can run the check without an interactive login. Additional concurrent sessions do not restart the same user manager or retrigger the unit. A user manager has no `network-online.target` readiness guarantee, so a linger boot run can occur before the relay is reachable. The check then fails closed with a nonzero exit and never prints `PREFLIGHT OK`. The oneshot does not retry automatically; any retry mechanism would repeatedly load the owner credential and requires a separately designed and explicitly approved contract. None is included here. The installer deliberately does not enable the unit, so it remains disabled until that standing automatic credential-use contract is separately approved.

The former combined mutation mode is rejected. An approved activation must use an owner-only transaction directory and the selective `--mempool-apply STATE`, `--mempool-complete STATE GATE`, `--genesis-apply STATE`, and `--genesis-complete STATE GATE` sequence. Genesis phase entry is impossible until the Mempool gate receipt binds the same source/package and reports passing config, credential, membership, and parity gates for the reviewed channel-set digest. The default full sweep performs only the Mempool/Genesis read check; it cannot mutate either managed identity.

## Install and rollback

Installation is outside this lane. It needs separate Victor or Rachel approval after terminal Tier 2 closure and real-host read-only checks.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" install \
  --bundle "$PACKAGE_DIR" \
  --receipt "$PREFLIGHT_RECEIPT" \
  --tier2-evidence "$TIER2_EVIDENCE" \
  --tier2-state "$TIER2_STATE_FILE"
```

The installer derives `/etc/buzz-agents/review-closure.json` from the validated Tier 2 state. It never accepts a caller-authored installed closure. The installed `buzz-agent-review-closure-v2` record binds the lineage, state, evidence, verdict, runtime files, package digest, and frozen candidate fingerprint. The package-installed `verify-installed-agent` prestart gate validates that same v2 contract before either service can start. Systemd's `+` prefix elevates only this prestart verifier so it can hash the root-only enrollment map and sudoers file; `ExecStart` still runs as `User=buzz-%i` with no privilege prefix.

The installer backs up every changed target, uses same-directory temporary files with `fsync` and `os.replace`, installs the derived closure last, verifies final state, and restores applied targets on failure. An exact second run returns `ALREADY_INSTALLED writes=0` without another backup.

The successful install output contains one backup ID. Roll back only while `buzz-agent@mempool.service`, `buzz-agent@genesis.service`, and the user unit `buzz-sats-channel-sweep.service` all remain stopped and disabled. Source can be frozen now, but the dynamic package and live-authority receipt remain blocked until Desktop supplies the two real Mempool/Genesis identities and the relay observation can bind them. This source does not claim that receipt exists.

```sh
sudo /usr/bin/python3 "$ACT/install-activation-bundle.py" rollback \
  --backup-id FULL_BACKUP_ID
```

Backups and install receipts live under `/var/lib/buzz-mgact-backups/` as mode-`0700` state. The install lock is `/run/lock/buzz-mgact-install.lock`. Rollback refuses digest, owner, mode, hard-link, symlink, or content drift.

Credential handoff and membership activation are covered by the separate `mempool-genesis-activation-transaction` state. `prepare` first verifies the persisted sealed parity envelope and writes canonical manifest/receipt copies under `/var/lib/buzz-agent-activation/current`; that exact directory is consumed by prestart. It records whether each credential was absent or present and stores any bytes only in owner-only backup files. The JSON receipt contains path classes, metadata, length, and a 12-character SHA-256 prefix, never a key value or full key digest. Membership intent is journaled before each relay write and confirmed only after readback. `begin-rollback` validates all credential post-state before atomically consuming its one-use claim; selective rollback then removes only confirmed `member` writes whose current role has not drifted, in reverse order. Unconfirmed writes that are present, role drift, credential byte or metadata drift, a reused claim, or incomplete membership rollback blocks credential restoration. `finish-rollback` restores exact previous bytes and metadata or exact previous absence.

If an activation transaction exists, run its selective rollback before the package installer rollback. The installer refuses package rollback until the matching transaction reports `rolled_back`, its claim is consumed, every membership is reversed, and both credential records are restored. This prevents removing the reviewed runtime while a credential or relay write remains live.

## Parent integration order

1. Read back and test `scripts/mempool-genesis/activation/**` plus `scripts/mempool-genesis/verify-installed-agent`. Leave the disabled intermediate candidate at Tier 1.
2. Freeze the exact code candidate. Run Tier 2 and merge only after terminal accepted closure.
3. Wait for Desktop to return the two public keys while both identities remain stopped. Put only those public values in `inputs.json`.
4. Generate `candidate-final`. Generate the Tier 1 receipt and current Tier 2 evidence.
5. Complete parent Tier 1 readback. Run `tier2 prepare`, `review`, and `check` on the exact dynamic package.
6. Run installer `check` and `dry-run` on the real host before the closure expires. Run sweep `--check` and `--dry-run` only with separate approval to use the live owner credential.
7. Seek separate approval for credential handoff, installation, and activation. Preserve the printed backup ID if installation is approved.
