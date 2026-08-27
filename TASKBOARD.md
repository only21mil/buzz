# Buzz CI migration task board

Generated from `BUZZ_CI_FULL_MIGRATION_STATUS.yaml` at `2026-08-27T15:09:59Z`.

## Routing state

`FROZEN_OWNER_STOP`. The migration remains frozen except for scoped repository delivery, standing CI repair and rerun authority, active web-app parity, completed reviewed Tier 2 fleet install, inventory-only roster planning, and the tracked Simplelift overlap remediation wave below. The program has no plan-level 90-minute stop; authorized work continues until done. Merge, additional install, roster mutation, deployment, activation, service, and canon gates remain closed unless their separate authority is recorded.

| Truth | Value | Evidence |
|---|---|---|
| Authoritative main | `148cad107f22f0b73aab23e559406beafaf57e64` | framework-desktop:/home/victor/work/buzz-relay refs/remotes/buzz/main |
| Last proven deployed source | `6ac00a946e06e3786491f2b213d35520c89d94e8` | framework-desktop:/home/victor/Obsidian/Victor/Agent-Shared/decisions-log.md#2026-08-26-mempool-and-genesis-live |
| Production migration | `34` | source-bound deployment receipt |
| Mempool and Genesis | `INACTIVE` | Mempool and Genesis are inactive and disabled after failed activation. Older active claims are superseded. |

## Qualified legacy aliases

| Alias | Stable work ID |
|---|---|
| `P0-RELAY/B1` | `BCI-P0-RELAY-01` |
| `P1-EXEC/B1` | `BCI-P1-EXEC-01` |

## Source-only execution checkpoint

These candidates are frozen and locally checked. No downstream authority is implied.

| Stable work ID | Source candidate | Verified scope | Includes |
|---|---|---|---|
| `BCI-REVIEW-ENGINE-01` | `e7023d766b09edca854130c810d2e000a3396174` | `VERIFIED_SOURCE_ONLY` | Portable 5400-second Tier 2 engine candidate |
| `BCI-REVIEW-C1-RECOVERY-01` | `c9229b6e7202c22ea5bd4f99161aedef5bc68f1f` | `VERIFIED_SOURCE_ONLY` | Exact C1 exhausted-transport recovery candidate |
| `BCI-MGACT-01` | `92b1639b99cc2ea5d1c35c569a44fe8c964f528a` | `VERIFIED_SOURCE_ONLY` | Integrated persistence and rollback source candidate |
| `BCI-GOV-LANDING-FACADE-01` | `be50713557bdedb7fce94967116c6ef054e500b2` | `VERIFIED_SOURCE_ONLY` | Current-schema landing facade candidate |
| `BCI-BUZZ-CUMULATIVE-01` | `d7677e177b9e3732bf92962e00b5d7ba161ce03c` | `VERIFIED_SOURCE_ONLY` | Cumulative Buzz source integrating relay, normal execution composition, control and runner, deploy hardening, and normal qualification |

## Downstream delivery states

| Gate | State | Approval required |
|---|---|---|
| `tier2_review` | `NOT_STARTED` | `yes` |
| `install` | `NOT_STARTED` | `yes` |
| `push` | `COMPLETE` | `yes` |
| `pr` | `DRAFT_OPEN` | `yes` |
| `ci` | `RUNNING` | `yes` |
| `merge` | `NOT_STARTED` | `yes` |
| `credentials_and_signing` | `NOT_STARTED` | `yes` |
| `docker_sudo_services` | `NOT_STARTED` | `yes` |
| `deployment` | `NOT_STARTED` | `yes` |
| `mgact_activation` | `NOT_STARTED` | `yes` |
| `live_parity` | `NOT_STARTED` | `yes` |

## Repository delivery tracking

| Record | Status | Exact target |
|---|---|---|
| Relay feature ref | `PUBLISHED` | `https://framework-desktop.tail69757d.ts.net:38443/git/73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812/buzz#refs/heads/sats/bci-p1-cumulative-successor-20260827` at `d7677e177b9e3732bf92962e00b5d7ba161ce03c` |
| GitHub mirror ref | `MIRRORED` | [sats/bci-p1-cumulative-successor-20260827](https://github.com/only21mil/buzz/tree/sats/bci-p1-cumulative-successor-20260827) at `d7677e177b9e3732bf92962e00b5d7ba161ce03c` |
| Buzz issue | `OPEN` | `buzz://issue?id=d3276e465093a35318ffda37f06346caa1ecf5412509ba2d5d33d9e7402648e2&owner=73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812&d=buzz` |
| Buzz PR | `DRAFT` | `buzz://pr?id=5e556209c04dd6bb6d9704a7f009710507290f7b66998e05f7fdf832aa3c6569&owner=73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812&d=buzz` |
| GitHub PR #107 | `DRAFT / PR_CHECKS_COMPLETE` | [PR #107](https://github.com/only21mil/buzz/pull/107) at `d7677e177b9e3732bf92962e00b5d7ba161ce03c` |
| Web relay feature ref | `PUBLISHED` | `https://framework-desktop.tail69757d.ts.net:38443/git/73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812/buzz#refs/heads/sats/web-app-parity-20260827` at `e627ff05edc57990982687669e3e47326857d1ab` |
| Web GitHub mirror ref | `MIRRORED` | [sats/web-app-parity-20260827](https://github.com/only21mil/buzz/tree/sats/web-app-parity-20260827) at `e627ff05edc57990982687669e3e47326857d1ab` |
| Web Buzz PR | `DRAFT` | `buzz://pr?id=3937c0aba0fddd58e954408e0e4eb8f74b9067de6d905e9b136adc085caf007f&owner=73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812&d=buzz` |
| GitHub PR #108 | `DRAFT / PR_CHECKS_COMPLETE` | [PR #108](https://github.com/only21mil/buzz/pull/108) at `e627ff05edc57990982687669e3e47326857d1ab` on base `d7677e177b9e3732bf92962e00b5d7ba161ce03c` |

## Active roster migration inventory

`ACTIVE` inventory. Live changes are `NOT_APPLIED`.

| Current label | Planned label | Planned model/profile |
|---|---|---|
| `DSV4F` | `Knots` | `qwen/qwen3.8-flash` |
| `GSV4F.2` | `Segwit` | `z-ai/glm-5.3-flash` |
| `GLM5.2` | `Ledger` | `z-ai/glm-5.3-flash` |
| `Codex-2` | `UTXO` | `preserve current model and reasoning` |
| `Sat Hermes` | `REMOVE` | tombstone plus service, configuration, and membership cleanup; rollback receipt required |

## Tier 2 fleet installation

| Receipt | Value |
|---|---|
| Reviewed commit | `4efbf03a5220b40984e339d88b649220bd235cd7` |
| Reviewed tree | `4e1a8d5859ad353225fa05f218b2f0d1950c56e9` |
| State / lineage | `c9555d146e210724ce5992722d243888` / `d98c842a7c14bf75d942251873cc8149` |
| Verdict / commit check | `PASS_WITH_RISKS` / `OK` |
| Fleet install | `7` byte/mode/owner-identical paths on Framework and Yoga |
| Live canaries | `5/5 PASS` |
| C1 reopen | `COMPLETE` |

## C1 recovery review

| Receipt | Value |
|---|---|
| Source candidate | `c9229b6e7202c22ea5bd4f99161aedef5bc68f1f` |
| Reviewed correction | `5ac44f9ff2d16d61f562e4de16f012ae0be9fd47` / tree `58630357d1fc0040b42d9e849b2f1bd2d43932a6` |
| Reviewer / verdict | `claude:6502c19de9be662396c3b1cf46858d6e` / `PASS` |
| Findings | `0` |
| Exact commit check | `OK` at `5ac44f9ff2d16d61f562e4de16f012ae0be9fd47` |
| Closure state | `COMPLETE` |

The earlier correction `afe030a4b66b21bb8d3458acc32c29228316a733` remains recorded as a superseded `PASS_WITH_RISKS` attempt whose exact commit check failed the sole-parent requirement.

## Standing CI authorization

`ACTIVE` for GitHub Actions CI and Buzz-native CI across the current Buzz plan. On failure, agents may diagnose, fix, record each new exact SHA and result, and rerun until green; there is no CI attempt limit.

This authority does not change Tier 2 independent-review transport retry law or grant merge, deployment, activation, credential, signing, service, or destructive authority.

## Program timing authorization

`ACTIVE`. The plan-level 90-minute stop is `REMOVED`; authorized work, CI fixes and reruns, audits, and delivery continue until `DONE`.

Each individual Tier 2 state still obeys the installed controller deadline and freshness invariant. An expired state is rerun as a fresh exact-candidate state and stale acceptance is forbidden.

## Simplelift overlap remediation

`ACTIVE / PLANNING_AND_TRACKING_ONLY`. Simplelift is the app and repository; Framework is the host. This wave made no source or live mutation.

| Audit fact | Current truth |
|---|---|
| Simplelift checkout | `/home/victor/projects`; main `CLEAN` |
| Simplelift dev / PR #24 | `bbae6a383727325e83b7480e7c8cbb323de2be20`; `CLOSED / NOT_MERGED / BRANCH_PRESERVED` |
| Overlap | `101` Buzz files plus LUKS header, rescue bundle, and broken budget gitlink |
| Live dependency | `9` Buzz seats and desktop launcher depend on the checkout |
| Roster commits | `WRONG_REPOSITORY / UNPUBLISHED` |
| Buzz draft PRs | `#107 CLEAN / #108 CLEAN` |
| Desktop / sweep / directory | `STALE_PIN / FAILED_UNBOUND / FAILED_UNBOUND` |
| Deploy checkouts | `DUPLICATE_AND_DIRTY`; canonical selection not started |
| Cross-scope prompts | Archimedes owner lane required |

### Ordered remediation actions

| Order | State | Action |
|---|---|---|
| `1` | `COMPLETE` | Close Simplelift PR 24 without merge and initially preserve its branch |
| `2` | `NOT_STARTED` | Finish reviewed Buzz-owned stable install roots and receipt-bound systemd and desktop cutover |
| `3` | `NOT_STARTED` | Complete all active in-scope prompts |
| `4` | `NOT_STARTED` | Execute roster model and Sat Hermes cutover with rollback receipts |
| `5` | `NOT_STARTED` | Correct MGACT policy and helper behavior |
| `6` | `NOT_STARTED` | Fix the sweep and directory sync with exact binding |
| `7` | `NOT_STARTED` | Move desktop to the current reviewed pin |
| `8` | `NOT_STARTED` | Select one canonical deploy checkout |
| `9` | `NOT_STARTED` | Preserve legitimate Simplelift dev history through 40985fbe5adb3a1aad08ca3223c744b47b8f425e |
| `10` | `NOT_STARTED` | Relocate private recovery material and complete history and security handling |
| `11` | `NOT_STARTED` | Remove contaminated refs and local branches only after readback |
| `12` | `NOT_STARTED` | Add a Simplelift repository-root CI guard |

## Active workstreams

| Stable work ID | Owner | Profile | State | Candidate |
|---|---|---|---|---|
| `BCI-WEB-PARITY-01` | `/root/web_app_parity` | `gpt-5.6-sol · high` | `READY_FOR_CI` | `e627ff05edc57990982687669e3e47326857d1ab` |

## Current candidates

Every row is non-routable while the owner stop remains in force.

| Stable work ID | Item | State | Candidate | Promotion | Review | Blockers |
|---|---|---|---|---|---|---|
| `BCI-GOV-DELIVERY-01` | Delivery lifecycle | `FROZEN` | `d24ab5b4dc6a28fe3c15dc19c9dfea0f47e35e1b` | `UNKNOWN` | `UNKNOWN` | Rebase onto current main; exact-head CI; fresh Tier 2; landing |
| `BCI-P0-RELAY-A1` | Relay proxy recovery | `FROZEN` | `433e6d2e64108811df1dd33b642ec224556b530d` | `UNKNOWN` | `UNKNOWN` | Current-main integration and delivery gates |
| `BCI-P0-RELAY-01` | Relay preflight | `FROZEN` | `3b7f068dc41a2f453a958cd94ce49f1dd64d3334` | `UNKNOWN` | `UNKNOWN` | Re-integrate onto current main |
| `BCI-P0-RELAY-A4` | Relay preflight policy fix | `FROZEN` | `23a7de9967065d3fdeabf2b0786d7ca06b60b9e2` | `UNKNOWN` | `UNKNOWN` | Compile and targeted tests; live 503 and 200 proof; integration with relay preflight |
| `BCI-P0-RELAY-A5` | CI logs route | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | Owner-session readback required |
| `BCI-P0-RELAY-A6` | Run request and immutable ref route | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | Owner-session readback required |
| `BCI-P1-EXEC-01` | Git host observer | `FROZEN` | `064fb242d801dad63c3fe094420995396061d5be` | `UNKNOWN` | `UNKNOWN` | Fresh pre-freeze; exact-head CI; review; integration |
| `BCI-P1-EXEC-B2` | Cleanup proof producer | `FROZEN` | `ba72e9c96874a8b08803de15f78087de5eca6a2b` | `UNKNOWN` | `UNKNOWN` | Determine current integrated coverage |
| `BCI-P1-EXEC-B3` | Job source installer | `FROZEN` | `da9ece0d9c999fa2171cda13565e8b71be498cc0` | `UNKNOWN` | `UNKNOWN` | Renderer and install integration; review |
| `BCI-P1-EXEC-B4` | Transient process handoff | `FROZEN` | `7acb7e4f7e64abd3d08b17008f2aea3a9b25e96c` | `UNKNOWN` | `UNKNOWN` | Same-lineage terminal review; integration |
| `BCI-P1-EXEC-B5` | Normal qualification backend | `FROZEN` | `2d7688bd5571294cb9d90de00685acff2ce63318` | `UNKNOWN` | `UNKNOWN` | Production adapter implementation |
| `BCI-P1-EXEC-B6` | Normal execution composition | `SUPERSEDED` | `111e34cf476206cc280b72151d05b954cf155de8` | `UNKNOWN` | `UNKNOWN` | Withdrawn because it embeds pre-revision-2 archive mediation; unresolved seams; replacement required |
| `BCI-P1-HARD-C1` | Archive mediator | `BLOCKED` | `afe030a4b66b21bb8d3458acc32c29228316a733` | `UNKNOWN` | `UNKNOWN` | Exact revision-2 review state exhausted transport; no verdict or check; audited recovery required |
| `BCI-P1-HARD-C2` | Exec hijack mediator | `FROZEN` | `2c4386f8ffa533424b40c66c4338da44d2a99d61` | `UNKNOWN` | `REVIEW_CLOSED` | Integrate with accepted archive mediator into replacement normal execution composition |
| `BCI-P1-HARD-C3` | Control daemon contract | `FROZEN` | `8eff0c7343470ad1a9ab03e6cae1ea511ca58352` | `UNKNOWN` | `REVIEW_CLOSED` | Delivery-bundled into runner promotion; no standalone route |
| `BCI-P1-HARD-C4` | Runner integration and promotion | `FROZEN` | `0ace191c25e4b5680779f95965910712eee1dec1` | `88734811828458a10752c9179724cd2e0542aee1` | `UNKNOWN` | Current-schema helper repair; exact-head CI; fresh review; exact promotion |
| `BCI-P1-HARD-C5` | Production ready proof | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | CONTRADICTED candidate evidence: 81fc41a97790b3dcd31799f8cdbde4996070cc1b, 7d657e9c9850321c250c268d40c095662966baff, e13354dcf735a3204743f2347d06a1e414a4bae6; Candidate identity contradiction requires owner reconciliation; explicit no-push override; dependency integration |
| `BCI-P1-HARD-C6` | Shared workflow schema | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | CONTRADICTED candidate evidence: 0a6d9541ba3aee1771442b93c7ef57e64fa0135f, 0e5b6ece65d416fde64c14acdd0750c66ce16148; Candidate identity contradiction; current authorized review closure absent; integration and exact-head CI required |
| `BCI-REVIEW-ENGINE-01` | Portable 5400-second Tier 2 engine | `REVIEW_CLOSED` | `e7023d766b09edca854130c810d2e000a3396174` | `4efbf03a5220b40984e339d88b649220bd235cd7` | `REVIEW_CLOSED` | Cumulative and web candidates need their own exact-head Tier 2 reviews |
| `BCI-REVIEW-C1-RECOVERY-01` | C1 exhausted-transport recovery tool | `REVIEW_CLOSED` | `c9229b6e7202c22ea5bd4f99161aedef5bc68f1f` | `5ac44f9ff2d16d61f562e4de16f012ae0be9fd47` | `REVIEW_CLOSED` | None recorded |
| `BCI-GOV-LANDING-FACADE-01` | Current-schema landing facade | `FROZEN` | `be50713557bdedb7fce94967116c6ef054e500b2` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; helper ownership decision; host installation and exact-head use |
| `BCI-BUZZ-CUMULATIVE-01` | Cumulative Buzz integration | `FROZEN` | `d7677e177b9e3732bf92962e00b5d7ba161ce03c` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; exact-head CI authority; push and PR authority; merge authority; production configuration and host acceptance |
| `BCI-ECONOMICS-01` | CI economics rebase | `FROZEN` | `99dc03cd123708d9bcd6468f595a15a30a9b1fdf` | `UNKNOWN` | `UNKNOWN` | Exact-head CI; current review and promotion receipt |
| `BCI-BUDGET-R3-01` | MasonsBudget native CI promotion | `FROZEN` | `ca670fde8399eadb21e3aa9e1a385e0a8b776f4a` | `UNKNOWN` | `UNKNOWN` | MasonsBudget authority; nine CI contexts; fresh review |
| `BCI-PARITY-01` | Native CI parity promotion | `FROZEN` | `02f24e7af165a414cb2fb09821ed44b5fe6760bf` | `UNKNOWN` | `UNKNOWN` | PR and CI; source landing only; no activation authority |
| `BCI-MGACT-01` | Mempool and Genesis repair integration | `FROZEN` | `92b1639b99cc2ea5d1c35c569a44fe8c964f528a` | `UNKNOWN` | `NOT_STARTED` | Inactive and uninstalled; Tier 2 review approval; real-host preflight; credentials and signing approval; fresh package and v3 receipt; install and activation authority; live parity |
| `BCI-WEB-PARITY-01` | Browser and web-app native parity | `READY_FOR_CI` | `e627ff05edc57990982687669e3e47326857d1ab` | `UNKNOWN` | `NOT_STARTED` | Exact-head CI running; Tier 2 not started; installed browser and live relay checks pending; physical device and full accessibility review pending; packaging and deployment pending; do not mark complete |
| `BCI-ROSTER-MIGRATION-01` | Authorized roster rename and retirement inventory | `FROZEN` | `UNKNOWN` | `UNKNOWN` | `NOT_STARTED` | Inventory active but live changes not applied; exact pre-change inventory pending; service and membership mutation receipts pending; rollback receipt required |

## Evidence precedence

1. Current owner events and reconciled live Buzz readback.
2. Authoritative refs, source-bound deployment receipts, and immutable Tier 2 states.
3. Direct clean-worktree and artifact readback.
4. Lane STATUS.md evidence.
5. Reconciled recovery plan and this generated task board.

A lower-precedence source cannot override a higher one. Unresolved contradictions remain `UNKNOWN`.

Regenerate and check with `python3 tools/status_ledger.py check`.
