# Buzz CI migration task board

Generated from `BUZZ_CI_FULL_MIGRATION_STATUS.yaml` at `2026-08-27T12:44:41Z`.

## Routing state

`FROZEN_OWNER_STOP`. No code, review, retry, push, PR, merge, CI trigger, service, deployment, activation, or canon work may resume without new scoped authority from Victor or Rachel.

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

## Closed downstream gates

| Gate | State | Approval required |
|---|---|---|
| `tier2_review` | `NOT_STARTED` | `yes` |
| `install` | `NOT_STARTED` | `yes` |
| `push` | `NOT_STARTED` | `yes` |
| `pr` | `NOT_STARTED` | `yes` |
| `ci` | `NOT_STARTED` | `yes` |
| `merge` | `NOT_STARTED` | `yes` |
| `credentials_and_signing` | `NOT_STARTED` | `yes` |
| `docker_sudo_services` | `NOT_STARTED` | `yes` |
| `deployment` | `NOT_STARTED` | `yes` |
| `mgact_activation` | `NOT_STARTED` | `yes` |
| `live_parity` | `NOT_STARTED` | `yes` |

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
| `BCI-REVIEW-ENGINE-01` | Portable 5400-second Tier 2 engine | `FROZEN` | `e7023d766b09edca854130c810d2e000a3396174` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; reviewed installation receipt; matching Framework and Yoga hashes |
| `BCI-REVIEW-C1-RECOVERY-01` | C1 exhausted-transport recovery tool | `FROZEN` | `c9229b6e7202c22ea5bd4f99161aedef5bc68f1f` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; reviewed tool installation; exact legacy-state recovery receipt |
| `BCI-GOV-LANDING-FACADE-01` | Current-schema landing facade | `FROZEN` | `be50713557bdedb7fce94967116c6ef054e500b2` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; helper ownership decision; host installation and exact-head use |
| `BCI-BUZZ-CUMULATIVE-01` | Cumulative Buzz integration | `FROZEN` | `d7677e177b9e3732bf92962e00b5d7ba161ce03c` | `UNKNOWN` | `NOT_STARTED` | Tier 2 review approval; exact-head CI authority; push and PR authority; merge authority; production configuration and host acceptance |
| `BCI-ECONOMICS-01` | CI economics rebase | `FROZEN` | `99dc03cd123708d9bcd6468f595a15a30a9b1fdf` | `UNKNOWN` | `UNKNOWN` | Exact-head CI; current review and promotion receipt |
| `BCI-BUDGET-R3-01` | MasonsBudget native CI promotion | `FROZEN` | `ca670fde8399eadb21e3aa9e1a385e0a8b776f4a` | `UNKNOWN` | `UNKNOWN` | MasonsBudget authority; nine CI contexts; fresh review |
| `BCI-PARITY-01` | Native CI parity promotion | `FROZEN` | `02f24e7af165a414cb2fb09821ed44b5fe6760bf` | `UNKNOWN` | `UNKNOWN` | PR and CI; source landing only; no activation authority |
| `BCI-MGACT-01` | Mempool and Genesis repair integration | `FROZEN` | `92b1639b99cc2ea5d1c35c569a44fe8c964f528a` | `UNKNOWN` | `NOT_STARTED` | Inactive and uninstalled; Tier 2 review approval; real-host preflight; credentials and signing approval; fresh package and v3 receipt; install and activation authority; live parity |

## Evidence precedence

1. Current owner events and reconciled live Buzz readback.
2. Authoritative refs, source-bound deployment receipts, and immutable Tier 2 states.
3. Direct clean-worktree and artifact readback.
4. Lane STATUS.md evidence.
5. Reconciled recovery plan and this generated task board.

A lower-precedence source cannot override a higher one. Unresolved contradictions remain `UNKNOWN`.

Regenerate and check with `python3 tools/status_ledger.py check`.
