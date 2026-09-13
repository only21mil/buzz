# Upstream sync baseline

Read-only inventory for the fork-to-upstream reconciliation. Written 2026-09-13
by the P00 worker. Nothing here changes code, merges branches, or approves a
release. It only records where things stand so later packages can work from one
shared page.

Authority is the two archived reports in the project store: the product
completion plan and the fork/upstream audit, both dated 2026-09-13. Where this
ledger disagrees with older reports, the audit synthesis wins. Older reports
stay linked as background, not as instructions.

## Pinned refs

| Role | Short | Full SHA |
| --- | --- | --- |
| Fork HEAD (audited source) | 1e05fce2 | 1e05fce27c658bf09a2c45fbebd1d8388d33bb15 |
| Adoption snapshot | 3c7f288c | 3c7f288c60d67df78577b237e27c3dfc8831aaa1 |
| Upstream target | 4cd82f51 | 4cd82f513214aad11c2b742ce7cc7c681e8e32a0 |
| Common ancestor | 5bf78671 | 5bf78671f45178f8de02ba18d3d321cbbf19cd1f |

See pinned-refs.md for what each pin means and which ones resolve in this
checkout. See current-state-matrix.md for why source, upstream, and deployed identity
are three separate columns that must never be merged into one.

## Files

P00 writes markdown only. P00b (PR #227) writes the two JSON ledgers. The
split is deliberate so P08 merges both branches with no filename conflicts.

- current-state-matrix.md. Source vs upstream vs deployed matrix. No guessed green cells.
- pinned-refs.md. The four pins, full SHAs, verification commands.
- adoption-ledger.md. Human index over all 86 finding IDs, port-order notes,
  and cross-references into the JSON ledgers. It duplicates no JSON row.
- upstream-dispositions.json (P00b). All 29 post-snapshot commits.
- finding-dispositions.json (P00b). 28 key pre-snapshot gaps.
- ci-checks.md. Required CI checks as observed at the fork tip, with the
  ruleset caveat spelled out.
- release-identity.md. Release identity and version routes per platform.
- known-holds.md. Holds that block release or qualification, with owners.
- ignored-tests.md. Ignored and skipped tests from the recovered check run,
  mapped to what must still prove each behavior.

## Rules for later packages

P03 owns schema. P07 owns dependency configuration. P04 owns the shared
admin bootstrap and roster file. P02 owns the shared relay side-effects
caller. P08 owns the integration worktree after P02-P07 freeze, and nobody
else writes there. Sync landings keep real upstream parents and stay
unsquashed. Applied migrations are never renumbered or rewritten.
