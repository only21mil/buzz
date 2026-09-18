# Known holds

A hold is a named fact that blocks release or qualification until it clears.
Each row has an owner and a next step. Silence never clears a hold.

## Release holds

| Hold | Owner | Next step |
| --- | --- | --- |
| No confirmed iOS device, TestFlight entitlement, or account access in scope | device lead, Victor | arrange access or record a scoped hold, never assume a family device |
| No kickoff readback of Apple signing, notarization, or TestFlight routes | release lead | inspect routes at kickoff without touching secrets |
| No kickoff readback of Android signer custody or installed identities | release lead | confirm adopted signer under the authorized workflow |
| Physical Fold acceptance missing | device lead, Victor | run install, upgrade, recovery, and daily use on the Fold |
| Mac helper and login state, reviewer quota caps from Sep 6 still on record | device lead | resume only required acceptance with a runnable environment and authorization |
| Victor closed the Mac release chase | Victor | no Mac release work restarts without his word |
| Conditional Databricks flow held | integration lead | keep held, consider only the bounded OAuth reader where fork auth uses it |
| Stale upstream image pin reported against deployed relay | release lead | verify and correct deployment inputs under separate production authorization |

## Qualification holds

| Hold | Owner | Next step |
| --- | --- | --- |
| Overall check verdict HOLD for all-checks-pass or full-functionality claims | test lead | BC-1, BC-3 dispositions with service-backed evidence |
| Eight source defects from Sep 11 still at audited HEAD (RB-3/4/5, MW-3/4/5, D1/D2) | relay/client leads | P02 and P06 fixes with regression tests |
| Admin-web runs zero tests with --passWithNoTests | admin lead | real role and protocol tests in P04 |
| GitHub required-contexts policy unverified after rate-limited ruleset read | delivery lead | verify actual canonical and GitHub rules in P09 |
| Native control/runner inactive in host read, no Mac job, landing unenforced | delivery lead | per-stage matrix, keep native completion separate (N01) |
| Six empty placeholder sidecars stand in for mandatory Tauri binaries | platform owners | real target binaries with size, arch, hash, and launch proof |
| Upstream ancestry absent from main | integration lead | P08 reconciliation with ancestor assertion |

## Standing product holds

These stay until Victor changes them: GIF provider, Bestie, conditional
Databricks, browser team mutation, community deletion, obsolete NIP-FI, unused
IFC, Google-dependent segmentation, closed hosted-browser PR108 recovery.
Deferred database candidates 0ccf934b, b3baa56b, and 24ec6a46 wait for their
own compatibility review. None of these is a silent exclusion; each keeps its
ledger row and revisit trigger.
