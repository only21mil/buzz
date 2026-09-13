# Current state matrix

Dated 2026-09-13. Source facts were read at fork HEAD 1e05fce2. Deployed and
upstream facts come from the audit and canon reports cited in each row. I did
not re-read production, devices, or the upstream remote, so those cells say
what the reports said and name the report.

The point of this page is one habit: source, upstream, and deployed identity
are separate claims. A green CI cell never proves what runs in production,
and a source version never proves what a device installed.

## Identity pins

| Claim | Value | Origin |
| --- | --- | --- |
| Fork HEAD (source) | 1e05fce27c658bf09a2c45fbebd1d8388d33bb15 | local checkout, verified |
| Common ancestor with upstream | 5bf78671f45178f8de02ba18d3d321cbbf19cd1f, 2026-08-08 | audit, git objects |
| Adoption snapshot | 3c7f288c60d67df78577b237e27c3dfc8831aaa1 | planning input, not an ancestor of main |
| Upstream target | 4cd82f513214aad11c2b742ce7cc7c681e8e32a0 | planning input |
| Deployed relay (canon, Sep 13) | 8f1911c6, migration 42 | canon report, not re-read here |
| Upstream commits since ancestor | 434 | audit recount |
| Fork commits since ancestor | 805, of which 271 first-parent | audit recount |
| Post-snapshot upstream backlog | 29 commits | audit ledger |
| Raw merge conflicts | 606 paths: 410 content, 186 add/add, 9 modify/delete, 1 rename/delete | audit recount |

PR #169 merge c9c541191 did not make the snapshot an ancestor of main. The
recorded snapshot check (`git merge-base --is-ancestor 3c7f288c 1e05fce2`)
returns nonzero today. That is expected before reconciliation, not a new
breakage. The re-authored September 6-7 adoption kept fork behavior but added
no upstream ancestry, which is why the ledger in adoption-ledger.md exists.

## Source vs deployed

| Area | Source at 1e05fce2 | Deployed per Sep 13 canon | Gap |
| --- | --- | --- | --- |
| Relay code | fork main | 8f1911c6 | deployed trails source, exact distance unknown |
| Schema | migrations through 0042 | migration 42 | numbers match, bytes unverified here |
| Relay image | source tree | stale upstream image pin reported | canon flags a hazard: never run an old image over newer schema, even as a test |
| Desktop | 0.5.20 | supported package per canon | kickoff must read back actual installed versions |
| Android | pubspec 0.0.0+1, last receipt 0.5.9-only21mil.rc.1 code 1000509001 | receipted install with retained signer | receipt is Sep 5, needs kickoff readback, not a next-release proposal |
| iOS | fork bundle idents, com.sats21m.buzz admission contract unresolved | no confirmed TestFlight baseline in scope | missing access becomes a named hold, never a silent scope cut |

## Upstream vs source

Upstream kept moving the same application areas the fork rewrote: relay
handlers, desktop modules, mobile identity, CI layout, migrations 0029-0042.
Fourteen migration versions collide numerically with different SQL on each
side. Three operations already exist under both numbers (fork 0036 = upstream
0031, fork 0037 = upstream 0040, fork 0038 = upstream 0043) and must execute
exactly once. None of the 29 recent upstream commits adds a migration, which
lowers the new-schema risk but changes nothing about the old collisions.

428 of the 606 conflict paths hold upstream blobs unchanged since the
snapshot. That trims review work but proves nothing about whether the fork
adopted those behaviors correctly. Clean merges still need semantic review.

## What stays separate

Source readiness, genuine native execution, packaged apps, device acceptance,
and deployed identity each get their own column in every later report. The
recovered check run (5819 passed, 8 failed, 669 ignored at root; Tauri
2853 passed, 15 ignored, with six empty placeholder sidecars) describes the
fork source only. Overall verdict: HOLD for any all-checks-pass or
full-functionality claim.
