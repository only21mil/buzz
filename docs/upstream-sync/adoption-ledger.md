# Adoption ledger skeleton

Every pre-snapshot adoption claim and every post-snapshot upstream commit gets
exactly one disposition here before P08. Status starts at open on all rows.
A row closes only with a fork landing SHA plus test evidence, or an explicit
accepted absence with a revisit trigger. Deferred rows stay discoverable after
any ancestry change.

Severity follows the audit synthesis, which already corrected several
inherited ratings. Evidence letters: V means checked against source or git
during synthesis, R means inherited read-only audit, H means dated host or
historical evidence. An inferred runtime effect is not a test result.

## Findings, strategy and process

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| MS-1 | high | re-authored adoption left ancestor at 5bf78671, snapshot not an ancestor | open | integration lead | V |
| MS-2 | high | migrations 0029-0042 collide numerically across branches | open | DB lead | V |
| MS-3 | medium | 186 add/add conflicts need ancestry plus content work together | open | integration lead | V/R |
| MS-4 | medium | lockfiles, manifests, scripts, aliases drift | open | dependency lead | R |
| MS-5 | medium | upstream reusable CI files differ from fork monolith | open | delivery lead | R |
| MS-6 | high | squash guidance conflicts with ancestry preservation | open | integration lead | R/V |
| MS-7 | medium | no sync ledger or ownership manifest, rerere unset | open | integration lead | R |
| MS-8 | low | ten conflict messages stored where paths belonged, cleaned | open | integration lead | V |
| MS-9 | medium | buzz-db layout differs, 18 upstream renames, align only where it pays | open | integration lead | V/R |
| UD-10 | high | plan claims adopt/adapt where records say deferred or missing | open | integration lead | V/R |
| UD-11 | low | MinIO images float or skip digests in compose and chart files | open | dependency lead | R |
| UD-8 | medium | optional mesh 0.74.0 vs 0.76.0-rc9, adopt coherently or defer named | open | dependency lead | R |
| UD-7 | medium | fork nostr git pin 94dac28e vs upstream registry versions | open | dependency lead | R |
| D4 | high | folded into MS-1 ancestry row, kept traceable here | open | integration lead | R |
| D7 | medium | folded into MS-7 ledger row, kept traceable here | open | integration lead | R |
| MW-1 | high | folded into MS-1 ancestry row, kept traceable here | open | integration lead | R |
| MW-9 | medium | folded into MS-7 ledger row, kept traceable here | open | integration lead | R |
| H1 | high | folded into MS-1 ancestry row, kept traceable here | open | integration lead | H |
| H2 | high | folded into MS-1 ancestry row, kept traceable here | open | integration lead | H |
| H3 | high | Aug 20-Sep 5 work favored native CI tooling over app integration | open | integration lead | H |
| H4 | high | Sep 5 accepted language conflicts with Sep 10/11 partial-execution record | open | integration lead | H |
| M1 | medium | 171 worktree entries, unmerged heads, keep unique work before cleanup | open | integration lead | H |
| M2 | medium | cleanup broke a mirror-consumed path, canon says repaired Sep 13 | open | delivery lead | H |
| M3 | medium | Sep 6 acceptance lacked devices, Mac chase closed by Victor | open | device lead | H |
| M4 | medium | superseded PRs and freeze checkouts repeated candidate work | open | integration lead | H |
| M5 | medium | Sep 11 B1-B3/C1-C5 defects remain at audited HEAD | open | relay/client leads | V/H |
| M6 | medium | PR #169 receipt hit REST diff limits, current route takes merge parents | open | delivery lead | V/H |
| M7 | high | deployed 8f1911c6/migration 42 vs main 1e05fce2, stale image pin | open | release lead | H |
| L1 | low | repeated closures bury current state, keep one dated index | open | integration lead | H |
| L2 | low | PR #221 on old native-admission state, revisit only if native resumes | open | delivery lead | H |
| L3 | low | old handoffs point at moved paths and paused lanes | open | integration lead | H |

## Findings, backend

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| RB-1 | high | folded into MS-2 migration row, kept traceable here | open | DB lead | V |
| RB-2 | medium | buzz-db flat modules vs upstream store/runtime layout | open | integration lead | V/R |
| RB-3 | medium | HTTP /query and /count skip the WebSocket count limit | open | relay lead | V |
| RB-4 | medium | COUNT sums overlapping filters, no request-wide dedup | open | relay lead | V |
| RB-5 | medium | workflow webhooks send headers/body without requiring HTTPS | open | relay lead | V |
| RB-6 | medium | admin host/origin gate lacks upstream per-operator roles | open | admin lead | V/R |
| RB-7 | medium | presence Redis failures discarded, then continues | open | relay lead | V |
| RB-8 | low | workflow SendDm and SetChannelTopic accepted, return NotImplemented | open | relay lead | V |
| RB-9 | low | migration tests pin count 42 and positions, stale comment in 0040 file | open | DB lead | V/R |
| RB-10 | low | re-authored security/SDK/push hunks recur as text disputes | open | integration lead | R |
| RB-11 | low | read-only CI preflight skips the replay check used elsewhere | open | relay lead | V |
| UD-1 | high | get_members LIMIT 1000, upstream #5765 marked adopted but missing | open | DB lead | V |
| UD-4 | medium | present payload tag without hash skips body-hash check | open | relay lead | V |
| UD-5 | medium | same presence failure as RB-7, from the delta report | open | relay lead | V |
| UD-6 | medium | folded into RB-6 admin roles row, kept traceable here | open | admin lead | V/R |
| UD-12 | low | agent base prompt omits shipped CLI commands | open | client lead | R |
| UD-13 | low | inline NIP-29 auth instead of upstream channel_authz.rs | open | relay lead | R |
| MW-10 | medium | folded into RB-6 admin roles row, kept traceable here | open | admin lead | V/R |

## Findings, desktop

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| D1 | medium | desktop repo sync ignores fetch failure, compares stale refs | open | client lead | V |
| D2 | medium | browser git refresh swallows fetch errors as success (with web) | open | client lead | V |
| D3 | high | fork e2e has 1199 test patterns vs 1609 upstream, specs shorter | open | test lead | R |
| D5 | medium | main window stays transparent, upstream opacity fix unmeasured here | open | client lead | V |
| UD-3 | high | codex-acp floor 1.1.7 vs required 1.10.0 for Astra | open | client lead | V |
| D6 | medium | web PAL manifest must account for new renderer commands, gate stays shut | open | client lead | R |
| D8 | low | idle-quiescence perf lacks script and CI invocation | open | client lead | R |
| D9 | low | matching basenames across browser/shared, distinct roles, no fix | open | client lead | R |
| D10 | low | two onboarding tests still test.fixme | open | test lead | R |
| UD-9 | medium | persona, native relay, model-manifest, login-shell, link-preview foundations missing | open | client lead | R |

## Findings, mobile and web

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| MW-2 | high | raw merge inserts duplicate image keys and ML Kit into pubspec | open | mobile lead | V |
| MW-3 | medium | media signing drops scheme and ports before comparing authorities | open | mobile lead | V |
| MW-4 | medium | web repo refs accept all event authors, relay key unused | open | client lead | V |
| MW-5 | medium | Nostr close-before-EOSE resolves partial events as success | open | client lead | V |
| MW-6 | medium | web CI skips unit and e2e tests, admin-web check not invoked | open | delivery lead | V/R |
| MW-7 | medium | device auth needs FragmentActivity against fork MainActivity callbacks | open | mobile lead | R |
| MW-8 | low | iOS bundle and team settings collide with Block identities | open | mobile lead | R |
| UD-2 | high | identity export lacks fresh device auth, upstream #5116 unported | open | mobile lead | V |

## Findings, CI and delivery

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| CD-1 | medium | capture/reuse steps repeated through monolithic ci.yml | open | delivery lead | R |
| CD-2 | high if split adopted | receipt selects bare job names, reusable caller naming can pick a proofless checker | open | delivery lead | V |
| CD-3 | high if native split enabled | gate and materializer resolve one workflow blob, called workflows escape digest | open | delivery lead | R |
| CD-4 | high on careless merge | desktop verifier binds versions, fork 0.5.20 vs upstream 0.5.23 | open | release lead | V |
| CD-5 | medium | moving main invalidates base-bound receipts, coordinate a short window | open | delivery lead | R |
| CD-6 | medium | contract scripts assume ci.yml formatting and blocks | open | delivery lead | R |
| CD-7 | low | fork recipes and hooks edit shared Justfile and lefthook.yml | open | delivery lead | R |
| CD-8 | high | mirror force-prunes heads and tags from relay to GitHub | open | delivery lead | H |
| CD-9 | medium | native control/runner inactive in host read, canary does not prove acceptance | open | delivery lead | H |
| CD-10 | low | fleet payloads and old basis scripts carry host paths | open | delivery lead | R |
| CD-11 | low | eight upstream script deletions recur, record keep-deleted reasons | open | delivery lead | R |
| CD-12 | low | branch-skew script assumes origin/main | open | delivery lead | R |
| CD-13 | info | deploy boolean parsing and entrypoint fixes exist, stale labels to correct | open | delivery lead | R |
| CD-14 | low | push CI triggers release only, changes job skips Hermit activation | open | delivery lead | R |
| CD-15 | medium | new security/staging workflows may run under fork credentials unguarded | open | delivery lead | R |

## Findings, recovered checks

| ID | Severity | One-line finding | Disposition | Owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| BC-1 | medium | root tests exit 101: six media PoolTimedOut, two admin 500-vs-404 on lazy PG pools | open | test lead | recovered logs |
| BC-2 | low | mobile analyze hit errno 24, serial retry clean | open | mobile lead | recovered logs |
| BC-3 | high as release gate | 669 root ignored plus 15 Tauri ignored, six empty sidecars, admin-web zero tests | open | test lead | recovered logs |
| BC-4 | low | cargo-deny passes with 111 warnings, Biome and chunk notes | open | dependency lead | recovered logs |

Count check: 31 strategy/process plus 18 backend plus 10 desktop plus 8
mobile/web plus 15 CI/delivery plus 4 build equals 86 IDs. Aliases from the
older B1-B3 and C1-C5 reports map onto RB-3/RB-4/RB-5 and MW-3/MW-4/MW-5/D2/D1
and stay traceable through those rows.

## Post-snapshot upstream commits

Recommendations only. No row authorizes implementation. Port order must respect
the dependency notes, especially the npub chain 18 through 23 and the help
pair 6 before 5.

| # | Upstream SHA | Subject | Decision | Disposition |
| --- | --- | --- | --- | --- |
| 1 | 4cd82f513 | Databricks reuse | keep existing conditional hold | open |
| 2 | 6c35e82bd | Pi setup hints | adapt safe copy after adapter decision | open |
| 3 | f3940ff21 | pinned MinIO images | adapt digests and compose refs | open |
| 4 | 78618804e | per-agent ACP session scope | reconcile design first | open |
| 5 | e17cdd9d5 | prompt uses help | adapt after entry 6 | open |
| 6 | 44c1cc7df | CLI help tree | adapt with fork-only groups | open |
| 7 | ec11f8e2f | avatar paths | adapt after correctness work | open |
| 8 | d07457687 | exact mobile mentions | adapt with identity binding tests | open |
| 9 | f3408fc62 | quota backoff | re-derive against fork client | open |
| 10 | 9847b0967 | login-shell probe tests | defer until foundation decision | open |
| 11 | 6146c4fd1 | default branch plus NIP-98 fix | split: land payload-tag fix early, branch ops need policy | open |
| 12 | 813bbd141 | Buzz Pi adapter | decision needed before replacing launcher | open |
| 13 | 092c6a727 | mention wrapping | adapt, keep fork mention authority | open |
| 14 | 00209076c | presence persistence | adapt early with failure tests | open |
| 15 | cec5c8fd9 | inbox truncation | adapt, keep fork badge semantics | open |
| 16 | 051c3a270 | missing model errors | explicit behavior decision, test both paths | open |
| 17 | 12023a3cb | Astra adapter minimum | adapt early with boundary tests | open |
| 18 | bfc384855 | npub foundation | adapt before entries 19-23 | open |
| 19 | 2226b6f95 | npub controls | adapt with entry 18 | open |
| 20 | ad2a84131 | npub displays | adapt with entry 18 | open |
| 21 | ad9591c43 | roster ordering | adapt after entry 18 | open |
| 22 | 82656ffea | mobile npub | adapt as identity series | open |
| 23 | 93761e411 | push npub | adapt with entry 22 | open |
| 24 | c045321a7 | ACP overflow pacing | adapt to fork structure | open |
| 25 | 218633b8f | link-preview pacing | re-derive and adapt | open |
| 26 | 44316ff72 | mesh rc9 | optional coordinated update or explicit defer | open |
| 27 | cd54e2682 | Responses routing | investigate then adapt | open |
| 28 | 86c189e85 | ACP wake and session fences | adapt, keep held-thread recovery | open |
| 29 | fa1b27bcc | mobile code styling | adapt without prohibited packages | open |

## Pre-snapshot items that stay on this ledger

These older claims need the same one-row treatment and must not fall off once
ancestry advances. Priorities first: #5765 complete rosters (UD-1), #5116
export authorization (UD-2), #3777 admin roles as a frontend/backend/database
unit (RB-6/MW-10/UD-6). Then #5599 opacity (D5) and the omitted
persona/native-relay/model foundations (UD-9) with adopt, adapt, exclude, or
defer each. Deferred database candidates 0ccf934b, b3baa56b, 24ec6a46 stay
listed until their own compatibility review closes. Standing holds keep their
disposition until Victor changes them: GIF provider, Bestie, conditional
Databricks, browser team mutation, community deletion, obsolete NIP-FI, unused
IFC, Google-dependent segmentation, closed hosted-browser PR108 recovery.

## Claims needing disposition

The audit names these as said-but-unproved. Each needs a row above to close
with evidence or an accepted-absence note:

- Pre-snapshot adoption completeness, especially e0940927f, d8281b9c9,
  86b9142a0, 24ec6a468, 5aed49b50, 70895b355.
- "428 unchanged upstream blobs means adopted", rejected as proof.
- "Cherry-pick preserves identity", rejected; use unsquashed merges, record
  cherry-picks as exceptional ports only.
- Blanket full-suite rerun claims and blanket delete recommendations, both
  rejected in favor of targeted action.
- Either unqualified "native accepted" or "never ran", both superseded by the
  per-stage status matrix in known-holds.md.
- Plaintext-settings and missing-key-dependency claims, both corrected and
  still leaving real export-auth and admin-role gaps.
