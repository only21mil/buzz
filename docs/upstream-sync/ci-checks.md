# Required CI checks inventory

Observed at fork HEAD 1e05fce2 on 2026-09-13 by reading
.github/workflows/ci.yml. This is a file inventory, not a policy readback:
the inherited GitHub ruleset read was rate-limited, so treat the required
set as unconfirmed until P09 verifies actual branch policy. That check is
assigned, not skipped.

## Triggers

CI runs on push to the release branch, on pull requests, and on manual
dispatch. Push CI otherwise triggers release only. Protected main PRs and
manual dispatches run every required check with dependencies; path filters
still limit PRs aimed at other branches.

## Jobs in ci.yml

| Job | What it runs |
| --- | --- |
| changes | path filter gating for the rest |
| rust-lint | fmt, clippy, deny class checks |
| unit-tests | workspace unit tests |
| desktop-core | desktop checks and core suites |
| desktop-smoke-e2e | smoke browser suites |
| desktop | desktop build |
| desktop-e2e-relay | relay-backed browser suites |
| desktop-e2e-integration-shard | sharded integration suites |
| desktop-e2e-integration | integration rollup |
| backend-integration | service-backed backend suites |
| relay-e2e | relay end to end |
| web | check, build, and currently no unit or e2e gate (see MW-6) |
| mobile | format, analyze, tests |
| mobile-ios | iOS-specific pass |
| security | security review workflow |
| dead-token-guard | stale token guard |
| server-cross-compile | cross-compile proof |
| desktop-build-macos | macOS build proof |

Upstream splits this monolith into reusable _ci-*.yml files. Keep the proven
topology for the first reconciliation if it is smaller (MS-5). Adopt the split
later only with receipt-consumer compatibility proved (CD-2, CD-3).

## Receipt and landing route

Source landing uses the relay-first protected route. The verifier at
scripts/protected-ci-landing.py:367 requires ordered [base, candidate] parents
and equal candidate and landed trees. Receipts bind to their base: moving main
invalidates a base-bound receipt, so land inside a short coordinated window
and acquire fresh candidate and base evidence (CD-5). Reuse stays allowed only
where the existing tree and input-equivalence rules permit it.

Known receipt limits: bare executing-job names can select a proofless checker
under reusable layouts (CD-2), the native gate path resolves one workflow blob
(CD-3), and PR #169 once hit a REST diff endpoint limit whose derivative was
not deploy-consumer-compatible (M6). Test the actual unsquashed sync shape
before trusting the receipt on it.

## Other workflows in scope

release.yml keeps upstream-only guards that must survive the sync. A reviewed
fork publisher or approved local route replaces them, never a deletion.
signed-macos-canary.yml and the desktop candidate workflow depend on Block
Apple signing OIDC roles a fork tag alone cannot satisfy. New
codex-security-review.yml and staging-dev-relay-image.yml must stay disabled
for the fork or gain repository guards before landing (CD-15). The changes job
needs Hermit activation wherever adopted upstream scripts assume it (CD-14).

## Mirror authority

Sync branches live under canonical relay authority. The GitHub mirror prunes
mirror-only heads and tags on a two-minute timer (CD-8). Fetch upstream
without tags. Never mirror or push upstream tags into canonical authority.
The desktop auto-tagger skips this fork's version-bump merges and cannot
create a GitHub-only desktop tag the mirror would prune.
