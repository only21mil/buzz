# Ignored tests inventory

From the recovered check run at 1e05fce2: root Rust 5819 passed, 8 failed,
669 ignored across 168 result summaries; relay library alone 1038 passed, 8
failed, 89 ignored; Tauri 2853 passed, 15 ignored; desktop frontend 6253
passed, 1 skipped; mobile and web green as listed in ci-checks.md. These
counts are diagnostics, never acceptance. No ignored case counts as passed.

## The 8 failures (BC-1)

Six media tests time out seeding a community through a lazy PostgreSQL pool
at crates/buzz-relay/src/api/media.rs:1017-1022, explicit Sqlx(PoolTimedOut).
Two admin tests at crates/buzz-relay/src/api/admin/mod.rs:392-434 expect 404
and get 500; their fixture builds a lazy pool at line 342, so unavailable
database access is the inferred cause. Fix: move all eight into the existing
disposable-database integration path with explicit dependencies, or inject
fakes for genuinely service-free assertions. Never change expected status to
hide a fixture failure. A passing run against a disposable migrated database
is still owed.

## Ignored and skipped (BC-3)

669 root plus 15 Tauri ignored, 1 desktop skip. Stated reason families cover
PostgreSQL, Redis, MinIO, live relays, native keychains, models, credentials,
and native performance. The old "27 ignored DB tests" line is not this run's
total; see ignored-reasons.json in the audit evidence for exact reason
counts, blanks included. P01 maps each ignored case to a retained feature
obligation, runs the applicable ones isolated, and records why the rest do
not apply.

Named items: two onboarding specs remain test.fixme at
desktop/tests/e2e/onboarding.spec.ts:3200,3231 (D10, restore or retire with a
reason). Admin-web passes with zero test files (needs real role and protocol
tests in P04). The web PAL coverage gate must keep failing on unreviewed
commands until each is classified (D6). The idle-quiescence perf spec has no
script or CI invocation (D8, documented opt-in only).

## Placeholder sidecars

The original worker touched six empty target-named sidecar files (buzz-acp,
buzz-agent, buzz-dev-mcp, git-credential-nostr, buzz, buzz-backend-kubernetes)
before Tauri compile and tests. Those runs prove Rust behavior with
placeholders. They prove nothing about real executables, bundles, packaging,
startup, or signing. Mandatory sidecars need nonzero size, target arch,
executable format, permissions, provenance, hashes, launch and handshake, and
bundle resolution where the bundle requires them. bundle-sidecars.sh checks
existence only.
