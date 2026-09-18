# P01 evidence map: fork contracts and check isolation

New contract files live beside the existing specs. No existing suite was
rewritten. Upstream source is `block/buzz@4cd82f51` (fetched 2026-09-13).
Fork chip key display differs from upstream on purpose: fork shows hex
truncation (`shared/lib/mentionDisplay.ts`), upstream shows npub truncation.
Ported chip assertions use the fork form.

## New contract files

| File | Behaviors restored | Upstream source |
| --- | --- | --- |
| `p01-persistent-agent-audience-contracts.spec.ts` (21 tests) | Upload/send submit lock, picker auto-mention, composer/global settings sync, disabled root draft, Tab one-time mention, opt-out empty send, Shift+M toggle and recency, mention-button undo, keyboard-operable setting, failed-send shake, manual-mention persistence, auto-pin turn-off/hover/chip-dismiss, thread scoping, root one-shot, removed-inheritance exclusion, draft exclusion, authored-duplicate draft survival | `persistent-agent-audience.spec.ts` |
| `p01-mention-recipient-contracts.spec.ts` (12 tests) | Ambiguous draft preservation (channel + forum), dual exact identities, edit blocking, team unfurl, automatic-recipient removal modes, duplicate-label roundtrip, edit focus/Escape, longer-alias replacement, absent-roster forwarding, qualified picker/automatic paste, mismatched-key rejection, partial-key binding | `mention-recipients.spec.ts` |
| `p01-mention-clipboard-contracts.spec.ts` (8 active, 7 quarantined) | Timeline/channel/forum copies, composer round-trip, half-chip text, NBSP paste, and the three bare-text pastes naming a known non-member (active; audit D2 in PR 255 adopted upstream bind-and-send and removed the fork-only send gate that used to reject them, and the gate's dead module `unresolvedMentionFeedback.ts` was deleted in the same PR). Paste-verify races, retype/edit/delete binding (quarantined, need the missing relay-lookup hold seam). Sidecar and inbox copies (quarantined, need the missing clipboard-capture seam) | `mention-clipboard.spec.ts`. The fork bridge dropped the upstream `mockDisplayNames` John Smith seed, so the file seeds it per test. |
| `p01-voice-note-contracts.spec.ts` (11 active, 2 quarantined) | Send-error restore, snapshot/drop exclusion, edit-mode discard, editor Enter gate, pending-decode discard, waveform failure retry, generic-audio download kept, voice-note download omitted, waveform card render, fork-native emoji coexistence, duplicate-player coordination (active). Audio-work caps and early-play resume (quarantined, need missing media-fetch seams; the fork loads audio through the media proxy) | `voice-note.spec.ts`. The fork picker is emoji-only, so the GIF-tab test became a fork-native emoji-coexistence contract. |
| `p01-workflow-contracts.spec.ts` (4 tests) | Card toggle off/on with activation confirmation, deleting the open workflow closes its editor, missing-route unavailable dialog with close, direct-route refresh and invalid-view detail | Adapted to the fork editor UI, see notes |
| `p01-onboarding-contracts.spec.ts` (2 quarantined scenarios) | Banner X dismiss removes guidance surface, dismiss persists after re-entry | Quarantined `test.fixme` pair in `onboarding.spec.ts:3200,3231` (audit D10), re-asserted here and reproduced on the fork 2026-09-13 with identical signatures, so both stay quarantined with fork evidence attached |
| `p01-mobile-contracts.spec.ts` (5 tests) | Exact-key chip wrap at 390px, mention-button placement at 390px, workflow library at phone width, voice-note card fit and send at 390px, thread audience send at 390px | Adapted from recipient/audience/workflow/voice-note responsive cases |

## Behavior mapping: dropped upstream tests not restored here

| Upstream behavior | Disposition |
| --- | --- |
| Audience: unfocused root menu stays closed, overlay-container click keeps menu open | Deferred. Layout-race sensitive, no fork regression signal. Revisit after contract run is green. |
| Audience: Shift+M recency in the thread composer, global settings toggle sync | Quarantined/divergent, mapped for the P06 desktop owner. The fork thread composer (`MessageThreadPanel.tsx`) receives no `recentMentionPubkeys` prop, so Shift+M falls back to the default agent. The fork settings agents panel has no automatic-mentions toggle (`AgentsSettingsPanel.tsx` is upstream-only). Composer-side sync is asserted instead. |
| Audience: unchecked-agent exclusion, immediate re-add restore, duplicate/removal draft variants, multi-word chip caret, reduced-motion removal | Deferred. Same mechanics as restored draft/exclusion tests. Owner lanes can adopt on a real failure. |
| Recipients: historical ambiguous thread edit to replacement | Deferred to the thread-edit owner. Mechanics duplicate the restored duplicate-label roundtrip. |
| Recipients/clipboard: boundary-crossing default copy, inbox selection-copy variant | Deferred. Copy-geometry edge cases with no fork signal. |
| Workflows: stale card toggle, rejected status change, rejected deletion, stale editor save | Deferred to relay/DB owners. The fork mock bridge has no revision or injected-error support (`expectedRevision`, `workflowUpdateError`, `workflowDeleteError` are absent from `e2eBridge.ts`). Asserting these now would test nothing. |
| Workflows: narrow-trigger activation warning, unsupported-YAML canonical view, editor screenshots, sequence affordances, pane-route sync, trigger inspector run history | Kept with existing fork specs (`workflows.spec.ts`, `workflow-navigation.spec.ts`) or intentionally fork-divergent UI. The fork shows activation confirmation for narrow triggers too. That divergence is recorded, not enshrined against upstream. |
| Voice-note: none outstanding | Full restore. Fork had 5 of 13, now 13 of 13 plus mobile fit. |
| Onboarding: two `test.fixme` | Re-asserted active in `p01-onboarding-contracts.spec.ts`. If either still fails on the fork, revert that scenario to `fixme` with the fork failure attached and hand the defect to the onboarding owner. |

## DB fixture commands (existing, unchanged)

Desktop contract tests need no database. They run against `installMockBridge`
in `tests/helpers/bridge.ts`, which fakes Tauri IPC, relay reads, sends, and
uploads in the page. The commands below matter when a failure looks like a
missing fixture rather than a product defect, and for the suites that do need
services.

| Command | Role |
| --- | --- |
| `scripts/postgres-test-local.py` | Runs ignored Rust tests in disposable local PostgreSQL clusters, one passing case per invocation. Refuses inherited `DATABASE_URL` values. Linux bubblewrap/namespaces path. |
| `scripts/postgres_test_fence.py` | Isolation fence for the local Postgres runner. |
| `scripts/postgres_test_inventory.py` | Classifies ignored tests for the runner. |
| `scripts/postgres-tests.tsv` | 667-row inventory of ignored Rust tests with package, binary, mode, and reason. |
| `scripts/start-isolated-test-relay.sh` | Stands up an isolated relay on override ports with the `buzz-harness` Compose project. Resets Docker fixtures. Not the default helper for service-free tests. |
| `scripts/start-relay-for-tests.sh` | Starts the test relay used with `tests/helpers/seedRelay.ts`, which publishes real signed events through `POST /events` (ingest-computed thread metadata, never raw SQL). |
| `desktop/tests/helpers/seed.ts` | Desktop-side seed helpers for mock-bridge runs. |

Known fixture-cause failures stay as-is (audit BC-1): root Rust tests exit 101
without services, six proven pool timeouts from lazy-PostgreSQL seeding in
`crates/buzz-relay/src/api/media.rs`, two inferred admin-DB failures at
`api/admin/mod.rs`. No expected status was changed to hide missing
infrastructure.

## Service-free tests and fakes

Every new `p01-*` spec is service-free: `installMockBridge` before each test,
no Docker, no Postgres, no relay process. Fakes already in the tree cover the
rest, so no new fake was added:

| Need | Fake |
| --- | --- |
| Voice-note mic and audio bytes | `tests/helpers/voiceNote.ts` (`installVoiceNote` fakes `getUserMedia` with an oscillator stream and routes the fixture WAV) |
| Avatar camera | `tests/helpers/fakeCamera.ts` |
| Channel/message/user seeds | `tests/helpers/bridge.ts` options (`managedAgents`, `searchProfiles`, `uploadDescriptors`, `sendMessageDelayMs`, `deferredComposerUploads`, `sendMessageErrors`, and others) |
| Live subscription gating | `__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__` waits inside the specs |

Suites that genuinely need services stay out of the contract set:
`agents-everywhere.live.spec.ts` and `relay-restart.live.spec.ts` (live relay),
plus relay-backed parity runs under `tests/e2e/helpers/twoRelayHarness.ts`.
Mobile checks run serially where descriptor pressure previously failed the
build with errno 24 (audit BC-2). The 669 root + 15 Tauri ignored tests keep
their recorded reasons (audit BC-3). No ignored test was un-ignored here.

## How to run

```bash
cd desktop
pnpm build:e2e
pnpm exec playwright test --project=smoke p01-
pnpm exec playwright test --project=smoke p01-mobile-contracts
```

The `p01-*` files are registered in the `smoke` project list in
`desktop/playwright.config.ts` (additive entries only, no existing entry
touched).
