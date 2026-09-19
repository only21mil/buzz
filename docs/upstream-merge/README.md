# Upstream merge, phase 1

Fork parent `1a8a614ea0b0e25488c8fec645bb78f9cc2e60aa`. Upstream parent `5511b56fcf0047f9d0d4887dc75125b6933a6bbd` from the already-fetched `refs/remotes/upstream/main`. Merge base `5bf78671f45178f8de02ba18d3d321cbbf19cd1f`. The upstream tracking ref was not fetched or moved.

This is a non-squashed, two-parent merge. Phase 1 records directory decisions and does not claim a compiling or deployable tree. No migration renumbering or production operation is included.

## Conflict inventory and decisions

703 conflicted paths, 2,688 conflict-marker hunks, counted before resolution. Status counts: UU 462, AA 222, UD 9, DU 9, AU 1. AA counts include whole-file conflicts; zero-hunk entries include delete, rename, and mode cases.

| Rule | Paths |
| --- | ---: |
| archive-delete-hand | 2 |
| both-added-upstream | 222 |
| buzz-db-upstream | 16 |
| cargo-lock-upstream | 1 |
| cargo-workspace-union | 1 |
| core-hand | 16 |
| desktop-feature-hand | 20 |
| desktop-small-upstream | 195 |
| migration-schema-hand | 2 |
| mobile-web-upstream | 87 |
| other-small-upstream | 24 |
| relay-admin-upstream | 3 |
| remaining-hand | 86 |
| root-ci-hand | 12 |
| upstream-delete-rename | 10 |
| upstream-deletion | 6 |

The rules apply only to conflicted paths; clean merges remain Git's automatic result. AA takes the entire upstream file. Small desktop conflicts, mobile, admin-web, web, buzz-db, and relay admin take upstream according to the task rules. Agent, archive, message-hooks, core, root/CI, and remaining large or crate conflicts retain the fork pending phase 2. Explicit migration/schema rules precede the generic buzz-db and UD rules, so `crates/buzz-db/src/migration.rs` survives for the migration worker. There were no conflicted `migrations/` paths; upstream-only additions remain. No strategy preference option was used.

`mobile/lib/shared/widgets/section_label.dart` is AU but absent from the pinned upstream tree; following upstream removes that rename destination. Other DU paths take upstream. The archive sync manager and its test remain despite upstream deletion. Executable modes follow the selected parent's tree.

557 paths take upstream whole, 138 retain the fork, seven follow upstream deletion, and Cargo.toml is merged now. Cargo.toml preserves both complete workspace member lists, all ten fork CI crates, and both dependency blocks. Cargo.lock is upstream's whole file. Any dependency or lockfile inconsistency is the build worker's first item; phase 1 does not generate a lockfile over the network.

## Phase 2 ledger

[handmerge.tsv](handmerge.tsv) contains exactly the 138 fork-held files, with original status, hunk count, and area. The disposition column records the final area decision. `ported` means a combined implementation, not adoption of every upstream hunk; `accepted-fork` keeps the fork design with the omissions below; `accepted-upstream` takes upstream behavior; `retired` removes an obsolete path. For a path in that ledger, inspect the patch with:

```bash
git diff 5bf78671f45178f8de02ba18d3d321cbbf19cd1f 5511b56fc -- <path>
```

Follow renames when that patch names an old path. In particular, `scripts/reconcile-schema-after-pgschema.sql` retains the fork stage-2 content from `scripts/attach-schema-partitions.sql` at the upstream rename destination. Cargo.toml is already hand-merged and is recorded as `union` in [resolutions.tsv](resolutions.tsv), not as a fork-held file. That complete resolution ledger also records the buzz-db files taken upstream, under `buzz-db-workflow-port`; port the fork workflow-storage API there in phase 2. Deleted buzz-db admin code is recorded there too. Use the report for the exact grouped phase-2 path lists.

## Fork behavior referenced by tests

[tested-fork-exports.tsv](tested-fork-exports.tsv) indexes fork declarations in upstream-whole files and fork tests that name those declarations. It uses the frozen fork parent, including tests that the merge replaced. This is a lexical candidate list for behavior reapplication, not proof that each behavior was lost. Desktop and mobile workers must inspect the named tests and compare both parents. Declarations include TypeScript exports, Rust public items, Dart public top-level declarations, and Swift declarations. Dynamic exports and indirect test references may need further investigation.

The following upstream-whole files have matching fork tests:

- `admin-web/src/api.ts`
- `crates/buzz-acp/src/scope.rs`
- `crates/buzz-db/src/lib.rs`
- `crates/buzz-relay/src/api/admin/auth.rs`
- `crates/buzz-relay/src/api/admin/error.rs`
- `crates/buzz-relay/src/api/admin/mod.rs`
- `desktop/src-tauri/src/app_state.rs`
- `desktop/src-tauri/src/commands/agent_discovery.rs`
- `desktop/src-tauri/src/commands/agent_discovery/relay_directory.rs`
- `desktop/src-tauri/src/commands/agent_models.rs`
- `desktop/src-tauri/src/commands/channels.rs`
- `desktop/src-tauri/src/commands/media.rs`
- `desktop/src-tauri/src/commands/media_download.rs`
- `desktop/src-tauri/src/commands/media_fetch_cancellation.rs`
- `desktop/src-tauri/src/commands/media_upload_progress.rs`
- `desktop/src-tauri/src/commands/messages/event_batch.rs`
- `desktop/src-tauri/src/commands/personas/create.rs`
- `desktop/src-tauri/src/commands/personas/mod.rs`
- `desktop/src-tauri/src/commands/personas/snapshot/import.rs`
- `desktop/src-tauri/src/commands/personas/update.rs`
- `desktop/src-tauri/src/commands/project_git.rs`
- `desktop/src-tauri/src/commands/project_git_recipient_notes.rs`
- `desktop/src-tauri/src/commands/project_git_workflow.rs`
- `desktop/src-tauri/src/commands/project_repo_paths.rs`
- `desktop/src-tauri/src/commands/teams/adopt/apply.rs`
- `desktop/src-tauri/src/commands/teams/mod.rs`
- `desktop/src-tauri/src/commands/workspace.rs`
- `desktop/src-tauri/src/events.rs`
- `desktop/src-tauri/src/huddle/agent_tts_publisher.rs`
- `desktop/src-tauri/src/huddle/tts_broadcast.rs`
- `desktop/src-tauri/src/huddle/tts_pipeline_controls.rs`
- `desktop/src-tauri/src/managed_agents/config_bridge/effort.rs`
- `desktop/src-tauri/src/managed_agents/config_bridge/effort_tests.rs`
- `desktop/src-tauri/src/managed_agents/discovery.rs`
- `desktop/src-tauri/src/managed_agents/mod.rs`
- `desktop/src-tauri/src/managed_agents/persona_events.rs`
- `desktop/src-tauri/src/managed_agents/readiness.rs`
- `desktop/src-tauri/src/managed_agents/runtime/test_fixtures.rs`
- `desktop/src-tauri/src/managed_agents/storage.rs`
- `desktop/src-tauri/src/managed_agents/team_catalog.rs`
- `desktop/src-tauri/src/managed_agents/types.rs`
- `desktop/src-tauri/src/relay.rs`
- `desktop/src-tauri/src/team_catalog.rs`
- `desktop/src/app/AppShell.tsx`
- `desktop/src/app/routes/ChannelRouteScreen.tsx`
- `desktop/src/app/routes/projects.$projectId.tsx`
- `desktop/src/app/useWebviewZoomShortcuts.ts`
- `desktop/src/features/agents/lib/teamCatalogRelay.ts`
- `desktop/src/features/agents/ui/CommunityCatalogDialog.tsx`
- `desktop/src/features/agents/ui/effortPicker.ts`
- `desktop/src/features/channels/hooks.ts`
- `desktop/src/features/channels/ui/AgentSessionThreadPanel.tsx`
- `desktop/src/features/channels/ui/useChannelAgentSessions.ts`
- `desktop/src/features/channels/useUnreadChannels.ts`
- `desktop/src/features/communities/useCommunities.tsx`
- `desktop/src/features/communities/useCommunityInit.ts`
- `desktop/src/features/forum/ui/ForumComposer.tsx`
- `desktop/src/features/forum/ui/useForumMentionPreparation.ts`
- `desktop/src/features/home/hooks.ts`
- `desktop/src/features/home/ui/HomeView.tsx`
- `desktop/src/features/home/ui/InboxDetailPane.tsx`
- `desktop/src/features/huddle/HuddleContext.tsx`
- `desktop/src/features/messages/lib/audioAttachment.ts`
- `desktop/src/features/messages/lib/audioMediaLoadScheduler.ts`
- `desktop/src/features/messages/lib/autoPinMentionedAgentsPreference.ts`
- `desktop/src/features/messages/lib/buildMentionCandidates.ts`
- `desktop/src/features/messages/lib/detachedToastScope.ts`
- `desktop/src/features/messages/lib/extractMentionPubkeys.ts`
- `desktop/src/features/messages/lib/mentionCandidates.ts`
- `desktop/src/features/messages/lib/mentionClipboard.ts`
- `desktop/src/features/messages/lib/mentionHighlightExtension.ts`
- `desktop/src/features/messages/lib/mentionPasteBinding.ts`
- `desktop/src/features/messages/lib/mentionTokenSpans.ts`
- `desktop/src/features/messages/lib/pastedMentionOccurrences.ts`
- `desktop/src/features/messages/lib/projectChannelWindow.ts`
- `desktop/src/features/messages/lib/sendToChannelSemantics.ts`
- `desktop/src/features/messages/lib/useDrafts.ts`
- `desktop/src/features/messages/lib/useFilePicker.ts`
- `desktop/src/features/messages/lib/useMediaUpload.ts`
- `desktop/src/features/messages/lib/useRichTextEditor.ts`
- `desktop/src/features/messages/lib/useVoiceNoteRecorder.ts`
- `desktop/src/features/messages/lib/videoReviewContext.ts`
- `desktop/src/features/messages/ui/ComposerAddressControls.tsx`
- `desktop/src/features/messages/ui/MentionAutocomplete.tsx`
- `desktop/src/features/messages/ui/MessageComposerToolbar.tsx`
- `desktop/src/features/messages/ui/MessageThreadPanel.tsx`
- `desktop/src/features/messages/ui/MessageTimeline.tsx`
- `desktop/src/features/messages/ui/useAgentAddressLockPicker.ts`
- `desktop/src/features/messages/ui/useComposerAttachmentSpoilers.ts`
- `desktop/src/features/messages/ui/useComposerVoiceNote.tsx`
- `desktop/src/features/messages/ui/useDetachedAgentStart.ts`
- `desktop/src/features/messages/ui/useMentionSendFlow.helpers.ts`
- `desktop/src/features/messages/ui/useMentionSendFlow.test-support.mjs`
- `desktop/src/features/messages/useThreadReplies.ts`
- `desktop/src/features/onboarding/ui/CommunityOnboardingFlow.tsx`
- `desktop/src/features/onboarding/ui/RuntimeIcon.tsx`
- `desktop/src/features/profile/hooks.ts`
- `desktop/src/features/profile/ui/UserProfilePrimaryActions.tsx`
- `desktop/src/features/projects/lib/discussionChannels.ts`
- `desktop/src/features/projects/lib/projectCollection.ts`
- `desktop/src/features/projects/lib/projectHomeChannel.ts`
- `desktop/src/features/projects/lib/projectHomeTemplate.ts`
- `desktop/src/features/projects/lib/projectRepoAvailability.ts`
- `desktop/src/features/projects/lib/projectShareLinks.ts`
- `desktop/src/features/projects/projectChannelRequest.ts`
- `desktop/src/features/projects/projectChannelRequestQueue.ts`
- `desktop/src/features/projects/projectDeletion.ts`
- `desktop/src/features/projects/projectDeletionMutation.ts`
- `desktop/src/features/projects/projectIssues.mjs`
- `desktop/src/features/projects/projectModels.ts`
- `desktop/src/features/projects/projectSnapshot.ts`
- `desktop/src/features/projects/repoSyncHooks.ts`
- `desktop/src/features/projects/ui/ProjectCreationDialog.tsx`
- `desktop/src/features/projects/useAddProjectRepository.ts`
- `desktop/src/features/projects/useAttachProjectRepository.ts`
- `desktop/src/features/projects/useBindProjectRepositoryChannel.ts`
- `desktop/src/features/projects/useCreateProject.ts`
- `desktop/src/features/projects/useProjectRepositoryRefSelection.ts`
- `desktop/src/features/search/lib/searchMatch.ts`
- `desktop/src/features/search/useSearchResults.ts`
- `desktop/src/features/settings/ui/SettingsPanels.tsx`
- `desktop/src/features/settings/ui/harnessCatalogCopy.ts`
- `desktop/src/features/sidebar/ui/MoreUnreadButton.tsx`
- `desktop/src/features/workflows/ui/WorkflowScheduleFields.tsx`
- `desktop/src/features/workflows/ui/WorkflowTriggerConditions.tsx`
- `desktop/src/features/workflows/ui/cronExpression.ts`
- `desktop/src/features/workflows/ui/useWorkflowListAuthorPresentations.ts`
- `desktop/src/features/workflows/ui/useWorkflowListMessagePresentations.ts`
- `desktop/src/features/workflows/ui/workflowAuthorCandidates.ts`
- `desktop/src/features/workflows/ui/workflowConditionExpression.ts`
- `desktop/src/features/workflows/ui/workflowEditorPane.ts`
- `desktop/src/features/workflows/ui/workflowFormTypes.ts`
- `desktop/src/features/workflows/ui/workflowMessageCandidates.ts`
- `desktop/src/features/workflows/ui/workflowMessageTextCondition.ts`
- `desktop/src/features/workflows/ui/workflowSchedule.ts`
- `desktop/src/features/workflows/ui/workflowStepDescription.ts`
- `desktop/src/features/workflows/ui/workflowTemplateVariables.ts`
- `desktop/src/features/workflows/ui/workflowTriggerDescription.ts`
- `desktop/src/features/workflows/ui/workflowYamlDocument.ts`
- `desktop/src/shared/api/projectGit.ts`
- `desktop/src/shared/api/relayClientSession.ts`
- `desktop/src/shared/api/relayQueryInvalidation.ts`
- `desktop/src/shared/api/tauri.ts`
- `desktop/src/shared/api/tauriManagedAgents.ts`
- `desktop/src/shared/api/tauriMedia.ts`
- `desktop/src/shared/api/tauriMessages.ts`
- `desktop/src/shared/api/tauriRelayAgents.ts`
- `desktop/src/shared/api/tauriTeams.ts`
- `desktop/src/shared/api/tauriWorkflows.ts`
- `desktop/src/shared/api/tauriWorkspace.ts`
- `desktop/src/shared/api/types.ts`
- `desktop/src/shared/api/workflowTypes.ts`
- `desktop/src/shared/lib/mentionBoundaries.ts`
- `desktop/src/shared/lib/mentionDisplay.ts`
- `desktop/src/shared/lib/rosterDerivations.ts`
- `desktop/src/shared/lib/useDocumentVisible.ts`
- `desktop/src/shared/lib/useNow.ts`
- `desktop/src/shared/lib/useResolvedLinkPreviews.ts`
- `desktop/src/shared/lib/videoPlaybackSpeedPreference.ts`
- `desktop/src/shared/ui/markdown/nodeCache.ts`
- `mobile/ios/BuzzPushKit/Sources/BuzzPushKit/BuzzCommunicationNotification.swift`
- `mobile/ios/BuzzPushKit/Sources/BuzzPushKit/BuzzDevPushEnrollmentDriver.swift`
- `mobile/ios/BuzzPushKit/Sources/BuzzPushKit/BuzzPushNotificationResolver.swift`
- `mobile/ios/BuzzPushKit/Sources/BuzzPushKit/BuzzPushPendingEnrollmentRecord.swift`
- `mobile/ios/BuzzPushKit/Sources/BuzzPushKit/BuzzPushTranscript.swift`
- `mobile/ios/Runner/JumpToLatestGlassButton.swift`
- `mobile/ios/Runner/PushEndpointGrantStore.swift`
- `mobile/ios/Runner/PushNativeState.swift`
- `mobile/ios/Runner/PushSnapshotBridge.swift`
- `mobile/lib/app.dart`
- `mobile/lib/features/channels/channel_actions_sheet.dart`
- `mobile/lib/features/channels/channel_detail_page.dart`
- `mobile/lib/features/channels/channel_detail_page/message_bubble.dart`
- `mobile/lib/features/channels/channel_directory.dart`
- `mobile/lib/features/channels/channel_management_provider.dart`
- `mobile/lib/features/channels/channels_provider.dart`
- `mobile/lib/features/channels/compose_bar/compose_bar_widget.dart`
- `mobile/lib/features/channels/dm_channel_labels.dart`
- `mobile/lib/features/channels/members_sheet.dart`
- `mobile/lib/features/channels/mentions/mention_candidates.dart`
- `mobile/lib/features/channels/mentions/mention_ranking.dart`
- `mobile/lib/features/channels/message_content.dart`
- `mobile/lib/features/channels/reaction_row.dart`
- `mobile/lib/features/channels/send_message_provider.dart`
- `mobile/lib/features/channels/thread_detail_page.dart`
- `mobile/lib/features/channels/voice_note_composer_recorder.dart`
- `mobile/lib/features/channels/voice_note_recording.dart`
- `mobile/lib/features/forum/forum_post_card.dart`
- `mobile/lib/features/forum/forum_thread_page.dart`
- `mobile/lib/features/home/home_page.dart`
- `mobile/lib/features/invites/invite_create_page.dart`
- `mobile/lib/features/invites/invite_create_provider.dart`
- `mobile/lib/features/invites/invite_join_provider.dart`
- `mobile/lib/features/pairing/pairing_page.dart`
- `mobile/lib/features/pairing/pairing_provider.dart`
- `mobile/lib/features/profile/animated_avatar_capture.dart`
- `mobile/lib/features/profile/animated_avatar_capture/frame_processing.dart`
- `mobile/lib/features/profile/profile_edit_page.dart`
- `mobile/lib/features/profile/profile_provider.dart`
- `mobile/lib/features/profile/profile_text_editor.dart`
- `mobile/lib/features/profile/set_status_sheet.dart`
- `mobile/lib/features/profile/user_profile_sheet.dart`
- `mobile/lib/features/pulse/compose_note_page.dart`
- `mobile/lib/features/pulse/note_card.dart`
- `mobile/lib/features/search/search_page.dart`
- `mobile/lib/features/settings/accent_picker_page.dart`
- `mobile/lib/features/settings/settings_page.dart`
- `mobile/lib/features/settings/theme_picker_page.dart`
- `mobile/lib/main.dart`
- `mobile/lib/shared/auth/auth_provider.dart`
- `mobile/lib/shared/community/community.dart`
- `mobile/lib/shared/community/community_provider.dart`
- `mobile/lib/shared/community/community_storage.dart`
- `mobile/lib/shared/deeplink/deep_link.dart`
- `mobile/lib/shared/deeplink/pending_deep_link_provider.dart`
- `mobile/lib/shared/huddle/huddle_session.dart`
- `mobile/lib/shared/mentions/agent_identity_provider.dart`
- `mobile/lib/shared/profile/user_cache_provider.dart`
- `mobile/lib/shared/profile/user_profile.dart`
- `mobile/lib/shared/push/push_bootstrap.dart`
- `mobile/lib/shared/push/push_bridge.dart`
- `mobile/lib/shared/push/push_presentation_cache.dart`
- `mobile/lib/shared/push/push_relay_capability_provider.dart`
- `mobile/lib/shared/relay/relay_provider.dart`
- `mobile/lib/shared/relay/relay_session.dart`
- `mobile/lib/shared/widgets/avatar_image.dart`
- `mobile/lib/shared/widgets/frosted_app_bar.dart`
- `mobile/lib/shared/widgets/ios_glass_navigation_button.dart`

## buzz-acp accepted hybrid

The integration accepts the fork's `pool.rs`, `queue.rs`, and `lib.rs` design
with selected upstream behavior. A full rewrite onto upstream's layout is not
part of this merge. This preserves tested session ownership and cancellation
behavior while incorporating the following upstream features:

- Hydrated thread context, model capability refresh and post-switch identity,
  per-session startup effort, and shared project-home prompt guidance.
- Nonblocking reap of completed respawn tasks and `PromptChannelInfo::default`.
- Provenance-aware pricing identity, cache-read/write accounting, missing and
  overflowed counter handling, and standard Claude/Codex usage parsing.
- Correlated model-control acknowledgements. Both idle and busy picks return
  provisional `sent`; only adapter application emits terminal `switched`.
  Rejection or setup failure emits a correlated failure. A pending pick keeps
  its original channel and is consumed once.

We deliberately retain the fork's async close/delete/resume lifecycle, exact
session-scope routing, bounded hold queues, inbox admission, stop/self-wake
handling, slash commands, and shared repository-backed project authority.
Tests naming these contracts include
`close_session_preserves_final_pending_metric_then_forgets_baseline`,
`test_shutdown_closes_every_live_session_but_keeps_cold_history`,
`affinity_expired_dispatch_survives_exhaustion_and_preserves_inbox`,
`test_discovery_without_metadata_stays_fail_closed_at_author_gate`,
`stop_after_a_steer_took_control_discards_the_returning_batch`, and
`self_wake_keeps_policy_rules_dedup_and_normal_queue_scheduling`.
Upstream's wholesale pool/queue/lib admission and dispatch layout, its
huddle prompt additions, and its `NewSessionChannelContext`
caller reshaping are not adopted here. Replacing the fork paths would require
re-proving those contracts; the accepted merge does not claim those differences
are resolved.

The final fixes port activates `relay/recovery.rs` and both recovery test files,
including targeted replay scheduling, capacity wakes and per-subscription retry
fairness. Rate-limited EVENT acknowledgements requeue only the refused observer
frame. Channel discovery now retains the `about` description. Channel descriptions also flow through the fork channel resolver into prompt
context. Huddle context still belongs to the unadopted pool layout.
`PermissionMode::Auto`, the 1500-second idle timeout, missing-binary setup nudges,
and the incoming-turn prompt contract are ported. The existing fork setup listener
keeps its tested workflow-effective-author gate and DM fail-closed behavior.
`--idle-pool-sleep` and its config fields are explicitly not adopted: the fork
pool lifecycle has no idle re-sleep consumer, so accepting the flag would advertise
an inert feature. Existing replay-floor and startup-effort implementations remain.

For a future full port, exact comparisons against pinned upstream `5511b56fc`
live outside the repository in the lane's reports directory:
`um9e-pool-remaining.patch`, `um9e-lib-remaining.patch`, and
`um9e-queue-remaining.patch`. These `*remaining.patch` files include intentional
fork differences, not just missing features. The decision and check receipt is
`rust_acp_workflow.md` in that directory.

## Status at polish

The um-14b continuation starts at integration head `82e28e7d7`. The earlier
fork-main merge and fleet-script removals remain intact. The accepted buzz-acp
hybrid section above remains the integration decision.

All thirteen orphaned ignored-test entries are reconciled. Twelve tests now
compile in active database and ACP modules. The obsolete standalone writer
isolation test is removed because
`runtime::postgres_tests::writer_pool_rejects_non_read_committed_database_default`
exercises the production constructor and its failure metrics. Four orphan files
are deleted. Unique paging, pressure, session-policy, and Pi restore coverage
survives. Three Pi transport/launch tests and the timeout-parser unit test pass.
The obsolete separate huddle-input assertions cannot bind to the accepted
hybrid API and are not claimed as retained coverage.

Reactivating these tests restored deterministic roster ordering, bounded timeout
environment parsing, readiness query outcome/cancellation handling, and the Buzz
Pi adapter's prompt and skill transport. The relay audit-pool helper and test
now live together in the admitted library; main calls that tested helper.
The existing runner reconciles its 155 ignored tests. Fresh workspace discovery
matches all 854 source inventory rows to compiled ignored tests across 144
Cargo targets. All seven PostgreSQL discovery contracts pass. Independent
source review found no actionable defects.

The complete `just test-unit` recipe passes with 4,266 Rust nextest cases,
three auth doctests, the native-CI Python batch, and its shell/inventory checks.
The run used `CARGO_BUILD_JOBS=4`, `NEXTEST_TEST_THREADS=4`, and
`TOKIO_WORKER_THREADS=4` inside the requested `TasksMax=600` user scope.
The previous four CLI failures and executable-start failure passed their six
focused rechecks and the full CLI suite. They were resource-exhaustion failures.
Formatting also passes. Per-crate results and logs are recorded in
`polish.md` in the lane's reports directory.

The earlier polish call passed mobile analysis, 2,416 Flutter tests with four
skipped, the separate unconfigured-push test, web typecheck/lint and 24 tests,
and admin-web typecheck/lint and its empty test command. Those checks were not
rerun in this Rust-focused continuation. Desktop verification remains with its
workers; this lane does not claim app builds or desktop checks passed. The
parent owns integration and the whole-branch review. No PR is opened.

Live PostgreSQL/Redis tests and the real Pi adapter restore test remain
unexecuted. Production remains Victor's decision under
[the migration-lineage runbook](../../deploy/migration-lineage/README.md).
Rehearse the exact candidate against an isolated backup restore and an empty
database, compare schemas and fences, and time migration 0033. Production
requires the approved ledger readback, a fresh backup, the reviewed forward
ledger rewrite, deployment through the migration count gate, and verification
of 59 successful migrations ending at 1044 plus healthy relay probes. Neither
the SQL cutover nor deployment was run by this lane.

## Final dispositions

The handmerge ledger covers all 138 original fork-held paths. Dispositions use
`rust_relay.md`, `rust_acp_workflow.md`, `desktop_agents.md`,
`desktop_messages.md`, `desktop_other.md`, `desktop_shared.md`, `root_ci.md`,
`migrations.md`, `rust_crates.md`, and `polish.md` in the lane reports directory.
Later reports supersede earlier incomplete checks. Exact parent-file matches
identify whole-side acceptances; mixed implementations are marked `ported`
unless the following explicit fork-design acceptance governs the path.

- `ci.yml` retains the fork job layout. Upstream's reusable-workflow refactor
  is not adopted. The six uncalled `_ci-*.yml` workflow-call files are retired.
- `docker.yml` retains the fork pipeline. The upstream same-SHA image
  qualification gate is not adopted by this merge.
- Projects UI retains the integrated project implementation. The review's
  unused upstream-import observation belongs to the desktop worker; it is
  recorded here without claiming those imports implement an upstream feature.
- `markdown.tsx` keeps the fork renderer; upstream lightbox/ImageMosaic is
  not ported. The size worker's extraction preserves that decision.
- Native `commands/workflows.rs` keeps the fork workflow API. Upstream run-cursor
  pagination is not ported.
- Workflow `executor.rs` and relay `workflow_sink.rs` keep the fork authority
  design, including `trigger_injected_rendered_mention_gets_no_authority`.
  Upstream rendering cannot grant authority to injected mentions.
- Desktop E2E `mentions.spec.ts` and `agents.spec.ts` keep the fork scenarios;
  the omitted upstream test lines are accepted omissions, not passing coverage.
- Relay admin `auth.rs` and `mod.rs` accept upstream roster authority in place
  of the fork database roster, with the owner fallback kept. The restored
  NIP-11 advertisement test covers configured, loopback and absent surfaces.
- ACP pool/queue/lib keep the hybrid decision above. Local archive keeps the
  fork feature despite upstream deletion. Migration guards moved into the
  active runtime module; the obsolete root module is retired.

### Accepted upstream code

The `unsafe` blocks in desktop native managed-agent discovery are unchanged
upstream code accepted with that implementation. This merge does not introduce
new unsafe operations in the final-fixes lane. Desktop extraction is owned by
the size worker.
