# iOS push source adoption

The selected source from `c432a111ca9ddd31a85e1312d5995f8b92191b82`,
`42b42447b0dc47c3e1a4d95caab893567dcd1677`, and
`b270437a62bc1049b27745799dc44268d0c23489` is integrated. This is prepared
source, not a deployed gateway or an approved iOS build.

Runner registers APNs, coordinates App Attest enrollment, stores endpoint grants,
and shares scoped snapshots with NotificationService through the configured App
Group and Keychain groups. Flutter bootstrap, community opt-in, subscription
publication, permission recovery, durable revocation outbox, and community-aware
notification taps are wired together. The extension verifies relay events before
presenting cached sender/channel data. Android retains local notifications and its
existing explicit tap route, native plugins, permissions and Google-free package
manifest. Huddles and voice-note entrypoints remain present.

The relay remains disabled by default (`BUZZ_PUSH_ENABLED=false`). Enabling it
advertises only `buzz-ios-dogfood`, APNs class `default`, and message kinds
9, 40002, 45001 and 45003. Gateway profile selection is server-owned. Certificate
transport, App Attest verification, challenge quotas and bounded metric labels
are part of the same packet. Gateway startup and chart rendering reject an App
Attest app identifier that does not end in the exact configured APNs topic.

## Existing fork identity

The actual fork iOS default is `com.buzz.buzzMobile`, retained for Release and
Profile. Debug retains `com.buzz.buzzMobile.<worktree>` through the existing
worktree override script. Android release/profile remains `xyz.block.buzz.mobile`;
that Android identity is not proof of an iOS provisioning identity.

`BUZZ_DEVELOPMENT_TEAM` remains empty until an approved iOS team is supplied in
`Flutter/AppOverrides.xcconfig`. That file is still included last. The App Group
is `group.$(BUNDLE_IDENTIFIER)`, the Keychain suffix is `$(BUNDLE_IDENTIFIER)`,
and NotificationService is `$(BUNDLE_IDENTIFIER).NotificationService`. Release
and Profile use production APNs/App Attest; Debug uses development. Custom
provisioned builds must set the bundle, team, groups and environments consistently
in their existing override path and configure the gateway for that exact app.
No source Apple team, actual credential, signing setting outside this source, or
provisioning profile was installed. The canonical protocol audience and gateway
URL remain the upstream NIP-PL contract; their suitability and ownership for a
fork deployment must be settled before enabling push or registering devices.

## Migration admissions and retirement

Relay versions 0001–0035 are frozen; admitted 0036/0037 remain byte-identical.
Source0040 remains fork0037, which preserves all legacy authority. Source0043 is
admitted as **0038_push_gateway_dogfood_profile.sql**, byte-identical to the
selected source. Desired schema changes only the current gateway profile
constraint for this admission.

The standalone gateway has its own SQLx ledger. Its 0001 is frozen. Source0002,
0003 and 0004 are admitted in that ledger with their original bytes and separate
SHA-256/SQLx SHA-384 evidence in `mobile-push-gateway-migrations.json`. They are
not relay versions or substitutions for relay0038. The source mapping and
prerequisites are recorded in `mobile-push-migration-map.json`.

Fork gateway0005 adds a consumed marker without changing gateway0001–0004.
It preserves outstanding challenge contents and retains every issuance in the
deployment-global 600-per-60-second rolling quota after single-use consumption.
The reaper removes consumed or expired challenges only after their issuance
leaves that window. Its bytes and SQLx checksum are admitted in the independent
gateway ledger. No real database has received these prepared migrations.

Legacy production/sandbox profile labels represented transport environments,
not proven application identities. **They cannot be mapped safely.** The
reviewable migration proposal deletes their gateway delegations before their
installations, and gateway0004 similarly retires dormant App Store authority.
Existing dogfood authority survives gateway0004 byte-for-byte. Relay0038 retains
relay leases, event history and queued work while retiring incompatible local
gateway authority. Old endpoint grants stop working; clients must re-attest and
publish newly authorized leases. Delivery quota/replay retention policy is unchanged.
There is no App Store profile in this MVP.

These SQL artifacts perform destructive retirement when actually applied.
Their presence in source does not approve applying them. Before a binary or
chart containing them is started against an existing database, obtain rollout
approval covering the affected registration inventory, retained recovery
material, retirement/reenrollment plan, downtime and rollback consequences.
Do not merely change profile strings or reuse old endpoint grants. Relay image
migration expectations must advance to38, and the independent gateway to5,
only as part of that approved delivery packet.

## Prepared unsigned iOS CI

The additional `Mobile iOS Release` job preserves all existing CI job IDs and
release workflows. It tests BuzzPushKit and runs
`flutter build ios --release --no-codesign --no-pub`, covering Runner, CocoaPods,
BuzzPushKit and NotificationService. All extension configurations explicitly
clear inherited Runner-only linker flags; Runner keeps its plugin flags.

The job is **inactive until runner admission**. An operator must configure
`BUZZ_IOS_CI_RUNNER_LABELS` as a JSON label array selecting the approved Victor
MBP runner for this repository. No runner label or registration was invented.
It accepts mobile changes on trusted same-repository main PRs, pushes, and manual
CI runs, and excludes external fork PRs. Its token is read-only and checkout
credentials are not persisted. MBP persistent-runner trust and repository access
must be reviewed before setting that variable. Existing MBP evidence proves a
Mason's Budget runner, not an admitted Buzz runner. No workflow was dispatched.

The standalone Swift unit package can be tested on the approved MBP without an
app build. An actual unsigned iOS Release build, native Runner/extension compiler
validation, parent/extension provisioning and Communication Notifications
entitlement verification, physical delivery/tap acceptance, dedicated gateway
DB roles, verified images, APNs certificate/root configuration and deployment
remain separately approved acceptance work. Upstream chart registry references
are source release contracts, not evidence that a fork artifact exists.
