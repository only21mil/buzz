# Mobile push source boundary

The source packet from `c432a111ca9ddd31a85e1312d5995f8b92191b82` is partially
adopted. It does **not** enable end-to-end iOS remote notifications.

The relay now opts into NIP-PL discovery, lease acceptance, matching and delivery
with `BUZZ_PUSH_ENABLED=true` (default false). Its message kinds are 9, 40002,
45001 and 45003 across the descriptor, activation backfill and event trigger.
Existing `buzz-ios-production` / `buzz-ios-sandbox` profile authority and
notification classes remain unchanged. Queue and gateway timing metrics contain
bounded outcome labels, not endpoint or event identifiers.

`mobile/ios/BuzzPushKit` contains the source's verified notification resolver,
presentation cache, conversation/navigation values, NIP-98 request signing and
lease-policy primitives with their source tests. Flutter contains matching
subscription and community-snapshot primitives. These libraries are not wired
into Runner or the application bootstrap yet. Android continues to use its
existing local-notification path. Huddle native plugins, microphone permissions,
repository browsing, dependency manifests and release workflows are unchanged.

## Deferred profile and enrollment packet

The existing gateway has only `0001_push_gateway_authority.sql`. It is
byte-identical to upstream's prefix and accepts production/sandbox profiles.
Upstream gateway `0002_application_profiles.sql` deletes those installations
and their delegations; `0004_dogfood_only_profile.sql` deletes App Store
registrations. Relay `0043_push_gateway_dogfood_profile.sql` from
`42b42447b0dc47c3e1a4d95caab893567dcd1677` also deletes legacy authority.
None of those migrations is admitted. Gateway `0003_challenge_issuance_quota.sql`
remains with its dependent runtime packet; its source number is not a fork
reservation. The gateway's SQLx ledger remains separate from the relay ledger.

This holds the dogfood App Attest enrollment driver, certificate/profile gateway
cutover, mobile enrollment and revocation orchestration, native APNs registration,
NotificationService target and entitlements, profile/team overrides, and the
dependent deployment chart corrections. A retention and application-identity
policy must resolve these together. No legacy profile is silently mapped to
`buzz-ios-dogfood`, and no source-defined Apple team is installed. Release/profile
identity remains `xyz.block.buzz.mobile`.

## Relay migration admission

- Source: `c432a111ca9ddd31a85e1312d5995f8b92191b82`,
  `migrations/0040_push_message_kinds.sql`.
- Source blob: `a76481b15923d0e819f0bf126409aa00588d2915`.
- Source and adapted SHA-256:
  `cc094648d73cf34ae6772e15359668e340d995344eb9b99f12cde1235ea60fe8`.
- Fork target: `migrations/0037_push_message_kinds.sql`, after unchanged 0001–0036.
- Prerequisites: push leases and endpoint state (0012–0015), queue (0018),
  shared activation gate (0023), and matching descriptor/backfill kinds.
- Desired schema: only `enqueue_push_match_job()`'s allowlist changes.

The migration preserves existing queued work and all profile authority. Focused
PostgreSQL tests exercise fresh install, populated upgrade, desired-schema
behavior and activation backfill. Test databases use private socket-only clusters.
Production migration, credential changes, signing, app packaging, physical-device
acceptance, APNs delivery and deployment require their separate authorized work.
