# Buzz browser chat MVP implementation spec

Status: implementation-ready, bounded to the existing `web/` SPA. This wave changes no Rust or relay code.

## 1. Scope

### Goal

Add a low-latency browser chat client to `buzz-web`. It connects directly to the same-origin Buzz relay over one authenticated WebSocket, renders sends optimistically, warms subscriptions after login, and never polls.

### MVP

- Login/onboarding with either a NIP-07 signer (preferred when available) or a pasted `nsec`.
- Channel discovery and channel list from relay-signed NIP-29 group state (`39000`, `39001`, `39002`), excluding `hidden` DM groups.
- Join open groups with kind `9021` and leave joined groups with kind `9022`.
- Channel timeline from kind `9`, ordered deterministically and updated live.
- NIP-10 replies grouped under their root message, initially collapsed with a reply count and inline expansion.
- Reactions: render kind `7` aggregates and publish kind `7` with `h` and `e` tags.
- Edits: overlay the latest accepted kind `40003` for each target `e` tag; break equal-`created_at` ties by event id.
- Composer with signed-event optimistic insertion, pending/failed state, retry, and no duplicate row when the relay echoes the event.
- Kind `20002` typing indicators, sent at most once per three seconds and expired after eight seconds.
- Kind `20001` presence dots for known channel members; publish `online` after auth and best-effort `offline` on explicit logout.
- Member list from `39002`, roles from `39001`, and kind `0` display metadata where available.
- Basic Blossom image rendering for sanitized same-origin `/media/*` URLs found in message content or `imeta` tags. Upload is not included.
- A visible but nonfunctional search entry that opens a “Coming later” stub.

### Explicitly out of scope

- DMs / NIP-17 gift-wrap (`1059`): phase 2.
- Huddles or voice, agents, and search execution / NIP-50.
- Moderation UI other than join and leave.
- Channel creation/editing, invites, media upload, message deletion, rich kind `40002` authoring/rendering, and kind `40003` edit authoring.
- Relay, fallback, container image, database, or migration changes.

## 2. Route plan under the relay fallback

Use a chat-only hash route namespace rooted at `/`:

| URL | View |
| --- | --- |
| `/` or `/#/chat` | Login when locked; otherwise channel list plus empty/welcome timeline |
| `/#/chat/<channel-uuid>` | Selected channel timeline |
| `/#/chat/<channel-uuid>?thread=<root-event-id>` | Selected channel with that inline thread expanded and focused |
| `/#/search` | Search stub |

The relay serves `index.html` for `/`, so every chat deep link requests only `/`; the fragment never reaches the server. Keep TanStack Router on its current browser history so `/repos`, `/repos/*`, and `/invite/<code>` retain their existing URLs. `web/src/app/routes/index.tsx` becomes the chat entry route, while a small hash parser/controller handles the fragment inside that route. Do not add `/chat` to the generated route tree and do not switch the whole application to hash history.

Use `encodeURIComponent`/`decodeURIComponent`, validate channel ids as UUIDs and event ids as 64-character lowercase hex before acting, and fall back to `/#/chat` on invalid input. Hash changes use `history.pushState` for channel selection and `replaceState` for normalization; the helper notifies its own subscribers after those calls and also listens to `hashchange`/`popstate` so Back/Forward and external fragment changes work.

## 3. Module and file plan

All paths are relative to the repository root. Files listed here are the complete planned additions; integration edits are listed separately.

### New `web/src/shared/nostr/**` files

- `web/src/shared/nostr/types.ts` — strict Nostr event, filter, relay-frame, publish-result, and connection-state types.
- `web/src/shared/nostr/kinds.ts` — MVP kind constants and channel/group filter sets.
- `web/src/shared/nostr/events.ts` — event/tag builders, signature/id verification, tag readers, and stable `(created_at, id)` comparison.
- `web/src/shared/nostr/key-store.ts` — consent-gated IndexedDB persistence for a decoded 32-byte pasted secret key, plus load/delete operations.
- `web/src/shared/nostr/signer.ts` — `NostrSigner` interface with NIP-07 and local-`nsec` implementations; never exposes key material to UI callers.
- `web/src/shared/nostr/auth.ts` — NIP-42 kind `22242` AUTH event construction and challenge/OK state handling.
- `web/src/shared/nostr/pool.ts` — same-origin singleton connection pool, socket state machine, relay-frame parsing, reconnect/backoff, and listener fan-out.
- `web/src/shared/nostr/subscriptions.ts` — logical REQ registry, EOSE lifecycle, reconnect replay, close, and event-id dedupe.
- `web/src/shared/nostr/publish.ts` — sign, enqueue, send `EVENT`, correlate `OK`, and return accepted/rejected/unknown results.
- `web/src/shared/nostr/index.ts` — narrow public exports for feature code.
- `web/src/shared/nostr/events.test.ts` — builders, verification, tag parsing, ordering, and edit-selection tests.
- `web/src/shared/nostr/auth.test.ts` — AUTH sequencing and rejection tests with a fake signer.
- `web/src/shared/nostr/subscriptions.test.ts` — EOSE, dedupe, close, and reconnect replay tests with a fake socket adapter.

The existing `web/src/shared/lib/nostr-client.ts` and `nostr-signer.ts` remain for repos/invite behavior during this wave; the chat entry point uses only the new core. A later cleanup may migrate those callers after the MVP is proven.

### New `web/src/features/chat/**` files

- `web/src/features/chat/model.ts` — channel, member, projected-message, thread, reaction, typing, presence, and optimistic-status models.
- `web/src/features/chat/event-projection.ts` — pure conversion of verified events into messages, thread groups, latest-edit overlays, and reaction aggregates.
- `web/src/features/chat/query-options.ts` — React Query keys/options for group state, member/profile snapshots, and initial timeline pages.
- `web/src/features/chat/live-store.ts` — thin `useSyncExternalStore`-compatible store for live/optimistic events and ephemeral typing/presence.
- `web/src/features/chat/use-chat-bootstrap.ts` — starts discovery/membership subscriptions after identity unlock and restores the last active channel.
- `web/src/features/chat/use-channel-timeline.ts` — joins historical snapshot, auxiliary backfill, live events, and optimistic outbox into one projection.
- `web/src/features/chat/use-typing.ts` — typing subscription, TTL pruning, and throttled publish behavior.
- `web/src/features/chat/use-presence.ts` — member-scoped presence subscription, TTL/status projection, and online/offline publishing.
- `web/src/features/chat/ChatEntry.tsx` — authenticated chat feature boundary selected by the index route.
- `web/src/features/chat/ui/ChatPage.tsx` — responsive three-pane chat layout and selected-channel orchestration.
- `web/src/features/chat/ui/ChannelSidebar.tsx` — discovered groups, selection, join/leave actions, connection state, and search-stub entry.
- `web/src/features/chat/ui/ChannelTimeline.tsx` — timeline loading/error/empty states and stable message list rendering.
- `web/src/features/chat/ui/MessageRow.tsx` — author metadata, edited marker, content, image attachments, and reaction controls.
- `web/src/features/chat/ui/ThreadReplies.tsx` — collapsed count plus inline NIP-10 reply expansion.
- `web/src/features/chat/ui/ReactionBar.tsx` — reaction aggregates and optimistic reaction publishing.
- `web/src/features/chat/ui/Composer.tsx` — message/reply composition, optimistic send, retry, and typing notification calls.
- `web/src/features/chat/ui/TypingIndicator.tsx` — bounded “who is typing” presentation.
- `web/src/features/chat/ui/MemberList.tsx` — member/profile/role rows with presence dots.
- `web/src/features/chat/ui/BlossomImage.tsx` — lazy, constrained image rendering with failure fallback and safe URL checks.
- `web/src/features/chat/ui/SearchStub.tsx` — explicit phase-2 placeholder.
- `web/src/features/chat/event-projection.test.ts` — thread grouping, latest edit, reactions, dedupe, and deterministic ordering tests.

### New route, identity, and deployment files

- `web/src/app/routes/chatHashRoute.ts` — parse, validate, format, and subscribe to the isolated chat hash route.
- `web/src/app/routes/chatHashRoute.test.ts` — valid, invalid, encoded, thread, and normalization cases.
- `web/src/features/identity/identity-store.ts` — selected signer/session state, unlock/logout, and last-channel preference (never private key data).
- `web/src/features/identity/IdentityProvider.tsx` — React context that supplies a ready signer/pubkey or locked/error state.
- `web/src/features/identity/ui/LoginPage.tsx` — NIP-07 connect and paste-`nsec` onboarding with explicit persistence consent.
- `web/src/features/identity/ui/IdentityMenu.tsx` — abbreviated pubkey, signer type, lock/logout, and delete-local-key controls.
- `web/src/features/identity/identity-store.test.ts` — signer selection, consent, lock, logout, and deletion behavior with fake storage.
- `deploy/compose/compose.webchat.yml` — local override mounting `../../web/dist` read-only at `/srv/buzz/web` on service `relay`.
- `scripts/deploy-webchat.sh` — run `pnpm -C web build`, validate the combined Compose model, then recreate only the `buzz-prod` relay service with the override.

### Integration edits (no other files)

- `web/src/app/routes/index.tsx` — replace the current `/` repo landing with identity-gated `ChatEntry`; repos remain at `/repos`.
- `web/src/app/routes/root.tsx` — mount `IdentityProvider` around the existing outlet without changing invite/repo routes.

No `web/src/app/routes.ts`, generated route tree, `router.tsx`, Rust, Dockerfile, or base Compose edit is needed.

## 4. WebSocket and subscription lifecycle

### Connection and NIP-42

1. After the user selects/unlocks a signer, derive the URL with the existing `relayWsUrl()` helper and create the one pool entry for that same-origin URL.
2. On socket open, wait for the relay's proactive `AUTH` challenge. Freeze outbound `REQ` and `EVENT` frames until the signer returns a valid kind `22242` event and the matching relay `OK` is accepted.
3. Treat signer refusal, malformed AUTH, negative `OK`, `CLOSED`, or `auth-required` notices as visible locked/auth-error states; do not fall back to an anonymous identity.
4. Verify every received event id/signature with `nostr-tools` before it reaches queries or the live store. Ignore malformed frames and surface rate-limited diagnostics without logging content or keys.

### REQ set

After AUTH, register these logical subscriptions on the same socket:

- Discovery snapshot: `{kinds:[39000]}` through `EOSE`; discard metadata with `hidden`, and select the newest addressable event per `d` coordinate.
- Membership changes: persistent `{kinds:[44100,44101], "#p":[currentPubkey]}`. On an event, invalidate/refetch discovery and affected group state; this exact `#p` is mandatory for the relay p-gate.
- Selected group state: snapshots `{kinds:[39001,39002], "#d":[channelId]}` and then kind `0` profiles with `authors` chunked from the member list.
- Warm selected-channel live stream: `{kinds:[9,7,40003], "#h":[channelId], since:now-2}`. Open this before history so events cannot fall into a history/live gap.
- Timeline history: `{kinds:[9], "#h":[channelId], limit:100}` through `EOSE`. After message ids are known, backfill late auxiliary events with chunked `{kinds:[7,40003], "#e":[...visibleMessageIds]}` queries.
- Typing: persistent `{kinds:[20002], "#h":[channelId], since:now-8}`; never persist it in React Query.
- Presence: persistent `{kinds:[20001], authors:[...visibleMemberPubkeys]}`, rebuilt in bounded chunks when membership changes.

Discovery, membership notifications, and the last active channel's live stream are started immediately after auth, before the chat shell finishes rendering. Switching channels closes only channel-scoped REQs and opens the next set on the already-authenticated socket. There is no timer-based refetch; discovery refetches only after membership events, reconnect, or an explicit user refresh.

### Reconnect, dedupe, and ordering

- Reconnect on unexpected close with full-jitter exponential backoff from 250 ms to 10 s; reset after a stable authenticated connection and retry immediately when the browser returns online.
- Re-authenticate every new socket before replaying the logical REQ registry. Replay live filters with a two-second overlap from their last accepted `created_at`; refetch EOSE snapshots where correctness requires it.
- Do not blindly republish an event after an ambiguous disconnect. Keep its signed id as `unknown`, rely on live echo/history dedupe, and let the user explicitly retry only after a bounded lookup by `ids:[eventId]` finds nothing.
- Dedupe globally by verified event id. For addressable group state, retain the newest `(created_at, id)` per `(kind, pubkey, d)` coordinate.
- Sort timeline events ascending by `(created_at, id)`. A signed optimistic event already has its final id, so the live echo replaces its pending status rather than inserting another row.
- Parse NIP-10 `root`/`reply` markers; tolerate a single legacy reply marker by resolving its root transitively from loaded events. Orphans remain collapsed under an “unavailable parent” row rather than becoming top-level messages.

## 5. State boundary

React Query owns fetch-shaped, EOSE-bounded snapshots: group metadata/admins/members, member kind `0` profiles, timeline history pages, and auxiliary backfills. These values have query keys, loading/error state, bounded retention, and event-driven invalidation.

`live-store.ts` owns only stream-shaped state: verified post-open channel events, signed optimistic outbox entries and publish status, active typing TTLs, and current presence values. It is an external store with per-channel maps and narrow selectors; it is not a second server cache.

For a channel render, `use-channel-timeline.ts` unions the React Query snapshot with live events by id, overlays optimistic status, and runs the pure projection once. Before the live REQ reaches `EOSE`, received events are buffered; its pre-EOSE batch seeds/merges the query snapshot and later frames go to the live store. Logout clears the live store and React Query keys containing identity- or membership-scoped data.

Connection/auth state stays in the Nostr pool; selected identity stays in the identity provider; navigable channel/thread state stays in the hash route. No server data is duplicated into React component state.

## 6. Three parallel implementation lanes

The lanes may run concurrently after agreeing on the exported `NostrSigner`, `VerifiedEvent`, `publish()`, and `subscribe()` types. They must preserve unrelated edits and may change only their owned paths.

### Lane A — Nostr core

Ownership: only `web/src/shared/nostr/**`.

Implement the signer abstraction, IndexedDB key store, single pool, NIP-42 gate, verified publish path, subscription manager, and listed unit tests. Do not edit existing shared-lib Nostr callers.

Acceptance:

1. `node --test web/src/shared/nostr/*.test.ts`
2. `pnpm -C web typecheck`
3. `pnpm -C web lint`
4. `pnpm -C web build`

### Lane B — chat feature and hash route

Ownership: only `web/src/features/chat/**` and `web/src/app/routes/chatHashRoute.ts`, `web/src/app/routes/chatHashRoute.test.ts`.

Implement event projection, query/live-store hooks, hash parsing, all chat UI, and feature tests against Lane A's agreed public types. Do not edit the index/root route or identity/deploy files.

Acceptance:

1. `node --test web/src/features/chat/*.test.ts web/src/app/routes/chatHashRoute.test.ts`
2. `pnpm -C web typecheck`
3. `pnpm -C web lint`
4. `pnpm -C web build`

### Lane C — identity, shell integration, and deployment

Ownership: only `web/src/features/identity/**`, `web/src/app/routes/index.tsx`, `web/src/app/routes/root.tsx`, `deploy/compose/compose.webchat.yml`, and `scripts/deploy-webchat.sh`.

Implement onboarding/unlock/logout, connect the root/index shell to Lane A/B exports, and add the opt-in deployment helper. The script must stop on errors, build with `pnpm -C web build`, validate with `docker compose -f deploy/compose/compose.yml -f deploy/compose/compose.webchat.yml config --quiet`, and recreate only service `relay`; it must not build or replace the relay image.

Acceptance:

1. `node --test web/src/features/identity/*.test.ts`
2. `bash -n scripts/deploy-webchat.sh` and the combined `docker compose ... config --quiet`
3. `pnpm -C web typecheck`
4. `pnpm -C web lint`
5. `pnpm -C web build`

After integration, the parent runs all three targeted test commands, `pnpm -C web check`, and one final `pnpm -C web build`. A manual relay smoke check must confirm login, warm discovery, send/live echo dedupe, reaction, thread expansion, reconnect, and a `/media/*` image. Running the deployment script is a separate production-action approval gate.

## 7. Identity storage and threat model

Prefer NIP-07: request its pubkey during onboarding and ask it to sign AUTH/messages; Buzz stores no secret. For paste-`nsec`, decode and validate it locally, keep only the 32-byte key in memory while unlocked, and persist it in IndexedDB only when the user explicitly checks “Remember this key on this device” after a warning. Never put an `nsec`, decoded key, signed AUTH payload, or event content in localStorage, React Query, logs, URLs, errors, analytics, or worker messages. Logout deletes the IndexedDB record, zeroes reachable key buffers where practical, clears scoped caches, closes the socket, and confirms local deletion.

IndexedDB avoids accidental string interpolation and synchronous reads but is not a security boundary: any same-origin XSS or compromised shipped dependency can use the unlocked signer or read persisted key bytes. Mitigate by preferring NIP-07, using no runtime third-party scripts, rendering message content as text/strict Markdown without raw HTML, validating all media URLs, keeping the dependency/CSP surface narrow, and making the persistence risk and delete control explicit. OS compromise and malicious browser extensions are outside the web client's protection.

## 8. Risks and blocking unknowns

- **Group discovery is historical, not globally live.** Mitigation: EOSE snapshot on login/reconnect, exact-pubkey `44100/44101` subscription, and explicit refresh; no polling.
- **Late edits/reactions can fall outside a channel time window.** Mitigation: `#e` auxiliary backfill for the visible message ids plus the channel live subscription.
- **Relay filter limits for large `authors`/`#e` arrays are not documented.** Mitigation: default to chunks of 100 and verify the limit in an integration smoke test; make chunk size a constant.
- **Presence is ephemeral and may lack an offline event after a crash.** Mitigation: render only recent/non-offline states as online, expire stale dots locally, and publish `offline` on explicit logout. The exact server TTL should be confirmed during implementation; absence always renders offline.
- **NIP-07 behavior varies and users can reject AUTH or publish signing.** Mitigation: model each request as cancellable, show the signer error, and never silently switch identities.
- **Persisted `nsec` is exposed to same-origin XSS.** Mitigation: explicit opt-in, NIP-07 preference, strict rendering, narrow dependencies, and one-click deletion. Passphrase encryption is deferred because client-side code that can use an unlocked key can also exfiltrate it.
- **Optimistic publish can be ambiguous across disconnect.** Mitigation: stable signed id, `unknown` state, lookup-before-retry, and id dedupe.
- **Compose mount assumptions may vary by operator checkout.** The verified base project is `buzz-prod`, service is `relay`, and image path is `/srv/buzz/web`; use the service name rather than assuming a container name. The override is intentionally local-checkout deployment and must fail if `web/dist/index.html` is absent or unreadable.
- **No component-test harness exists in `web/`.** Pure routing/projection/core behavior uses Node's TypeScript test runner; interaction behavior is covered by the final authenticated relay smoke check. Adding a browser component-test framework is outside this wave.

No protocol or relay unknown currently blocks implementation. The two values to confirm during integration are relay filter chunk limits and presence expiry behavior; both have fail-safe client defaults above.
