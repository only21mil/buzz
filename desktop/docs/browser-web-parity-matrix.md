# Browser client parity matrix

Base audited: `d7677e177b9e3732bf92962e00b5d7ba161ce03c`; this
successor continues from browser-parity commit
`e627ff05edc57990982687669e3e47326857d1ab` on 2026-08-27.

This matrix covers the hosted build of the full React client, produced by
`pnpm -C desktop build:web`. It also records the other browser bundles so the
name "web app" is not ambiguous.

## Browser path inventory

| Path | Purpose | Consumer chat parity scope |
| --- | --- | --- |
| `desktop/` with Vite mode `web` | Full Buzz renderer at base `/app/`. `desktop/src/platform/web/` replaces native commands with browser implementations. | In scope. This is the browser client. |
| `web/` | Relay-hosted repository browser and invite claim SPA. | Out of scope. It keeps `/`, `/repos/*`, and `/invite/*`; it is not a second chat client. |
| `admin-web/` | Operator reports and product-feedback console on the separately configured admin host. | Out of scope. It must not inherit member chat or identity state. |
| `desktop/public/media-auth-sw.js` | Same-origin service worker that adds short-lived signed Blossom authorization to `/media/*` requests. | In scope. It does not cache messages, credentials, or media. |
| `desktop/public/manifest.webmanifest` | Install metadata for the `/app/` browser client. | In scope. It uses the existing Buzz icon and standalone presentation. |

Status terms:

- **Parity** means the browser invokes the same renderer contract and relay
  authorization rules as desktop.
- **Browser-native** means the behavior is equivalent but uses a browser API.
- **Desktop-only** means the operation requires local processes, files, audio,
  Git, pairing, or managed-agent secrets and fails with an explicit capability
  error.
- **Open** means a user-visible gap remains.

## Feature matrix

| Area | Desktop and mobile reference | Hosted browser state | Status and evidence |
| --- | --- | --- | --- |
| Auth and session | Desktop identity archive and mobile pairing both end in one Nostr identity and NIP-42/NIP-98 authenticated relay access. | Browser identity is generated or imported, encrypted as NIP-49 in IndexedDB under a non-extractable device key, and cleared on sign-out. NIP-42 signs socket challenges. NIP-98 signs exact HTTP URL, method, payload digest, and nonce. Fetches omit cookies. | **Parity.** `identity.ts`, `identityStore.ts`, `nip98.ts`, `relayClientSession.ts`. Pairing remains desktop-only. |
| Origin and credential boundary | Native clients use the configured community relay. | The hosted build now accepts only the WebSocket origin derived from its page origin. It rejects scheme downgrade, credentials, paths, query strings, fragments, ports, and foreign hosts before socket creation. Hosted CSP limits `connect-src` to `'self'` and also constrains scripts, workers, forms, frames, media, and objects. | **Parity for the one-community hosted model.** `originPolicy.ts`, `workspace.ts`, `websocket.ts`, relay `router.rs`. Multiple hosted community origins remain explicitly unsupported and fail closed. |
| Channel list and open channels | Desktop/mobile list relay-scoped NIP-29 groups and current membership. | Browser PAL implements `get_channels`, discovery snapshots, join/leave, create/update/archive/unarchive/delete, topics, purpose, canvas, and member counts. | **Parity.** `relayQueries.ts`, `relayDiscovery.ts`, `relayChannelAdmin.ts`, `relayCanvas.ts`. |
| Private channels | Desktop/mobile rely on relay membership and hidden-channel read gates. | The browser issues authenticated, kind-bounded filters and receives only relay-authorized group state and messages. No fallback broad query exists. | **Parity, relay-enforced.** `relayQueries.ts`, `relayMembership.ts`. Live cross-tenant testing is still required. |
| Direct messages | Desktop/mobile open or reuse hidden NIP-29 DM groups and apply per-viewer kind `30622` visibility. | Browser PAL implements `open_dm` and `hide_dm`; ordinary channel reads preserve relay scope. | **Parity.** `relayDms.ts`. Gift-wrap NIP-17 is not part of the current desktop DM contract. |
| Mentions and inbox | Desktop/mobile tag mentioned pubkeys and build the Home feed from scoped message kinds. | The full renderer is shared. Browser PAL implements `get_feed`, search, people lookup, member/profile batches, and message sends with tags unchanged. | **Parity.** `relayPeople.ts`, `relaySocial.ts`, `messageMutations.ts`. |
| Membership and roles | Desktop/mobile expose channel owner/admin/member/guest/bot and relay owner/admin/member roles. | Browser implements join/leave, add/remove members, role changes, relay membership list, and relay member mutations through signed events. | **Parity.** `relayMembership.ts`, `relayChannelAdmin.ts`, `desktopOnly/relayWorkflowsMembers.ts`. |
| Message send and read | Desktop/mobile send kinds `9` and `40002`, hydrate history, threads, edits, deletes, read state, and reactions. | Browser implements send, history-before, channel windows, thread replies, read-state operations, reactions, edit, delete, live subscriptions, and media upload/download. | **Parity for current renderer contracts.** `relayQueries.ts`, `relayMessageReads.ts`, `messageMutations.ts`, `mediaUpload.ts`. |
| Reactions | Desktop/mobile aggregate kind `7`, optimistic updates, and delete authored reactions. | Shared renderer plus browser `add_reaction` and `remove_reaction` commands. | **Parity.** `messageMutations.ts`, `relaySocial.ts`. |
| Directory and agent identity | Desktop/mobile merge kind `0` profiles, kind `10100` agent directory records, membership, presence, and NIP-OA ownership. | Browser lists every valid kind `10100` record without a hard-coded name allowlist, including Mempool, Genesis, and Codex-R when their relay records are visible. Sparse records fail to offline/default values. NIP-OA owner resolution verifies the signature before exposing ownership. | **Parity for public directory data.** `desktopOnly/relayWorkflowsMembers.ts`, `relayMembershipStatus.ts`. Managed-agent configuration and private personas stay desktop-only. |
| Rachel and Archimedes privacy | Native clients depend on community binding, membership gates, author-only kinds, shared-gated kinds, and NIP-OA checks. | Browser does not read filesystem/vault data. It does not expose unverified profile owners. Persona/team/private managed-agent commands remain capability-off, and the relay remains the authority for private and author-only event kinds. | **Fail closed.** No browser code contains Rachel/Archimedes keys, allowlists, private records, or scope exceptions. |
| Notifications | Desktop uses native notifications; mobile uses local/APNs notification paths. | Browser maps the shared notification call to the Notifications API only after permission is already granted. Activation returns the same target event. The current NIP-PL v1 server contract is APNs-only and explicitly has no Web Push/VAPID subscription transport. | **Parity with the current browser-capable contract.** `relayMembershipStatus.ts`. Background Web Push remains fail-closed until a versioned server/browser contract exists; it is not safe to reuse APNs leases. |
| Settings | Desktop/mobile share profile, theme, status, presence, channel settings, notification preferences, and community views. | Shared renderer and browser PAL support profile, status, presence, channel settings, identity backup/import, and theme. Local repository, terminal, huddle device, managed-agent runtime, and auto-update settings report capability-off or inert values. | **Parity where state is relay or browser owned.** Hardware and local-runtime settings are desktop-only. |
| Workflow approvals | Workflow run traces display pending approval cards. The canonical relay contract authorizes signed kind `46030`/`46031` decisions against an immutable public approval UUID. | Browser reads only signed kind `46010` requests addressed to its active pubkey, validates the frozen request fields and channel/signer tags, maps them to the existing renderer wire shape, and will decide only a request previously loaded into that identity scope. Each relay event is parsed independently, so a hostile or schema-drifted event is discarded without denying valid sibling requests. Denials require a note. | **Browser parity.** `relayWorkflowApprovals.ts`, `WorkflowApprovalCard.tsx`. The relay remains the decision authority; approval UUIDs confer no authority. |
| Workflow and CI observability | Desktop reads workflow definitions from Nostr and authoritative run rows from `GET /workflows/{id}/runs`; the native CLI reduces CI kinds `46100`–`46106` using a separately owner-configured nonempty signer set. | Browser uses the same NIP-98 workflow-run endpoint and exact-schema validation. A read-only `GET /ci/runs/{run}/status?channel_id=…` route applies NIP-98, replay/rate limits, relay membership, current run-channel membership, a DB run/channel binding, a 1,000-event cap, and the zero-I/O `buzz-core` reducer shared with the CLI. Only startup-configured `BUZZ_CI_STATUS_SIGNER_PUBKEYS` authorize status facts; empty authority returns 503. The relay isolates malformed linked events, valid but unexpected request events, and structurally valid status events from non-config signers. It returns bounded counts plus sorted, bounded untrusted-signer provenance without admitting those events to the reducer. A configured signer's validly signed but structurally ambiguous event still returns 409. The PR Checks tab independently parses each kind `46100` discovery event, keeps valid signed requests bound to that repository/channel/PR, and reports bounded rejections. Discovery returns at most 20 runs from a repository/channel query bounded at 100 events. When that query window is not saturated, the UI reports the exact count of discovered older runs omitted by the 20-run limit. When the 100-event window is saturated, the exact omission count is unknown and the UI instead warns that older runs for the pull request may be omitted, including when no matching run was visible in the window. Status reads settle per run, preserving valid siblings while visibly classifying each 409, 503, transport, HTTP, or unparseable failure. Polling continues only while a run is pending or a transport, 429, or unavailable response can recover; empty or failure-only terminal result sets stop. | **Parity for workflow runs, approvals, and CI status graphs.** `relayWorkflowRuns.ts`, `relayWorkflowApprovals.ts`, `relayCiStatus.ts`, `ciPolling.ts`, relay `api/ci.rs`. The UI visibly distinguishes "status signer not trusted by browser configuration" from a genuinely pending trusted run. Response or event content cannot add authority. |
| Schema and API versions | `buzz-core` owns event kinds; renderer command census is schema version 1. | Browser PAL coverage accounts for all renderer commands. Workflow history pins the current REST response and fails closed on unknown status, fields, or malformed trace rows. Event filters use explicit kinds. | **Parity for implemented commands.** `coverage.json`, `desktop/docs/web-pal-commands.json`, `relayWorkflowRuns.ts`. A relay-advertised client compatibility version remains open. |
| Offline and reconnect | Desktop/mobile reconnect on network and lifecycle events and preserve local drafts/read markers. | The shared relay session supplies bounded backoff, online/focus/visibility resume triggers, subscription replay, and connection UI. Signed/scoped message snapshots provide bounded offline reads. When `navigator.onLine` is explicitly false, or an online publish fails with a recognized retryable transport error, the web PAL stores only complete signed channel-message events in an IndexedDB outbox scoped to relay and pubkey. It caps each `{relayUrl, pubkey}` queue at 50 and expires records at 24 hours. An in-session driver wakes at the persisted `nextAttemptAt` and on online, focus, visible, and relay-reconnect signals; concurrent wakes coalesce. Each record is attempted at most five times with bounded exponential backoff. FIFO is preserved within each channel, while a retrying channel cannot block eligible messages in another channel. TTL sweeps, max-count eviction, and terminal failure reporting act only on the owning scope and cannot remove or report another account or relay's records. A queued send returns an explicit `queued` outcome instead of a delivered envelope, and the message row plus notifications expose queued, delivered, retry-failed, and expired states without message content. Authentication, authorization, validation, signature, policy, relay rejection, duplicate, rate-limit, permanent, and unknown failures are never queued. | **Parity for bounded offline read and send recovery.** `messageSnapshot.ts`, `offlineMessageOutbox.ts`, `bootStubs.ts`, `relayQueries.ts`, `messageDeliveryStatus.ts`. Scope-local TTL, maximum-count, max-attempt, fake-time scheduling, signal coalescing, FIFO, and cross-channel progress have focused tests. The service worker still caches no identity, message, media, API response, or token. |
| Responsive layout | Desktop is wide by default; mobile supplies the narrow reference. | The full renderer uses its existing narrow shell. The browser smoke covers 1440x900 desktop, 390x844 phone, and Pixel Fold unfolded 852x883 dp without document-level horizontal overflow. | **Covered by `tests/web/browser-parity.spec.ts`.** Authenticated visual review on physical Safari and Pixel Fold remains open. |
| Accessibility | Desktop renderer supplies semantic buttons, labels, focus management, theme contrast, and reduced-motion CSS. | The browser matrix runs with reduced motion, keyboard reachability, and automated axe checks for WCAG 2/2.1 A and AA. The shared shell provides a visible-on-focus skip link, a named main landmark, route-change focus transfer, and a polite atomic live-region announcement. Skip activation prevents fragment navigation, focuses the main landmark, and preserves the hash-router history stack. The document has a nonempty title. | **Automated parity.** `AppRouteAccessibility.tsx`, `browser-parity.spec.ts`. Chromium and Firefox mount the real shell and verify focus plus route/back behavior. Physical screen-reader acceptance remains a live-device gate. |
| Browser support | Existing Playwright tooling configures Chromium, Firefox, and WebKit. | `playwright.web.config.ts` runs the same responsive, keyboard, CSP, installability, and axe checks in all three engines. | **Chromium and Firefox automated.** Framework-desktop cannot run the maintained WebKit binary because Playwright's standard dependency installer requires `apt-get`, which the host does not provide. Physical Safari remains the shipping-browser gate. |
| Build and deployment | The relay image previously built and served `web/` plus `admin-web/`; the full renderer already built at base `/app/`. | The reviewed multi-stage Docker path now installs and builds the desktop package, copies `desktop/dist` to `/srv/buzz/app`, and sets `BUZZ_APP_WEB_DIR`. Relay startup validates `index.html`; exact `/app` and `/app/*` requests use SPA fallback without exposing the app on the admin host. Responses add CSP, no-sniff, and no-referrer headers. | **Source-complete and promotion-ready, not deployed.** `.dockerignore`, `Dockerfile`, `config.rs`, `router.rs`. Deployment remains a parent-controlled action after review. |

## Security invariants

1. Browser requests use NIP-42 or NIP-98. Cookies are neither required nor sent
   by the NIP-98 helper.
2. The hosted client connects only to its own relay origin. A new multi-origin
   design needs an explicit trusted-origin policy and separate review.
3. Nostr secret material and NIP-49 backups remain behind the existing egress
   guard. No token, secret, signed AUTH event, message, or response body is
   logged by the additions in this change.
4. The service worker authenticates same-origin `/media/*` GET and HEAD requests
   and stores no response cache.
5. Workflow run history accepts only the redacted relay schema and rejects any
   extra field. This prevents a server change from silently rendering newly
   sensitive execution data.
6. The offline outbox stores only already-signed, bounded channel-message
   events. It contains no NIP-49 material, auth event, cookie, bearer token, or
   response body, and it never crosses a relay/signer scope.
7. Approval decisions require an exact request addressed to the active signer.
   CI status fails closed without startup-configured signer authority and uses
   the same pure reducer as the native CLI. Untrusted or malformed linked
   events are reported but cannot change trusted reduction state.

The pure reducer now lives beside its validated CI envelopes in zero-I/O
`buzz-core::ci_reducer`. Both `buzz-cli` and `buzz-relay` import that single
implementation, so the production relay no longer depends on the full CLI
crate or its transport and command-line dependency graph.

## Promotion checks

Run from the repository Hermit environment:

```sh
pnpm -C desktop test
pnpm -C desktop typecheck
pnpm -C desktop check
pnpm -C desktop build:web
pnpm -C desktop test:web:e2e
./bin/cargo test -p buzz-relay --lib router::tests::hosted_app --no-fail-fast
node desktop/scripts/web-pal-census.mjs --check
node desktop/scripts/check-web-pal-coverage.mjs
```

The last two commands prove that every renderer command is still classified
and that `get_workflow_runs` moved from inert browser behavior to an implemented
contract. Deployment, live relay authorization, physical Safari/screen-reader,
Pixel Fold, private-scope, and any future Web Push transport are separate
promotion gates.
