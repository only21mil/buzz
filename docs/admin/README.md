# Deployment admin API and dashboard

Buzz can expose a private, deployment-wide moderation surface from the relay
process: JSON reads across every community, operator/moderator staffing, and
the `admin-web` dashboard. Set `BUZZ_ADMIN_HOST` to activate it. Leave it
unset and the surface stays absent.

## Authentication

`BUZZ_ADMIN_AUTH` selects the credential check. Unset means `nip98`
(fail-secure). Any other value besides `disabled` is a startup error. Token
(bearer) auth is not supported: a lingering `BUZZ_ADMIN_TOKEN` is ignored
with a startup warning.

- `nip98` (default). Every request carries
  `Authorization: Nostr <base64 kind-27235 event>`. The relay verifies the
  signature, the timestamp (±60s), the `u` tag against the canonical admin
  URL derived from config (never the inbound `Host`), the `method` tag
  against the request method, and the `payload` sha256 tag for requests
  with a body. Verified event ids are claimed once in a deployment-scoped
  replay guard; reuse and replay-guard outages both fail closed with `401`
  plus a `WWW-Authenticate: Nostr` challenge. Reads and mutations are
  available per resolved principal.
- `disabled`. No credential; always read-only (mutations and staffing
  always `403`). Use only behind network-layer protection (VPN, private
  ingress). Logs a `WARN` on every boot.

In both modes the exact admin `Host` check and the same-origin `Origin`
check stay active as defense-in-depth. A wrong host or a foreign browser
origin gets `403` before any database work.

## Roles

Relay-level roles (deployment-global, through this API) and
community-level roles (tenant-scoped, through signed Nostr moderation
commands) are independent axes.

| Role | Scope | Powers |
| --- | --- | --- |
| Operator | Relay | Read everything; manage the roster via staffing endpoints |
| Moderator | Relay | Read everything; never view or change the roster |
| Owner | Community | Full authority inside their community, no guard rails |
| Admin | Community | Community moderation, except actioning the owner or a fellow admin |
| Member | Community | None |

Report resolution with enforcement (resolve, reopen, cancel) and feedback
lifecycle writes arrive with the enforcement bundle once its tables land;
this unit ships reads, discovery, and staffing.

A pubkey resolves to a relay role in this order; config always outranks the
roster store:

1. In `RELAY_OPERATOR_PUBKEYS` → operator, source `config`.
2. Equals `RELAY_OWNER_PUBKEY` while `RELAY_OPERATOR_PUBKEYS` is empty →
   operator, source `owner_fallback`. Break-glass for self-hosters;
   staffing any operator deactivates it. Immutable through the API.
3. Row in the `relay_operators` table → operator or moderator, source
   `db`. Managed through the staffing endpoints.
4. No match → `403`. There is no fall-through role.

## Routes

Reads:

- `GET /api/admin/v1/reports`, `GET /api/admin/v1/reports/:id`
- `GET /api/admin/v1/feedback`, `GET /api/admin/v1/feedback/:id`
- `GET /api/admin/v1/feedback/:id/attachments/:sha256`

Report reads accept optional `communityId`, `status`, `reportType`,
`targetKind`, `after`, `before`, and `limit` (capped at 200).

Discovery and staffing:

- `GET /api/admin/v1/probe` reports `{auth, role, source, canAct,
  canStaff}`. In NIP-98 mode it needs a credential like any other route,
  so an unauthenticated `401` is itself the mode signal (`200` means
  `disabled`). The dashboard probes this once at load.
- `GET /api/admin/v1/operators` lists the union of config, owner-fallback,
  and roster grants. Operator-only.
- `GET /api/admin/v1/operators/:pubkey` reads one grant. Operator-only.
- `PUT /api/admin/v1/operators/:pubkey` with `{"role":
  "operator"|"moderator"}` grants or replaces a roster grant.
  Operator-only. Config-backed and owner-fallback pubkeys conflict with
  `409`; the path pubkey is canonicalized to lowercase hex first, so an
  uppercase spelling cannot bypass the guard. Unknown roles are `400`.
- `DELETE /api/admin/v1/operators/:pubkey` revokes a roster grant.
  Operator-only. Revoking a missing grant is `404` and writes nothing.

Until the roster migration lands, reads resolve no DB grants and staffing
writes answer `503` with code `roster_unavailable`. Config and
owner-fallback grants work regardless.

## Startup matrix

| Configuration | Result |
| --- | --- |
| `BUZZ_ADMIN_HOST` unset | Surface absent; `BUZZ_ADMIN_AUTH` ignored |
| `BUZZ_ADMIN_AUTH` unset or `nip98` | NIP-98 mode |
| `BUZZ_ADMIN_AUTH=disabled` | Read-only, no credential, boot WARN |
| `BUZZ_ADMIN_AUTH` anything else | Startup error |
| `BUZZ_ADMIN_TOKEN` set | Ignored with a startup warning; remove it |
| `RELAY_OWNER_PUBKEY` malformed | Startup error (it can be the break-glass root) |
| `RELAY_OPERATOR_PUBKEYS` set, `RELAY_OPERATOR_API_ORIGIN` unset | Boots with a WARN; community provisioning refuses until the origin is set; the console is unaffected |

## Discovery

With `BUZZ_ADMIN_HOST` set, the NIP-11 document gains an `admin_api`
field: the canonical admin origin (`scheme://host[:port]`, no path).
Loopback hosts map to `http`, everything else to `https`, under the same
rule the relay verifies NIP-98 `u` tags with, so the advertised origin and
the verified origin cannot diverge schemes. Clients discover the console
through this field instead of manual URL entry.

## Dashboard auth

`admin-web` carries no token field. It probes `/probe` once: `200` means
`disabled`, anything else means NIP-98. In NIP-98 mode every request is
signed as a kind-27235 event through a NIP-07 browser extension, with a
fresh `nonce` tag per call (same-second requests would otherwise share an
event id and trip the replay guard) and a `payload` tag on mutations. A
`401` re-signs once, then surfaces a sign-in-expired state. Attachments
render through object URLs fetched with the credential, because `<img>`
and `<a>` tags send no Authorization header.

## Feedback attachment boundary

Attachment bytes are available only through the feedback-scoped read
route. It uses the same private-ingress, exact admin `Host`, and
same-origin boundary as the JSON API, plus the credential check above. It
is not a generic media endpoint. The relay loads the feedback row, derives
its community from server-owned provenance, verifies that host resolution
still maps to the row's `community_id`, and requires the requested SHA-256
to match both the `x` field and source-community `/media/` URL in that
row's persisted `imeta` tag. Unknown feedback, unreferenced hashes,
malformed paths, and cross-community substitutions all collapse to `404`.

Only `GET` and `HEAD` are routed. The browser receives no reusable signed
URL. Responses are uncached, `nosniff`, governed by a restrictive CSP,
streamed from object storage, and non-previewable content retains
attachment disposition. Successful reads produce a structured trace with
feedback ID, community ID, and attachment hash, but no body or URL.

## Repair CLI

`buzz-admin reconcile-channels` backfills kind:39000/39001/39002 discovery
events for channels missing them. `buzz-admin reconcile-channels --channel
<uuid>` force-republishes only that channel's kind:39002 roster snapshot
after rollout, leaving metadata and admin events untouched. The targeted
path refuses ephemeral keys: pass `--relay-key` or set
`BUZZ_RELAY_PRIVATE_KEY`.
