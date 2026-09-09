# Durable agent drafts and owner review

This source implements durable delivery for the existing Desktop managed-agent
and shared-channel review policy. It continues the stale-review candidate
`c96d499c8c344159e171df3688b13b7b723a7d28` on Buzz main
`cd31b58d95631f3419ae364f007ae5146b14f720`, and incorporates the content-bound
revision repair `a2d00f759b5d27e5d2e61fcf814db6f87a894ae9`.

## Wire and relay storage

Kind **14201** is an immutable owner-encrypted request. Its exact tags are `p`
(owner), `agent` (signer), `r` (request UUID), `h` (originating channel UUID), and
`v=1`. The versioned encrypted body retains the existing narrow agent management
create/update payload and repeats the UUID/channel bindings. Desktop verifies
those encrypted bindings before retaining or reviewing the request. Project
channel requests keep the existing ephemeral observer path.

Kind **14202** is an immutable owner-encrypted decision. Its tags are `p`, `e`
(exact request event ID), `previous` (expected selected predecessor), `generation`,
`state`, and `v=1`. The owner signs it with self-tagging enabled, preserving `p`.
There is no parameterized replacement or timestamp winner. The relay accepts:

- pending → applying, generation 1, predecessor=request;
- pending → rejected, generation 1, predecessor=request;
- applying → applied, generation 2, predecessor=the winning claim.

Requests and decisions require valid event signatures, canonical owner keys,
exact tag cardinality, bounded structurally valid NIP-44 v2 content, and no extra
plaintext metadata. Common HTTP/WebSocket ingest enforces authenticated signer
and scope, current owner relationship, and archived-identity restrictions. A
claim also requires current owner/agent shared-channel membership. An exact
signed request retry remains valid after the usual event freshness window;
future timestamps remain bounded. Normal telemetry is never made persistent.

The database transaction reserves `(community, owner, agent, request UUID)` and
stores the signed event and owner mention together. Different signed bytes at
that identity conflict. Claims lock the request row and compare predecessor,
generation, and state before storing their event. Identical request, claim, and
outcome retries return the existing result. A quota rejects new requests once an
owner has 10,000 pending/applying requests; it never discards accepted requests.

Both kinds are owner-result gated through REQ, COUNT, IDs-only reads, HTTP
queries, local fan-out, and cross-node pubsub fan-out. `search_tsv` is NULL.
Their stored `channel_id` is NULL so global owner subscriptions receive them;
`h` remains a signed review-eligibility binding, not a channel delivery topic.
Deletion/update triggers protect pending history and terminal tombstones. No
expiry or physical cleanup horizon is introduced.

Migration 0040 adds this schema. Its numbered prerequisite 0039 is copied
verbatim from reviewed relay-authorization candidate
`cc606d9725d54962bb9291020732fb3d49932194`; its audit CHECK constraint is reflected
in the desired schema. This carries the schema prerequisite, not that candidate's
unrelated authorization code. Source migrations have only been exercised on
explicit disposable test databases.

## CLI and Desktop receipt

CLI creates a request UUID and signed ciphertext once, writes an owner-only
outbox file and fsyncs it before transmission. `buzz agents draft-retry UUID`
reloads the original bytes in the same relay/agent/owner scope. No re-signing or
ephemeral fallback occurs. The response requires the relay's durable-protocol
acknowledgment and reports `stored=true`, `review_eligible=null`, `applied=false`.
Storage does not promise that an unregistered CLI identity has an actionable
Desktop review. No new registration grant or trust expansion is introduced.

Desktop stores verified signed ciphertext and self-encrypted operation records
in the existing community/owner retention scope. It subscribes independently of
managed-agent count and performs full keyset backfill using `(until,before_id)`;
same-second pages cannot silently omit requests. Live delivery, offline reload,
terminal-before-request ordering, and duplicate pages converge on one queue
record. The global queue and matching agent detail show that same record.
Malformed, unavailable, ambiguous, and missing-target requests remain visible
without apply authority. Opening, refresh, backfill, account switching, and
ordinary dialog close do not invoke save, start, or publication.

## Explicit review and recovery

Reject is an explicit terminal owner decision and may discard an otherwise
unavailable request. Save, Create a stopped instance, and Start now each bind
the exact edited input and action to a retained claim. A shared update explicitly
shows Save and publish. Updates pin stable persona ID, editable content, revision,
and sharing; native comparison runs under the existing persona store lock.
Prepared callbacks are invalidated by owner/community changes, including native
scope epoch changes during asynchronous admission or review.

The native operation allocates a new persona ID once and journals its prepared
result before the first persona write. A crash between persona save and outcome
is reconciled against the saved stable ID and complete reviewed content. Own
relay echoes may normalize timestamps; they do not allocate another definition.
Changed content or removed targets fail closed. The operation records the local
save before sending definition sync and terminal outcome. Private definitions
use the existing author-private persona protocol. Shared publication requires
explicit review. Signed publication content, owner and target remain fixed;
an explicit delayed retry may refresh only an expired signature timestamp.
Successful publication is retained as an accepted head without an automatic
pending send.

Create/Start journals an uncertain marker before entering the existing instance
creation path. A lost response or crash never blindly repeats that side effect.
Safe instance result metadata is retained; private keys never enter queue results.
Start also journals the exact owner-signed add-member event for the originating
channel and submits it before reporting applied. A failed attachment or
publication remains visible on the existing saved result and can be retried
explicitly. Creating a stopped instance keeps the existing no-attachment behavior.

The winning relay claim cannot expire or be automatically stolen by another
device. An uncertain operation requires inspection and reconciliation of the
original result. There is no cross-device takeover or invented proof of absence.
A local claim/save can resume only after another explicit owner click; queue
lifecycle work never replays mutations or publications.

## Verification and practical limits

Deterministic tests use synthetic identities, actual signed encryption, local
SQLite storage, and fenced disposable PostgreSQL. They cover stable ciphertext
retry, atomic conflict/rollback, same-second multi-page reads, actual PostgreSQL
restart, owner-result privacy, competing device claims, terminal ordering,
content-bound stale review, native journal-before-save and crash-after-save
recovery, and UI lifecycle paths with zero mutation calls. Focused relay fixtures
exercise global owner delivery, cross-node privacy, common ingest, and membership
revocation. Test evidence is reported with the frozen candidate.

These checks do not constitute CI, deployment, or an installed-app smoke test.
The native Start boundary calls the established instance implementation; tests
do not launch real agent processes or publish real catalog/channel events.
Uncertain starts and partial profile publication remain inspectable failures,
not automatically recoverable operations. Expanding Desktop eligibility to
owner-attested identities outside its managed-agent registry remains separate.
