# Durable agent drafts and owner review

Status: proposed follow-up design. The accompanying source change hardens existing
review submission only. It does not implement draft persistence or close issues
`bbbbe4aa327ed366834a1a9e1fa959b616d17621e943da9a7a150ebc8e38e1d6` and
`252aee1475a3b2b6d97aa8de11a4c9507fd4f559c8181b07ee511dba57991c12`.

Baseline: Buzz main `cd31b58d95631f3419ae364f007ae5146b14f720`.

## Existing behavior and completed pieces

- `crates/buzz-cli/src/agent_management.rs` encrypts a management request to the
  owner and signs a kind 24200 observer event. Both the request UUID and event
  signature are generated afresh for each CLI invocation.
- `crates/buzz-cli/src/commands/agents.rs` requires a NIP-OA auth tag. Its owner
  can differ from the CLI signing identity. Successful relay delivery currently
  reports `saved=false` and says the draft was sent for owner review.
- `crates/buzz-relay/src/handlers/event.rs` checks the authenticated signature,
  NIP-OA owner relationship or stored agent ownership, and observer timestamp.
  It fans the ephemeral event out without storing it.
- Desktop already starts the observer subscription with zero managed agents.
  It parses management requests and renders global review dialogs through
  `OwnerReviewDialogs`. The old audit's claim that no review UI exists is stale.
- `observerRelayStore.ts` routes owner-signed requests and known managed-agent
  requests. `useAgentManagement.ts` then requires the sender to be a managed
  agent and both sender and owner to belong to the originating channel.
- Request IDs, buffered requests, and reviewed IDs exist only in hook memory.
  A reconnect/backfill alone would re-offer previously completed requests.
- Persona creation chooses a fresh UUID. Local save and persona publication
  retention are separate writes. A crash or partial failure is therefore not
  safe to fix by blindly retrying the create operation.

## Decision required for CLI identities outside the managed-agent registry

Preserving the current Desktop policy is already authorized. Durable storage,
request-ID idempotency and recovery for admitted registered drafts are engineering
work within the original issue scope. The decision below concerns optional
unregistered-sender eligibility and does not block that implementation. Receiving,
reviewing, or retaining a draft never grants its author permission to save,
publish, join a channel, or start an agent.

There are two concrete policy choices:

1. Align CLI success with the narrower Desktop gate. Define a verifiable
   registration binding for the owner's managed agents and originating channel.
   Relay intake must check that binding before reporting an actionable draft.
   A NIP-OA relationship alone is insufficient. An offline Desktop cannot be
   used as a synchronous preflight service, and its local managed-agent list
   must not be silently replaced by the broader relay agent directory. Until
   that binding exists, report durable receipt as `stored`, with review
   eligibility separate and potentially unavailable.
2. Permit any currently owner-attested CLI identity to submit actionable drafts,
   subject to shared-channel membership. This expands the current Desktop
   eligibility policy and needs an explicit owner decision. It still grants no
   mutation authority; only an explicit owner submission can apply a draft.

The original issues require accepted CLI drafts to appear but do not specify
which policy should govern an attested, unregistered CLI sender. The current
source fix implements neither expansion nor a new registration grant.

## Proposed wire and storage contract

Use a distinct persistent request kind and a distinct owner decision kind.
Suggested unused numbers at the baseline are 14201 and 34201; these are proposed,
not registered by this change. Do not make all kind 24200 telemetry persistent.

A request has one immutable signed event, one request UUID, one `p` owner, one
`agent` signer, and one originating channel binding. The NIP-44 ciphertext
contains the existing narrow create/update payload, protocol version, and the
same request UUID and channel. Reject duplicate or inconsistent tags, an
incorrect owner/signer relationship, invalid signatures, unsupported versions,
and oversized content. Bind the request to the canonical community, signer,
owner and UUID; a different event or payload at that key is a conflict. Store
that binding atomically with the event. Reusing an identical signed event is an
idempotent retry, including when the first response was lost.

Preserve the existing admission boundary. The persistent path must reuse the
applicable owner-relationship and scope checks in the common ingest pipeline so
HTTP, WebSocket, and mesh delivery cannot bypass them. Any stricter registration
proof depends on the decision above. Do not trust an unsigned frontend claim
that a sender is an owned managed agent.

The request is owner-addressed, not author-only. The author can be a delegated
agent, so an author-only read rule would hide the request from its owner. Add
explicit filter and per-result owner gates covering REQ, COUNT, IDs-only reads,
search, live fan-out and exports. Store no searchable text for either private
kind. Carry over the repository's tenant/community isolation rules. SQL schema,
migration and retention changes must agree; changing a TypeScript kind constant
alone is insufficient.

The decision is signed by the owner, bound to the exact request event ID and
review revision, and encrypted to the owner. Use a monotonic generation and
predecessor check at the relay, rather than last-timestamp-wins approval. A
client clock cannot revive a rejected request or replace an applied result.
A durable rejected or applied outcome remains a tombstone for the corresponding
request. Pending requests and terminal tombstones must not disappear under the
ordinary event-age cleanup. Quotas must reject new requests explicitly instead
of dropping already accepted pending reviews. Physical cleanup requires a
specified recovery horizon before implementation, with no implicit expiry of
pending requests.

CLI creates its request ID and signed bytes once and retains an encrypted
outbox entry before sending. A retry command resubmits those same bytes; it
must not silently create another request. An acceptance response distinguishes
`stored`, `review_eligible`, and `applied=false`. Failure to detect durable-draft
support is an error; never fall back to ephemeral delivery while promising
persistence. Retaining ciphertext does not retain a new credential.

## Desktop queue and review contract

Keep a persistent queue partitioned by canonical community and owner pubkey.
Persist the original signed encrypted event and receipt metadata. Verify the
signature, owner address, request binding and ciphertext before exposing its
payload. Do not persist plaintext system prompts in browser localStorage.

On connection, subscribe first, then backfill requests and outcomes to EOSE,
with stable pagination beyond the existing 100-item UI buffer and 1000-event
subscription limit. Merge both streams by the immutable request key and exact
event ID. Terminal outcomes take precedence regardless of arrival order.
Reconnect must also rescan requests missed while offline; a five-minute `since`
window cannot satisfy this requirement. Local receipt is not an owner decision.

Show pending requests in an owner review queue. An update also appears on the
matching agent detail screen, referring to the same queue record. Multiple
matches and missing targets are visible unavailable states, never an arbitrary
name match. Resolve a target to its stable persona ID and revision at review
open, then pin that snapshot while the owner edits. The source hardening in
this change applies that rule to the existing dialogs.

Keep received, pending, applying, applied, rejected, stale and unavailable
states distinct. Closing a dialog leaves a request pending. An explicit Reject
button records a terminal rejection; it is not a generic close handler. Viewing,
backfilling, refreshing and switching accounts never invoke a save or publish.

Before submission, recheck the exact active request, community, owner,
managed-agent eligibility, shared-channel membership and target revision.
An identity or community switch invalidates in-flight callbacks. Offline owners
can inspect cached drafts; applying requires current eligibility and a durable
claim. Loss of eligibility makes the request unavailable without granting a
fallback. The owner must reopen stale content before making a fresh decision.

Use the existing deliberate choices for saving a definition, creating a stopped
instance and Start now. Bind the chosen action and exact edited content to the
owner decision. A shared persona's catalog publication must be explicit in the
review UI. Neither a received draft nor a prior approval may authorize a new
publication target, new edited content or a changed start action.

## Application, partial failures and retry

A reviewed request needs a durable operation record before its first mutation.
Bind it to the owner, community, request event ID, target persona ID, expected
revision, exact approved input and selected action. Create allocates its target
persona ID once in this record. A retry returns the same result or continues a
recorded authorized step; it never allocates another persona or starts another
instance because a response was lost.

The existing `personas.json` save plus best-effort publication retention cannot
serve as this transaction. Introduce a transactional local operation store or a
recoverable write-ahead journal integrated with the persona store lock. Recovery
must distinguish a saved persona from an unsaved one and record its actual
result before sending the terminal outcome. Reconcile after a crash without
replaying unrecorded side effects. A failed catalog publish remains a distinct
pending publication for the already saved definition.

For two Desktop instances, acquire the owner-signed relay claim for the exact
request before mutation. Relay CAS chooses one claim. A crash leaves an
inspectable applying state. A different device must not automatically steal it:
recovery requires either the original device's operation result or an explicit
owner recovery decision with proven absence of the earlier side effect. An
elapsed lease alone cannot prove that a persona was not created. This preserves
at-most-once application while failing closed on uncertain cross-device state.

These records do not authorize automatic external sends. Any queued publication
must correspond to the explicit owner action already recorded, with unchanged
identity, destination and content. New content or a different action requires
another review. Do not silently mark the draft applied when only its local save
succeeded but a promised publish failed.

## Deterministic acceptance required before claiming implementation

These are follow-up acceptance requirements, not passing test claims for this
source change. Use synthetic identities, a local relay/storage fixture and a
controllable clock. Capture actual signed-event storage and mutation calls.

| Scenario | Required result |
| --- | --- |
| Desktop closed when CLI stores draft | On next connection, one pending queue item and one matching detail entry |
| Desktop has no managed agents | Connection/backfill starts; no unregistered sender gains apply authority |
| CLI loses successful storage response | Retrying the same signed event returns the same request, with one stored row |
| Relay restarts before Desktop connects | Stored request and owner-only read restrictions survive |
| More than one backfill page | All pending requests arrive once; no silent buffer eviction |
| Outcome arrives before request | Terminal request never opens an actionable review |
| Reject then restart and replay | One terminal rejection; zero persona saves or publications |
| Approve then lose response | One persona ID and one authorized instance/publication operation |
| Crash between persona save and outcome | Recovery finds the operation's existing result; no duplicate create |
| Publication fails after local save | Existing result is retained; failure remains visible and retry binds to exact approved bytes |
| Switch owner or community during decrypt/review | Old data is not displayed and retained callbacks cannot apply it |
| Agent removed or channel membership revoked | Apply fails before mutation, even if the review was already open |
| Persona changes while owner edits | Store-lock revision check rejects the stale overwrite |
| Different content with reused request UUID | Explicit conflict; neither duplicate nor replacement approval |
| Unauthorized signer, reader or owner decision | No intake/apply authority; no count, ID, content or tag disclosure |
| Two owners/devices race review outcomes | Exactly one valid claim; no timestamp-based override or duplicate mutation |
| Offline queue view, reconnect, ordinary close | Zero save, start or publish calls |

The candidate's focused tests cover existing review guards and the local
revision check. They do not exercise this proposed durable protocol, relay
persistence, crash recovery, backfill, or cross-device decision transaction.

## Next implementation assignment

Continue from the stale-review candidate on an isolated non-default branch.
Implement durable delivery for the existing managed-agent/channel eligibility
policy. No additional owner decision is required for that engineering work.
Do not broaden the eligible sender set.

1. Add the persistent request codec and builder in `buzz-core` and `buzz-sdk`.
   Update `buzz-cli/src/agent_management.rs` and `commands/agents.rs` to retain
   stable request IDs/signed ciphertext for retry and report stored-versus-applied
   state accurately. Keep project-channel drafts on their existing path.
2. Add durable intake through `buzz-relay/src/handlers/ingest.rs`, with the
   existing scope/owner checks reused by every transport. Add the kind registry,
   p/result privacy gates, SQL null-search expression, request identity conflict
   index/transaction, and pending retention rules in `buzz-core`, `buzz-db`,
   `schema/schema.sql` and a new migration source. Add deterministic relay/DB
   fixture tests. Do not execute a production migration.
3. Add a queue/operation store scoped by community and owner in Desktop's native
   layer and commands. Retain verified ciphertext, deduplication state, terminal
   outcomes and a stable target persona ID. Integrate the operation journal with
   persona create/update under the store lock. Refactor only the native save
   seam necessary for request-bound idempotency; ordinary edit behavior stays
   compatible. Never recover uncertain starts or sends by blindly repeating them.
4. Add the dedicated backfill/live queue bridge and native API adapter. Mount it
   independently of managed-agent count. Merge requests/outcomes, paginate all
   pending items, preserve ineligible requests as unavailable, and expose the
   same queue item in the review queue and matching agent detail. Actionability
   continues to require the existing managed-agent and shared-channel gate.
5. Wire explicit Reject and reviewed Save/Create/Start actions to the durable
   operation contract. Pin community, identity, target, revision, sharing,
   selected action and edited content. Distinguish saved/queued/published results.
   Integrate owner claim CAS and durable terminal outcomes before claiming
   multi-device at-most-once behavior.
6. Execute the acceptance matrix above using synthetic local fixtures, including
   restart, offline backfill, retry, identity switch and stale/unauthorized
   review. Obtain fresh source review. The current focused guard tests are not
   substitutes for those acceptance checks.

The remaining unregistered-CLI choice is separate. The compatible implementation
can store such relay-authorized ciphertext and label it unavailable under the
existing review policy; it must not tell the caller that an actionable review
was accepted. Expanding the eligible sender set or introducing a new persistent
registration grant belongs to a separately approved decision.
