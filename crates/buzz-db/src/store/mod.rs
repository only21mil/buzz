//! Domain-owned persistence implementations.

/// Explicit deployment-global admin report reads.
pub mod admin_moderation;
/// Fork agent drafts persistence.
pub mod agent_drafts;
/// Community-scoped authentication allowlist persistence.
pub mod allowlist;
/// API token storage and lookup.
pub mod api_token;
/// Relay-scoped archived identity persistence (NIP-IA).
pub mod archived_identities;
/// Channel lifecycle and metadata persistence.
pub mod channel;
/// Channel membership and roster persistence.
pub mod channel_members;
/// Fork ci persistence.
pub mod ci;
mod ci_api;
/// Fork ci grants persistence.
pub mod ci_grants;
/// Fork ci landing persistence.
pub mod ci_landing;
/// Fork ci merge bypass persistence.
pub mod ci_merge_bypass;
/// Community lifecycle and host-map persistence.
pub mod community;
/// Durable whole-community deletion lifecycle and PostgreSQL adapter.
pub mod deletion;
/// Direct message channel persistence.
pub mod dm;
/// Event storage and retrieval.
pub mod event;
/// Home feed queries.
pub mod feed;
/// Fork git merge gate persistence.
pub mod git_merge_gate;
/// Git repository name registry (NIP-34 kind:30617).
pub mod git_repo;
/// Community moderation: reports, bans/timeouts, audit actions.
pub mod moderation;
/// Monthly table partition management.
pub mod partition;
/// Buzz product-feedback sidecar persistence.
pub mod product_feedback;
/// Community-scoped push lease and durable wake-outbox persistence.
pub mod push;
/// Reaction persistence.
pub mod reaction;
/// HTTP report-resolution enforcement state machine persistence.
pub mod relay_admin_actions;
/// Use-limited relay invite persistence (v2 opaque tokens).
pub mod relay_invite;
/// Relay-level membership persistence (NIP-43).
pub mod relay_members;
/// Deployment-global relay operator/moderator roster persistence.
pub mod relay_operators;
/// Event-reminder delivery query, claim, and release persistence.
pub mod reminder;
/// Replaceable-event persistence and coordinate locking.
pub mod replaceable;
/// Durable completed snapshots from the isolated media-storage worker.
pub mod storage_accounting;
/// Thread metadata persistence.
pub mod thread;
/// Per-community usage rollup queries for Prometheus gauges.
pub mod usage;
/// User profile persistence.
pub mod user;
/// Workflow, run, and approval persistence.
pub mod workflow;
/// Fork workflow approval persistence.
pub mod workflow_approval;
/// Fork workflow effect persistence.
pub mod workflow_effect;
/// Fork workflow run transition persistence.
pub mod workflow_run_transition;
/// Fork workflow state persistence.
pub mod workflow_state;
