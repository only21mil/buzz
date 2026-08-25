//! Action sink trait — interface for workflow side-effects.
//!
//! The relay implements [`ActionSink`] to provide direct DB access to the
//! executor, replacing the HTTP loopback pattern.

use std::future::Future;
use std::pin::Pin;

use buzz_core::tenant::CommunityId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Stable delivery identity for one claimed workflow effect.
///
/// Sinks must use this identity when they can make a retry naturally
/// idempotent. Relay events use both fields and the persisted payload to
/// reproduce the same signed event. Relay dedup makes those effects
/// exactly-once. Webhooks are at-least-once: retries reuse the persisted bytes
/// and `idempotency_key`, so receivers must deduplicate `Idempotency-Key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionEffectContext {
    /// UUID fixed by the durable effect claim and reused across generations.
    pub idempotency_key: Uuid,
    /// Database timestamp fixed by the first claim.
    pub claimed_at: DateTime<Utc>,
}

/// Errors from action sink operations.
#[derive(Debug, thiserror::Error)]
pub enum ActionSinkError {
    /// An input parameter is malformed (e.g. invalid UUID).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The target channel does not exist.
    #[error("channel not found: {0}")]
    ChannelNotFound(String),
    /// The target channel is archived.
    #[error("channel is archived: {0}")]
    ChannelArchived(String),
    /// Nostr event construction or signing failed.
    #[error("event construction failed: {0}")]
    EventBuild(String),
    /// A database operation failed.
    #[error("database error: {0}")]
    Database(String),
    /// Message content is empty or whitespace-only.
    #[error("empty message content")]
    EmptyContent,
    /// The target event does not exist in the workflow's community.
    #[error("target event not found: {0}")]
    TargetNotFound(String),
}

impl From<ActionSinkError> for crate::WorkflowError {
    fn from(e: ActionSinkError) -> Self {
        crate::WorkflowError::WebhookError(e.to_string())
    }
}

/// Interface for workflow actions that produce side effects.
///
/// Implemented by the relay to provide direct DB/event access to the executor.
/// This replaces the HTTP loopback where the executor POSTed to the relay's
/// REST API (which failed with 401 auth errors).
///
/// Returns `Pin<Box<dyn Future>>` for dyn-compatibility — required because
/// `WorkflowEngine` stores `Arc<dyn ActionSink>`.
pub trait ActionSink: Send + Sync {
    /// Resolve message mentions before the durable effect claim is written.
    ///
    /// The returned pubkeys become part of the immutable effect payload. A
    /// retry must deliver those pubkeys and must not resolve names again.
    fn resolve_message_mentions(
        &self,
        _community_id: CommunityId,
        _channel_id: &str,
        _text: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, ActionSinkError>> + Send + '_>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Post a message to a channel on behalf of a workflow owner.
    ///
    /// - `community_id`: the server-resolved community that owns the workflow
    ///   run driving this side effect. The relay-signed message is published
    ///   under *this* community, never the deployment/default tenant — the run
    ///   carries its owning community so a workflow in community B posts into B
    ///   even though the side effect has no inbound connection to bind.
    /// - `channel_id`: UUID string of the target channel
    /// - `text`: message body (must not be empty/whitespace-only)
    /// - `author_pubkey`: hex-encoded pubkey of the workflow owner (used for
    ///   the `p` attribution tag; the relay keypair signs the event)
    ///
    /// Returns the event ID hex string on success.
    fn send_message(
        &self,
        effect: ActionEffectContext,
        community_id: CommunityId,
        channel_id: &str,
        text: &str,
        author_pubkey: &str,
        mentioned_pubkeys: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<String, ActionSinkError>> + Send + '_>>;

    /// Add a reaction to an event on behalf of a workflow owner.
    ///
    /// The sink must resolve the target inside `community_id`, verify that it
    /// belongs to `channel_id`, and attribute the relay-signed event to
    /// `author_pubkey`. `Ok(Some(event_id))` means the deterministic reaction
    /// event exists, whether inserted now or recovered during replay. `Ok(None)`
    /// means a different event already represents the same active reaction.
    fn add_reaction(
        &self,
        effect: ActionEffectContext,
        community_id: CommunityId,
        channel_id: &str,
        target_event_id: &str,
        emoji: &str,
        author_pubkey: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, ActionSinkError>> + Send + '_>>;
}
