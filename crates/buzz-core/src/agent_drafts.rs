//! Immutable, owner-addressed agent drafts and compare-and-swap decisions.
use crate::{
    kind::{KIND_AGENT_DRAFT, KIND_AGENT_DRAFT_DECISION},
    observer::content_looks_like_nip44,
};
use base64::Engine;
use nostr::{Event, PublicKey};
use serde::{Deserialize, Serialize};

/// Version of the encrypted draft payload and signed envelope.
pub const VERSION: &str = "1";
/// Validated routing data; no plaintext draft is exposed to the relay.
#[derive(Debug, Clone)]
pub struct DraftRoute {
    /// Sole owner allowed to read or decide.
    pub owner: PublicKey,
    /// Delegated signer.
    pub agent: PublicKey,
    /// Stable request UUID.
    pub request_id: uuid::Uuid,
    /// Originating shared channel.
    pub channel: uuid::Uuid,
}
/// Monotonic owner decision. Claims never expire or transfer automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    /// Exclusive in-progress owner claim.
    Applying,
    /// Terminal completed operation.
    Applied,
    /// Terminal rejection without mutation.
    Rejected,
}
/// Validated owner CAS envelope.
#[derive(Debug, Clone)]
pub struct DraftDecision {
    /// Sole owner allowed to read or decide.
    pub owner: PublicKey,
    /// Exact immutable request event.
    pub request_event: nostr::EventId,
    /// Expected selected request or claim event.
    pub predecessor: nostr::EventId,
    /// One for first claim/rejection, two for applied outcome.
    pub generation: u64,
    /// Requested state transition.
    pub state: DecisionState,
}
/// Require exactly one two-field tag; reject duplicates and ambiguous extensions.
pub fn exact_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, String> {
    let mut tags = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|v| v == name));
    let tag = tags.next().ok_or_else(|| format!("missing {name} tag"))?;
    if tags.next().is_some() || tag.as_slice().len() != 2 {
        return Err(format!("ambiguous {name} tag"));
    }
    Ok(&tag.as_slice()[1])
}
fn encrypted(event: &Event) -> Result<(), String> {
    if event.content.len() > 100_000 {
        return Err("draft ciphertext too large".into());
    }
    event.verify().map_err(|e| e.to_string())?;
    let allowed: &[&str] = if u32::from(event.kind.as_u16()) == KIND_AGENT_DRAFT {
        &["p", "agent", "r", "h", "v"]
    } else {
        &["p", "e", "previous", "generation", "state", "v"]
    };
    if event.tags.iter().any(|t| {
        !t.as_slice()
            .first()
            .is_some_and(|name| allowed.contains(&name.as_str()))
    }) {
        return Err("draft contains unsupported plaintext metadata tags".into());
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|_| "draft content is not NIP-44 base64".to_string())?;
    if decoded.len() < 99 || decoded.first() != Some(&2) {
        return Err("draft content is not NIP-44 v2".into());
    }
    if exact_tag(event, "v")? != VERSION
        || !content_looks_like_nip44(&event.content)
        || event.content.len() > 100_000
    {
        return Err("unsupported draft version or encrypted content".into());
    }
    if event.tags.iter().any(|t| {
        matches!(
            t.as_slice().first().map(String::as_str),
            Some("expiration" | "not_before" | "d")
        )
    }) {
        return Err("drafts cannot expire, be scheduled, or replace history".into());
    }
    Ok(())
}
/// Validate a durable draft's immutable owner, signer, request and channel binding.
pub fn validate_request(event: &Event) -> Result<DraftRoute, String> {
    if u32::from(event.kind.as_u16()) != KIND_AGENT_DRAFT {
        return Err("wrong request kind".into());
    }
    encrypted(event)?;
    let owner = PublicKey::from_hex(exact_tag(event, "p")?).map_err(|e| e.to_string())?;
    if exact_tag(event, "p")? != owner.to_hex() {
        return Err("owner tag must be canonical lowercase hex".into());
    }
    let agent = PublicKey::from_hex(exact_tag(event, "agent")?).map_err(|e| e.to_string())?;
    if exact_tag(event, "agent")? != agent.to_hex() {
        return Err("agent tag must be canonical lowercase hex".into());
    }
    if agent != event.pubkey || owner == agent {
        return Err("draft signer must be the delegated agent".into());
    }
    Ok(DraftRoute {
        owner,
        agent,
        request_id: uuid::Uuid::parse_str(exact_tag(event, "r")?).map_err(|e| e.to_string())?,
        channel: uuid::Uuid::parse_str(exact_tag(event, "h")?).map_err(|e| e.to_string())?,
    })
}
/// Validate an owner-authored immutable decision. The DB verifies its predecessor.
pub fn validate_decision(event: &Event) -> Result<DraftDecision, String> {
    if u32::from(event.kind.as_u16()) != KIND_AGENT_DRAFT_DECISION {
        return Err("wrong decision kind".into());
    }
    encrypted(event)?;
    let owner = PublicKey::from_hex(exact_tag(event, "p")?).map_err(|e| e.to_string())?;
    if exact_tag(event, "p")? != owner.to_hex() {
        return Err("owner tag must be canonical lowercase hex".into());
    }
    if owner != event.pubkey {
        return Err("only owner may decide a draft".into());
    }
    let generation = exact_tag(event, "generation")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    if !(1..=2).contains(&generation) {
        return Err("unsupported decision generation".into());
    }
    let state = match exact_tag(event, "state")? {
        "applying" => DecisionState::Applying,
        "applied" => DecisionState::Applied,
        "rejected" => DecisionState::Rejected,
        _ => return Err("invalid decision state".into()),
    };
    Ok(DraftDecision {
        owner,
        generation,
        state,
        request_event: nostr::EventId::from_hex(exact_tag(event, "e")?)
            .map_err(|e| e.to_string())?,
        predecessor: nostr::EventId::from_hex(exact_tag(event, "previous")?)
            .map_err(|e| e.to_string())?,
    })
}
