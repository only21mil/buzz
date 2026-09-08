//! Durable agent draft builders. The caller retains the signed event before sending.
use buzz_core::kind::{KIND_AGENT_DRAFT, KIND_AGENT_DRAFT_DECISION};
use nostr::{EventBuilder, Kind, Tag};
fn build(kind: u32, tags: Vec<Vec<String>>, content: &str) -> Result<EventBuilder, String> {
    let tags = tags
        .into_iter()
        .map(Tag::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(EventBuilder::new(Kind::Custom(kind as u16), content)
        .allow_self_tagging()
        .tags(tags))
}
/// Build a persistent encrypted request with a stable caller-allocated UUID.
pub fn build_agent_draft(
    owner: &str,
    agent: &str,
    request_id: &str,
    channel: &str,
    content: &str,
) -> Result<EventBuilder, String> {
    build(
        KIND_AGENT_DRAFT,
        vec![
            vec!["p".into(), owner.into()],
            vec!["agent".into(), agent.into()],
            vec!["r".into(), request_id.into()],
            vec!["h".into(), channel.into()],
            vec!["v".into(), "1".into()],
        ],
        content,
    )
}
/// Build an owner claim or terminal outcome bound to its exact predecessor.
pub fn build_agent_draft_decision(
    owner: &str,
    request: &str,
    previous: &str,
    generation: u64,
    state: &str,
    content: &str,
) -> Result<EventBuilder, String> {
    build(
        KIND_AGENT_DRAFT_DECISION,
        vec![
            vec!["p".into(), owner.into()],
            vec!["e".into(), request.into()],
            vec!["previous".into(), previous.into()],
            vec!["generation".into(), generation.to_string()],
            vec!["state".into(), state.into()],
            vec!["v".into(), "1".into()],
        ],
        content,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_decision_keeps_its_self_recipient_when_signed() {
        let owner = nostr::Keys::generate();
        let request = "11".repeat(32);
        let content = buzz_core::observer::encrypt_observer_payload(
            &owner,
            &owner.public_key(),
            &serde_json::json!({"version":1}),
        )
        .unwrap();
        let event = build_agent_draft_decision(
            &owner.public_key().to_hex(),
            &request,
            &request,
            1,
            "rejected",
            &content,
        )
        .unwrap()
        .sign_with_keys(&owner)
        .unwrap();
        assert_eq!(
            buzz_core::agent_drafts::validate_decision(&event)
                .unwrap()
                .owner,
            owner.public_key()
        );
        assert!(buzz_core::filter::reader_authorized_for_event(
            &event,
            &owner.public_key().to_hex()
        ));
    }
}
