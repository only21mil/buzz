use super::check_pubkey;
use nostr::Tag;

const AGENT_ADDRESS_MENTION_MARKER: &str = "agent-address";

pub(super) fn mention_reference_tags(
    mentions: &[Vec<String>],
    tags: &mut Vec<Tag>,
) -> Result<(), String> {
    for mention in mentions {
        if mention.first().map(String::as_str) != Some("mention") {
            return Err(format!(
                "mention reference tags must use 'mention' prefix (got {:?})",
                mention.first()
            ));
        }
        let Some(pubkey) = mention.get(1) else {
            return Err("mention reference tag missing pubkey".into());
        };
        if mention.len() > 3
            || (mention.len() == 3
                && mention.get(2).map(String::as_str) != Some(AGENT_ADDRESS_MENTION_MARKER))
        {
            return Err("mention reference tag has invalid display metadata".into());
        }
        check_pubkey(pubkey)?;
        let normalized_pubkey = pubkey.to_ascii_lowercase();
        let mut parts = vec!["mention", normalized_pubkey.as_str()];
        if mention.len() == 3 {
            parts.push(AGENT_ADDRESS_MENTION_MARKER);
        }
        tags.push(
            Tag::parse(parts).map_err(|error| format!("invalid mention reference tag: {error}"))?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_address_metadata_preserves_exact_recipient_without_new_p_tags() {
        let key = "a".repeat(64);
        let mut tags = Vec::new();
        mention_reference_tags(
            &[vec!["mention".into(), key.clone(), "agent-address".into()]],
            &mut tags,
        )
        .unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(
            tags[0].as_slice(),
            &["mention", key.as_str(), "agent-address"]
        );
        assert!(mention_reference_tags(
            &[vec!["mention".into(), key, "p".into()]],
            &mut Vec::new()
        )
        .is_err());
    }
}
