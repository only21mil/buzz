//! Explicit tooling opt-in to the self-message loop guard.
//!
//! This only opens the self filter. Author policy, subscription rules, inbox
//! replay tracking and queue scheduling still run in their normal order.
use crate::relay::BuzzEvent;
use buzz_core::kind::KIND_STREAM_MESSAGE;

pub(crate) fn should_ignore_self(event: &BuzzEvent, agent: &str, ignore_self: bool) -> bool {
    ignore_self && event.event.pubkey.to_hex() == agent && !is_self_wake(event, agent)
}

fn is_self_wake(event: &BuzzEvent, agent: &str) -> bool {
    let signed = &event.event;
    if signed.kind.as_u16() as u32 != KIND_STREAM_MESSAGE
        || signed.pubkey.to_hex() != agent
        || signed.verify().is_err()
    {
        return false;
    }
    let wake_tags: Vec<&[String]> = signed
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|tag| tag.first().map(String::as_str) == Some("wake"))
        .collect();
    let channel_tags: Vec<&[String]> = signed
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|tag| tag.first().map(String::as_str) == Some("h"))
        .collect();
    wake_tags.as_slice() == [["wake", "self"]]
        && channel_tags.as_slice() == [["h", event.channel_id.to_string().as_str()]]
        && signed.tags.iter().any(|tag| tag.as_slice() == ["p", agent])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};
    use uuid::Uuid;

    fn message(keys: &Keys, channel: Uuid, kind: u16, tags: Vec<Vec<String>>) -> BuzzEvent {
        BuzzEvent {
            event: EventBuilder::new(Kind::from(kind), "tool finished")
                .allow_self_tagging()
                .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
                .sign_with_keys(keys)
                .unwrap(),
            channel_id: channel,
            connection_generation: 0,
        }
    }

    fn tags(agent: &str, channel: Uuid) -> Vec<Vec<String>> {
        vec![
            vec!["h".into(), channel.to_string()],
            vec!["p".into(), agent.into()],
            vec!["wake".into(), "self".into()],
        ]
    }

    #[test]
    fn self_wake_requires_signed_opt_in_target_and_channel() {
        let keys = Keys::generate();
        let other = Keys::generate();
        let agent = keys.public_key().to_hex();
        let channel = Uuid::new_v4();
        let valid = message(&keys, channel, 9, tags(&agent, channel));
        assert!(is_self_wake(&valid, &agent));
        assert!(!should_ignore_self(&valid, &agent, true));
        let mut forged = valid.clone();
        forged.event.content = "forged".into();
        assert!(!is_self_wake(&forged, &agent));
        let mut variants = Vec::new();
        let mut missing = tags(&agent, channel);
        missing.pop();
        variants.push(missing); // ordinary self-mention, including an agent's reply
        let mut duplicate = tags(&agent, channel);
        duplicate.push(vec!["wake".into(), "self".into()]);
        variants.push(duplicate);
        let mut malformed = tags(&agent, channel);
        malformed[2].push("extra".into());
        variants.push(malformed);
        let mut wrong_target = tags(&agent, channel);
        wrong_target[1][1] = other.public_key().to_hex();
        variants.push(wrong_target);
        let mut duplicate_channel = tags(&agent, channel);
        duplicate_channel.push(vec!["h".into(), channel.to_string()]);
        variants.push(duplicate_channel);
        variants.push(tags(&agent, Uuid::new_v4()));
        for variant in variants {
            let event = message(&keys, channel, 9, variant);
            assert!(should_ignore_self(&event, &agent, true));
            assert!(
                !should_ignore_self(&event, &agent, false),
                "explicit legacy opt-out is preserved"
            );
        }
        assert!(!is_self_wake(
            &message(&keys, channel, 7, tags(&agent, channel)),
            &agent
        ));
        assert!(!is_self_wake(
            &message(&other, channel, 9, tags(&agent, channel)),
            &agent
        ));
        assert!(!is_self_wake(&valid, &other.public_key().to_hex()));
    }

    #[tokio::test]
    async fn self_wake_keeps_policy_rules_dedup_and_normal_queue_scheduling() {
        use crate::{
            filter,
            workflow_auth::{tests::test_relay, InboundAuthorGate},
        };
        use std::{
            collections::HashSet,
            sync::{atomic::AtomicU64, Arc},
        };
        let keys = Keys::generate();
        let agent = keys.public_key().to_hex();
        let channel = Uuid::new_v4();
        let owner = Keys::generate().public_key().to_hex();
        let server = test_relay(serde_json::json!({})).await;
        let cache = crate::OwnerCache::new(Some(owner));
        // Existing author policy still requires a verified same-owner profile.
        cache.cache_sibling(agent.clone(), true);
        let unowned = crate::OwnerCache::new(None);
        let mut gate =
            InboundAuthorGate::connect(&server.rest, &agent, Arc::new(AtomicU64::new(0))).await;
        let event = message(&keys, channel, 9, tags(&agent, channel));
        assert!(!should_ignore_self(&event, &agent, true));
        for is_dm in [false, true] {
            for policy in [
                crate::RespondTo::OwnerOnly,
                crate::RespondTo::Allowlist,
                crate::RespondTo::Anyone,
                crate::RespondTo::Nobody,
            ] {
                let (decision, author) = gate
                    .evaluate(
                        &event,
                        &policy,
                        &HashSet::new(),
                        is_dm,
                        &cache,
                        &server.rest,
                    )
                    .await;
                assert_eq!(
                    decision.is_allowed(),
                    !matches!(policy, crate::RespondTo::Nobody)
                );
                assert_eq!(author, agent, "self wake must not impersonate its owner");
            }
            assert!(!gate
                .evaluate(
                    &event,
                    &crate::RespondTo::OwnerOnly,
                    &HashSet::new(),
                    is_dm,
                    &unowned,
                    &server.rest
                )
                .await
                .0
                .is_allowed());
        }
        let forged_target = message(&Keys::generate(), channel, 9, tags(&agent, channel));
        assert!(
            !gate
                .evaluate(
                    &forged_target,
                    &crate::RespondTo::OwnerOnly,
                    &HashSet::new(),
                    false,
                    &cache,
                    &server.rest,
                )
                .await
                .0
                .is_allowed(),
            "another signer cannot use the self marker as an authority grant"
        );
        let rules = vec![filter::SubscriptionRule {
            kinds: vec![9],
            require_mention: true,
            ..Default::default()
        }];
        let matched = filter::match_event(&event.event, channel, &rules, &agent)
            .await
            .unwrap();
        let excluded = vec![filter::SubscriptionRule {
            kinds: vec![7],
            ..Default::default()
        }];
        assert!(
            filter::match_event(&event.event, channel, &excluded, &agent)
                .await
                .is_none()
        );
        let temp = std::env::temp_dir().join(format!("buzz-self-wake-{}", Uuid::new_v4()));
        let mut inbox = crate::inbox_cursor::InboxCursorStore::load(&temp, &agent, 0, 10);
        let mut queue = crate::EventQueue::new(crate::DedupMode::Queue);
        assert!(inbox.begin_event(&event.event));
        assert!(queue.push(crate::queue::QueuedEvent {
            channel_id: channel,
            scope: crate::scope::SessionScope::Conversation {
                channel_id: channel
            },
            event: event.event.clone(),
            received_at: std::time::Instant::now(),
            prompt_tag: matched.prompt_tag,
        }));
        assert!(!inbox.begin_event(&event.event));
        let mut lifecycle = crate::pool_lifecycle::PoolLifecycle::<()>::listening();
        let now = tokio::time::Instant::now();
        assert_eq!(
            lifecycle.start_wake_if_due(queue.has_flushable_work(), now),
            Some(1)
        );
        assert_eq!(
            lifecycle.start_wake_if_due(queue.has_flushable_work(), now),
            None
        );
        let batch = queue.flush_next().unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].event.id, event.event.id);
        assert_eq!(batch.events[0].event.pubkey, keys.public_key());
        inbox.mark_processed([&event.event]);
        let mut reloaded = crate::inbox_cursor::InboxCursorStore::load(&temp, &agent, 0, 10);
        assert!(
            !reloaded.begin_event(&event.event),
            "completed replay must not wake again"
        );
        // Ordinary agent output never copies the opt-in marker and cannot recurse.
        let mut reply_tags = tags(&agent, channel);
        reply_tags.pop();
        let reply = message(&keys, channel, 9, reply_tags);
        assert!(should_ignore_self(&reply, &agent, true));
        assert!(crate::mode_gate_signal(
            crate::MultipleEventHandling::OwnerInterrupt,
            &agent,
            cache.get()
        )
        .is_none());
        std::fs::remove_dir_all(temp).unwrap();
    }
}
