//! Authenticated workflow delegation shared by the normal and setup listeners.
//! Event content and owner control commands retain the raw event signer.
use crate::{author_gate_decision, relay, AuthorGateDecision, OwnerCache, RespondTo};
use buzz_core::kind::KIND_STREAM_MESSAGE;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Accept only the relay's explicit, canonical owner and authored target tags.
fn verified_workflow_owner(
    event: &nostr::Event,
    relay_self: Option<&str>,
    agent_pubkey_hex: &str,
    channel_id: uuid::Uuid,
) -> Option<String> {
    if event.kind.as_u16() as u32 != KIND_STREAM_MESSAGE {
        return None;
    }

    let relay_self = nostr::PublicKey::from_hex(relay_self?).ok()?;
    if event.pubkey != relay_self || event.verify().is_err() {
        return None;
    }

    let markers: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().map(String::as_str) == Some("buzz:workflow"))
        .collect();
    if markers.as_slice() != [["buzz:workflow", "true"]] {
        return None;
    }

    let owners: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().map(String::as_str) == Some("buzz:workflow-owner"))
        .collect();
    let [owner_tag] = owners.as_slice() else {
        return None;
    };
    let [_, owner_value] = owner_tag else {
        return None;
    };
    let owner = nostr::PublicKey::from_hex(owner_value).ok()?.to_hex();
    if owner_value.as_str() != owner {
        return None;
    }

    let agent_pubkey = nostr::PublicKey::from_hex(agent_pubkey_hex).ok()?.to_hex();
    let workflow_mentions: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().map(String::as_str) == Some("buzz:workflow-mention"))
        .collect();
    let mut mentioned_pubkeys = HashSet::with_capacity(workflow_mentions.len());
    for mention_tag in workflow_mentions {
        let [_, mention_value] = mention_tag else {
            return None;
        };
        let mention = nostr::PublicKey::from_hex(mention_value).ok()?.to_hex();
        if mention_value.as_str() != mention || !mentioned_pubkeys.insert(mention) {
            return None;
        }
    }
    if !mentioned_pubkeys.contains(&agent_pubkey) {
        return None;
    }

    // Bind the attribution to the delivered channel and both wire target sets.
    let channel = channel_id.to_string();
    let channels: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().map(String::as_str) == Some("h"))
        .collect();
    if channels.as_slice() != [["h", channel.as_str()]] {
        return None;
    }
    let recipients: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|values| values.first().map(String::as_str) == Some("p"))
        .collect();
    if recipients.first().copied() != Some(&["p".to_string(), owner.clone()][..])
        || !mentioned_pubkeys.iter().all(|mentioned| {
            recipients
                .iter()
                .any(|tag| *tag == ["p", mentioned.as_str()])
        })
    {
        return None;
    }

    Some(owner)
}

/// Owns NIP-11 discovery and its connection binding for both listeners.
pub(crate) struct InboundAuthorGate {
    agent_pubkey: String,
    connection_generation: Arc<AtomicU64>,
    identity_generation: Option<u64>,
    relay_self: Option<String>,
}

impl InboundAuthorGate {
    pub(crate) async fn connect(
        rest: &relay::RestClient,
        agent_pubkey: &str,
        connection_generation: Arc<AtomicU64>,
    ) -> Self {
        let mut gate = Self {
            agent_pubkey: agent_pubkey.to_owned(),
            connection_generation,
            identity_generation: None,
            relay_self: None,
        };
        gate.refresh(rest).await;
        gate
    }

    async fn refresh(&mut self, rest: &relay::RestClient) {
        let generation = self.connection_generation.load(Ordering::Acquire);
        if self.identity_generation == Some(generation) {
            return;
        }
        // Never carry an old signing identity across an unverified reconnect.
        self.relay_self = None;
        self.identity_generation = None;
        let identity = rest.relay_self().await;
        if self.connection_generation.load(Ordering::Acquire) != generation {
            return;
        }
        match identity {
            Ok(identity) => {
                self.relay_self = identity;
                self.identity_generation = Some(generation);
            }
            Err(error) => tracing::warn!(%error, generation,
                "workflow relay identity unavailable; using raw signer policy"),
        }
    }

    /// Apply the existing author/DM policy after verifying workflow delegation.
    /// Failed discovery retries on later events. A successful document without
    /// `self` disables delegation until the next authenticated connection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn evaluate(
        &mut self,
        buzz_event: &relay::BuzzEvent,
        respond_to: &RespondTo,
        allowlist: &HashSet<String>,
        is_dm: bool,
        owner_cache: &OwnerCache,
        rest: &relay::RestClient,
    ) -> (AuthorGateDecision, String) {
        self.refresh(rest).await;
        let generation = self.connection_generation.load(Ordering::Acquire);
        let raw_author = buzz_event.event.pubkey.to_hex();
        let trusted_identity = (buzz_event.connection_generation == generation
            && self.identity_generation == Some(generation))
        .then_some(self.relay_self.as_deref())
        .flatten();
        let author = verified_workflow_owner(
            &buzz_event.event,
            trusted_identity,
            &self.agent_pubkey,
            buzz_event.channel_id,
        )
        .unwrap_or_else(|| raw_author.clone());
        let decision =
            author_gate_decision(respond_to, allowlist, &author, is_dm, owner_cache, rest).await;
        // Owner/sibling policy can await HTTP while the socket reconnects.
        if author != raw_author && self.connection_generation.load(Ordering::Acquire) != generation
        {
            return (
                author_gate_decision(respond_to, allowlist, &raw_author, is_dm, owner_cache, rest)
                    .await,
                raw_author,
            );
        }
        (decision, author)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nostr::{Event, EventBuilder, Keys, Kind, Tag};
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    pub(crate) struct TestRelay {
        pub(crate) rest: relay::RestClient,
        pub(crate) reply: Arc<Mutex<(u16, Value)>>,
        pub(crate) requests: Arc<AtomicU64>,
        pub(crate) advance_generation: Arc<Mutex<Option<Arc<AtomicU64>>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for TestRelay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub(crate) async fn test_relay(identity: Value) -> TestRelay {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let reply = Arc::new(Mutex::new((200, identity)));
        let requests = Arc::new(AtomicU64::new(0));
        let advance_generation: Arc<Mutex<Option<Arc<AtomicU64>>>> = Arc::new(Mutex::new(None));
        let task_reply = reply.clone();
        let task_requests = requests.clone();
        let task_advance = advance_generation.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 16384];
                let n = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..n]);
                task_requests.fetch_add(1, Ordering::AcqRel);
                let (status, body) = if request.starts_with("GET ") {
                    let (status, value) = task_reply.lock().unwrap().clone();
                    (status, value.to_string())
                } else {
                    // Deterministic negative sibling lookup; never contact providers.
                    (200, "[]".to_string())
                };
                if let Some(generation) = task_advance.lock().unwrap().take() {
                    generation.fetch_add(1, Ordering::AcqRel);
                }
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        TestRelay {
            rest: relay::RestClient {
                http: reqwest::Client::new(),
                base_url,
                keys: Keys::generate(),
                auth_tag_json: None,
            },
            reply,
            requests,
            advance_generation,
            task,
        }
    }

    pub(crate) fn tags(owner: &str, agent: &str, channel: Uuid) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["h".into(), channel.to_string()],
            vec!["p".into(), owner.into()],
            vec!["buzz:workflow".into(), "true".into()],
            vec!["buzz:workflow-owner".into(), owner.into()],
            vec!["buzz:workflow-effect".into(), Uuid::new_v4().to_string()],
            vec!["buzz:workflow-mention".into(), agent.into()],
        ];
        if owner != agent {
            tags.push(vec!["p".into(), agent.into()]);
        }
        tags
    }

    pub(crate) fn signed(signer: &Keys, tags: Vec<Vec<String>>, kind: Kind) -> Event {
        EventBuilder::new(kind, "scheduled prompt")
            .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
            .sign_with_keys(signer)
            .unwrap()
    }

    pub(crate) fn workflow(
        signer: &Keys,
        owner: &str,
        agent: &str,
        channel: Uuid,
        generation: u64,
    ) -> relay::BuzzEvent {
        relay::BuzzEvent {
            connection_generation: generation,
            channel_id: channel,
            event: signed(signer, tags(owner, agent, channel), Kind::Custom(9)),
        }
    }

    #[test]
    fn explicit_target_and_owner_target_are_verified() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let channel = Uuid::new_v4();
        for target in [&agent, &owner] {
            let event = workflow(&relay, &owner, target, channel, 0).event;
            assert_eq!(
                verified_workflow_owner(
                    &event,
                    Some(&relay.public_key().to_hex()),
                    target,
                    channel
                ),
                Some(owner.clone())
            );
        }
        let other = Keys::generate().public_key().to_hex();
        let mut both = tags(&owner, &agent, channel);
        both.push(vec!["p".into(), other.clone()]);
        both.push(vec!["buzz:workflow-mention".into(), other.clone()]);
        let event = signed(&relay, both, Kind::Custom(9));
        for target in [&agent, &other] {
            assert_eq!(
                verified_workflow_owner(
                    &event,
                    Some(&relay.public_key().to_hex()),
                    target,
                    channel
                ),
                Some(owner.clone())
            );
        }
    }

    #[test]
    fn forged_tampered_wrong_kind_and_missing_identity_fail_closed() {
        let relay = Keys::generate();
        let attacker = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let channel = Uuid::new_v4();
        let valid = workflow(&relay, &owner, &agent, channel, 0).event;
        let mut tampered = valid.clone();
        tampered.content.push_str(" tampered");
        let forged = workflow(&attacker, &owner, &agent, channel, 0).event;
        let wrong_kind = signed(&relay, tags(&owner, &agent, channel), Kind::TextNote);
        for event in [&tampered, &forged, &wrong_kind] {
            assert_eq!(
                verified_workflow_owner(event, Some(&relay.public_key().to_hex()), &agent, channel),
                None
            );
        }
        assert_eq!(verified_workflow_owner(&valid, None, &agent, channel), None);
        assert_eq!(
            verified_workflow_owner(
                &valid,
                Some(&attacker.public_key().to_hex()),
                &agent,
                channel
            ),
            None
        );
    }

    #[test]
    fn malformed_ambiguous_and_implicit_authority_fail_closed() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let channel = Uuid::new_v4();
        let base = tags(&owner, &agent, channel);
        let mut cases = Vec::new();
        for name in [
            "buzz:workflow",
            "buzz:workflow-owner",
            "buzz:workflow-mention",
            "h",
        ] {
            let tag = base.iter().find(|tag| tag[0] == name).unwrap();
            let mut absent = base.clone();
            absent.retain(|tag| tag[0] != name);
            cases.push((format!("absent {name}"), absent));
            let mut duplicate = base.clone();
            duplicate.push(tag.clone());
            cases.push((format!("duplicate {name}"), duplicate));
            let mut extra = base.clone();
            extra
                .iter_mut()
                .find(|tag| tag[0] == name)
                .unwrap()
                .push("extra".into());
            cases.push((format!("extra {name}"), extra));
            let mut malformed = base.clone();
            malformed.iter_mut().find(|tag| tag[0] == name).unwrap()[1] = "invalid".into();
            cases.push((format!("invalid {name}"), malformed));
        }
        for name in ["buzz:workflow-owner", "buzz:workflow-mention"] {
            let mut uppercase = base.clone();
            let tag = uppercase.iter_mut().find(|tag| tag[0] == name).unwrap();
            tag[1] = tag[1].to_uppercase();
            cases.push((format!("uppercase {name}"), uppercase));
        }
        let mut missing_rendered_target = base.clone();
        missing_rendered_target.retain(|tag| tag != &vec!["p".to_string(), agent.clone()]);
        cases.push((
            "explicit target lacks rendered p".into(),
            missing_rendered_target,
        ));
        let mut wrong_owner_p = base.clone();
        wrong_owner_p[1][1] = agent.clone();
        cases.push(("owner disagrees with attribution p".into(), wrong_owner_p));
        let mut legacy = base.clone();
        legacy.retain(|tag| {
            !["buzz:workflow-owner", "buzz:workflow-mention"].contains(&tag[0].as_str())
        });
        cases.push(("legacy claim".into(), legacy));
        for (name, tags) in cases {
            let event = signed(&relay, tags, Kind::Custom(9));
            assert_eq!(
                verified_workflow_owner(
                    &event,
                    Some(&relay.public_key().to_hex()),
                    &agent,
                    channel
                ),
                None,
                "{name}"
            );
        }
        let valid = workflow(&relay, &owner, &agent, channel, 0).event;
        assert_eq!(
            verified_workflow_owner(&valid, Some(&relay.public_key().to_hex()), &owner, channel),
            None,
            "implicit owner p must never authorize owner wake"
        );
        assert_eq!(
            verified_workflow_owner(
                &valid,
                Some(&relay.public_key().to_hex()),
                &agent,
                Uuid::new_v4()
            ),
            None,
            "wrong delivered channel"
        );
    }

    #[tokio::test]
    async fn production_gate_preserves_owner_allowlist_sibling_dm_and_nobody_policy() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let sibling = Keys::generate().public_key().to_hex();
        let external = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let server = test_relay(json!({"self": relay.public_key().to_hex()})).await;
        let generation = Arc::new(AtomicU64::new(0));
        let mut gate = InboundAuthorGate::connect(&server.rest, &agent, generation).await;
        let cache = OwnerCache::new(Some(owner.clone()));
        cache.cache_sibling(sibling.clone(), true);
        cache.cache_sibling(external.clone(), false);
        cache.cache_sibling(relay.public_key().to_hex(), false);
        let allowlist = HashSet::from([external.clone()]);
        for policy in [
            RespondTo::OwnerOnly,
            RespondTo::Allowlist,
            RespondTo::Anyone,
            RespondTo::Nobody,
        ] {
            for is_dm in [false, true] {
                for author in [&owner, &sibling, &external] {
                    let event = workflow(&relay, author, &agent, Uuid::new_v4(), 0);
                    let (decision, effective) = gate
                        .evaluate(&event, &policy, &allowlist, is_dm, &cache, &server.rest)
                        .await;
                    let allowed = !matches!(policy, RespondTo::Nobody)
                        && (author != &external
                            || (!is_dm && !matches!(policy, RespondTo::OwnerOnly)));
                    assert_eq!(
                        decision.is_allowed(),
                        allowed,
                        "{policy:?} DM {is_dm} author {author}"
                    );
                    assert_eq!(effective, *author);
                }
            }
        }
        let event = workflow(&Keys::generate(), &owner, &agent, Uuid::new_v4(), 0);
        let (decision, author) = gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest,
            )
            .await;
        assert!(!decision.is_allowed());
        assert_eq!(author, event.event.pubkey.to_hex());
        // Neither workflow attribution nor its owner can turn relay-signed text into an owner control.
        assert_ne!(event.event.pubkey.to_hex(), owner);
    }

    #[tokio::test]
    async fn reconnect_failure_cannot_reuse_old_identity_and_stale_events_cannot_delegate() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let server = test_relay(json!({"self": relay.public_key().to_hex()})).await;
        let generation = Arc::new(AtomicU64::new(0));
        let mut gate = InboundAuthorGate::connect(&server.rest, &agent, generation.clone()).await;
        let cache = OwnerCache::new(Some(owner.clone()));
        cache.cache_sibling(relay.public_key().to_hex(), false);
        let allowlist = HashSet::new();
        let mut event = workflow(&relay, &owner, &agent, Uuid::new_v4(), 0);
        assert!(gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        generation.store(1, Ordering::Release);
        *server.reply.lock().unwrap() = (503, json!({}));
        event.connection_generation = 1;
        assert!(!gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        assert!(gate.relay_self.is_none());
        *server.reply.lock().unwrap() = (200, json!({"self": relay.public_key().to_hex()}));
        event.connection_generation = 0;
        assert!(
            !gate
                .evaluate(
                    &event,
                    &RespondTo::OwnerOnly,
                    &allowlist,
                    false,
                    &cache,
                    &server.rest
                )
                .await
                .0
                .is_allowed(),
            "buffered previous-generation event must fail even when key is unchanged"
        );
        event.connection_generation = 2;
        assert!(
            !gate
                .evaluate(
                    &event,
                    &RespondTo::OwnerOnly,
                    &allowlist,
                    false,
                    &cache,
                    &server.rest
                )
                .await
                .0
                .is_allowed(),
            "future generation is not authenticated"
        );
        event.connection_generation = 1;
        assert!(gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
    }

    #[tokio::test]
    async fn reconnect_key_rotation_replaces_signer_authority() {
        let old_relay = Keys::generate();
        let new_relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let server = test_relay(json!({"self": old_relay.public_key().to_hex()})).await;
        let generation = Arc::new(AtomicU64::new(0));
        let mut gate = InboundAuthorGate::connect(&server.rest, &agent, generation.clone()).await;
        let cache = OwnerCache::new(Some(owner.clone()));
        cache.cache_sibling(old_relay.public_key().to_hex(), false);
        let allowlist = HashSet::new();
        *server.reply.lock().unwrap() = (200, json!({"self": new_relay.public_key().to_hex()}));
        generation.store(1, Ordering::Release);
        for (signer, allowed) in [(&old_relay, false), (&new_relay, true)] {
            let event = workflow(signer, &owner, &agent, Uuid::new_v4(), 1);
            assert_eq!(
                gate.evaluate(
                    &event,
                    &RespondTo::OwnerOnly,
                    &allowlist,
                    false,
                    &cache,
                    &server.rest
                )
                .await
                .0
                .is_allowed(),
                allowed
            );
        }
    }

    #[tokio::test]
    async fn startup_failure_retries_but_successful_missing_identity_is_definitive() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let server = test_relay(json!({})).await;
        *server.reply.lock().unwrap() = (503, json!({}));
        let generation = Arc::new(AtomicU64::new(0));
        let mut gate = InboundAuthorGate::connect(&server.rest, &agent, generation.clone()).await;
        let cache = OwnerCache::new(Some(owner.clone()));
        cache.cache_sibling(relay.public_key().to_hex(), false);
        let allowlist = HashSet::new();
        let mut event = workflow(&relay, &owner, &agent, Uuid::new_v4(), 0);
        assert!(!gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        *server.reply.lock().unwrap() = (200, json!({"self": relay.public_key().to_hex()}));
        assert!(gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        generation.store(1, Ordering::Release);
        event.connection_generation = 1;
        *server.reply.lock().unwrap() = (200, json!({}));
        assert!(!gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        let requests = server.requests.load(Ordering::Acquire);
        *server.reply.lock().unwrap() = (200, json!({"self": relay.public_key().to_hex()}));
        assert!(!gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
        assert_eq!(requests, server.requests.load(Ordering::Acquire));
        generation.store(2, Ordering::Release);
        event.connection_generation = 2;
        assert!(gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &allowlist,
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
    }

    #[tokio::test]
    async fn identity_response_crossing_a_reconnect_is_discarded() {
        let relay = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let agent = Keys::generate().public_key().to_hex();
        let server = test_relay(json!({"self": relay.public_key().to_hex()})).await;
        let generation = Arc::new(AtomicU64::new(0));
        *server.advance_generation.lock().unwrap() = Some(generation.clone());
        let mut gate = InboundAuthorGate::connect(&server.rest, &agent, generation).await;
        assert!(gate.relay_self.is_none());
        let cache = OwnerCache::new(Some(owner.clone()));
        cache.cache_sibling(relay.public_key().to_hex(), false);
        let event = workflow(&relay, &owner, &agent, Uuid::new_v4(), 1);
        assert!(gate
            .evaluate(
                &event,
                &RespondTo::OwnerOnly,
                &HashSet::new(),
                false,
                &cache,
                &server.rest
            )
            .await
            .0
            .is_allowed());
    }
}
