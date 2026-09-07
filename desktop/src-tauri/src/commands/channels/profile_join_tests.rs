use super::*;
use crate::{
    commands::channels::enrich_channel_members_from_profile_events, models::ChannelMembersResponse,
};
use nostr::{EventBuilder, Keys, Kind, Tag};
use std::{cell::RefCell, collections::HashMap, future::Future};

fn roster(count: usize) -> ChannelMembersResponse {
    ChannelMembersResponse {
        members: (0..count)
            .map(|i| ChannelMemberInfo {
                pubkey: format!("{i:064x}"),
                role: "member".to_string(),
                is_agent: false,
                joined_at: None,
                display_name: None,
            })
            .collect(),
        next_cursor: None,
    }
}

fn owned_profile(keys: &Keys) -> nostr::Event {
    let owner = Keys::generate();
    let auth = buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner, &keys.public_key(), "").unwrap();
    let tag: Vec<String> = serde_json::from_str(&auth).unwrap();
    EventBuilder::new(Kind::Metadata, r#"{"display_name":"Late agent"}"#)
        .tag(Tag::parse(tag).unwrap())
        .sign_with_keys(keys)
        .unwrap()
}

#[tokio::test]
async fn cold_large_roster_classifies_late_profiles_with_bounded_sequential_queries() {
    let agent = owned_profile(&Keys::generate());
    let human = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Late human"}"#)
        .sign_with_keys(&Keys::generate())
        .unwrap();
    let mut response = roster(10_000);
    response.members[500].pubkey = agent.pubkey.to_hex();
    response.members[9_999].pubkey = human.pubkey.to_hex();
    response.members[9_998].role = "bot".to_string();
    let expected: Vec<_> = response
        .members
        .iter()
        .map(|member| member.pubkey.clone())
        .collect();
    let calls = RefCell::new(Vec::new());
    let events = query_member_profiles(&response.members, |filter| {
        let authors = filter["authors"].as_array().unwrap();
        assert_eq!(filter["kinds"], serde_json::json!([0]));
        assert_eq!(filter["limit"], authors.len());
        assert!(authors.len() <= 500);
        calls.borrow_mut().push(authors.clone());
        let events = [&agent, &human]
            .into_iter()
            .filter(|event| authors.contains(&serde_json::json!(event.pubkey.to_hex())))
            .cloned()
            .collect();
        std::future::ready(Ok(events))
    })
    .await;
    assert_eq!(calls.borrow().len(), 20);
    assert_eq!(
        calls.into_inner().into_iter().flatten().collect::<Vec<_>>(),
        serde_json::json!(expected).as_array().unwrap().clone()
    );
    let mut cache = HashMap::new();
    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, String>(&events),
        "relay-a",
        1,
        &mut cache,
    );
    assert_eq!(response.members.len(), 10_000);
    assert_eq!(response.members[500].role, "member");
    assert!(response.members[500].is_agent);
    assert_eq!(
        response.members[500].display_name.as_deref(),
        Some("Late agent")
    );
    assert!(!response.members[9_999].is_agent);
    assert_eq!(
        response.members[9_999].display_name.as_deref(),
        Some("Late human")
    );
    assert!(response.members[9_998].is_agent);
    // The IPC flag remains classification evidence only, with no owner or
    // remote-invoke authorization fields synthesized from channel membership.
    let wire = serde_json::to_value(&response).unwrap();
    assert_eq!(wire["members"][500]["is_agent"], true);
    assert!(wire["members"][500].get("owner_pubkey").is_none());
}

#[tokio::test]
async fn failed_batches_keep_late_cache_fallback_and_do_not_skip_later_authors() {
    let keys = Keys::generate();
    let agent = owned_profile(&keys);
    let mut response = roster(1_001);
    response.members[500].pubkey = agent.pubkey.to_hex();
    let mut cache = HashMap::new();
    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, String>(&[agent]),
        "relay-a",
        1,
        &mut cache,
    );
    let human = EventBuilder::new(Kind::Metadata, "{}")
        .sign_with_keys(&keys)
        .unwrap();
    for mode in ["error", "empty", "revoked"] {
        let calls = RefCell::new(0);
        let events = query_member_profiles(&response.members, |_| {
            *calls.borrow_mut() += 1;
            std::future::ready(match mode {
                "error" => Err("relay timeout".to_string()),
                "revoked" if *calls.borrow() == 2 => Ok(vec![human.clone()]),
                _ => Ok(vec![]),
            })
        })
        .await;
        assert_eq!(*calls.borrow(), 3);
        response.members[500].is_agent = false;
        response.members[500].display_name = None;
        enrich_channel_members_from_profile_events(
            &mut response,
            Ok::<_, String>(&events),
            "relay-a",
            2,
            &mut cache,
        );
        assert_eq!(response.members[500].is_agent, mode != "revoked");
    }
    assert!(!cache[&("relay-a".to_string(), keys.public_key().to_hex())].is_agent);
}

#[tokio::test]
async fn a_failed_batch_does_not_hide_a_cold_agent_in_the_next_batch() {
    let agent = owned_profile(&Keys::generate());
    let mut response = roster(501);
    response.members[500].pubkey = agent.pubkey.to_hex();
    let events = query_member_profiles(&response.members, |filter| {
        std::future::ready(if filter["authors"].as_array().unwrap().len() == 500 {
            Err("relay timeout".to_string())
        } else {
            Ok(vec![agent.clone()])
        })
    })
    .await;
    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, String>(&events),
        "relay-a",
        1,
        &mut HashMap::new(),
    );
    assert!(response.members[500].is_agent);
}

#[tokio::test]
async fn cancellation_does_not_start_another_batch() {
    let response = roster(1_001);
    let calls = RefCell::new(0);
    let mut work = Box::pin(query_member_profiles(&response.members, |_| {
        *calls.borrow_mut() += 1;
        // The first batch completes; the second stays in flight.
        let first = *calls.borrow() == 1;
        async move {
            if !first {
                std::future::pending::<()>().await;
            }
            Ok(vec![])
        }
    }));
    std::future::poll_fn(|cx| {
        assert!(work.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(*calls.borrow(), 2);
    drop(work);
    assert_eq!(*calls.borrow(), 2);
}

#[tokio::test]
async fn empty_roster_makes_no_profile_request() {
    let calls = RefCell::new(0);
    let events = query_member_profiles(&[], |_| {
        *calls.borrow_mut() += 1;
        std::future::ready(Ok(vec![]))
    })
    .await;
    assert!(events.is_empty());
    assert_eq!(*calls.borrow(), 0);
}
