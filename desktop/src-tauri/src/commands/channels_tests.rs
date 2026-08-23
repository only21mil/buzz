// Tests for commands/channels.rs — split into a sibling file to keep
// channels.rs under the per-file line cap.

use super::*;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

/// Build a signed event for testing with the given kind, content, and tags.
fn ev(kind: u16, content: &str, tags: Vec<Vec<&str>>) -> nostr::Event {
    ev_at(kind, content, tags, Timestamp::now())
}

fn ev_at(kind: u16, content: &str, tags: Vec<Vec<&str>>, created_at: Timestamp) -> nostr::Event {
    let keys = Keys::generate();
    let parsed: Vec<Tag> = tags
        .into_iter()
        .map(|t| Tag::parse(t).expect("parse tag"))
        .collect();
    EventBuilder::new(Kind::from_u16(kind), content)
        .tags(parsed)
        .custom_created_at(created_at)
        .sign_with_keys(&keys)
        .expect("sign")
}

fn oa_profile_event(content: &str) -> nostr::Event {
    let agent_keys = Keys::generate();
    oa_profile_event_with_keys(content, &agent_keys)
}

fn oa_profile_event_with_keys(content: &str, agent_keys: &Keys) -> nostr::Event {
    let owner_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key();
    let auth_tag_json =
        buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_pubkey, "").unwrap();
    let auth_tag: Vec<String> = serde_json::from_str(&auth_tag_json).unwrap();

    EventBuilder::new(Kind::Metadata, content)
        .tag(Tag::parse(auth_tag).unwrap())
        .sign_with_keys(agent_keys)
        .unwrap()
}

// A 64-hex pubkey (nostr p-tags require 32-byte hex).
const PK_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PK_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PK_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn profile_ownership_marks_non_bot_members_as_agents() {
    let agent_profile = oa_profile_event(r#"{"display_name":"Admin agent"}"#);
    let human_profile = ev(0, r#"{"display_name":"Human member"}"#, vec![]);
    let legacy_bot = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent_profile.pubkey.to_hex();
    let human_pubkey = human_profile.pubkey.to_hex();
    let membership = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", &agent_pubkey, "", "admin"],
            vec!["p", &human_pubkey, "", "member"],
            vec!["p", &legacy_bot, "", "bot"],
        ],
    );
    let mut response = nostr_convert::channel_members_from_event(&membership).unwrap();

    assert!(!response.members[0].is_agent);
    assert!(!response.members[1].is_agent);
    assert!(response.members[2].is_agent);
    let profile_events = [agent_profile, human_profile];
    let mut profile_cache = std::collections::HashMap::new();
    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, &str>(&profile_events),
        &mut profile_cache,
    );

    assert!(response.members[0].is_agent);
    assert_eq!(response.members[0].role, "admin");
    assert_eq!(
        response.members[0].display_name.as_deref(),
        Some("Admin agent")
    );
    assert!(!response.members[1].is_agent);
    assert_eq!(response.members[1].role, "member");
    assert!(response.members[2].is_agent);
    assert_eq!(response.members[2].role, "bot");
}

#[test]
fn cached_agent_profile_survives_timeout_and_empty_lookup() {
    let agent_profile = oa_profile_event(r#"{"display_name":"Admin agent"}"#);
    let agent_pubkey = agent_profile.pubkey.to_hex();
    let membership = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", &agent_pubkey, "", "admin"],
        ],
    );
    let mut profile_cache = std::collections::HashMap::new();
    let mut fresh = nostr_convert::channel_members_from_event(&membership).unwrap();

    enrich_channel_members_from_profile_events(
        &mut fresh,
        Ok::<_, &str>(std::slice::from_ref(&agent_profile)),
        &mut profile_cache,
    );
    assert!(fresh.members[0].is_agent);
    assert_eq!(
        profile_cache.get(&agent_pubkey),
        Some(&Some("Admin agent".to_string()))
    );

    let mut after_timeout = nostr_convert::channel_members_from_event(&membership).unwrap();
    enrich_channel_members_from_profile_events(
        &mut after_timeout,
        Err("relay timeout"),
        &mut profile_cache,
    );
    assert!(after_timeout.members[0].is_agent);
    assert_eq!(
        after_timeout.members[0].display_name.as_deref(),
        Some("Admin agent")
    );

    let mut after_empty = nostr_convert::channel_members_from_event(&membership).unwrap();
    enrich_channel_members_from_profile_events(
        &mut after_empty,
        Ok::<_, &str>(&[]),
        &mut profile_cache,
    );
    assert!(after_empty.members[0].is_agent);
    assert_eq!(
        after_empty.members[0].display_name.as_deref(),
        Some("Admin agent")
    );
}

#[test]
fn unparseable_owned_profile_still_marks_and_caches_agent() {
    let agent_profile = oa_profile_event("not json");
    let agent_pubkey = agent_profile.pubkey.to_hex();
    let membership = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", &agent_pubkey, "", "admin"],
        ],
    );
    let mut response = nostr_convert::channel_members_from_event(&membership).unwrap();
    let mut profile_cache = std::collections::HashMap::new();

    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, &str>(std::slice::from_ref(&agent_profile)),
        &mut profile_cache,
    );

    assert!(response.members[0].is_agent);
    assert_eq!(response.members[0].display_name, None);
    assert_eq!(profile_cache.get(&agent_pubkey), Some(&None));
}

#[test]
fn valid_non_agent_profile_clears_cached_agent_status() {
    let agent_keys = Keys::generate();
    let agent_profile =
        oa_profile_event_with_keys(r#"{"display_name":"Former agent"}"#, &agent_keys);
    let agent_pubkey = agent_profile.pubkey.to_hex();
    let human_profile = EventBuilder::new(
        Kind::Metadata,
        r#"{"display_name":"Human profile"}"#,
    )
    .sign_with_keys(&agent_keys)
    .unwrap();
    let membership = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", &agent_pubkey, "", "admin"],
        ],
    );
    let mut profile_cache = std::collections::HashMap::new();
    let mut initial = nostr_convert::channel_members_from_event(&membership).unwrap();
    enrich_channel_members_from_profile_events(
        &mut initial,
        Ok::<_, &str>(std::slice::from_ref(&agent_profile)),
        &mut profile_cache,
    );
    assert!(initial.members[0].is_agent);

    let mut response = nostr_convert::channel_members_from_event(&membership).unwrap();
    enrich_channel_members_from_profile_events(
        &mut response,
        Ok::<_, &str>(std::slice::from_ref(&human_profile)),
        &mut profile_cache,
    );

    assert!(!response.members[0].is_agent);
    assert!(!profile_cache.contains_key(&agent_pubkey));
}

#[test]
fn directory_cursor_keeps_same_second_tiebreaker() {
    let timestamp = Timestamp::from(1_700_000_000);
    let event = ev_at(39000, "{}", vec![], timestamp);
    let mut filter = serde_json::json!({"kinds": [39000], "limit": DIRECTORY_PAGE_SIZE});

    advance_directory_cursor(&mut filter, std::slice::from_ref(&event));

    assert_eq!(filter["until"], serde_json::json!(timestamp.as_secs()));
    assert_eq!(filter["before_id"], serde_json::json!(event.id.to_hex()));
}

#[test]
fn counts_unique_p_tags_per_channel() {
    let e1 = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", PK_A, "", "member"],
            vec!["p", PK_B, "", "admin"],
        ],
    );
    let e2 = ev(
        39002,
        "",
        vec![vec!["d", "chan-2"], vec!["p", PK_C, "", "member"]],
    );

    let membership = collect_members_by_channel(&[e1, e2]);
    assert_eq!(membership.get("chan-1").map(|m| m.count), Some(2));
    assert_eq!(membership.get("chan-2").map(|m| m.count), Some(1));
    assert_eq!(membership.len(), 2);

    let mut pks: Vec<&str> = membership["chan-1"]
        .pubkeys
        .iter()
        .map(|s| s.as_str())
        .collect();
    pks.sort();
    assert_eq!(pks, vec![PK_A, PK_B]);
}

#[test]
fn dedupes_repeated_pubkeys() {
    let e = ev(
        39002,
        "",
        vec![
            vec!["d", "chan-1"],
            vec!["p", PK_A, "", "member"],
            vec!["p", PK_A, "", "admin"], // duplicate pubkey, different role
            vec!["p", PK_B, "", "member"],
        ],
    );
    let membership = collect_members_by_channel(&[e]);
    assert_eq!(membership.get("chan-1").map(|m| m.count), Some(2));
}

#[test]
fn skips_event_without_d_tag() {
    let e = ev(39002, "", vec![vec!["p", PK_A, "", "member"]]);
    let membership = collect_members_by_channel(&[e]);
    assert!(membership.is_empty());
}

#[test]
fn zero_member_channel_is_recorded() {
    // A channel with a members event but no p-tags should report 0,
    // not be absent from the map (the caller relies on `get` returning
    // `Some(0)` to overwrite a default).
    let e = ev(39002, "", vec![vec!["d", "chan-1"]]);
    let membership = collect_members_by_channel(&[e]);
    assert_eq!(membership.get("chan-1").map(|m| m.count), Some(0));
    assert!(membership["chan-1"].pubkeys.is_empty());
}

#[test]
fn empty_input_yields_empty_map() {
    let membership = collect_members_by_channel(&[]);
    assert!(membership.is_empty());
}

#[test]
fn pending_overlay_marks_relay_signed_channel_as_member() {
    // The real production shape: kind:39000 is relay-signed (#1761), so the
    // event's author is never the creator. A fresh channel's owner is
    // classified via the pending-owner overlay (populated by `create_channel`
    // in this same process), not via the event's pubkey.
    let relay_keys = Keys::generate();
    let e = EventBuilder::new(Kind::from_u16(39000), "")
        .tags(vec![
            Tag::parse(["d", "chan-1"]).expect("parse tag"),
            Tag::parse(["name", "n"]).expect("parse tag"),
        ])
        .sign_with_keys(&relay_keys)
        .expect("sign");

    let state = crate::app_state::build_app_state();
    state.mark_pending_owned_channel(PK_A, "chan-1");

    let info = crate::nostr_convert::channel_info_from_event(
        &e,
        None,
        Some(classify_pending_owner(&state, PK_A, Some("chan-1"))),
    )
    .unwrap();
    assert!(info.is_member);
}

#[test]
fn pending_overlay_leaves_unrelated_channel_as_non_member() {
    // A relay-signed channel this identity never created (not in the
    // overlay) must stay `is_member=false` — no over-broad match.
    let relay_keys = Keys::generate();
    let e = EventBuilder::new(Kind::from_u16(39000), "")
        .tags(vec![
            Tag::parse(["d", "chan-1"]).expect("parse tag"),
            Tag::parse(["name", "n"]).expect("parse tag"),
        ])
        .sign_with_keys(&relay_keys)
        .expect("sign");

    let state = crate::app_state::build_app_state();
    // Overlay has a different channel pending for the same identity, not
    // this one.
    state.mark_pending_owned_channel(PK_A, "chan-other");

    let info = crate::nostr_convert::channel_info_from_event(
        &e,
        None,
        Some(classify_pending_owner(&state, PK_A, Some("chan-1"))),
    )
    .unwrap();
    assert!(!info.is_member);
}

#[test]
fn pending_overlay_cleared_once_real_membership_observed() {
    // Once the real kind:39002 lands (modeled here as `get_channels`'s
    // cleanup step: clearing every channel id it just found real membership
    // for), the overlay must stop speaking for that channel — otherwise a
    // later leave would never flip `is_member` back to false.
    let state = crate::app_state::build_app_state();
    state.mark_pending_owned_channel(PK_A, "chan-1");
    assert!(state.is_pending_owned_channel(PK_A, "chan-1"));

    // Mirrors the `for id in &channel_ids { state.clear_pending_owned_channel(&my_pubkey, id) }`
    // step in `get_channels` once "chan-1" appears in PK_A's real member set.
    state.clear_pending_owned_channel(PK_A, "chan-1");
    assert!(!state.is_pending_owned_channel(PK_A, "chan-1"));
}

#[test]
fn pending_overlay_does_not_leak_across_identity_swap() {
    // Regression for the IMPORTANT Thufir flagged on the bare-channel-id
    // overlay: `import_identity`/workspace-apply can replace `state.keys` in
    // process without clearing the overlay. Identity A creates a channel and
    // is recorded pending-owner; if the process then switches to identity B
    // (same `AppState`, same channel id), B must NOT inherit A's entry.
    let state = crate::app_state::build_app_state();
    state.mark_pending_owned_channel(PK_A, "chan-1");

    assert!(state.is_pending_owned_channel(PK_A, "chan-1"));
    assert!(!state.is_pending_owned_channel(PK_B, "chan-1"));
}

#[test]
fn classify_pending_owner_matches_only_the_owning_identity() {
    // Exercises the exact branch-level decision `get_channels`'s open-channel
    // fallthrough makes, not just the underlying `AppState` helpers in
    // isolation.
    let state = crate::app_state::build_app_state();
    state.mark_pending_owned_channel(PK_A, "chan-1");

    assert!(classify_pending_owner(&state, PK_A, Some("chan-1")));
    // Different identity, same channel id: must not match.
    assert!(!classify_pending_owner(&state, PK_B, Some("chan-1")));
    // Same identity, different channel id: must not match.
    assert!(!classify_pending_owner(&state, PK_A, Some("chan-other")));
    // No `d` tag on the event at all: must not match.
    assert!(!classify_pending_owner(&state, PK_A, None));
}

#[test]
fn pending_owner_mark_uses_signer_captured_before_identity_swap() {
    // Regression for the write-side IMPORTANT Thufir flagged in pass 3:
    // `create_channel` used to re-read `state.keys` *after* the submit
    // await, so an identity swap that lands during the in-flight request
    // could mark the overlay under the new identity instead of the one that
    // actually signed the create. The fix captures the signer up front and
    // marks with that captured identity, so a swap that happens afterward
    // (i.e. during what would be the submit await) can't retarget the mark.
    let state = crate::app_state::build_app_state();

    // Mirrors `create_channel`'s new capture-before-submit step: read the
    // signer identity once, before anything that could race with a swap.
    let creator_keys = state.signing_keys().expect("signable");
    let creator_pubkey = creator_keys.public_key().to_hex();

    // Simulate an in-process identity swap landing during the (here,
    // implicit) submit await — e.g. `import_identity` replacing
    // `state.keys` while the create request is in flight.
    *state.keys.lock().expect("lock keys") = Keys::generate();

    // The mark must use the captured signer, not whatever `state.keys`
    // holds now.
    state.mark_pending_owned_channel(&creator_pubkey, "chan-1");

    assert!(state.is_pending_owned_channel(&creator_pubkey, "chan-1"));
    let post_swap_pubkey = state.keys.lock().expect("lock keys").public_key().to_hex();
    assert!(!state.is_pending_owned_channel(&post_swap_pubkey, "chan-1"));
}

#[test]
fn starter_channel_uuid_is_stable_and_scoped() {
    let first = starter_channel_uuid("https://relay-a.example", "general");
    let second = starter_channel_uuid("https://relay-a.example", "general");
    let other_slug = starter_channel_uuid("https://relay-a.example", "welcome-everyone");
    let other_relay = starter_channel_uuid("https://relay-b.example", "general");

    assert_eq!(first, second);
    assert_ne!(first, other_slug);
    assert_ne!(first, other_relay);
}

#[test]
fn duplicate_channel_rejection_is_ensure_success_only() {
    assert!(is_duplicate_channel_rejection(
        "relay rejected event: duplicate: channel already exists"
    ));
    assert!(!is_duplicate_channel_rejection(
        "relay rejected event: auth: not authorized"
    ));
    assert!(!is_duplicate_channel_rejection(
        "duplicate: unrelated local error"
    ));
}

#[test]
fn starter_match_requires_open_unarchived_stream_by_normalized_name() {
    let spec = &STARTER_CHANNELS[0];
    let mut channel = ChannelInfo {
        id: "chan-1".to_string(),
        name: " General ".to_string(),
        channel_type: "stream".to_string(),
        visibility: "open".to_string(),
        description: "".to_string(),
        topic: None,
        purpose: None,
        member_count: 0,
        member_pubkeys: Vec::new(),
        last_message_at: None,
        archived_at: None,
        participants: Vec::new(),
        participant_pubkeys: Vec::new(),
        is_member: true,
        ttl_seconds: None,
        ttl_deadline: None,
    };

    assert!(is_matching_starter_channel(&channel, spec));

    channel.visibility = "private".to_string();
    assert!(!is_matching_starter_channel(&channel, spec));

    channel.visibility = "open".to_string();
    channel.channel_type = "forum".to_string();
    assert!(!is_matching_starter_channel(&channel, spec));

    channel.channel_type = "stream".to_string();
    channel.archived_at = Some("2026-07-16T00:00:00Z".to_string());
    assert!(!is_matching_starter_channel(&channel, spec));
}
