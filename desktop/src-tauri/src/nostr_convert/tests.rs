use super::*;
use nostr::{EventBuilder, Keys, Kind, Tag};

/// Build a signed event for testing with the given kind, content, and tags.
fn ev(kind: u16, content: &str, tags: Vec<Vec<&str>>) -> Event {
    let keys = Keys::generate();
    let parsed: Vec<Tag> = tags
        .into_iter()
        .map(|t| Tag::parse(t).expect("parse tag"))
        .collect();
    EventBuilder::new(Kind::from_u16(kind), content)
        .tags(parsed)
        .sign_with_keys(&keys)
        .expect("sign")
}

/// Build a kind:0 profile with a valid NIP-OA auth tag.
fn oa_profile_event(content: &str) -> (Event, String) {
    let agent_keys = Keys::generate();
    let owner_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key();
    let tag_json = buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_pubkey, "")
        .expect("compute auth tag");
    let tag_values: Vec<String> = serde_json::from_str(&tag_json).expect("parse auth tag json");
    let auth_tag = Tag::parse(tag_values).expect("parse auth tag");

    let event = EventBuilder::new(Kind::Metadata, content)
        .tags(vec![auth_tag])
        .sign_with_keys(&agent_keys)
        .expect("sign");
    (event, owner_keys.public_key().to_hex())
}

#[test]
fn channel_info_minimal() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "chan-uuid-1"],
            vec!["name", "general"],
            vec!["about", "main channel"],
            vec!["t", "stream"],
            vec!["public"],
        ],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.id, "chan-uuid-1");
    assert_eq!(info.name, "general");
    assert_eq!(info.description, "main channel");
    assert_eq!(info.channel_type, "stream");
    assert_eq!(info.visibility, "open");
    assert_eq!(info.member_count, 0);
    assert!(info.is_member);
}

#[test]
fn channel_info_private_when_visibility_tag_present() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "u"],
            vec!["name", "n"],
            vec!["t", "forum"],
            vec!["visibility", "private"],
            vec!["ttl", "86400"],
        ],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.visibility, "private");
    assert_eq!(info.channel_type, "forum");
    assert_eq!(info.ttl_seconds, Some(86400));
}

#[test]
fn channel_info_open_when_neither_public_nor_private() {
    // Neither tag present → open (matches NIP-29 default).
    let e = ev(
        39000,
        "",
        vec![vec!["d", "u"], vec!["name", "n"], vec!["t", "forum"]],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.visibility, "open");
}

#[test]
fn channel_info_dm_inferred_from_hidden_tag() {
    // Fallback: relays without ["t", "dm"] still emit ["hidden"] for DMs.
    let e = ev(
        39000,
        "",
        vec![vec!["d", "u"], vec!["name", "n"], vec!["hidden"]],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.channel_type, "dm");
}

#[test]
fn channel_info_merges_summary() {
    let chan = ev(39000, "", vec![vec!["d", "u"], vec!["name", "n"]]);
    let summary = ev(
        40901,
        r#"{"member_count": 7, "last_message_at": "2026-01-01T00:00:00Z"}"#,
        vec![vec!["d", "u"]],
    );
    let info = channel_info_from_event(&chan, Some(&summary), None).unwrap();
    assert_eq!(info.member_count, 7);
    assert_eq!(
        info.last_message_at.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
}

#[test]
fn channel_info_missing_d_errors() {
    let e = ev(39000, "", vec![vec!["name", "n"]]);
    assert!(channel_info_from_event(&e, None, None).is_err());
}

#[test]
fn channel_detail_basic() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "uuid"],
            vec!["name", "n"],
            vec!["about", "desc"],
            vec!["topic", "tt"],
            vec!["purpose", "pp"],
            vec!["t", "dm"],
            vec!["visibility", "private"],
            vec!["ttl", "86400"],
            vec!["ttl_deadline", "2026-06-11T00:00:00Z"],
        ],
    );
    let d = channel_detail_from_event(&e).unwrap();
    assert_eq!(d.id, "uuid");
    assert_eq!(d.topic.as_deref(), Some("tt"));
    assert_eq!(d.purpose.as_deref(), Some("pp"));
    assert_eq!(d.channel_type, "dm");
    assert_eq!(d.visibility, "private");
    assert_eq!(d.ttl_seconds, Some(86400));
    assert_eq!(d.ttl_deadline.as_deref(), Some("2026-06-11T00:00:00Z"));
    assert!(d.created_at.ends_with("Z"));
    assert_eq!(d.created_by, e.pubkey.to_hex());
}

#[test]
fn channel_members_extracts_p_tags() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    let e = ev(
        39002,
        "",
        vec![
            vec!["d", "uuid"],
            vec!["p", &pk1, "", "admin"],
            vec!["p", &pk2],
            // Duplicate must be deduped.
            vec!["p", &pk1, "wss://x", "owner"],
        ],
    );
    let r = channel_members_from_event(&e).unwrap();
    assert_eq!(r.members.len(), 2);
    assert_eq!(r.members[0].pubkey, pk1);
    assert_eq!(r.members[0].role, "admin");
    assert!(r.members[0].joined_at.is_none());
    assert_eq!(r.members[1].role, "member"); // default
}

#[test]
fn channel_members_missing_d_errors() {
    let e = ev(39002, "", vec![]);
    assert!(channel_members_from_event(&e).is_err());
}

#[test]
fn profile_info_parses_content() {
    let e = ev(
        0,
        r#"{"name":"alice","display_name":"Alice","picture":"http://x/a.png","about":"hi","nip05":"alice@x"}"#,
        vec![],
    );
    let p = profile_info_from_event(&e).unwrap();
    assert_eq!(p.display_name.as_deref(), Some("Alice"));
    assert_eq!(p.avatar_url.as_deref(), Some("http://x/a.png"));
    assert_eq!(p.about.as_deref(), Some("hi"));
    assert_eq!(p.nip05_handle.as_deref(), Some("alice@x"));
    assert_eq!(p.pubkey, e.pubkey.to_hex());
    assert!(p.owner_pubkey.is_none());
}

#[test]
fn profile_info_extracts_valid_nip_oa_owner() {
    let (event, owner_pubkey) = oa_profile_event(r#"{"display_name":"Mira"}"#);
    let p = profile_info_from_event(&event).unwrap();

    assert_eq!(p.owner_pubkey.as_deref(), Some(owner_pubkey.as_str()));
}

#[test]
fn profile_info_falls_back_to_name() {
    let e = ev(0, r#"{"name":"bob"}"#, vec![]);
    let p = profile_info_from_event(&e).unwrap();
    assert_eq!(p.display_name.as_deref(), Some("bob"));
}

#[test]
fn profile_info_invalid_json_errors() {
    let e = ev(0, "not-json", vec![]);
    assert!(profile_info_from_event(&e).is_err());
}

#[test]
fn users_batch_keeps_latest_and_reports_missing() {
    let e1 = ev(0, r#"{"name":"old"}"#, vec![]);
    // Same author, newer event with display_name.
    let keys = Keys::generate();
    let e_old = EventBuilder::new(Kind::Metadata, r#"{"name":"old"}"#)
        .custom_created_at(nostr::Timestamp::from(1000))
        .sign_with_keys(&keys)
        .unwrap();
    let e_new = EventBuilder::new(Kind::Metadata, r#"{"display_name":"New"}"#)
        .custom_created_at(nostr::Timestamp::from(2000))
        .sign_with_keys(&keys)
        .unwrap();
    let pk = keys.public_key().to_hex();
    let other_pk = e1.pubkey.to_hex();

    let missing_pk = "f".repeat(64);
    let resp = users_batch_from_events(
        &[e1, e_old, e_new],
        &[pk.clone(), other_pk.clone(), missing_pk.clone()],
    );
    assert_eq!(resp.profiles.len(), 2);
    assert_eq!(resp.profiles[&pk].display_name.as_deref(), Some("New"));
    assert_eq!(resp.missing, vec![missing_pk]);
}

#[test]
fn users_batch_marks_valid_nip_oa_profiles_as_agents() {
    let (agent, owner_pubkey) = oa_profile_event(r#"{"display_name":"Mira"}"#);
    let pubkey = agent.pubkey.to_hex();
    let resp = users_batch_from_events(std::slice::from_ref(&agent), std::slice::from_ref(&pubkey));

    assert!(resp.profiles[&pubkey].is_agent);
    assert_eq!(
        resp.profiles[&pubkey].owner_pubkey.as_deref(),
        Some(owner_pubkey.as_str())
    );
}

#[test]
fn user_notes_builds_cursor_from_last() {
    let e1 = ev(1, "first", vec![]);
    let e2 = ev(1, "second", vec![]);
    let r = user_notes_from_events(&[e1, e2]);
    assert_eq!(r.notes.len(), 2);
    assert_eq!(r.notes[0].content, "first");
    let cursor = r.next_cursor.expect("cursor");
    assert_eq!(cursor.before_id, r.notes[1].id);
}

#[test]
fn user_notes_empty_has_no_cursor() {
    let r = user_notes_from_events(&[]);
    assert!(r.notes.is_empty());
    assert!(r.next_cursor.is_none());
}

#[test]
fn contact_list_preserves_tags_and_content() {
    let pk = "1".repeat(64);
    let e = ev(3, "rel-json", vec![vec!["p", &pk]]);
    let r = contact_list_from_event(&e).unwrap();
    assert_eq!(r.content, "rel-json");
    assert_eq!(r.tags.len(), 1);
    assert_eq!(r.tags[0], vec!["p".to_string(), pk]);
}

#[test]
fn search_response_assigns_descending_scores() {
    let e1 = ev(1, "one", vec![vec!["h", "chan"]]);
    let e2 = ev(1, "two", vec![]);
    let r = search_response_from_events(&[e1, e2]);
    assert_eq!(r.found, 2);
    assert!(r.hits[0].score > r.hits[1].score);
    assert_eq!(r.hits[0].channel_id.as_deref(), Some("chan"));
    assert!(r.hits[1].channel_id.is_none());
}

#[test]
fn search_response_single_hit_full_score() {
    let e = ev(1, "only", vec![]);
    let r = search_response_from_events(&[e]);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].score, 1.0);
}

#[test]
fn agents_overwrites_pubkey_from_event_author() {
    let e = ev(10100, r#"{"pubkey":"forged","name":"agent-1"}"#, vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let arr = v.get("agents").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("pubkey").and_then(Value::as_str).unwrap(),
        e.pubkey.to_hex()
    );
    assert_eq!(arr[0].get("name").and_then(Value::as_str), Some("agent-1"));
}

#[test]
fn agents_handles_invalid_content() {
    let e = ev(10100, "not-json", vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let arr = v.get("agents").and_then(Value::as_array).unwrap();
    assert_eq!(
        arr[0].get("pubkey").and_then(Value::as_str).unwrap(),
        e.pubkey.to_hex()
    );
}

#[test]
fn agents_default_sparse_agent_profiles_for_directory_parse() {
    let e = ev(
        10100,
        r#"{"channel_add_policy":"owner-only","display_name":"Scout"}"#,
        vec![],
    );
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].pubkey, e.pubkey.to_hex());
    assert_eq!(parsed[0].name, "Scout");
    assert_eq!(parsed[0].agent_type, "agent");
    assert_eq!(parsed[0].channels, Vec::<String>::new());
    assert_eq!(parsed[0].capabilities, Vec::<String>::new());
    assert_eq!(parsed[0].status, "offline");
    assert_eq!(parsed[0].respond_to, None);
}

#[test]
fn agents_preserves_public_respond_to_mode_for_directory_parse() {
    let e = ev(10100, r#"{"name":"Scout","respond_to":"anyone"}"#, vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].respond_to,
        Some(crate::managed_agents::RespondTo::Anyone)
    );
}

#[test]
fn agents_preserves_allowlist_metadata_for_directory_parse() {
    let e = ev(
        10100,
        r#"{"name":"Scout","respond_to":"allowlist","respond_to_allowlist":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
        vec![],
    );
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].respond_to,
        Some(crate::managed_agents::RespondTo::Allowlist)
    );
    assert_eq!(parsed[0].respond_to_allowlist, vec!["a".repeat(64)]);
}

#[test]
fn relay_members_dedupes_and_defaults_role() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    // Current relay format: ["member", pubkey, role]
    let e = ev(
        13534,
        "",
        vec![
            vec!["member", &pk1, "owner"],
            vec!["member", &pk2],
            vec!["member", &pk1, "moderator"], // dupe — ignored
        ],
    );
    let v = relay_members_from_event(&e);
    let arr = v.get("members").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].get("role").and_then(Value::as_str), Some("owner"));
    assert_eq!(arr[1].get("role").and_then(Value::as_str), Some("member"));
}

#[test]
fn relay_members_fallback_p_tags() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    // Legacy/fallback format: ["p", pubkey, relay_url?, role?]
    let e = ev(
        13534,
        "",
        vec![vec!["p", &pk1, "", "admin"], vec!["p", &pk2]],
    );
    let v = relay_members_from_event(&e);
    let arr = v.get("members").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].get("role").and_then(Value::as_str), Some("admin"));
    assert_eq!(arr[1].get("role").and_then(Value::as_str), Some("member"));
}

#[test]
fn timestamp_to_iso_known_value() {
    // 2021-01-01T00:00:00Z = 1609459200
    assert_eq!(timestamp_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
    // Epoch
    assert_eq!(timestamp_to_iso(0), "1970-01-01T00:00:00Z");
}
