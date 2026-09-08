//! Tests for the Nostr conversion surface.

use super::*;
use nostr::{EventBuilder, Keys, Kind, Tag};

#[path = "runtime_policy_tests.rs"]
mod runtime_policy_tests;

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

fn managed_agent_event(
    owner_keys: &Keys,
    agent_pubkey: &str,
    name: &str,
    respond_to: &str,
    respond_to_allowlist: &[String],
) -> Event {
    let content = serde_json::json!({
        "name": name,
        "parallelism": 1,
        "respond_to": respond_to,
        "respond_to_allowlist": respond_to_allowlist,
    })
    .to_string();
    EventBuilder::new(Kind::Custom(30177), content)
        .tags([Tag::parse(["d", agent_pubkey]).expect("parse d tag")])
        .sign_with_keys(owner_keys)
        .expect("sign managed-agent event")
}

#[test]
fn relay_agent_directory_tolerates_malformed_descriptive_arrays() {
    use crate::managed_agents::{RelayAgentInfo, RespondTo};

    let peer = ev(
        10100,
        r#"{"name":"Valid peer","respond_to":"owner-only"}"#,
        vec![],
    );
    for field in ["channels", "channel_ids", "capabilities"] {
        for (value, expected) in [
            (
                json!(["valid", 17, null, {}, [], false, "also-valid"]),
                vec!["valid", "also-valid"],
            ),
            (json!(null), vec![]),
            (json!("not-an-array"), vec![]),
            (json!({}), vec![]),
        ] {
            let mut content = json!({
                "name": "Mixed profile",
                "status": "online",
                "respond_to": "allowlist",
                "respond_to_allowlist": ["a".repeat(64)],
            });
            content[field] = value;
            let malformed = ev(10100, &content.to_string(), vec![]);
            let events = [malformed.clone(), peer.clone()];
            let converted = agents_from_events(&events);
            let typed: Vec<RelayAgentInfo> =
                serde_json::from_value(converted["agents"].clone()).expect("typed directory");
            assert_eq!(typed.len(), 2, "field: {field}");
            let mixed = typed
                .iter()
                .find(|agent| agent.name == "Mixed profile")
                .unwrap();
            let normalized = serde_json::to_value(mixed).unwrap();
            assert_eq!(normalized[field], json!(expected), "field: {field}");
            assert_eq!(mixed.respond_to, Some(RespondTo::Allowlist));
            assert_eq!(mixed.respond_to_allowlist, vec!["a".repeat(64)]);

            let directory = relay_agents_from_directory_events(&events, &[], &[]);
            assert_eq!(directory.len(), 2, "field: {field}");
            let mixed = directory
                .iter()
                .find(|agent| agent.pubkey == malformed.pubkey.to_hex())
                .unwrap();
            assert_eq!(mixed.status, "online");
            assert!(
                mixed.channel_ids.is_empty(),
                "runtime profile cannot grant membership"
            );
        }
    }
}

#[test]
fn relay_agent_directory_rejects_malformed_policy_without_losing_valid_peers() {
    let peer = ev(
        10100,
        r#"{"name":"Valid peer","respond_to":"owner-only"}"#,
        vec![],
    );
    for (field, value) in [
        ("respond_to", json!("unknown-mode")),
        ("respond_to", json!(17)),
        ("respond_to_allowlist", json!(["a".repeat(64), 17])),
        ("respond_to_allowlist", json!("not-an-array")),
        ("respond_to_allowlist", json!(null)),
    ] {
        let mut content = json!({"name": "Malformed policy", "respond_to": "allowlist"});
        content[field] = value.clone();
        let malformed = ev(10100, &content.to_string(), vec![]);
        let converted = agents_from_events(std::slice::from_ref(&malformed));
        assert_eq!(
            converted["agents"][0][field], value,
            "policy must remain strict"
        );
        for events in [[malformed.clone(), peer.clone()], [peer.clone(), malformed]] {
            let directory = relay_agents_from_directory_events(&events, &[], &[]);
            assert_eq!(directory.len(), 1, "field: {field}, value: {value}");
            assert_eq!(directory[0].pubkey, peer.pubkey.to_hex());
        }
    }
}

#[test]
fn managed_agent_directory_accepts_only_the_verified_owner_policy() {
    let agent_keys = Keys::generate();
    let owner_keys = Keys::generate();
    let attacker_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key().to_hex();
    let viewer_pubkey = "a".repeat(64);

    let auth_tag_json =
        buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_keys.public_key(), "")
            .expect("compute auth tag");
    let auth_tag_values: Vec<String> =
        serde_json::from_str(&auth_tag_json).expect("parse auth tag json");
    let profile = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Codex"}"#)
        .tags([Tag::parse(auth_tag_values).expect("parse auth tag")])
        .sign_with_keys(&agent_keys)
        .expect("sign profile");
    let authentic = managed_agent_event(
        &owner_keys,
        &agent_pubkey,
        "Codex",
        "allowlist",
        std::slice::from_ref(&viewer_pubkey),
    );
    let forged = managed_agent_event(&attacker_keys, &agent_pubkey, "Fake Codex", "anyone", &[]);

    let agents = relay_agents_from_managed_agent_events(
        &[forged, authentic],
        std::slice::from_ref(&profile),
    );

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].pubkey, agent_pubkey);
    assert_eq!(agents[0].name, "Codex");
    assert_eq!(agents[0].status, "unknown");
    assert_eq!(
        serde_json::to_value(&agents[0]).unwrap()["status"],
        "unknown"
    );
    assert_eq!(
        agents[0].respond_to,
        Some(crate::managed_agents::RespondTo::Allowlist)
    );
    assert_eq!(agents[0].respond_to_allowlist, vec![viewer_pubkey]);
}

#[test]
fn managed_agent_directory_rejects_agents_without_verified_owner_profiles() {
    let owner_keys = Keys::generate();
    let unverified_agent_keys = Keys::generate();
    let agent_pubkey = unverified_agent_keys.public_key().to_hex();
    let profile = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Codex"}"#)
        .sign_with_keys(&unverified_agent_keys)
        .expect("sign profile");
    let managed = managed_agent_event(&owner_keys, &agent_pubkey, "Codex", "anyone", &[]);

    let agents = relay_agents_from_managed_agent_events(
        std::slice::from_ref(&managed),
        std::slice::from_ref(&profile),
    );

    assert!(agents.is_empty());
}

#[test]
fn managed_agent_directory_uses_the_latest_profile_head() {
    let agent_keys = Keys::generate();
    let owner_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key().to_hex();
    let auth_tag_json =
        buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_keys.public_key(), "")
            .expect("compute auth tag");
    let auth_tag_values: Vec<String> =
        serde_json::from_str(&auth_tag_json).expect("parse auth tag json");
    let verified_profile = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Codex"}"#)
        .tags([Tag::parse(auth_tag_values).expect("parse auth tag")])
        .custom_created_at(nostr::Timestamp::from(10))
        .sign_with_keys(&agent_keys)
        .expect("sign verified profile");
    let revoked_profile = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Codex"}"#)
        .custom_created_at(nostr::Timestamp::from(20))
        .sign_with_keys(&agent_keys)
        .expect("sign revoked profile");
    let managed = managed_agent_event(&owner_keys, &agent_pubkey, "Codex", "anyone", &[]);

    let agents = relay_agents_from_managed_agent_events(
        std::slice::from_ref(&managed),
        &[verified_profile, revoked_profile],
    );

    assert!(agents.is_empty());
}

#[test]
fn managed_agent_candidates_use_only_relay_signed_bot_membership() {
    let relay_keys = Keys::generate();
    let agent_pubkey = Keys::generate().public_key().to_hex();
    let stranger = Keys::generate().public_key().to_hex();
    let general = EventBuilder::new(Kind::Custom(39002), "")
        .tags([
            Tag::parse(["d", "family"]).expect("parse d tag"),
            Tag::parse(["p", &agent_pubkey, "", "bot"]).expect("parse agent tag"),
            Tag::parse(["p", &stranger, "", "member"]).expect("parse member tag"),
        ])
        .sign_with_keys(&relay_keys)
        .expect("sign membership");
    let forged = ev(
        39002,
        "",
        vec![vec!["d", "forged"], vec!["p", &agent_pubkey, "", "bot"]],
    );

    let channel_ids = member_agent_channel_ids_from_events(
        &[forged, general],
        &relay_keys.public_key().to_hex(),
        &Default::default(),
    );

    assert_eq!(
        channel_ids.get(&agent_pubkey),
        Some(&vec!["family".to_string()])
    );
    assert!(!channel_ids.contains_key(&stranger));
}

#[test]
fn managed_agent_directory_query_pubkeys_reject_malformed_d_tags() {
    let valid_pubkey = Keys::generate().public_key().to_hex();
    let valid = ev(30177, "{}", vec![vec!["d", &valid_pubkey]]);
    let malformed = ev(30177, "{}", vec![vec!["d", "not-a-pubkey"]]);

    let pubkeys = managed_agent_pubkeys_from_events(&[malformed, valid]);

    assert_eq!(pubkeys, [valid_pubkey].into_iter().collect());
}

#[test]
fn relay_agent_directory_preserves_headless_profiles_and_prefers_verified_managed_policy() {
    let owner_keys = Keys::generate();
    let managed_agent_keys = Keys::generate();
    let managed_pubkey = managed_agent_keys.public_key().to_hex();
    let headless_keys = Keys::generate();
    let headless_pubkey = headless_keys.public_key().to_hex();
    let viewer_pubkey = "a".repeat(64);

    let headless_profile = EventBuilder::new(
        Kind::Custom(10100),
        serde_json::json!({
            "name": "Headless",
            "respond_to": "anyone",
            "channel_ids": ["untrusted-channel"]
        })
        .to_string(),
    )
    .sign_with_keys(&headless_keys)
    .expect("sign headless directory profile");
    let stale_managed_profile = EventBuilder::new(
        Kind::Custom(10100),
        serde_json::json!({
            "name": "Stale Codex",
            "respond_to": "anyone"
        })
        .to_string(),
    )
    .sign_with_keys(&managed_agent_keys)
    .expect("sign managed directory profile");

    let auth_tag_json =
        buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &managed_agent_keys.public_key(), "")
            .expect("compute auth tag");
    let auth_tag_values: Vec<String> =
        serde_json::from_str(&auth_tag_json).expect("parse auth tag json");
    let managed_identity = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Codex"}"#)
        .tags([Tag::parse(auth_tag_values).expect("parse auth tag")])
        .sign_with_keys(&managed_agent_keys)
        .expect("sign managed profile");
    let managed_policy = managed_agent_event(
        &owner_keys,
        &managed_pubkey,
        "Codex",
        "allowlist",
        std::slice::from_ref(&viewer_pubkey),
    );

    let agents = relay_agents_from_directory_events(
        &[headless_profile, stale_managed_profile],
        std::slice::from_ref(&managed_policy),
        std::slice::from_ref(&managed_identity),
    );

    assert_eq!(agents.len(), 2);
    let headless = agents
        .iter()
        .find(|agent| agent.pubkey == headless_pubkey)
        .expect("headless profile retained");
    assert_eq!(
        headless.respond_to,
        Some(crate::managed_agents::RespondTo::Anyone)
    );
    assert!(
        headless.channel_ids.is_empty(),
        "claimed channel ids are not trusted"
    );

    let managed = agents
        .iter()
        .find(|agent| agent.pubkey == managed_pubkey)
        .expect("managed profile retained");
    assert_eq!(managed.name, "Codex");
    assert_eq!(
        managed.respond_to,
        Some(crate::managed_agents::RespondTo::Allowlist)
    );
    assert_eq!(managed.respond_to_allowlist, vec![viewer_pubkey]);
}

#[test]
fn authenticated_malformed_managed_policy_does_not_fall_back_to_legacy_permissions() {
    let owner_keys = Keys::generate();
    let agent_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key().to_hex();
    let legacy = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"Stale","respond_to":"anyone"}"#,
    )
    .sign_with_keys(&agent_keys)
    .expect("sign legacy profile");
    let auth_tag_json =
        buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_keys.public_key(), "")
            .expect("compute auth tag");
    let auth_tag_values: Vec<String> =
        serde_json::from_str(&auth_tag_json).expect("parse auth tag json");
    let profile = EventBuilder::new(Kind::Metadata, "{}")
        .tags([Tag::parse(auth_tag_values).expect("parse auth tag")])
        .sign_with_keys(&agent_keys)
        .expect("sign profile");
    let malformed = EventBuilder::new(
        Kind::Custom(30177),
        r#"{"name":"Current","parallelism":1,"respond_to":"future-mode"}"#,
    )
    .tags([Tag::parse(["d", &agent_pubkey]).expect("parse d tag")])
    .sign_with_keys(&owner_keys)
    .expect("sign managed policy");

    let agents = relay_agents_from_directory_events(&[legacy], &[malformed], &[profile]);

    assert!(agents.is_empty());
}

#[test]
fn relay_agent_directory_resolves_equal_timestamp_heads_by_event_id() {
    let keys = Keys::generate();
    let timestamp = nostr::Timestamp::from(42);
    let first = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"First","respond_to":"anyone"}"#,
    )
    .custom_created_at(timestamp)
    .sign_with_keys(&keys)
    .expect("sign first directory head");
    let second = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"Second","respond_to":"anyone"}"#,
    )
    .custom_created_at(timestamp)
    .sign_with_keys(&keys)
    .expect("sign second directory head");
    let expected_name = if first.id < second.id {
        "First"
    } else {
        "Second"
    };

    let forward = relay_agents_from_directory_events(&[first.clone(), second.clone()], &[], &[]);
    let reverse = relay_agents_from_directory_events(&[second, first], &[], &[]);

    assert_eq!(forward.len(), 1);
    assert_eq!(reverse.len(), 1);
    assert_eq!(forward[0].name, expected_name);
    assert_eq!(reverse[0].name, expected_name);
}

#[test]
fn forged_managed_policy_cannot_suppress_a_headless_directory_agent() {
    let attacker_keys = Keys::generate();
    let targeted_agent_keys = Keys::generate();
    let targeted_pubkey = targeted_agent_keys.public_key().to_hex();
    let headless_keys = Keys::generate();
    let headless_pubkey = headless_keys.public_key().to_hex();
    let targeted_profile = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"Targeted","respond_to":"anyone"}"#,
    )
    .sign_with_keys(&targeted_agent_keys)
    .expect("sign targeted profile");
    let headless = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"Headless","respond_to":"anyone"}"#,
    )
    .sign_with_keys(&headless_keys)
    .expect("sign headless profile");
    let forged_policy = managed_agent_event(
        &attacker_keys,
        &targeted_pubkey,
        "Codex",
        "allowlist",
        &["a".repeat(64)],
    );

    let agents = relay_agents_from_directory_events(
        &[targeted_profile, headless],
        std::slice::from_ref(&forged_policy),
        &[],
    );

    assert_eq!(agents.len(), 2);
    assert!(agents.iter().any(|agent| agent.pubkey == targeted_pubkey));
    assert!(agents.iter().any(|agent| agent.pubkey == headless_pubkey));
}

#[test]
fn known_owned_agents_have_membership_independent_of_role() {
    let relay = Keys::generate();
    let agent = Keys::generate().public_key().to_hex();
    let event = EventBuilder::new(Kind::Custom(39002), "")
        .tags([
            Tag::parse(["d", "general"]).unwrap(),
            Tag::parse(["p", &agent, "", "member"]).unwrap(),
        ])
        .sign_with_keys(&relay)
        .unwrap();
    let memberships = member_agent_channel_ids_from_events(
        &[event],
        &relay.public_key().to_hex(),
        &std::collections::HashSet::from([agent.clone()]),
    );
    assert_eq!(memberships.get(&agent), Some(&vec!["general".to_string()]));
}

#[test]
fn managed_directory_rejects_tampered_event_envelopes() {
    let agent = Keys::generate();
    let owner = Keys::generate();
    let auth = buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").unwrap();
    let auth: Vec<String> = serde_json::from_str(&auth).unwrap();
    let profile = EventBuilder::new(Kind::Metadata, "{}")
        .tags([Tag::parse(auth).unwrap()])
        .sign_with_keys(&agent)
        .unwrap();
    let policy = managed_agent_event(
        &owner,
        &agent.public_key().to_hex(),
        "Scout",
        "owner-only",
        &[],
    );
    let tamper = |event: &Event, content: &str| -> Event {
        let mut value = serde_json::to_value(event).unwrap();
        value["content"] = serde_json::json!(content);
        serde_json::from_value(value).unwrap()
    };
    let forged_policy = tamper(
        &policy,
        r#"{"name":"Scout","parallelism":1,"respond_to":"anyone"}"#,
    );
    assert!(forged_policy.verify().is_err());
    assert!(
        relay_agents_from_managed_agent_events(&[forged_policy], std::slice::from_ref(&profile),)
            .is_empty(),
        "an owner pubkey string is not an owner signature"
    );
    let forged_profile = tamper(&profile, r#"{"name":"forged"}"#);
    assert!(forged_profile.verify().is_err());
    assert!(
        relay_agents_from_managed_agent_events(&[policy], &[forged_profile],).is_empty(),
        "a valid OA tag does not authenticate the profile envelope"
    );
}

#[test]
fn membership_is_bound_to_viewer_destination_and_latest_removals() {
    let relay = Keys::generate();
    let attacker = Keys::generate();
    let viewer = Keys::generate().public_key().to_hex();
    let agent = Keys::generate().public_key().to_hex();
    let known = std::collections::HashSet::from([agent.clone()]);
    let membership = |signer: &Keys, channel: &str, include_viewer: bool, timestamp: u64| {
        let mut tags = vec![
            Tag::parse(["d", channel]).unwrap(),
            Tag::parse(["p", &agent, "", "bot"]).unwrap(),
        ];
        if include_viewer {
            tags.push(Tag::parse(["p", &viewer]).unwrap());
        }
        EventBuilder::new(Kind::Custom(39002), "")
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(timestamp))
            .sign_with_keys(signer)
            .unwrap()
    };
    let check = |events: &[Event]| {
        member_agent_channel_ids_for_viewer(
            events,
            &relay.public_key().to_hex(),
            &known,
            &viewer,
            Some("target"),
        )
    };
    assert!(check(&[membership(&relay, "other", true, 1)]).is_empty());
    assert!(check(&[membership(&relay, "target", false, 1)]).is_empty());
    assert!(check(&[membership(&attacker, "target", true, 1)]).is_empty());
    let valid = membership(&relay, "target", true, 1);
    assert_eq!(check(std::slice::from_ref(&valid))[&agent], vec!["target"]);
    let removed_viewer = membership(&relay, "target", false, 2);
    assert!(check(&[valid.clone(), removed_viewer]).is_empty());
    let mut tampered = serde_json::to_value(valid).unwrap();
    tampered["content"] = json!("tampered");
    assert!(check(&[serde_json::from_value(tampered).unwrap()]).is_empty());
}

#[test]
fn relay_bot_identity_preserves_foreign_agent_roles_without_granting_policy() {
    let relay = Keys::generate();
    let viewer = Keys::generate().public_key().to_hex();
    let agent = Keys::generate();
    let agent_pubkey = agent.public_key().to_hex();
    let owner = Keys::generate();
    let attacker = Keys::generate();
    let auth = buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "")
        .expect("owner attestation");
    let auth: Vec<String> = serde_json::from_str(&auth).expect("auth values");
    let profile = EventBuilder::new(Kind::Metadata, "{}")
        .tags([Tag::parse(auth).expect("auth tag")])
        .sign_with_keys(&agent)
        .expect("signed profile");
    let policy = managed_agent_event(
        &owner,
        &agent_pubkey,
        "Shared",
        "allowlist",
        std::slice::from_ref(&viewer),
    );
    let forged_policy = managed_agent_event(&attacker, &agent_pubkey, "Forged", "anyone", &[]);
    let membership = |signer: &Keys, role: &str, timestamp: u64, include_identity: bool| {
        let mut tags = vec![
            Tag::parse(["d", "target"]).expect("channel"),
            Tag::parse(["p", &viewer, "", "member"]).expect("viewer"),
            Tag::parse(["p", &agent_pubkey, "", role]).expect("agent role"),
            // A bot marker without a matching member must not create membership.
            Tag::parse(["bot", &attacker.public_key().to_hex()]).expect("orphan bot"),
        ];
        if include_identity {
            tags.push(Tag::parse(["bot", &agent_pubkey]).expect("bot identity"));
        }
        EventBuilder::new(Kind::Custom(39002), "")
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(timestamp))
            .sign_with_keys(signer)
            .expect("signed membership")
    };
    let discover = |events: &[Event], destination: &str, current_viewer: &str| {
        member_agent_channel_ids_for_viewer(
            events,
            &relay.public_key().to_hex(),
            &std::collections::HashSet::new(),
            current_viewer,
            Some(destination),
        )
    };
    for role in ["owner", "admin", "guest"] {
        let event = membership(&relay, role, 10, true);
        let memberships = discover(std::slice::from_ref(&event), "target", &viewer);
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[&agent_pubkey], vec!["target"]);
        let mut agents = relay_agents_from_directory_events(
            &[],
            &[policy.clone(), forged_policy.clone()],
            std::slice::from_ref(&profile),
        );
        agents.retain(|agent| memberships.contains_key(&agent.pubkey));
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].owner_pubkey, Some(owner.public_key().to_hex()));
        assert_eq!(
            agents[0].respond_to,
            Some(crate::managed_agents::RespondTo::Allowlist)
        );
        assert_eq!(agents[0].respond_to_allowlist, vec![viewer.clone()]);
        assert!(relay_agents_from_directory_events(
            &[],
            std::slice::from_ref(&forged_policy),
            std::slice::from_ref(&profile)
        )
        .is_empty());
        assert!(discover(&[membership(&attacker, role, 10, true)], "target", &viewer).is_empty());
        assert!(discover(std::slice::from_ref(&event), "other", &viewer).is_empty());
        assert!(discover(
            std::slice::from_ref(&event),
            "target",
            &attacker.public_key().to_hex()
        )
        .is_empty());
        assert!(discover(
            &[event.clone(), membership(&relay, role, 11, false)],
            "target",
            &viewer
        )
        .is_empty());
        let mut tampered = serde_json::to_value(&event).expect("membership value");
        tampered["content"] = json!("tampered");
        assert!(discover(
            &[serde_json::from_value(tampered).expect("tampered event")],
            "target",
            &viewer
        )
        .is_empty());
    }
}
