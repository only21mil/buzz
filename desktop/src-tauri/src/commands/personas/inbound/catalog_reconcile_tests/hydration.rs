//! Returning-device and live delivery exercise the actual signed inbound path.
use super::*;
use crate::managed_agents::{
    load_personas, load_teams, persona_events::build_persona_event, save_personas, save_teams,
    team_events::build_team_event,
};

struct TestPaths(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl TestPaths {
    fn new(path: &std::path::Path) -> Self {
        let vars = ["HOME", "XDG_DATA_HOME"];
        let saved = vars
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        for name in vars {
            std::env::set_var(name, path);
        }
        Self(saved)
    }
}
impl Drop for TestPaths {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn retained_witness_survives_missing_member(deliver_new_catalog_last: bool, reactivate: bool) {
    let _guard = crate::managed_agents::lock_path_mutex();
    let temp = tempfile::tempdir().unwrap();
    let _paths = TestPaths::new(temp.path());
    let keys = nostr::Keys::generate();
    let owner = keys.public_key().to_hex();
    let app = mock_app(&keys);
    let base = crate::managed_agents::managed_agents_base_dir(app.handle()).unwrap();
    let db = scoped_retention_db_path(&base, RELAY, &owner);
    let apply = |event: nostr::Event| {
        reconcile_inbound_persona_event_blocking(
            event.as_json(),
            RELAY.into(),
            app.handle().clone(),
        )
        .unwrap();
    };
    let old_members = vec![member("m1", "One"), member("m2", "Two")];
    save_personas(app.handle(), &old_members).unwrap();
    save_teams(app.handle(), &[team()]).unwrap();
    let witness = signed_catalog_head(&keys);
    apply(witness.clone());

    let mut updated_team = team();
    updated_team.persona_ids.push("m3".into());
    apply(
        build_team_event(&updated_team)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap(),
    );
    // A second member upsert must also defer while m3 is still in flight.
    apply(
        build_persona_event(&member("m1", "One edited"))
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap(),
    );
    let conn = open_retention_db(&db).unwrap();
    let retained = get_retained_event(&conn, KIND_TEAM_CATALOG, &owner, TEAM_ID)
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.raw_event,
        witness.as_json(),
        "retained witness must survive incomplete membership"
    );
    assert!(
        get_pending_sync(&conn).unwrap().is_empty(),
        "no refresh or tombstone before the delayed member saves"
    );
    drop(conn);

    if reactivate {
        // Startup and community activation use this same reconciliation core.
        // Reload the durable inbound midpoint before the delayed member arrives.
        // Repeating it also covers switching away and returning while offline.
        for _ in 0..2 {
            assert_eq!(
                crate::event_sync::reconcile_team_catalog_heads_at_for_test(&base, &keys, &db)
                    .unwrap(),
                0,
                "scope activation must defer an unresolved inbound team"
            );
            let conn = open_retention_db(&db).unwrap();
            assert_eq!(
                get_retained_event(&conn, KIND_TEAM_CATALOG, &owner, TEAM_ID)
                    .unwrap()
                    .unwrap()
                    .raw_event,
                witness.as_json()
            );
            assert!(get_pending_sync(&conn).unwrap().is_empty());
        }
    }

    apply(
        build_persona_event(&member("m3", "Three"))
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap(),
    );
    let personas = load_personas(app.handle()).unwrap();
    let teams = load_teams(app.handle()).unwrap();
    assert!(teams
        .iter()
        .any(|team| team.id == TEAM_ID && team.persona_ids.contains(&"m3".into())));
    assert!(personas.iter().any(|persona| persona.id == "m3"));
    let conn = open_retention_db(&db).unwrap();
    let refreshed = get_retained_event(&conn, KIND_TEAM_CATALOG, &owner, TEAM_ID)
        .unwrap()
        .unwrap();
    assert!(refreshed.content.contains("Three"));
    assert!(refreshed.content.contains("One edited"));
    assert!(refreshed.created_at > witness.created_at.as_secs() as i64);
    assert!(get_pending_sync(&conn)
        .unwrap()
        .iter()
        .all(|row| row.kind != 5));
    drop(conn);
    if deliver_new_catalog_last {
        // Newest-first backfill postpones 30178 until after its constituents.
        // The older retained witness existed throughout this batch.
        let head = build_team_catalog_event(&updated_team, &personas, true)
            .unwrap()
            .custom_created_at(nostr::Timestamp::from(refreshed.created_at as u64 + 1))
            .sign_with_keys(&keys)
            .unwrap();
        apply(head.clone());
        let conn = open_retention_db(&db).unwrap();
        assert_eq!(
            get_retained_event(&conn, KIND_TEAM_CATALOG, &owner, TEAM_ID)
                .unwrap()
                .unwrap()
                .raw_event,
            head.as_json()
        );
        assert!(get_pending_sync(&conn)
            .unwrap()
            .iter()
            .all(|row| row.kind != 5));
    }
}

#[test]
fn returning_device_backfill_keeps_retained_witness_until_members_hydrate() {
    retained_witness_survives_missing_member(true, false);
}

#[test]
fn live_team_and_persona_updates_wait_for_delayed_new_member() {
    retained_witness_survives_missing_member(false, false);
}

#[test]
fn interrupted_inbound_hydration_survives_startup_and_scope_reactivation() {
    retained_witness_survives_missing_member(true, true);
}

#[test]
fn signed_member_deletion_retracts_a_team_held_for_hydration() {
    let _guard = crate::managed_agents::lock_path_mutex();
    let temp = tempfile::tempdir().unwrap();
    let _paths = TestPaths::new(temp.path());
    let keys = nostr::Keys::generate();
    let owner = keys.public_key().to_hex();
    let app = mock_app(&keys);
    let base = crate::managed_agents::managed_agents_base_dir(app.handle()).unwrap();
    let db = scoped_retention_db_path(&base, RELAY, &owner);
    let apply = |event: nostr::Event| {
        reconcile_inbound_persona_event_blocking(
            event.as_json(),
            RELAY.into(),
            app.handle().clone(),
        )
        .unwrap();
    };
    save_personas(app.handle(), &[member("m1", "One"), member("m2", "Two")]).unwrap();
    save_teams(app.handle(), &[team()]).unwrap();
    apply(signed_catalog_head(&keys));
    let mut updated_team = team();
    updated_team.persona_ids.push("m3".into());
    apply(
        build_team_event(&updated_team)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap(),
    );
    assert_eq!(
        crate::event_sync::reconcile_team_catalog_heads_at_for_test(&base, &keys, &db).unwrap(),
        0
    );

    // A signed deletion is authoritative even while a different member is
    // missing. It must retract immediately and stay retracted after activation.
    apply(
        crate::managed_agents::persona_events::build_persona_delete("m1", &owner)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap(),
    );
    assert!(!load_personas(app.handle())
        .unwrap()
        .iter()
        .any(|p| p.id == "m1"));
    assert_eq!(
        crate::event_sync::reconcile_team_catalog_heads_at_for_test(&base, &keys, &db).unwrap(),
        0
    );
    let conn = open_retention_db(&db).unwrap();
    assert!(
        get_retained_event(&conn, KIND_TEAM_CATALOG, &owner, TEAM_ID)
            .unwrap()
            .is_none()
    );
    let pending = get_pending_sync(&conn).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, 5);
    let deletion = nostr::Event::from_json(&pending[0].raw_event).unwrap();
    deletion.verify().unwrap();
    assert_eq!(
        crate::commands::personas::inbound::parse_deletion_coordinate(&deletion),
        Some((KIND_TEAM_CATALOG, TEAM_ID.to_string()))
    );
}
