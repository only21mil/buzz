//! Exercise canonical Save and the actual local Command boundary.
use super::{env, goose, record, ACP_KEY, GOOSE_KEY};
use crate::managed_agents::config_bridge::effort::{
    apply_launch_effort, prepare_inherited_effort_env, update_saved_effort,
};
use std::collections::BTreeMap;

#[test]
fn effort_save_clear_and_legacy_record_roundtrip() {
    let mut record = record();
    record.env_vars = env(&[
        ("GoOsE_ThInKiNg_EfFoRt", "low"),
        (ACP_KEY, "stale"),
        ("OTHER", "keep"),
    ]);
    update_saved_effort(&mut record, Some(goose()), Some("XHIGH".into())).unwrap();
    assert_eq!(record.effort_level.as_deref(), Some("max"));
    assert_eq!(record.env_vars, env(&[("OTHER", "keep")]));
    let encoded = serde_json::to_value(&record).unwrap();
    let restored: crate::managed_agents::ManagedAgentRecord =
        serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(restored.effort_level, record.effort_level);
    let mut legacy = encoded;
    legacy.as_object_mut().unwrap().remove("effort_level");
    assert!(
        serde_json::from_value::<crate::managed_agents::ManagedAgentRecord>(legacy)
            .unwrap()
            .effort_level
            .is_none()
    );
    let before = serde_json::to_value(&record).unwrap();
    assert!(update_saved_effort(&mut record, Some(goose()), Some("unsupported".into())).is_err());
    assert_eq!(serde_json::to_value(&record).unwrap(), before);
    update_saved_effort(&mut record, Some(goose()), None).unwrap();
    assert!(record.effort_level.is_none());
    assert_eq!(
        record.env_vars.get("OTHER").map(String::as_str),
        Some("keep")
    );
}

#[test]
fn effort_request_distinguishes_omitted_null_and_value() {
    use crate::managed_agents::UpdateManagedAgentRequest;
    for (patch, expected) in [
        (serde_json::json!({}), None),
        (serde_json::json!({"effortLevel":null}), Some(None)),
        (
            serde_json::json!({"effortLevel":"high"}),
            Some(Some("high".to_string())),
        ),
    ] {
        let mut value = patch;
        value["pubkey"] = serde_json::json!("test");
        let request: UpdateManagedAgentRequest = serde_json::from_value(value).unwrap();
        assert_eq!(request.effort_level, expected);
    }
}

#[test]
#[cfg(unix)]
fn effort_real_child_receives_single_authority_after_set_and_clear() {
    let mut record = record();
    let global = env(&[(GOOSE_KEY, "medium")]);
    for saved in [Some("max".to_string()), None] {
        update_saved_effort(&mut record, Some(goose()), saved.clone()).unwrap();
        let mut projected = env(&[("BuZz_AcP_EfFoRt_LeVeL", "stale")]);
        apply_launch_effort(
            &mut projected,
            &record,
            Some(goose()),
            &[],
            &global,
            None,
            &BTreeMap::new(),
        );
        let mut command = std::process::Command::new("/usr/bin/env");
        command
            .env_clear()
            .env("GoOsE_ThInKiNg_EfFoRt", "stale")
            .env(ACP_KEY, "stale")
            .env("OTHER", "keep");
        prepare_inherited_effort_env(&mut command, Some(goose()), &projected);
        command.envs(&projected);
        let output = command.output().unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(output
            .lines()
            .any(|line| line == format!("{GOOSE_KEY}={}", saved.as_deref().unwrap_or("medium"))));
        assert_eq!(
            output
                .lines()
                .filter(|line| line.to_ascii_lowercase().contains("effort"))
                .count(),
            1
        );
        assert!(output.lines().any(|line| line == "OTHER=keep"));
    }
}

#[test]
fn custom_effort_save_preserves_foreign_native_environment() {
    let mut record = record();
    record.env_vars = env(&[(GOOSE_KEY, "wrapper-owned"), (ACP_KEY, "old")]);
    update_saved_effort(&mut record, None, Some("high".into())).unwrap();
    assert_eq!(record.env_vars, env(&[(GOOSE_KEY, "wrapper-owned")]));
    update_saved_effort(&mut record, None, None).unwrap();
    assert_eq!(record.env_vars, env(&[(GOOSE_KEY, "wrapper-owned")]));
}

#[test]
fn inherit_harness_cannot_restore_a_stale_effort_draft() {
    use crate::managed_agents::config_bridge::effort::effort_patch_after_harness_selection;
    assert_eq!(
        effort_patch_after_harness_selection(Some(Some("high".into())), true),
        Some(None)
    );
    assert_eq!(effort_patch_after_harness_selection(None, false), None);
    assert_eq!(
        effort_patch_after_harness_selection(Some(Some("high".into())), false),
        Some(Some("high".into()))
    );
}
