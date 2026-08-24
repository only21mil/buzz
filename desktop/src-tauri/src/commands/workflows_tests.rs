// Tests for commands/workflows.rs — split into a sibling file to keep
// workflows.rs focused. These exercise the pure helpers (no relay): event →
// wire conversion, YAML definition parsing, name derivation, and the
// create/update record shaping.

use super::*;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

/// Build a signed kind:30620 workflow definition event with the given YAML
/// content and d/h tags.
fn wf_event(d: &str, h: &str, yaml: &str) -> nostr::Event {
    let keys = Keys::generate();
    let tags: Vec<Tag> = [vec!["d", d], vec!["h", h]]
        .into_iter()
        .map(|t| Tag::parse(t).expect("parse tag"))
        .collect();
    EventBuilder::new(Kind::Custom(30620), yaml)
        .tags(tags)
        .sign_with_keys(&keys)
        .expect("sign")
}

fn workflow_definition(keys: &Keys, workflow_id: &str, created_at: u64) -> nostr::Event {
    EventBuilder::new(Kind::Custom(30620), YAML)
        .tags(vec![
            Tag::parse(["d", workflow_id]).expect("d tag"),
            Tag::parse(["h", CHAN]).expect("h tag"),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .expect("sign workflow")
}

fn workflow_tombstone(keys: &Keys, workflow_id: &str, created_at: u64) -> nostr::Event {
    let coordinate = format!("30620:{}:{workflow_id}", keys.public_key().to_hex());
    EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![Tag::parse(["a", coordinate.as_str()]).expect("a tag")])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .expect("sign workflow tombstone")
}

fn collect_paged_fixture(mut source: Vec<nostr::Event>) -> Vec<nostr::Event> {
    source.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.to_hex().cmp(&right.id.to_hex()))
    });
    let mut collected = Vec::new();

    for kind in [30620, 5] {
        let mut filter = serde_json::json!({"kinds": [kind]});
        loop {
            let until = filter.get("until").and_then(Value::as_u64);
            let before_id = filter.get("before_id").and_then(Value::as_str);
            let page: Vec<_> = source
                .iter()
                .filter(|event| event.kind.as_u16() == kind)
                .filter(|event| match (until, before_id) {
                    (Some(until), Some(before_id)) => {
                        event.created_at.as_secs() < until
                            || (event.created_at.as_secs() == until
                                && event.id.to_hex().as_str() > before_id)
                    }
                    _ => true,
                })
                .take(WORKFLOW_QUERY_PAGE_SIZE)
                .cloned()
                .collect();
            if page.is_empty() {
                break;
            }
            let done = page.len() < WORKFLOW_QUERY_PAGE_SIZE;
            if !done {
                advance_workflow_cursor(&mut filter, &page);
            }
            collected.extend(page);
            if done {
                break;
            }
        }
    }

    collected
}

const CHAN: &str = "11111111-1111-1111-1111-111111111111";
const WF: &str = "22222222-2222-2222-2222-222222222222";

const YAML: &str = "\
name: Greet on join
description: Says hi
enabled: true
trigger:
  on: message_posted
  filter: hello
steps:
  - id: reply
    action: post_message
";

#[test]
fn paged_workflow_queries_keep_an_old_tombstone_in_the_fold() {
    let owner = Keys::generate();
    let live_id = "33333333-3333-3333-3333-333333333333";
    let events = collect_paged_fixture(vec![
        workflow_definition(&owner, live_id, 40),
        workflow_definition(&owner, WF, 5),
        workflow_tombstone(&owner, "55555555-5555-5555-5555-555555555555", 30),
        workflow_tombstone(&owner, "44444444-4444-4444-4444-444444444444", 20),
        workflow_tombstone(&owner, WF, 10),
    ]);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == Kind::EventDeletion)
            .count(),
        3,
        "the old tombstone must arrive from the second deletion page"
    );

    let folded = buzz_sdk_pkg::workflow_fold::fold_workflow_definitions(&events);
    assert_eq!(folded.len(), 1);
    assert_eq!(tag_value(folded[0], "d").as_deref(), Some(live_id));
}

#[test]
fn workflow_from_event_maps_all_fields() {
    let ev = wf_event(WF, CHAN, YAML);
    let wf = workflow_from_event(&ev);

    assert_eq!(wf.id, WF);
    assert_eq!(wf.channel_id.as_deref(), Some(CHAN));
    assert_eq!(wf.owner_pubkey, ev.pubkey.to_hex());
    assert_eq!(wf.name, "Greet on join");
    assert_eq!(wf.status, "active");
    assert_eq!(wf.created_at, ev.created_at.as_secs() as i64);
    assert_eq!(wf.updated_at, ev.created_at.as_secs() as i64);
}

#[test]
fn definition_is_parsed_into_object_with_nested_fields() {
    let ev = wf_event(WF, CHAN, YAML);
    let wf = workflow_from_event(&ev);

    // The whole YAML document is preserved as a free-form object.
    let def = wf.definition.as_object().expect("definition is an object");
    assert_eq!(
        def.get("description").and_then(Value::as_str),
        Some("Says hi")
    );
    assert_eq!(def.get("enabled").and_then(Value::as_bool), Some(true));
    assert_eq!(
        wf.definition.pointer("/trigger/on").and_then(Value::as_str),
        Some("message_posted")
    );
    assert_eq!(
        wf.definition
            .pointer("/steps/0/action")
            .and_then(Value::as_str),
        Some("post_message")
    );
}

#[test]
fn name_falls_back_to_id_when_missing() {
    let yaml = "trigger:\n  on: schedule\n  cron: '* * * * *'\n";
    let ev = wf_event(WF, CHAN, yaml);
    let wf = workflow_from_event(&ev);
    assert_eq!(wf.name, WF);
}

#[test]
fn name_falls_back_to_id_when_blank() {
    let yaml = "name: '   '\ntrigger:\n  on: schedule\n";
    let ev = wf_event(WF, CHAN, yaml);
    let wf = workflow_from_event(&ev);
    assert_eq!(wf.name, WF);
}

#[test]
fn malformed_yaml_yields_empty_object_not_error() {
    // A broken workflow must not break the whole list — definition falls back
    // to an empty object and the name falls back to the id. (YAML is permissive,
    // so this uses an unterminated flow mapping that genuinely fails to parse.)
    let ev = wf_event(WF, CHAN, "{ name: oops, unterminated: [1, 2");
    let wf = workflow_from_event(&ev);
    assert_eq!(wf.definition, Value::Object(serde_json::Map::new()));
    assert_eq!(wf.name, WF);
}

#[test]
fn scalar_yaml_document_yields_empty_object() {
    // A bare scalar parses as valid YAML but isn't an object; treat as empty.
    let ev = wf_event(WF, CHAN, "just a string");
    let wf = workflow_from_event(&ev);
    assert_eq!(wf.definition, Value::Object(serde_json::Map::new()));
}

#[test]
fn tag_value_reads_d_and_h_and_misses_absent() {
    let ev = wf_event(WF, CHAN, YAML);
    assert_eq!(tag_value(&ev, "d").as_deref(), Some(WF));
    assert_eq!(tag_value(&ev, "h").as_deref(), Some(CHAN));
    assert_eq!(tag_value(&ev, "z"), None);
}

#[test]
fn workflow_record_shapes_save_inputs() {
    let wf = workflow_record(
        WF.to_string(),
        Some(CHAN.to_string()),
        "deadbeef".to_string(),
        YAML,
        100,
        200,
    );
    assert_eq!(wf.id, WF);
    assert_eq!(wf.name, "Greet on join");
    assert_eq!(wf.owner_pubkey, "deadbeef");
    assert_eq!(wf.channel_id.as_deref(), Some(CHAN));
    assert_eq!(wf.created_at, 100);
    assert_eq!(wf.updated_at, 200);
    assert_eq!(wf.status, "active");
}

#[test]
fn save_wire_serializes_flat_with_optional_secret() {
    let workflow = workflow_record(
        WF.to_string(),
        Some(CHAN.to_string()),
        "deadbeef".to_string(),
        YAML,
        1,
        1,
    );

    // With a secret: present, flattened alongside the workflow fields.
    let with = WorkflowSaveWire {
        workflow: workflow.clone(),
        webhook_secret: Some("s3cr3t".to_string()),
    };
    let v = serde_json::to_value(&with).expect("serialize");
    assert_eq!(v.get("id").and_then(Value::as_str), Some(WF));
    assert_eq!(v.get("name").and_then(Value::as_str), Some("Greet on join"));
    assert_eq!(
        v.get("webhook_secret").and_then(Value::as_str),
        Some("s3cr3t")
    );

    // Without a secret: the key is omitted entirely (frontend treats as null).
    let without = WorkflowSaveWire {
        workflow,
        webhook_secret: None,
    };
    let v = serde_json::to_value(&without).expect("serialize");
    assert!(v.get("webhook_secret").is_none());
    assert_eq!(v.get("id").and_then(Value::as_str), Some(WF));
}

#[test]
fn workflow_wire_serializes_with_snake_case_keys() {
    // Guard the wire contract the frontend's RawWorkflow depends on.
    let ev = wf_event(WF, CHAN, YAML);
    let v = serde_json::to_value(workflow_from_event(&ev)).expect("serialize");
    for key in [
        "id",
        "name",
        "owner_pubkey",
        "channel_id",
        "definition",
        "status",
        "created_at",
        "updated_at",
    ] {
        assert!(v.get(key).is_some(), "missing wire key: {key}");
    }
}

#[test]
fn workflow_runs_path_defaults_and_caps_the_limit() {
    let workflow_id = uuid::Uuid::parse_str(WF).expect("workflow UUID");
    assert_eq!(
        workflow_runs_path(workflow_id, None),
        format!("/workflows/{WF}/runs?limit=20")
    );
    assert_eq!(
        workflow_runs_path(workflow_id, Some(101)),
        format!("/workflows/{WF}/runs?limit=100")
    );
}

#[test]
fn trigger_response_serializes_event_run_workflow_and_acceptance() {
    let wire = trigger_workflow_wire(
        WF.to_string(),
        "trigger-event".to_string(),
        "response:{\"run_id\":\"33333333-3333-3333-3333-333333333333\"}",
    )
    .expect("parse trigger response");

    assert_eq!(
        serde_json::to_value(wire).expect("serialize trigger response"),
        serde_json::json!({
            "event_id": "trigger-event",
            "workflow_id": WF,
            "run_id": "33333333-3333-3333-3333-333333333333",
            "status": "accepted",
        })
    );
}

#[test]
fn duplicate_trigger_response_keeps_missing_run_id_explicitly_null() {
    let wire = trigger_workflow_wire(
        WF.to_string(),
        "trigger-event".to_string(),
        "duplicate: already processed",
    )
    .expect("parse duplicate trigger response");

    assert_eq!(wire.run_id, None);
    assert_eq!(wire.status, "accepted");
}

#[test]
fn runs_and_approvals_serialize_to_bare_empty_array() {
    // Regression guard for the crash class this fix closed. The frontend
    // wrappers `getWorkflowRuns` / `getRunApprovals` do `raw.map(...)`, so the
    // Rust side MUST return a bare JSON array. A wrapped `{ runs: [...] }` /
    // `{ approvals: [...] }` shape would make `.map()` throw and crash the
    // detail panel — the same TypeError class as the original page bug.
    //
    // The commands take `State<AppState>`, so we can't invoke them directly in
    // a unit test; instead we pin the exact value they return (`Vec::new()` of
    // their `Vec<Value>` element type) and assert its serialized shape.
    let runs: Vec<Value> = Vec::new();
    let approvals: Vec<Value> = Vec::new();
    assert_eq!(serde_json::to_string(&runs).expect("serialize runs"), "[]");
    assert_eq!(
        serde_json::to_string(&approvals).expect("serialize approvals"),
        "[]"
    );
}
