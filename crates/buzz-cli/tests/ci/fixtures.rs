use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CHANNEL_ID: &str = "018f4f4e-f60a-7b47-b8dc-68f59a4dc8f1";
pub const RUN_ID: &str = "018f4f52-390d-7db6-b199-8f751c01b38b";
pub const IDEMPOTENCY_KEY: &str = "018f4f53-4369-7765-9948-c595989703e9";
pub const OWNER_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const TIP_OID: &str = "1111111111111111111111111111111111111111";
pub const OTHER_TIP_OID: &str = "9999999999999999999999999999999999999999";
pub const BASE_OID: &str = "2222222222222222222222222222222222222222";
pub const WORKFLOW_ID: &str = "ci";
pub const WORKFLOW_DIGEST: &str =
    "fd22ec34e6b90211644b6e1967aa6a7a8e1828177954b6f80180bee0168c9f4e";
pub const CANONICAL_WORKFLOW_BASE64: &str =
    "dmVyc2lvbjogMQpqb2JzOgogIHRlc3Q6CiAgICBydW5zLW9uOiBsaW51eAo=";
pub const PR_ROOT_EVENT_ID: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
pub const PR_UPDATE_EVENT_ID: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
pub const REQUEST_CREATED_AT: u64 = 1_787_180_000;
pub const STATUS_CREATED_AT: u64 = 1_787_180_001;

#[derive(Clone, Copy)]
pub struct JobStatusSpec<'a> {
    pub job_id: &'a str,
    pub attempt: u32,
    pub parent_attempt: Option<u32>,
    pub sequence: u64,
    pub state: &'a str,
}

pub fn request_keys() -> Keys {
    Keys::parse(&"11".repeat(32)).expect("request fixture key must be valid")
}

pub fn relay_keys() -> Keys {
    Keys::parse(&"22".repeat(32)).expect("relay fixture key must be valid")
}

pub fn unauthorized_relay_keys() -> Keys {
    Keys::parse(&"33".repeat(32)).expect("unauthorized relay fixture key must be valid")
}

pub fn target_repo_a() -> String {
    format!("30617:{OWNER_HEX}:buzz")
}

pub fn preflight_response() -> Value {
    json!({
        "target_repo_a": target_repo_a(),
        "pr_root_event_id": PR_ROOT_EVENT_ID,
        "pr_update_event_id": PR_UPDATE_EVENT_ID,
        "trigger_event_id": PR_UPDATE_EVENT_ID,
        "source_clone_url": "https://git.example.invalid/buzz.git",
        "immutable_source_ref": format!("refs/nostr/{PR_ROOT_EVENT_ID}"),
        "tip_oid": TIP_OID,
        "source_branch": "feature/ci",
        "base_ref": "refs/heads/main",
        "base_oid": BASE_OID,
        "workflow_id": WORKFLOW_ID,
        "workflow_path": ".buzz/workflows/ci.yaml",
        "workflow_digest": WORKFLOW_DIGEST,
        "canonical_workflow_base64": CANONICAL_WORKFLOW_BASE64,
        "jobs": [
            {
                "job_id": "lint",
                "name": "Lint",
                "required": true,
                "skip_policy": "forbid",
                "needs": []
            },
            {
                "job_id": "test",
                "name": "Test",
                "required": true,
                "skip_policy": "allow",
                "needs": ["lint"]
            }
        ],
        "selected_job_ids": ["lint", "test"],
        "policy": {
            "min_timeout_seconds": 60,
            "max_timeout_seconds": 1800,
            "max_expiry_seconds": 300,
            "acknowledgement_timeout_seconds": 5,
            "max_attempts": 3
        }
    })
}

pub fn preflight_tip_mismatch() -> Value {
    let mut response = preflight_response();
    response["tip_oid"] = Value::String(OTHER_TIP_OID.to_owned());
    response
}

pub fn preflight_workflow_digest_mismatch() -> Value {
    let mut response = preflight_response();
    response["workflow_digest"] = Value::String("00".repeat(32));
    response
}

pub fn request_content() -> String {
    let actor = request_keys().public_key().to_hex();
    format!(
        concat!(
            "{{\"schema_version\":1,",
            "\"request_type\":\"run\",",
            "\"target_repo_a\":\"{}\",",
            "\"pr_root_event_id\":\"{}\",",
            "\"pr_update_event_id\":\"{}\",",
            "\"source_clone_url\":\"https://git.example.invalid/buzz.git\",",
            "\"immutable_source_ref\":\"refs/nostr/{}\",",
            "\"tip_oid\":\"{}\",",
            "\"source_branch\":\"feature/ci\",",
            "\"base_ref\":\"refs/heads/main\",",
            "\"base_oid\":\"{}\",",
            "\"workflow_id\":\"{}\",",
            "\"workflow_digest\":\"{}\",",
            "\"job_ids\":[\"lint\",\"test\"],",
            "\"run_id\":\"{}\",",
            "\"attempt\":1,",
            "\"trigger_event_id\":\"{}\",",
            "\"actor\":\"{}\",",
            "\"timeout_seconds\":1800,",
            "\"idempotency_key\":\"{}\",",
            "\"issued_at\":1787180000,",
            "\"expires_at\":1787180300}}"
        ),
        target_repo_a(),
        PR_ROOT_EVENT_ID,
        PR_UPDATE_EVENT_ID,
        PR_ROOT_EVENT_ID,
        TIP_OID,
        BASE_OID,
        WORKFLOW_ID,
        WORKFLOW_DIGEST,
        RUN_ID,
        PR_UPDATE_EVENT_ID,
        actor,
        IDEMPOTENCY_KEY
    )
}

pub fn request_event() -> Event {
    sign_ci_event(
        &request_keys(),
        46_100,
        request_content(),
        request_tags(),
        REQUEST_CREATED_AT,
    )
}

pub fn rerun_request_event() -> Event {
    let original: Value =
        serde_json::from_str(&request_content()).expect("request fixture content");
    let mut rerun = original;
    rerun["request_type"] = Value::String("rerun".to_owned());
    rerun["job_ids"] = json!(["test"]);
    rerun["attempt"] = json!(2);
    rerun["parent_attempt"] = json!(1);
    rerun["parent_run_id"] = Value::String(RUN_ID.to_owned());
    rerun["idempotency_key"] = Value::String("018f4f58-938b-78e9-9533-0b0d48351570".to_owned());
    rerun["issued_at"] = json!(REQUEST_CREATED_AT + 60);
    rerun["expires_at"] = json!(REQUEST_CREATED_AT + 360);
    sign_ci_event(
        &request_keys(),
        46_100,
        serde_json::to_string(&rerun).expect("rerun request content"),
        common_tags(2),
        REQUEST_CREATED_AT + 60,
    )
}

pub fn queued_ack_content(request_event_id: &str, relay_signer: &str) -> String {
    format!(
        concat!(
            "{{\"schema_version\":1,",
            "\"request_event_id\":\"{}\",",
            "\"run_id\":\"{}\",",
            "\"workflow_id\":\"{}\",",
            "\"target_repo_a\":\"{}\",",
            "\"tip_oid\":\"{}\",",
            "\"base_oid\":\"{}\",",
            "\"attempt\":1,",
            "\"sequence\":1,",
            "\"state\":\"queued\",",
            "\"job_ids\":[\"lint\",\"test\"],",
            "\"relay_signer\":\"{}\"}}"
        ),
        request_event_id,
        RUN_ID,
        WORKFLOW_ID,
        target_repo_a(),
        TIP_OID,
        BASE_OID,
        relay_signer
    )
}

pub fn queued_ack_event() -> Event {
    let request = request_event();
    status_event_for(&relay_keys(), request.id.to_hex())
}

pub fn wrong_request_ack_event() -> Event {
    status_event_for(&relay_keys(), "55".repeat(32))
}

pub fn unauthorized_ack_event() -> Event {
    let request = request_event();
    status_event_for(&unauthorized_relay_keys(), request.id.to_hex())
}

pub fn job_status_event(spec: JobStatusSpec<'_>) -> Event {
    let request = request_event();
    let relay_signer = relay_keys().public_key().to_hex();
    let name = match spec.job_id {
        "lint" => "Lint",
        "test" => "Test",
        other => other,
    };
    let mut content = json!({
        "schema_version": 1,
        "request_event_id": request.id.to_hex(),
        "run_id": RUN_ID,
        "workflow_id": WORKFLOW_ID,
        "target_repo_a": target_repo_a(),
        "tip_oid": TIP_OID,
        "base_oid": BASE_OID,
        "job_id": spec.job_id,
        "name": name,
        "attempt": spec.attempt,
        "sequence": spec.sequence,
        "state": spec.state,
        "required": true,
        "skip_policy": "forbid",
        "selected_job_instance": spec.job_id,
        "also_reruns": [],
        "artifact_refs": [],
        "relay_signer": relay_signer
    });
    if let Some(parent_attempt) = spec.parent_attempt {
        content["parent_attempt"] = json!(parent_attempt);
    }
    if matches!(
        spec.state,
        "success" | "failure" | "cancelled" | "timed_out" | "skipped"
    ) {
        content["conclusion"] = Value::String(spec.state.to_owned());
        content["finished_at"] = json!(STATUS_CREATED_AT + spec.attempt as u64);
    } else if spec.state == "running" {
        content["started_at"] = json!(STATUS_CREATED_AT + spec.attempt as u64);
    }

    sign_ci_event(
        &relay_keys(),
        46_102,
        serde_json::to_string(&content).expect("job status content"),
        status_tags_for_job(&request.id.to_hex(), spec.job_id, spec.attempt),
        STATUS_CREATED_AT + spec.attempt as u64,
    )
}

pub fn log_reference_event(job_id: &str, attempt: u32, bytes: &[u8]) -> Event {
    let request = request_event();
    let hash = hex::encode(Sha256::digest(bytes));
    let content = json!({
        "schema_version": 1,
        "request_event_id": request.id.to_hex(),
        "run_id": RUN_ID,
        "workflow_id": WORKFLOW_ID,
        "target_repo_a": target_repo_a(),
        "tip_oid": TIP_OID,
        "job_id": job_id,
        "attempt": attempt,
        "log_sha256": hash,
        "byte_length": bytes.len(),
        "cap_bytes": 65536,
        "truncated": false,
        "inline": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
        "created_at": STATUS_CREATED_AT + attempt as u64,
        "relay_signer": relay_keys().public_key().to_hex()
    });
    let mut tags = status_tags_for_job(&request.id.to_hex(), job_id, attempt);
    tags.push(Tag::parse(["x", hash.as_str()]).expect("log hash tag"));
    sign_ci_event(
        &relay_keys(),
        46_103,
        serde_json::to_string(&content).expect("log reference content"),
        tags,
        STATUS_CREATED_AT + attempt as u64,
    )
}

pub fn mixed_attempt_status_events() -> Vec<Event> {
    vec![
        job_status_event(JobStatusSpec {
            job_id: "lint",
            attempt: 1,
            parent_attempt: None,
            sequence: 1,
            state: "queued",
        }),
        job_status_event(JobStatusSpec {
            job_id: "lint",
            attempt: 1,
            parent_attempt: None,
            sequence: 2,
            state: "running",
        }),
        job_status_event(JobStatusSpec {
            job_id: "lint",
            attempt: 1,
            parent_attempt: None,
            sequence: 3,
            state: "success",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 1,
            parent_attempt: None,
            sequence: 1,
            state: "queued",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 1,
            parent_attempt: None,
            sequence: 2,
            state: "running",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 1,
            parent_attempt: None,
            sequence: 3,
            state: "failure",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 2,
            parent_attempt: Some(1),
            sequence: 1,
            state: "queued",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 2,
            parent_attempt: Some(1),
            sequence: 2,
            state: "running",
        }),
        job_status_event(JobStatusSpec {
            job_id: "test",
            attempt: 2,
            parent_attempt: Some(1),
            sequence: 3,
            state: "success",
        }),
    ]
}

pub fn watch_page() -> Value {
    json!({
        "events": [
            {
                "run_id": RUN_ID,
                "sha": TIP_OID,
                "attempt": 1,
                "watch_cursor": 40,
                "event_id": "66".repeat(32),
                "scope": "run",
                "state": "running",
                "timestamp": STATUS_CREATED_AT
            },
            {
                "run_id": RUN_ID,
                "sha": TIP_OID,
                "attempt": 1,
                "watch_cursor": 41,
                "event_id": "77".repeat(32),
                "scope": "job",
                "job_id": "lint",
                "state": "success",
                "timestamp": STATUS_CREATED_AT + 1
            }
        ],
        "next_cursor": 41
    })
}

fn status_event_for(signer: &Keys, request_event_id: impl AsRef<str>) -> Event {
    let request_event_id = request_event_id.as_ref();
    sign_ci_event(
        signer,
        46_101,
        queued_ack_content(request_event_id, &signer.public_key().to_hex()),
        status_tags(request_event_id),
        STATUS_CREATED_AT,
    )
}

fn request_tags() -> Vec<Tag> {
    common_tags(1)
}

fn status_tags(request_event_id: &str) -> Vec<Tag> {
    let mut tags = common_tags(1);
    tags.push(Tag::parse(["e", request_event_id, "", "request"]).expect("request e tag"));
    tags
}

fn status_tags_for_job(request_event_id: &str, job_id: &str, attempt: u32) -> Vec<Tag> {
    let mut tags = common_tags(attempt);
    tags.push(Tag::parse(["job", job_id]).expect("job tag"));
    tags.push(Tag::parse(["e", request_event_id, "", "request"]).expect("request e tag"));
    tags
}

fn common_tags(attempt: u32) -> Vec<Tag> {
    let attempt = attempt.to_string();
    vec![
        Tag::parse(["h", CHANNEL_ID]).expect("channel tag"),
        Tag::parse(["a", target_repo_a().as_str()]).expect("repository tag"),
        Tag::parse(["run", RUN_ID]).expect("run tag"),
        Tag::parse(["workflow", WORKFLOW_ID]).expect("workflow tag"),
        Tag::parse(["c", TIP_OID]).expect("commit tag"),
        Tag::parse(["attempt", attempt.as_str()]).expect("attempt tag"),
    ]
}

fn sign_ci_event(
    keys: &Keys,
    kind: u16,
    content: String,
    tags: Vec<Tag>,
    created_at: u64,
) -> Event {
    EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .expect("CI fixture event must sign")
}
