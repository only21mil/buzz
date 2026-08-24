//! Slice-1 contracts for durable workflow approval gates.
//!
//! The adapter in `create_gate` is the only provisional seam. Production may
//! choose different Rust names, but integration should adapt that seam instead
//! of weakening the persistence assertions below.
//!
//! These tests deliberately stop at gate creation. Decision handling, expiry,
//! membership invalidation, publishing, and resume workers belong to later
//! slices.

use buzz_core::CommunityId;
use buzz_db::workflow_approval::{
    create_workflow_approval_gate, decide_workflow_approval_gate, ApprovalActionSummary,
    ApprovalDecisionPayload, ApprovalRequestPayload, ApprovalRole, CanonicalApprovalPolicy,
    CreateWorkflowApprovalGateParams, DecideWorkflowApprovalGateParams,
    WorkflowApprovalDecisionEvent, WorkflowApprovalDecisionOutcome,
    WorkflowApprovalGateCreationOutcome,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
const PRE_APPROVAL_MIGRATION_VERSION: i64 = 30;
const DEFINITION_SECRET: &str = "definition-secret-must-not-enter-request-outbox";
const OUTPUT_SECRET: &str = "raw-step-output-must-not-enter-request-outbox";

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone, Debug)]
struct GateSpec {
    community_id: CommunityId,
    channel_id: Uuid,
    workflow_id: Uuid,
    run_id: Uuid,
    expected_generation: i64,
    definition_hash: Vec<u8>,
    step_id: String,
    step_index: i32,
    policy: CanonicalApprovalPolicy,
    action_summary: String,
    expires_at: DateTime<Utc>,
    prior_step_outputs: Value,
    prior_execution_trace: Value,
    waiting_trace_entry: Value,
    request_payload: Value,
}

#[derive(Debug, PartialEq, Eq)]
enum ObservedCreate {
    Created { approval_id: Uuid, generation: i64 },
    Reused { approval_id: Uuid, generation: i64 },
    Conflict,
    StaleGeneration { current_generation: i64 },
    NoEligibleApprovers,
}

async fn create_gate(pool: &PgPool, spec: &GateSpec) -> buzz_db::Result<ObservedCreate> {
    let action_summary = ApprovalActionSummary::new(spec.action_summary.clone())?;
    let request_payload = ApprovalRequestPayload::new(spec.request_payload.clone())?;
    let outcome = create_workflow_approval_gate(
        pool,
        CreateWorkflowApprovalGateParams {
            community_id: spec.community_id,
            channel_id: spec.channel_id,
            workflow_id: spec.workflow_id,
            run_id: spec.run_id,
            expected_generation: spec.expected_generation,
            definition_hash: &spec.definition_hash,
            step_id: &spec.step_id,
            step_index: spec.step_index,
            policy: &spec.policy,
            action_summary: &action_summary,
            expires_at: spec.expires_at,
            prior_step_outputs: &spec.prior_step_outputs,
            prior_execution_trace: &spec.prior_execution_trace,
            waiting_trace_entry: &spec.waiting_trace_entry,
            request_payload: &request_payload,
        },
    )
    .await?;

    Ok(match outcome {
        WorkflowApprovalGateCreationOutcome::Created { gate, .. } => ObservedCreate::Created {
            approval_id: gate.approval_id,
            generation: gate.gate_generation,
        },
        WorkflowApprovalGateCreationOutcome::Reused { gate, .. } => ObservedCreate::Reused {
            approval_id: gate.approval_id,
            generation: gate.gate_generation,
        },
        WorkflowApprovalGateCreationOutcome::Conflict => ObservedCreate::Conflict,
        WorkflowApprovalGateCreationOutcome::StaleGeneration { current_generation } => {
            ObservedCreate::StaleGeneration { current_generation }
        }
        WorkflowApprovalGateCreationOutcome::NoEligibleApprovers => {
            ObservedCreate::NoEligibleApprovers
        }
    })
}

async fn decide_gate(
    fixture: &Fixture,
    approval_id: Uuid,
    actor: &[u8],
    decision: &str,
    note: Option<&str>,
    event_marker: u8,
) -> buzz_db::Result<WorkflowApprovalDecisionOutcome> {
    let event = decision_event_fixture(approval_id, actor, decision, note, event_marker);
    decide_gate_event(fixture, approval_id, actor, decision, note, &event).await
}

#[derive(Clone)]
struct DecisionEventFixture {
    event_id: Vec<u8>,
    pubkey: Vec<u8>,
    created_at: DateTime<Utc>,
    kind: i32,
    tags: Value,
    content: String,
    signature: Vec<u8>,
}

fn decision_event_fixture(
    approval_id: Uuid,
    actor: &[u8],
    decision: &str,
    note: Option<&str>,
    event_marker: u8,
) -> DecisionEventFixture {
    DecisionEventFixture {
        event_id: vec![event_marker; 32],
        pubkey: actor.to_vec(),
        created_at: DateTime::from_timestamp(1_700_000_000 + i64::from(event_marker), 0)
            .expect("stable decision event timestamp"),
        kind: if decision == "grant" { 46_030 } else { 46_031 },
        tags: json!([["d", approval_id.to_string()]]),
        content: json!({"decision": decision, "note": note}).to_string(),
        signature: vec![event_marker.wrapping_add(1); 64],
    }
}

async fn decide_gate_event(
    fixture: &Fixture,
    approval_id: Uuid,
    actor: &[u8],
    decision: &str,
    note: Option<&str>,
    event: &DecisionEventFixture,
) -> buzz_db::Result<WorkflowApprovalDecisionOutcome> {
    let payload = ApprovalDecisionPayload::new(json!({
        "decision": decision,
        "note": note,
    }))?;
    decide_workflow_approval_gate(
        &fixture.pool,
        DecideWorkflowApprovalGateParams {
            community_id: fixture.community_id,
            approval_id,
            actor_pubkey: actor,
            actor_kind: "human",
            payload: &payload,
            event: WorkflowApprovalDecisionEvent {
                event_id: &event.event_id,
                pubkey: &event.pubkey,
                created_at: event.created_at,
                kind: event.kind,
                tags: &event.tags,
                content: &event.content,
                signature: &event.signature,
                received_at: Utc::now(),
            },
        },
    )
    .await
}

#[derive(Clone, Debug)]
struct FixtureIds {
    community_id: Uuid,
    channel_id: Uuid,
    workflow_id: Uuid,
    run_id: Uuid,
}

impl FixtureIds {
    fn random() -> Self {
        Self {
            community_id: Uuid::new_v4(),
            channel_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
        }
    }
}

struct Fixture {
    pool: PgPool,
    ids: FixtureIds,
    community_id: CommunityId,
    owner: Vec<u8>,
    approver: Vec<u8>,
    definition_hash: Vec<u8>,
}

impl Fixture {
    async fn new() -> Self {
        let pool = connect_pool().await;
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("apply workflow approval migrations");
        Self::insert(pool, FixtureIds::random(), 0x61).await
    }

    async fn insert(pool: PgPool, ids: FixtureIds, marker: u8) -> Self {
        let community_id = CommunityId::from_uuid(ids.community_id);
        let owner = vec![marker; 32];
        let approver = vec![marker.wrapping_add(1); 32];
        let definition_hash = vec![marker.wrapping_add(2); 32];

        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(ids.community_id)
            .bind(format!(
                "approval-contract-{}.test",
                ids.community_id.simple()
            ))
            .execute(&pool)
            .await
            .expect("insert approval contract community");
        buzz_db::user::ensure_user(&pool, community_id, &owner)
            .await
            .expect("insert workflow owner");
        buzz_db::user::ensure_user(&pool, community_id, &approver)
            .await
            .expect("insert resolved approver");
        insert_channel(&pool, community_id, ids.channel_id, &owner).await;
        sqlx::query(
            "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
             VALUES ($1, $2, $3, 'owner'), ($1, $2, $4, 'admin')",
        )
        .bind(ids.community_id)
        .bind(ids.channel_id)
        .bind(&owner)
        .bind(&approver)
        .execute(&pool)
        .await
        .expect("insert active approval members");

        let definition = json!({
            "trigger": {"on": "message_posted"},
            "steps": [
                {"id": "prepare", "run": "prepare"},
                {"id": "build", "run": DEFINITION_SECRET},
                {"id": "approve-release", "approval": {"role": "owner"}}
            ]
        });
        sqlx::query(
            "INSERT INTO workflows \
             (community_id, id, name, owner_pubkey, channel_id, definition, definition_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(ids.community_id)
        .bind(ids.workflow_id)
        .bind(format!("approval-contract-{}", ids.workflow_id.simple()))
        .bind(&owner)
        .bind(ids.channel_id)
        .bind(&definition)
        .bind(&definition_hash)
        .execute(&pool)
        .await
        .expect("insert workflow");

        sqlx::query(
            "INSERT INTO workflow_runs \
             (community_id, id, workflow_id, definition_snapshot, definition_hash, generation, \
              status, current_step, next_step, step_outputs, execution_trace) \
             VALUES ($1, $2, $3, $4, $5, 1, 'running', 2, 2, '{}'::jsonb, $6)",
        )
        .bind(ids.community_id)
        .bind(ids.run_id)
        .bind(ids.workflow_id)
        .bind(&definition)
        .bind(&definition_hash)
        .bind(json!([
            {"step_id": "prepare", "status": "completed"},
            {"step_id": "build", "status": "completed"}
        ]))
        .execute(&pool)
        .await
        .expect("insert running workflow run");

        Self {
            pool,
            ids,
            community_id,
            owner,
            approver,
            definition_hash,
        }
    }

    fn gate_spec(&self) -> GateSpec {
        GateSpec {
            community_id: self.community_id,
            channel_id: self.ids.channel_id,
            workflow_id: self.ids.workflow_id,
            run_id: self.ids.run_id,
            expected_generation: 1,
            definition_hash: self.definition_hash.clone(),
            step_id: "approve-release".to_owned(),
            step_index: 2,
            policy: CanonicalApprovalPolicy::new(
                vec![self.approver.clone()],
                vec![ApprovalRole::Owner],
            )
            .expect("valid approval policy"),
            action_summary: "release the prepared artifact".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            prior_step_outputs: json!({
                "prepare": {"artifact": "candidate"},
                "build": {"digest": "sha256:abc", "private": OUTPUT_SECRET}
            }),
            prior_execution_trace: json!([
                {"step_id": "prepare", "status": "completed"},
                {"step_id": "build", "status": "completed"}
            ]),
            waiting_trace_entry: json!({
                "step_id": "approve-release",
                "step_index": 2,
                "status": "waiting_approval"
            }),
            request_payload: json!({
                "class": "approval_requested",
                "timeout_seconds": 3_600
            }),
        }
    }

    async fn add_running_run(&self, marker: u8) -> (Uuid, Uuid, Vec<u8>) {
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let definition_hash = vec![marker; 32];
        let definition = json!({
            "trigger": {"on": "message_posted"},
            "steps": [{"id": "approve-release", "approval": {"role": "owner"}}]
        });
        sqlx::query(
            "INSERT INTO workflows \
             (community_id, id, name, owner_pubkey, channel_id, definition, definition_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(self.ids.community_id)
        .bind(workflow_id)
        .bind(format!("approval-contract-{marker}"))
        .bind(&self.owner)
        .bind(self.ids.channel_id)
        .bind(&definition)
        .bind(&definition_hash)
        .execute(&self.pool)
        .await
        .expect("insert additional workflow");
        sqlx::query(
            "INSERT INTO workflow_runs \
             (community_id, id, workflow_id, definition_snapshot, definition_hash, generation, \
              status, current_step, next_step, step_outputs, execution_trace) \
             VALUES ($1, $2, $3, $4, $5, 1, 'running', 0, 0, '{}'::jsonb, '[]'::jsonb)",
        )
        .bind(self.ids.community_id)
        .bind(run_id)
        .bind(workflow_id)
        .bind(&definition)
        .bind(&definition_hash)
        .execute(&self.pool)
        .await
        .expect("insert additional workflow run");
        (workflow_id, run_id, definition_hash)
    }
}

async fn connect_pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned());
    PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .expect("connect to workflow approval contract database")
}

async fn insert_channel(pool: &PgPool, community: CommunityId, id: Uuid, owner: &[u8]) {
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(community.as_uuid())
    .bind(id)
    .bind(format!("approval-contract-{}", id.simple()))
    .bind(owner)
    .execute(pool)
    .await
    .expect("insert approval contract channel");
}

#[derive(Debug, PartialEq)]
struct PersistenceSnapshot {
    run: Value,
    approvals: Vec<Value>,
    outbox: Vec<Value>,
}

async fn persistence_snapshot(
    pool: &PgPool,
    community: CommunityId,
    run_id: Uuid,
) -> PersistenceSnapshot {
    let run = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(r) FROM workflow_runs r WHERE community_id = $1 AND id = $2",
    )
    .bind(community.as_uuid())
    .bind(run_id)
    .fetch_one(pool)
    .await
    .expect("read workflow run persistence");
    let approvals = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(a) FROM workflow_approval_gates a \
         WHERE community_id = $1 AND run_id = $2 ORDER BY step_index",
    )
    .bind(community.as_uuid())
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("read workflow approval persistence");
    let outbox = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(o) FROM workflow_approval_outbox o \
         JOIN workflow_approval_gates g \
           ON g.community_id = o.community_id AND g.id = o.approval_id \
         WHERE o.community_id = $1 AND g.run_id = $2 ORDER BY o.id",
    )
    .bind(community.as_uuid())
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("read workflow outbox persistence");
    PersistenceSnapshot {
        run,
        approvals,
        outbox,
    }
}

fn created_receipt(outcome: ObservedCreate) -> (Uuid, i64) {
    match outcome {
        ObservedCreate::Created {
            approval_id,
            generation,
        } => (approval_id, generation),
        other => panic!("expected a new approval gate, got {other:?}"),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing persisted field {key}: {value}"))
}

fn assert_bound_gate(row: &Value, fixture: &Fixture, spec: &GateSpec, approval_id: Uuid) {
    assert_eq!(field(row, "id"), &json!(approval_id));
    assert_eq!(field(row, "community_id"), &json!(fixture.ids.community_id));
    assert_eq!(field(row, "channel_id"), &json!(fixture.ids.channel_id));
    assert_eq!(field(row, "workflow_id"), &json!(fixture.ids.workflow_id));
    assert_eq!(field(row, "run_id"), &json!(fixture.ids.run_id));
    assert_eq!(field(row, "step_id"), &json!(spec.step_id));
    assert_eq!(field(row, "step_index"), &json!(spec.step_index));
    assert_eq!(field(row, "generation"), &json!(2));
    assert_eq!(
        field(row, "policy_snapshot"),
        &serde_json::to_value(&spec.policy).expect("serialize expected policy")
    );
    assert_eq!(
        field(row, "resolved_approver_set"),
        &json!({
            "pubkeys": [hex::encode(&fixture.owner), hex::encode(&fixture.approver)],
            "roles": ["owner"]
        })
    );
    assert_eq!(field(row, "status"), "pending");
}

#[tokio::test]
#[ignore = "requires Postgres and exclusive access to the public schema"]
async fn populated_migration_preserves_legacy_approval_and_backfills_resume_state() {
    let pool = connect_pool().await;
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("drop public schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create public schema");
    MIGRATOR
        .run_to(PRE_APPROVAL_MIGRATION_VERSION, &pool)
        .await
        .expect("apply migrations through the pinned state-slice base");

    let ids = FixtureIds::random();
    let owner = vec![0x31; 32];
    let definition_hash = vec![0x32u8; 32];
    let definition = json!({"steps": [{"id": "one"}, {"id": "two"}, {"id": "gate"}]});
    let community = CommunityId::from_uuid(ids.community_id);
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(ids.community_id)
        .bind(format!("pre-approval-{}.test", ids.community_id.simple()))
        .execute(&pool)
        .await
        .expect("insert populated community");
    buzz_db::user::ensure_user(&pool, community, &owner)
        .await
        .expect("insert populated owner");
    insert_channel(&pool, community, ids.channel_id, &owner).await;
    sqlx::query(
        "INSERT INTO workflows \
         (community_id, id, name, owner_pubkey, channel_id, definition, definition_hash) \
         VALUES ($1, $2, 'populated-approval', $3, $4, $5, $6)",
    )
    .bind(ids.community_id)
    .bind(ids.workflow_id)
    .bind(&owner)
    .bind(ids.channel_id)
    .bind(&definition)
    .bind(&definition_hash)
    .execute(&pool)
    .await
    .expect("insert populated workflow");
    let original_trace = json!([
        {"step_id": "one", "status": "completed"},
        {"step_id": "two", "status": "completed"},
        {"step_id": "gate", "status": "waiting_approval"}
    ]);
    sqlx::query(
        "INSERT INTO workflow_runs \
         (community_id, id, workflow_id, definition_snapshot, definition_hash, generation, \
          status, current_step, execution_trace) \
         VALUES ($1, $2, $3, $4, $5, 7, 'waiting_approval', 2, $6)",
    )
    .bind(ids.community_id)
    .bind(ids.run_id)
    .bind(ids.workflow_id)
    .bind(&definition)
    .bind(&definition_hash)
    .bind(&original_trace)
    .execute(&pool)
    .await
    .expect("insert populated waiting run");
    sqlx::query(
        "INSERT INTO workflow_approvals \
         (community_id, token, workflow_id, run_id, step_id, step_index, approver_spec, expires_at) \
         VALUES ($1, $2, $3, $4, 'gate', 2, 'owner', NOW() + interval '1 hour')",
    )
    .bind(ids.community_id)
    .bind(vec![0x33u8; 32])
    .bind(ids.workflow_id)
    .bind(ids.run_id)
    .execute(&pool)
    .await
    .expect("insert populated pending approval");

    MIGRATOR
        .run(&pool)
        .await
        .expect("upgrade populated database through approval slice");

    let run: (i32, Value, Value, i64) = sqlx::query_as(
        "SELECT next_step, step_outputs, execution_trace, generation \
         FROM workflow_runs WHERE community_id = $1 AND id = $2",
    )
    .bind(ids.community_id)
    .bind(ids.run_id)
    .fetch_one(&pool)
    .await
    .expect("read migrated waiting run");
    assert_eq!(run.0, 3, "a migrated waiting gate resumes after its step");
    assert_eq!(run.1, json!({}));
    assert_eq!(run.2, original_trace);
    assert_eq!(run.3, 7, "migration must preserve the generation fence");

    let approval: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM workflow_approvals a \
         WHERE community_id = $1 AND run_id = $2 AND step_index = 2",
    )
    .bind(ids.community_id)
    .bind(ids.run_id)
    .fetch_one(&pool)
    .await
    .expect("read retained legacy approval");
    assert_eq!(
        field(&approval, "token"),
        &json!("\\x3333333333333333333333333333333333333333333333333333333333333333")
    );
    assert_eq!(field(&approval, "approver_spec"), "owner");
    let gate_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_approval_gates \
         WHERE community_id = $1 AND run_id = $2",
    )
    .bind(ids.community_id)
    .bind(ids.run_id)
    .fetch_one(&pool)
    .await
    .expect("count new approval gates");
    assert_eq!(
        gate_count, 0,
        "0031 must not rewrite legacy token approvals"
    );

    let state_version_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'workflow_runs' \
           AND column_name = 'state_version')",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect workflow run fencing columns");
    assert!(!state_version_exists, "generation is the only state fence");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn gate_creation_persists_exact_resume_cursor_outputs_and_waiting_trace() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    let (approval_id, generation) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    assert_eq!(generation, 2);

    let persisted =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(field(&persisted.run, "status"), "waiting_approval");
    assert_eq!(field(&persisted.run, "current_step"), &json!(2));
    assert_eq!(field(&persisted.run, "next_step"), &json!(3));
    assert_eq!(
        field(&persisted.run, "step_outputs"),
        &spec.prior_step_outputs
    );
    assert_eq!(field(&persisted.run, "generation"), &json!(2));
    assert_eq!(
        field(&persisted.run, "execution_trace"),
        &json!([
            spec.prior_execution_trace[0],
            spec.prior_execution_trace[1],
            spec.waiting_trace_entry
        ])
    );
    assert_eq!(persisted.approvals.len(), 1);
    assert_bound_gate(&persisted.approvals[0], &fixture, &spec, approval_id);
    assert_eq!(persisted.outbox.len(), 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn stale_generation_rolls_back_gate_run_and_outbox_writes() {
    let fixture = Fixture::new().await;
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    let mut stale = fixture.gate_spec();
    stale.expected_generation = 0;

    let outcome = create_gate(&fixture.pool, &stale)
        .await
        .expect("stale generation returns a typed outcome");
    assert_eq!(
        outcome,
        ObservedCreate::StaleGeneration {
            current_generation: 1
        }
    );
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(after, before, "a stale fence must roll back every write");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn no_current_policy_match_returns_without_gate_run_or_outbox_writes() {
    let fixture = Fixture::new().await;
    sqlx::query(
        "UPDATE channel_members SET removed_at = now() \
         WHERE community_id = $1 AND channel_id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .execute(&fixture.pool)
    .await
    .expect("remove all policy matches");
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    let outcome = create_gate(&fixture.pool, &fixture.gate_spec())
        .await
        .expect("resolve an unsatisfied policy");
    assert_eq!(outcome, ObservedCreate::NoEligibleApprovers);
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(after, before, "an unsatisfied policy must not write");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn membership_changes_and_gate_creation_share_the_channel_lock() {
    let fixture = Fixture::new().await;
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    let mut holder = fixture.pool.begin().await.expect("begin membership change");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "buzz_channel_membership:{}:{}",
            fixture.ids.community_id, fixture.ids.channel_id
        ))
        .execute(&mut *holder)
        .await
        .expect("hold channel membership lock");

    let task_pool = fixture.pool.clone();
    let task_spec = fixture.gate_spec();
    let mut gate_task = tokio::spawn(async move { create_gate(&task_pool, &task_spec).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut gate_task)
            .await
            .is_err(),
        "gate creation must wait behind the membership lock"
    );

    sqlx::query(
        "UPDATE channel_members SET removed_at = now() \
         WHERE community_id = $1 AND channel_id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .execute(&mut *holder)
    .await
    .expect("remove approvers while holding membership lock");
    holder.commit().await.expect("commit membership change");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), gate_task)
        .await
        .expect("gate creation unblocks")
        .expect("gate task joins")
        .expect("gate creation returns an outcome");
    assert_eq!(outcome, ObservedCreate::NoEligibleApprovers);
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(after, before, "serialized no-match creation must not write");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_channel_changes_and_gate_creation_share_the_workflow_row_lock() {
    let fixture = Fixture::new().await;
    let replacement_channel_id = Uuid::new_v4();
    insert_channel(
        &fixture.pool,
        fixture.community_id,
        replacement_channel_id,
        &fixture.owner,
    )
    .await;
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    let mut holder = fixture.pool.begin().await.expect("begin workflow change");
    sqlx::query("SELECT id FROM workflows WHERE community_id = $1 AND id = $2 FOR UPDATE")
        .bind(fixture.ids.community_id)
        .bind(fixture.ids.workflow_id)
        .fetch_one(&mut *holder)
        .await
        .expect("hold workflow row lock");

    let task_pool = fixture.pool.clone();
    let task_spec = fixture.gate_spec();
    let mut gate_task = tokio::spawn(async move { create_gate(&task_pool, &task_spec).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut gate_task)
            .await
            .is_err(),
        "gate creation must wait behind the workflow row lock"
    );

    sqlx::query(
        "UPDATE workflows SET channel_id = $3, updated_at = now() \
         WHERE community_id = $1 AND id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.workflow_id)
    .bind(replacement_channel_id)
    .execute(&mut *holder)
    .await
    .expect("move workflow while holding its row lock");
    holder
        .commit()
        .await
        .expect("commit workflow channel change");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), gate_task)
        .await
        .expect("gate creation unblocks")
        .expect("gate task joins")
        .expect("gate creation returns an outcome");
    assert_eq!(outcome, ObservedCreate::Conflict);
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(after, before, "a stale workflow binding must not write");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn identical_gate_replay_reuses_gate_and_outbox_without_mutation() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    let (approval_id, generation) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    let replay = create_gate(&fixture.pool, &spec)
        .await
        .expect("replay identical approval gate");
    assert_eq!(
        replay,
        ObservedCreate::Reused {
            approval_id,
            generation
        }
    );
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(
        after, before,
        "replay must not refresh timestamps or payloads"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn same_run_step_with_different_payload_conflicts_without_mutation() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    let mut changed = spec.clone();
    changed.action_summary = "release a different artifact".to_owned();

    assert_eq!(
        create_gate(&fixture.pool, &changed)
            .await
            .expect("different replay returns conflict"),
        ObservedCreate::Conflict
    );
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(after, before, "conflict must preserve the winning request");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn replay_requires_exact_run_gate_trace_policy_expiry_and_request() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    let mut mutations = Vec::new();

    let mut changed_outputs = spec.clone();
    changed_outputs.prior_step_outputs["build"]["digest"] = json!("sha256:different");
    mutations.push(("outputs", changed_outputs));

    let mut changed_trace = spec.clone();
    changed_trace
        .prior_execution_trace
        .as_array_mut()
        .expect("fixture trace")
        .push(json!({"step_id": "unexpected", "status": "completed"}));
    mutations.push(("prior trace", changed_trace));

    let mut changed_waiting = spec.clone();
    changed_waiting.waiting_trace_entry["display"] = json!("different");
    let waiting_error = create_gate(&fixture.pool, &changed_waiting)
        .await
        .expect_err("an overbroad waiting trace must fail validation");
    assert!(
        waiting_error
            .to_string()
            .contains("waiting trace entry must contain only the exact step"),
        "unexpected waiting trace validation error: {waiting_error}"
    );
    let after_invalid_waiting =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(
        after_invalid_waiting, before,
        "an invalid waiting trace mutated the winning gate"
    );

    let mut changed_policy = spec.clone();
    changed_policy.policy =
        CanonicalApprovalPolicy::new(vec![], vec![ApprovalRole::Admin]).expect("admin policy");
    mutations.push(("policy", changed_policy));

    let mut changed_expiry = spec.clone();
    changed_expiry.expires_at += Duration::seconds(1);
    mutations.push(("expiry", changed_expiry));

    let mut changed_request = spec.clone();
    changed_request.request_payload = json!({
        "class": "approval_requested",
        "timeout_seconds": 3_601
    });
    mutations.push(("request payload", changed_request));

    let mut changed_step = spec.clone();
    changed_step.step_id = "approve-other".to_owned();
    changed_step.waiting_trace_entry["step_id"] = json!("approve-other");
    mutations.push(("gate step", changed_step));

    for (label, changed) in mutations {
        assert_eq!(
            create_gate(&fixture.pool, &changed)
                .await
                .unwrap_or_else(|error| panic!("{label} replay returned an error: {error}")),
            ObservedCreate::Conflict,
            "{label} replay must conflict"
        );
        let after =
            persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
        assert_eq!(after, before, "{label} replay mutated the winning gate");
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn replay_rejects_a_mismatched_current_step_without_mutation() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    sqlx::query("UPDATE workflow_runs SET current_step = 1 WHERE community_id = $1 AND id = $2")
        .bind(fixture.ids.community_id)
        .bind(fixture.ids.run_id)
        .execute(&fixture.pool)
        .await
        .expect("inject a mismatched replay cursor");
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    assert_eq!(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("mismatched replay returns an outcome"),
        ObservedCreate::Conflict
    );
    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(
        after, before,
        "replay must not repair or rewrite the cursor"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn tenant_and_channel_collisions_fail_closed() {
    let fixture = Fixture::new().await;
    let tenant_a_before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    let tenant_b = Fixture::insert(
        fixture.pool.clone(),
        FixtureIds {
            community_id: Uuid::new_v4(),
            channel_id: fixture.ids.channel_id,
            workflow_id: fixture.ids.workflow_id,
            run_id: fixture.ids.run_id,
        },
        0x81,
    )
    .await;
    let tenant_b_before =
        persistence_snapshot(&tenant_b.pool, tenant_b.community_id, tenant_b.ids.run_id).await;

    let mut wrong_tenant = fixture.gate_spec();
    wrong_tenant.community_id = tenant_b.community_id;
    assert!(
        matches!(
            create_gate(&fixture.pool, &wrong_tenant).await,
            Err(_) | Ok(ObservedCreate::Conflict)
        ),
        "colliding IDs must not let tenant A's definition authorize tenant B's run"
    );

    let wrong_channel_id = Uuid::new_v4();
    insert_channel(
        &fixture.pool,
        fixture.community_id,
        wrong_channel_id,
        &fixture.owner,
    )
    .await;
    let mut wrong_channel = fixture.gate_spec();
    wrong_channel.channel_id = wrong_channel_id;
    assert!(
        matches!(
            create_gate(&fixture.pool, &wrong_channel).await,
            Err(_) | Ok(ObservedCreate::Conflict)
        ),
        "the run's tenant is insufficient without its exact bound channel"
    );

    let tenant_a_after =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(
        tenant_a_after, tenant_a_before,
        "collision attempts must not touch tenant A"
    );
    let tenant_b_after =
        persistence_snapshot(&tenant_b.pool, tenant_b.community_id, tenant_b.ids.run_id).await;
    assert_eq!(
        tenant_b_after, tenant_b_before,
        "collision attempts must not touch tenant B"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn approval_history_survives_workflow_deletion() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    let before =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;

    buzz_db::workflow::delete_workflow(
        &fixture.pool,
        fixture.community_id,
        fixture.ids.workflow_id,
    )
    .await
    .expect("delete workflow");

    let tombstone: (bool, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT enabled, deleted_at FROM workflows WHERE community_id = $1 AND id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.workflow_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read workflow tombstone");
    assert!(!tombstone.0, "soft deletion must disable the workflow");
    assert!(tombstone.1.is_some(), "soft deletion must set deleted_at");
    assert!(
        matches!(
            buzz_db::workflow::get_workflow(
                &fixture.pool,
                fixture.community_id,
                fixture.ids.workflow_id,
            )
            .await,
            Err(buzz_db::DbError::NotFound(_))
        ),
        "public workflow reads must hide tombstones"
    );
    assert!(matches!(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("deleted workflow gate attempt returns an outcome"),
        ObservedCreate::Conflict
    ));

    let after = persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(
        after.run, before.run,
        "the workflow run must survive soft deletion unchanged"
    );
    assert_eq!(
        after.approvals, before.approvals,
        "approval history bytes must survive soft deletion unchanged"
    );
    assert_eq!(
        after.outbox, before.outbox,
        "approval outbox bytes must survive soft deletion unchanged"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn outbox_deduplicates_replays_and_orders_gate_requests() {
    let fixture = Fixture::new().await;
    let first = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &first)
            .await
            .expect("create first gate"),
    );
    assert!(matches!(
        create_gate(&fixture.pool, &first)
            .await
            .expect("replay first gate"),
        ObservedCreate::Reused { .. }
    ));

    let (workflow_id, run_id, definition_hash) = fixture.add_running_run(0x71).await;
    let mut second = fixture.gate_spec();
    second.workflow_id = workflow_id;
    second.run_id = run_id;
    second.definition_hash = definition_hash;
    second.step_id = "approve-release".to_owned();
    second.step_index = 0;
    second.waiting_trace_entry =
        json!({"step_id": "approve-release", "step_index": 0, "status": "waiting_approval"});
    created_receipt(
        create_gate(&fixture.pool, &second)
            .await
            .expect("create second gate"),
    );

    let rows: Vec<(i64, String, Uuid)> = sqlx::query_as(
        "SELECT o.id, o.dedupe_key, g.run_id FROM workflow_approval_outbox o \
         JOIN workflow_approval_gates g \
           ON g.community_id = o.community_id AND g.id = o.approval_id \
         WHERE o.community_id = $1 AND g.channel_id = $2 ORDER BY o.id",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("read ordered approval request outbox");
    assert_eq!(rows.len(), 2, "an exact replay must not enqueue twice");
    assert!(
        rows[0].0 < rows[1].0,
        "outbox sequence must define replay order"
    );
    assert_ne!(
        rows[0].1, rows[1].1,
        "different gates need different dedupe keys"
    );
    assert_eq!(rows[0].2, fixture.ids.run_id);
    assert_eq!(rows[1].2, run_id);
}

#[derive(Clone, Copy)]
enum FailPoint {
    ApprovalInsert,
    RunUpdate,
    EventInsert,
    OutboxInsert,
}

impl FailPoint {
    fn table(self) -> &'static str {
        match self {
            Self::ApprovalInsert => "workflow_approval_gates",
            Self::RunUpdate => "workflow_runs",
            Self::EventInsert => "events",
            Self::OutboxInsert => "workflow_approval_outbox",
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::RunUpdate => "UPDATE",
            Self::ApprovalInsert | Self::EventInsert | Self::OutboxInsert => "INSERT",
        }
    }
}

async fn install_fail_trigger(pool: &PgPool, point: FailPoint, suffix: &str) -> (String, String) {
    let function = format!("approval_contract_fail_{suffix}");
    let trigger = format!("approval_contract_trigger_{suffix}");
    let function_sql = format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'approval contract injected failure'; END $$"
    );
    sqlx::query(sqlx::AssertSqlSafe(function_sql))
        .execute(pool)
        .await
        .expect("install fault function");
    let trigger_sql = format!(
        "CREATE TRIGGER {trigger} AFTER {} ON {} \
         FOR EACH ROW EXECUTE FUNCTION {function}()",
        point.operation(),
        point.table()
    );
    sqlx::query(sqlx::AssertSqlSafe(trigger_sql))
        .execute(pool)
        .await
        .expect("install fault trigger");
    (trigger, function)
}

async fn remove_fail_trigger(pool: &PgPool, point: FailPoint, trigger: &str, function: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {trigger} ON {}",
        point.table()
    )))
    .execute(pool)
    .await
    .expect("remove fault trigger");
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {function}()")))
        .execute(pool)
        .await
        .expect("remove fault function");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn transaction_abort_after_each_write_leaves_no_partial_state() {
    for (index, point) in [
        FailPoint::ApprovalInsert,
        FailPoint::RunUpdate,
        FailPoint::OutboxInsert,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new().await;
        let before =
            persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
        let suffix = format!("{}_{}", fixture.ids.run_id.simple(), index);
        let (trigger, function) = install_fail_trigger(&fixture.pool, point, &suffix).await;

        let result = create_gate(&fixture.pool, &fixture.gate_spec()).await;
        remove_fail_trigger(&fixture.pool, point, &trigger, &function).await;
        assert!(result.is_err(), "fault injection must abort gate creation");

        let after =
            persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
        assert_eq!(after, before, "fault point {index} leaked partial state");
    }

    for (index, point) in [FailPoint::EventInsert, FailPoint::OutboxInsert]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new().await;
        let (approval_id, _) = created_receipt(
            create_gate(&fixture.pool, &fixture.gate_spec())
                .await
                .expect("create gate before decision fault"),
        );
        let before =
            persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
        let suffix = format!("decision_{}_{}", fixture.ids.run_id.simple(), index);
        let (trigger, function) = install_fail_trigger(&fixture.pool, point, &suffix).await;

        let result = decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            None,
            0x90 + index as u8,
        )
        .await;
        remove_fail_trigger(&fixture.pool, point, &trigger, &function).await;
        assert!(result.is_err(), "decision fault injection must abort");

        let after =
            persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
        assert_eq!(
            after, before,
            "decision fault point {index} leaked run, gate, or outbox state"
        );
        let event_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events \
             WHERE community_id = $1 AND d_tag = $2",
        )
        .bind(fixture.ids.community_id)
        .bind(approval_id.to_string())
        .fetch_one(&fixture.pool)
        .await
        .expect("count rolled-back decision events");
        assert_eq!(
            event_count, 0,
            "decision event must roll back with the transaction"
        );
    }
}

fn json_has_token_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            key.to_ascii_lowercase().contains("token") || json_has_token_key(nested)
        }),
        Value::Array(values) => values.iter().any(json_has_token_key),
        _ => false,
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn approval_row_and_request_payload_have_no_raw_token_contract() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );

    let forbidden_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'workflow_approval_gates' \
           AND column_name IN ('token', 'approval_token', 'raw_approval_token')",
    )
    .fetch_all(&fixture.pool)
    .await
    .expect("inspect approval token columns");
    assert!(
        forbidden_columns.is_empty(),
        "approval rows must use public IDs, never raw token columns: {forbidden_columns:?}"
    );

    let persisted =
        persistence_snapshot(&fixture.pool, fixture.community_id, fixture.ids.run_id).await;
    assert_eq!(persisted.approvals.len(), 1);
    assert!(field(&persisted.approvals[0], "id").is_string());
    assert_eq!(persisted.outbox.len(), 1);
    let payload = field(&persisted.outbox[0], "payload");
    assert!(
        !json_has_token_key(payload),
        "request payload exposes token-shaped data"
    );
    let serialized = serde_json::to_string(payload).expect("serialize request payload");
    assert!(serialized.contains(&fixture.ids.channel_id.to_string()));
    assert!(serialized.contains(&fixture.ids.workflow_id.to_string()));
    assert!(serialized.contains(&fixture.ids.run_id.to_string()));
    assert!(serialized.contains("approve-release"));
    assert!(serialized.contains("release the prepared artifact"));
    assert!(!serialized.contains(DEFINITION_SECRET));
    assert!(!serialized.contains(OUTPUT_SECRET));

    let tags = field(payload, "tags")
        .as_array()
        .expect("request payload tags are an array");
    let h_tags: Vec<Value> = tags
        .iter()
        .filter(|tag| tag.get(0) == Some(&json!("h")))
        .cloned()
        .collect();
    assert_eq!(
        h_tags,
        vec![json!(["h", fixture.ids.channel_id.to_string()])],
        "request must contain exactly one h tag for the bound channel"
    );
    let p_tags: Vec<Value> = tags
        .iter()
        .filter(|tag| tag.get(0) == Some(&json!("p")))
        .cloned()
        .collect();
    assert_eq!(
        p_tags,
        vec![
            json!(["p", hex::encode(&fixture.owner)]),
            json!(["p", hex::encode(&fixture.approver)]),
        ],
        "request must contain exactly one p tag per resolved approver"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn decision_grant_is_atomic_generation_fenced_and_exactly_replayable() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    let (approval_id, gate_generation) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    assert_eq!(gate_generation, 2);

    let applied = decide_gate(
        &fixture,
        approval_id,
        &fixture.approver,
        "grant",
        Some("ship it"),
        0xa1,
    )
    .await
    .expect("grant approval");
    assert_eq!(
        applied,
        WorkflowApprovalDecisionOutcome::Applied {
            run_id: fixture.ids.run_id,
            generation: 3,
        }
    );

    let row: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object(\
            'run_status', run.status::text, 'generation', run.generation,\
            'next_step', run.next_step, 'completed_at', run.completed_at,\
            'gate_status', gate.status, 'actor', encode(gate.decision_actor_pubkey, 'hex'),\
            'role', gate.decision_actor_role::text, 'matched', gate.matched_policy,\
            'decision_event', encode(gate.decision_event_id, 'hex')) \
         FROM workflow_runs run JOIN workflow_approval_gates gate \
           ON gate.community_id = run.community_id AND gate.run_id = run.id \
         WHERE run.community_id = $1 AND run.id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.run_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read granted gate and run");
    assert_eq!(row["run_status"], "resume_pending");
    assert_eq!(row["generation"], 3);
    assert_eq!(row["next_step"], 3);
    assert!(row["completed_at"].is_null());
    assert_eq!(row["gate_status"], "granted");
    assert_eq!(row["actor"], hex::encode(&fixture.approver));
    assert_eq!(row["role"], "admin");
    assert_eq!(row["matched"]["kind"], "exact_pubkey");
    assert_eq!(row["decision_event"], hex::encode(vec![0xa1; 32]));
    let decision_event: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object(\
            'pubkey', encode(pubkey, 'hex'), 'kind', kind, 'tags', tags,\
            'content', content, 'signature', encode(sig, 'hex'),\
            'channel_id', channel_id, 'd_tag', d_tag) \
         FROM events WHERE community_id = $1 AND id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(vec![0xa1_u8; 32])
    .fetch_one(&fixture.pool)
    .await
    .expect("read persisted signed decision event");
    assert_eq!(decision_event["pubkey"], hex::encode(&fixture.approver));
    assert_eq!(decision_event["kind"], 46_030);
    assert_eq!(
        decision_event["tags"],
        json!([["d", approval_id.to_string()]])
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            decision_event["content"]
                .as_str()
                .expect("decision event content text")
        )
        .expect("decision event content JSON"),
        json!({"decision": "grant", "note": "ship it"})
    );
    assert_eq!(decision_event["signature"], hex::encode(vec![0xa2; 64]));
    assert_eq!(decision_event["channel_id"], json!(fixture.ids.channel_id));
    assert_eq!(decision_event["d_tag"], json!(approval_id.to_string()));
    let lifecycle_classes: Vec<String> = sqlx::query_scalar(
        "SELECT class FROM workflow_approval_outbox \
         WHERE community_id = $1 AND approval_id = $2 AND class <> 'approval_requested' \
         ORDER BY class",
    )
    .bind(fixture.ids.community_id)
    .bind(approval_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("read lifecycle rows");
    assert_eq!(
        lifecycle_classes,
        vec!["approval_granted", "workflow_resume_pending"]
    );

    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            Some("ship it"),
            0xa1,
        )
        .await
        .expect("replay grant"),
        WorkflowApprovalDecisionOutcome::Reused {
            run_id: fixture.ids.run_id,
            generation: 3,
        }
    );
    let exact_event = decision_event_fixture(
        approval_id,
        &fixture.approver,
        "grant",
        Some("ship it"),
        0xa1,
    );
    let mut altered_events = Vec::new();
    let mut altered_signature = exact_event.clone();
    altered_signature.signature = vec![0xfe; 64];
    altered_events.push(("signature", altered_signature));
    let mut altered_content = exact_event.clone();
    altered_content.content = r#"{"decision":"grant","note":"ship it" }"#.to_owned();
    altered_events.push(("content bytes", altered_content));
    let mut altered_tags = exact_event.clone();
    altered_tags.tags = json!([
        ["d", approval_id.to_string()],
        ["client", "approval-contract"]
    ]);
    altered_events.push(("tags", altered_tags));
    let mut altered_created_at = exact_event;
    altered_created_at.created_at += Duration::seconds(1);
    altered_events.push(("created_at", altered_created_at));
    for (field, event) in altered_events {
        assert_eq!(
            decide_gate_event(
                &fixture,
                approval_id,
                &fixture.approver,
                "grant",
                Some("ship it"),
                &event,
            )
            .await
            .unwrap_or_else(|error| panic!("altered {field} replay failed: {error}")),
            WorkflowApprovalDecisionOutcome::Conflict,
            "altered signed {field} must not be reused",
        );
    }
    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "deny",
            Some("changed mind"),
            0xa2,
        )
        .await
        .expect("conflicting decision"),
        WorkflowApprovalDecisionOutcome::Conflict
    );
    for (actor, note, marker) in [
        (fixture.approver.as_slice(), Some("ship it"), 0xa3),
        (fixture.approver.as_slice(), Some("different note"), 0xa1),
        (fixture.owner.as_slice(), Some("ship it"), 0xa1),
    ] {
        assert_eq!(
            decide_gate(&fixture, approval_id, actor, "grant", note, marker)
                .await
                .expect("conflicting replay"),
            WorkflowApprovalDecisionOutcome::Conflict
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn decision_deny_cancels_without_advancing_the_resume_cursor() {
    let fixture = Fixture::new().await;
    let spec = fixture.gate_spec();
    let (approval_id, _) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create approval gate"),
    );
    assert!(matches!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.owner,
            "deny",
            Some("release rejected"),
            0xb1,
        )
        .await
        .expect("deny approval"),
        WorkflowApprovalDecisionOutcome::Applied { generation: 3, .. }
    ));
    let run: (String, i64, i32, Option<DateTime<Utc>>, Option<String>) = sqlx::query_as(
        "SELECT status::text, generation, next_step, completed_at, error_message \
         FROM workflow_runs WHERE community_id = $1 AND id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.run_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read denied run");
    assert_eq!(run.0, "cancelled");
    assert_eq!(run.1, 3);
    assert_eq!(run.2, 3, "deny must not execute or advance a later step");
    assert!(run.3.is_some());
    assert_eq!(
        run.4.as_deref(),
        Some("workflow cancelled: approval denied")
    );
    let classes: Vec<String> = sqlx::query_scalar(
        "SELECT class FROM workflow_approval_outbox \
         WHERE community_id = $1 AND approval_id = $2 AND class <> 'approval_requested' \
         ORDER BY class",
    )
    .bind(fixture.ids.community_id)
    .bind(approval_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("read denial lifecycle rows");
    assert_eq!(classes, vec!["approval_denied", "workflow_cancelled"]);
    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.owner,
            "deny",
            Some("release rejected"),
            0xb1,
        )
        .await
        .expect("replay denial"),
        WorkflowApprovalDecisionOutcome::Reused {
            run_id: fixture.ids.run_id,
            generation: 3,
        }
    );
    assert_eq!(
        decide_gate(&fixture, approval_id, &fixture.owner, "grant", None, 0xb2,)
            .await
            .expect("conflicting grant after denial"),
        WorkflowApprovalDecisionOutcome::Conflict
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn decision_rejects_wrong_tenant_removed_member_role_drift_stale_generation_and_expiry() {
    let fixture = Fixture::new().await;
    let mut spec = fixture.gate_spec();
    spec.policy =
        CanonicalApprovalPolicy::new(vec![], vec![ApprovalRole::Admin]).expect("admin policy");
    let (approval_id, _) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create role-bound gate"),
    );

    let wrong_tenant = Fixture::insert(fixture.pool.clone(), FixtureIds::random(), 0xc1).await;
    assert_eq!(
        decide_gate(
            &wrong_tenant,
            approval_id,
            &wrong_tenant.approver,
            "grant",
            None,
            0xc2,
        )
        .await
        .expect("wrong tenant decision"),
        WorkflowApprovalDecisionOutcome::Conflict
    );

    sqlx::query(
        "UPDATE channel_members SET role = 'member' \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .bind(&fixture.approver)
    .execute(&fixture.pool)
    .await
    .expect("demote admin");
    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            None,
            0xc3,
        )
        .await
        .expect("role drift decision"),
        WorkflowApprovalDecisionOutcome::Unauthorized
    );

    let decoy_channel = Uuid::new_v4();
    insert_channel(
        &fixture.pool,
        fixture.community_id,
        decoy_channel,
        &fixture.owner,
    )
    .await;
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'admin')",
    )
    .bind(fixture.ids.community_id)
    .bind(decoy_channel)
    .bind(&fixture.approver)
    .execute(&fixture.pool)
    .await
    .expect("insert approver only in decoy channel");
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .bind(&fixture.approver)
    .execute(&fixture.pool)
    .await
    .expect("remove approver");
    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            None,
            0xc4,
        )
        .await
        .expect("decoy-channel member decision"),
        WorkflowApprovalDecisionOutcome::Unauthorized
    );

    sqlx::query(
        "UPDATE channel_members SET removed_at = NULL, role = 'admin' \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .bind(&fixture.approver)
    .execute(&fixture.pool)
    .await
    .expect("restore approver");
    sqlx::query(
        "UPDATE workflow_runs SET generation = generation + 1 \
         WHERE community_id = $1 AND id = $2",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.run_id)
    .execute(&fixture.pool)
    .await
    .expect("advance run generation");
    assert_eq!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            None,
            0xc5,
        )
        .await
        .expect("stale generation decision"),
        WorkflowApprovalDecisionOutcome::Conflict
    );

    let expiry_fixture = Fixture::new().await;
    let mut expiry_spec = expiry_fixture.gate_spec();
    expiry_spec.expires_at = Utc::now() + Duration::milliseconds(25);
    let (expiry_id, _) = created_receipt(
        create_gate(&expiry_fixture.pool, &expiry_spec)
            .await
            .expect("create short approval gate"),
    );
    sqlx::query("SELECT pg_sleep(0.05)")
        .execute(&expiry_fixture.pool)
        .await
        .expect("pass database expiry");
    assert_eq!(
        decide_gate(
            &expiry_fixture,
            expiry_id,
            &expiry_fixture.approver,
            "grant",
            None,
            0xc6,
        )
        .await
        .expect("expired decision"),
        WorkflowApprovalDecisionOutcome::Expired
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn exact_pubkey_policy_survives_role_drift_but_not_channel_removal() {
    let fixture = Fixture::new().await;
    let mut spec = fixture.gate_spec();
    spec.policy = CanonicalApprovalPolicy::new(vec![fixture.approver.clone()], vec![])
        .expect("exact pubkey policy");
    let (approval_id, _) = created_receipt(
        create_gate(&fixture.pool, &spec)
            .await
            .expect("create exact-key gate"),
    );
    sqlx::query(
        "UPDATE channel_members SET role = 'member' \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(fixture.ids.community_id)
    .bind(fixture.ids.channel_id)
    .bind(&fixture.approver)
    .execute(&fixture.pool)
    .await
    .expect("change exact approver role");
    assert!(matches!(
        decide_gate(
            &fixture,
            approval_id,
            &fixture.approver,
            "grant",
            None,
            0xd1,
        )
        .await
        .expect("exact-key decision after role drift"),
        WorkflowApprovalDecisionOutcome::Applied { .. }
    ));

    let removed_fixture = Fixture::new().await;
    let mut removed_spec = removed_fixture.gate_spec();
    removed_spec.policy =
        CanonicalApprovalPolicy::new(vec![removed_fixture.approver.clone()], vec![])
            .expect("removed-member exact pubkey policy");
    let (removed_approval_id, _) = created_receipt(
        create_gate(&removed_fixture.pool, &removed_spec)
            .await
            .expect("create removed-member gate"),
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(removed_fixture.ids.community_id)
    .bind(removed_fixture.ids.channel_id)
    .bind(&removed_fixture.approver)
    .execute(&removed_fixture.pool)
    .await
    .expect("remove exact-key approver");
    assert_eq!(
        decide_gate(
            &removed_fixture,
            removed_approval_id,
            &removed_fixture.approver,
            "grant",
            None,
            0xd2,
        )
        .await
        .expect("exact-key decision after channel removal"),
        WorkflowApprovalDecisionOutcome::Unauthorized
    );
}
