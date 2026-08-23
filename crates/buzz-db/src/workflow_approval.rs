//! Atomic creation of workflow approval gates and their request outbox rows.
//!
//! This module has no approval-token input. A public UUID locates a gate; later
//! decision handlers must establish authority from a signed actor and the
//! stored policy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use buzz_core::CommunityId;

use crate::error::{DbError, Result};
use crate::workflow::RunStatus;
use crate::workflow_run_transition::acquire_workflow_approval_channel_lock;

/// Maximum UTF-8 size of the safe action summary stored with a gate.
pub const ACTION_SUMMARY_MAX_BYTES: usize = 2_000;
/// Maximum serialized size of a request lifecycle payload.
pub const REQUEST_PAYLOAD_MAX_BYTES: usize = 65_536;

/// A built-in channel role that may satisfy an approval policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalRole {
    /// The actor must be a current channel owner.
    Owner,
    /// The actor must be a current channel admin.
    Admin,
}

/// Canonical immutable approval policy stored on a gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalApprovalPolicy {
    exact_pubkeys: Vec<String>,
    roles: Vec<ApprovalRole>,
}

impl CanonicalApprovalPolicy {
    /// Build a policy from exact 32-byte pubkeys and supported built-in roles.
    ///
    /// Pubkeys and roles are sorted and deduplicated so JSONB equality is a
    /// reliable idempotency check. At least one exact pubkey or role is required.
    pub fn new(exact_pubkeys: Vec<Vec<u8>>, mut roles: Vec<ApprovalRole>) -> Result<Self> {
        let mut exact_pubkeys = exact_pubkeys
            .into_iter()
            .map(|pubkey| {
                validate_pubkey(&pubkey)?;
                Ok(hex::encode(pubkey))
            })
            .collect::<Result<Vec<_>>>()?;
        exact_pubkeys.sort_unstable();
        exact_pubkeys.dedup();
        roles.sort_unstable();
        roles.dedup();

        if exact_pubkeys.is_empty() && roles.is_empty() {
            return Err(DbError::InvalidData(
                "approval policy must name an exact pubkey or owner/admin role".to_owned(),
            ));
        }

        Ok(Self {
            exact_pubkeys,
            roles,
        })
    }

    /// Canonical lowercase hex pubkeys authorized by the definition.
    pub fn exact_pubkeys(&self) -> &[String] {
        &self.exact_pubkeys
    }

    /// Canonically ordered built-in roles authorized by the definition.
    pub fn roles(&self) -> &[ApprovalRole] {
        &self.roles
    }

    fn validate_canonical(&self) -> Result<()> {
        let decoded = self
            .exact_pubkeys
            .iter()
            .map(|pubkey| {
                if pubkey.len() != 64
                    || pubkey
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                {
                    return Err(DbError::InvalidData(
                        "approval policy pubkeys must be lowercase 32-byte hex".to_owned(),
                    ));
                }
                hex::decode(pubkey).map_err(|error| {
                    DbError::InvalidData(format!("invalid approval policy pubkey: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let canonical = Self::new(decoded, self.roles.clone())?;
        if &canonical != self {
            return Err(DbError::InvalidData(
                "approval policy is not canonically ordered and deduplicated".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ApprovalRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
        }
    }
}

/// Canonical concrete approvers resolved from current channel membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApprovers(Vec<Vec<u8>>);

impl ResolvedApprovers {
    /// Validate, sort, and deduplicate resolved 32-byte pubkeys.
    pub fn new(mut pubkeys: Vec<Vec<u8>>) -> Result<Self> {
        for pubkey in &pubkeys {
            validate_pubkey(pubkey)?;
        }
        pubkeys.sort_unstable();
        pubkeys.dedup();
        if pubkeys.is_empty() {
            return Err(DbError::InvalidData(
                "approval gate requires at least one resolved approver".to_owned(),
            ));
        }
        Ok(Self(pubkeys))
    }

    /// Canonically ordered resolved pubkeys.
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.0
    }
}

/// A bounded caller-reviewed summary safe to publish in an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalActionSummary(String);

impl ApprovalActionSummary {
    /// Validate a non-empty summary no larger than [`ACTION_SUMMARY_MAX_BYTES`].
    pub fn new(summary: impl Into<String>) -> Result<Self> {
        let summary = summary.into();
        if summary.trim().is_empty() {
            return Err(DbError::InvalidData(
                "approval action summary must not be empty".to_owned(),
            ));
        }
        if summary.len() > ACTION_SUMMARY_MAX_BYTES {
            return Err(DbError::InvalidData(format!(
                "approval action summary exceeds {ACTION_SUMMARY_MAX_BYTES} UTF-8 bytes"
            )));
        }
        Ok(Self(summary))
    }

    /// The validated summary text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded request-event payload persisted in the transactional outbox.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequestPayload(Value);

impl ApprovalRequestPayload {
    /// Validate an object payload and reject fields that could carry raw gate
    /// authority, frozen definitions, prior outputs, headers, or credentials.
    pub fn new(payload: Value) -> Result<Self> {
        if !payload.is_object() {
            return Err(DbError::InvalidData(
                "approval request payload must be a JSON object".to_owned(),
            ));
        }
        reject_forbidden_payload_fields(&payload)?;
        let size = serde_json::to_vec(&payload)?.len();
        if size > REQUEST_PAYLOAD_MAX_BYTES {
            return Err(DbError::InvalidData(format!(
                "approval request payload exceeds {REQUEST_PAYLOAD_MAX_BYTES} serialized bytes"
            )));
        }
        Ok(Self(payload))
    }

    /// The validated JSON payload.
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

/// Inputs to the atomic approval-gate creation transaction.
pub struct CreateWorkflowApprovalGateParams<'a> {
    /// Server-resolved community that owns every row in the transaction.
    pub community_id: CommunityId,
    /// Channel whose membership lock serializes policy resolution.
    pub channel_id: Uuid,
    /// Workflow snapshot identity expected on the run.
    pub workflow_id: Uuid,
    /// Running workflow execution that reached the gate.
    pub run_id: Uuid,
    /// Exact 32-byte hash of the run's frozen definition.
    pub definition_hash: &'a [u8],
    /// Stable step identifier from the frozen definition.
    pub step_id: &'a str,
    /// Zero-based index of the approval step.
    pub step_index: i32,
    /// Generation held by the executor before it enters the gate.
    pub expected_generation: i64,
    /// Canonical policy snapshot from the approval step.
    pub policy: &'a CanonicalApprovalPolicy,
    /// Bounded summary safe for the channel-scoped request event.
    pub action_summary: &'a ApprovalActionSummary,
    /// Database expiry instant for the pending gate.
    pub expires_at: DateTime<Utc>,
    /// Complete durable outputs of steps before this approval step.
    pub prior_step_outputs: &'a Value,
    /// Exact display-only trace item appended when the run starts waiting.
    pub waiting_trace_entry: &'a Value,
    /// Request lifecycle payload for the durable outbox.
    pub request_payload: &'a ApprovalRequestPayload,
}

/// Immutable approval gate returned after creation or exact replay.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowApprovalGateRecord {
    /// Public, non-authorizing approval identifier.
    pub approval_id: Uuid,
    /// Community that owns the gate.
    pub community_id: CommunityId,
    /// Channel whose current membership governs decisions.
    pub channel_id: Uuid,
    /// Workflow snapshot identity.
    pub workflow_id: Uuid,
    /// Run waiting at the gate.
    pub run_id: Uuid,
    /// Frozen definition hash.
    pub definition_hash: Vec<u8>,
    /// Frozen step identifier.
    pub step_id: String,
    /// Frozen zero-based step index.
    pub step_index: i32,
    /// Run generation after it moved to `waiting_approval`.
    pub gate_generation: i64,
    /// Canonical policy snapshot.
    pub policy: CanonicalApprovalPolicy,
    /// Approver pubkeys resolved when the request was created.
    pub resolved_approvers: ResolvedApprovers,
    /// Gate expiry.
    pub expires_at: DateTime<Utc>,
    /// Database creation time.
    pub created_at: DateTime<Utc>,
}

/// Durable request-outbox identity returned with a gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowApprovalRequestRecord {
    /// Outbox row identifier.
    pub outbox_id: i64,
    /// Stable key that limits this gate to one request lifecycle row.
    pub dedupe_key: String,
}

/// Result of attempting to create a workflow approval gate.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum WorkflowApprovalGateCreationOutcome {
    /// The transaction created the gate, advanced the run, and enqueued a request.
    Created {
        /// Immutable gate state.
        gate: WorkflowApprovalGateRecord,
        /// Durable request row.
        request: WorkflowApprovalRequestRecord,
    },
    /// An exact committed retry reused the gate and request without new writes.
    Reused {
        /// Immutable gate state.
        gate: WorkflowApprovalGateRecord,
        /// Existing durable request row.
        request: WorkflowApprovalRequestRecord,
    },
    /// A tenant, channel, workflow, state, definition, or payload fence failed.
    Conflict,
    /// The bound run exists, but its generation no longer matches the caller's snapshot.
    StaleGeneration {
        /// Current generation held by the run.
        current_generation: i64,
    },
    /// No active channel member currently satisfies the frozen policy.
    NoEligibleApprovers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunGateState {
    Fresh { gate_generation: i64 },
    Replay { gate_generation: i64 },
    Conflict,
}

fn classify_run_gate_state(
    status: RunStatus,
    generation: i64,
    expected_generation: i64,
) -> RunGateState {
    let Some(gate_generation) = expected_generation.checked_add(1) else {
        return RunGateState::Conflict;
    };
    match (status, generation) {
        (RunStatus::Running, current) if current == expected_generation => {
            RunGateState::Fresh { gate_generation }
        }
        (RunStatus::WaitingApproval, current) if current == gate_generation => {
            RunGateState::Replay { gate_generation }
        }
        _ => RunGateState::Conflict,
    }
}

/// Create or exactly reuse a workflow approval gate in one transaction.
///
/// The channel advisory lock is the transaction's first database statement.
/// The function then locks and fences the run, resolves the policy from active
/// channel membership, creates the immutable gate, stores `next_step =
/// step_index + 1` and prior outputs, appends one waiting trace item, advances
/// the run generation, and inserts one request outbox row.
/// Any mismatch returns [`WorkflowApprovalGateCreationOutcome::Conflict`] and
/// rolls back every write. An exact retry after commit returns `Reused`.
pub async fn create_workflow_approval_gate(
    pool: &PgPool,
    params: CreateWorkflowApprovalGateParams<'_>,
) -> Result<WorkflowApprovalGateCreationOutcome> {
    validate_params(&params)?;
    let next_step = params.step_index.checked_add(1).ok_or_else(|| {
        DbError::InvalidData("approval step index cannot advance past i32::MAX".to_owned())
    })?;
    let gate_generation = params.expected_generation.checked_add(1).ok_or_else(|| {
        DbError::InvalidData("workflow run generation cannot advance past i64::MAX".to_owned())
    })?;
    let expires_at = DateTime::from_timestamp_micros(params.expires_at.timestamp_micros())
        .ok_or_else(|| DbError::InvalidData("approval expiry is out of range".to_owned()))?;
    let policy_json = serde_json::to_value(params.policy)?;
    let dedupe_key = request_dedupe_key(params.run_id, params.step_index);
    let proposed_approval_id = Uuid::new_v4();

    let mut tx = pool.begin().await?;
    acquire_workflow_approval_channel_lock(&mut tx, params.community_id, params.channel_id).await?;

    let run = sqlx::query(
        r#"
        SELECT run.workflow_id, run.status::text AS status, run.definition_hash,
               run.generation, run.next_step, run.step_outputs, run.execution_trace,
               clock_timestamp() AS database_now
        FROM workflow_runs AS run
        JOIN workflows AS workflow
          ON workflow.community_id = run.community_id
         AND workflow.id = run.workflow_id
        WHERE run.community_id = $1
          AND run.id = $2
          AND workflow.channel_id = $3
        FOR UPDATE OF run
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(params.run_id)
    .bind(params.channel_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(run) = run else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    };
    let run_workflow_id: Uuid = run.try_get("workflow_id")?;
    let run_status: RunStatus = run.try_get::<String, _>("status")?.parse()?;
    let run_definition_hash: Vec<u8> = run.try_get("definition_hash")?;
    let run_generation: i64 = run.try_get("generation")?;
    let database_now: DateTime<Utc> = run.try_get("database_now")?;

    if run_workflow_id != params.workflow_id
        || run_definition_hash.as_slice() != params.definition_hash
    {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    }

    let run_gate_state = classify_run_gate_state(
        run_status.clone(),
        run_generation,
        params.expected_generation,
    );
    if run_gate_state == RunGateState::Conflict {
        tx.rollback().await?;
        if matches!(run_status, RunStatus::Running | RunStatus::WaitingApproval)
            && run_generation != params.expected_generation
        {
            return Ok(WorkflowApprovalGateCreationOutcome::StaleGeneration {
                current_generation: run_generation,
            });
        }
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    }
    if matches!(run_gate_state, RunGateState::Fresh { .. }) && expires_at <= database_now {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    }

    let is_fresh = matches!(run_gate_state, RunGateState::Fresh { .. });
    let resolved_approvers = if is_fresh {
        let resolved = resolve_current_approvers(&mut tx, &params).await?;
        let Some(resolved) = resolved else {
            tx.rollback().await?;
            return Ok(WorkflowApprovalGateCreationOutcome::NoEligibleApprovers);
        };
        Some(resolved)
    } else {
        None
    };
    if is_fresh {
        let advanced_generation = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE workflow_runs
            SET status = 'waiting_approval',
                next_step = $1,
                step_outputs = $2,
                execution_trace = execution_trace || jsonb_build_array($3::jsonb),
                generation = generation + 1
            WHERE community_id = $4
              AND id = $5
              AND workflow_id = $6
              AND status = 'running'
              AND generation = $7
              AND definition_hash = $8
            RETURNING generation
            "#,
        )
        .bind(next_step)
        .bind(params.prior_step_outputs)
        .bind(params.waiting_trace_entry)
        .bind(params.community_id.as_uuid())
        .bind(params.run_id)
        .bind(params.workflow_id)
        .bind(params.expected_generation)
        .bind(params.definition_hash)
        .fetch_optional(&mut *tx)
        .await?;
        if advanced_generation != Some(gate_generation) {
            tx.rollback().await?;
            return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
        }
    }

    let inserted_gate = if is_fresh {
        let Some(resolved_approvers) = resolved_approvers.as_ref() else {
            tx.rollback().await?;
            return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
        };
        sqlx::query(
            r#"
            INSERT INTO workflow_approval_gates
                (id, community_id, channel_id, workflow_id, run_id,
                 definition_hash, step_id, step_index, generation,
                 policy_snapshot, resolved_approver_set, status, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                    'pending', $12)
            ON CONFLICT (community_id, run_id, step_index) DO NOTHING
            RETURNING id
            "#,
        )
        .bind(proposed_approval_id)
        .bind(params.community_id.as_uuid())
        .bind(params.channel_id)
        .bind(params.workflow_id)
        .bind(params.run_id)
        .bind(params.definition_hash)
        .bind(params.step_id)
        .bind(params.step_index)
        .bind(gate_generation)
        .bind(&policy_json)
        .bind(resolved_approver_set(params.policy, resolved_approvers))
        .bind(expires_at)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
    } else {
        false
    };

    let gate = load_gate_for_update(
        &mut tx,
        params.community_id,
        params.run_id,
        params.step_index,
    )
    .await?;
    let Some(gate) = gate else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    };

    if !gate_matches(&gate, &params, gate_generation, &policy_json, expires_at) {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    }

    match run_gate_state {
        RunGateState::Fresh { .. } => {
            if !inserted_gate {
                tx.rollback().await?;
                return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
            }
        }
        RunGateState::Replay { .. } => {
            let stored_next_step: i32 = run.try_get("next_step")?;
            let stored_outputs: Value = run.try_get("step_outputs")?;
            let stored_trace: Value = run.try_get("execution_trace")?;
            if stored_next_step != next_step
                || stored_outputs != *params.prior_step_outputs
                || stored_trace.as_array().and_then(|trace| trace.last())
                    != Some(params.waiting_trace_entry)
            {
                tx.rollback().await?;
                return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
            }
        }
        RunGateState::Conflict => {
            tx.rollback().await?;
            return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
        }
    }

    let request = insert_or_load_request(
        &mut tx,
        &params,
        &gate,
        gate_generation,
        expires_at,
        &dedupe_key,
    )
    .await?;
    let Some(request) = request else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalGateCreationOutcome::Conflict);
    };

    tx.commit().await?;
    if inserted_gate {
        Ok(WorkflowApprovalGateCreationOutcome::Created { gate, request })
    } else {
        Ok(WorkflowApprovalGateCreationOutcome::Reused { gate, request })
    }
}

fn validate_params(params: &CreateWorkflowApprovalGateParams<'_>) -> Result<()> {
    if params.definition_hash.len() != 32 {
        return Err(DbError::InvalidData(format!(
            "workflow definition hash must be 32 bytes, got {}",
            params.definition_hash.len()
        )));
    }
    if params.step_index < 0 {
        return Err(DbError::InvalidData(
            "approval step index must not be negative".to_owned(),
        ));
    }
    if params.step_id.is_empty() || params.step_id.len() > 64 {
        return Err(DbError::InvalidData(
            "approval step ID must be 1-64 UTF-8 bytes".to_owned(),
        ));
    }
    params.policy.validate_canonical()?;
    ApprovalActionSummary::new(params.action_summary.as_str())?;
    ApprovalRequestPayload::new(params.request_payload.as_value().clone())?;
    if !params.prior_step_outputs.is_object() {
        return Err(DbError::InvalidData(
            "prior workflow step outputs must be a JSON object".to_owned(),
        ));
    }
    validate_waiting_trace_entry(params)?;
    Ok(())
}

fn validate_waiting_trace_entry(params: &CreateWorkflowApprovalGateParams<'_>) -> Result<()> {
    let Some(entry) = params.waiting_trace_entry.as_object() else {
        return Err(DbError::InvalidData(
            "waiting trace entry must be a JSON object".to_owned(),
        ));
    };
    if entry.get("step_id").and_then(Value::as_str) != Some(params.step_id)
        || entry.get("step_index").and_then(Value::as_i64) != Some(i64::from(params.step_index))
        || entry.get("status").and_then(Value::as_str) != Some("waiting_approval")
    {
        return Err(DbError::InvalidData(
            "waiting trace entry must bind the exact step and waiting_approval status".to_owned(),
        ));
    }
    reject_forbidden_payload_fields(params.waiting_trace_entry)
}

fn resolved_approver_set(policy: &CanonicalApprovalPolicy, approvers: &ResolvedApprovers) -> Value {
    serde_json::json!({
        "pubkeys": approvers.as_slice().iter().map(hex::encode).collect::<Vec<_>>(),
        "roles": policy.roles(),
    })
}

async fn resolve_current_approvers(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &CreateWorkflowApprovalGateParams<'_>,
) -> Result<Option<ResolvedApprovers>> {
    let roles = params
        .policy
        .roles()
        .iter()
        .map(|role| role.as_str().to_owned())
        .collect::<Vec<_>>();
    let pubkeys = sqlx::query_scalar::<_, Vec<u8>>(
        r#"
        SELECT member.pubkey
        FROM channel_members AS member
        WHERE member.community_id = $1
          AND member.channel_id = $2
          AND member.removed_at IS NULL
          AND (
              encode(member.pubkey, 'hex') = ANY($3::text[])
              OR member.role::text = ANY($4::text[])
          )
        ORDER BY member.pubkey
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(params.channel_id)
    .bind(params.policy.exact_pubkeys())
    .bind(&roles)
    .fetch_all(&mut **tx)
    .await?;

    if pubkeys.is_empty() {
        Ok(None)
    } else {
        ResolvedApprovers::new(pubkeys).map(Some)
    }
}

fn validate_pubkey(pubkey: &[u8]) -> Result<()> {
    if pubkey.len() != 32 {
        return Err(DbError::InvalidData(format!(
            "approval pubkey must be 32 bytes, got {}",
            pubkey.len()
        )));
    }
    Ok(())
}

fn reject_forbidden_payload_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let normalized = key.to_ascii_lowercase();
                if normalized.contains("token")
                    || matches!(
                        normalized.as_str(),
                        "definition"
                            | "definition_snapshot"
                            | "step_outputs"
                            | "outputs"
                            | "headers"
                            | "secret"
                            | "secrets"
                            | "credentials"
                    )
                {
                    return Err(DbError::InvalidData(format!(
                        "approval request payload contains forbidden field '{key}'"
                    )));
                }
                reject_forbidden_payload_fields(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_forbidden_payload_fields(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn request_dedupe_key(run_id: Uuid, step_index: i32) -> String {
    format!("workflow-approval-request:{run_id}:{step_index}")
}

async fn load_gate_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    step_index: i32,
) -> Result<Option<WorkflowApprovalGateRecord>> {
    let row = sqlx::query(
        r#"
        SELECT id, community_id, channel_id, workflow_id, run_id,
               definition_hash, step_id, step_index, generation,
               policy_snapshot, resolved_approver_set,
               expires_at, created_at
        FROM workflow_approval_gates
        WHERE community_id = $1 AND run_id = $2 AND step_index = $3
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(step_index)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(row_to_gate).transpose()
}

fn row_to_gate(row: sqlx::postgres::PgRow) -> Result<WorkflowApprovalGateRecord> {
    let community_id: Uuid = row.try_get("community_id")?;
    let policy: CanonicalApprovalPolicy = serde_json::from_value(row.try_get("policy_snapshot")?)?;
    policy.validate_canonical()?;
    let resolved: Value = row.try_get("resolved_approver_set")?;
    let resolved_pubkeys = resolved
        .get("pubkeys")
        .and_then(Value::as_array)
        .ok_or_else(|| DbError::InvalidData("resolved approver set has no pubkeys".to_owned()))?
        .iter()
        .map(|pubkey| {
            let pubkey = pubkey.as_str().ok_or_else(|| {
                DbError::InvalidData("resolved approver pubkey is not text".to_owned())
            })?;
            hex::decode(pubkey).map_err(|error| {
                DbError::InvalidData(format!("invalid resolved approver pubkey: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let resolved_approvers = ResolvedApprovers::new(resolved_pubkeys)?;
    Ok(WorkflowApprovalGateRecord {
        approval_id: row.try_get("id")?,
        community_id: CommunityId::from_uuid(community_id),
        channel_id: row.try_get("channel_id")?,
        workflow_id: row.try_get("workflow_id")?,
        run_id: row.try_get("run_id")?,
        definition_hash: row.try_get("definition_hash")?,
        step_id: row.try_get("step_id")?,
        step_index: row.try_get("step_index")?,
        gate_generation: row.try_get("generation")?,
        policy,
        resolved_approvers,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn gate_matches(
    gate: &WorkflowApprovalGateRecord,
    params: &CreateWorkflowApprovalGateParams<'_>,
    gate_generation: i64,
    policy_json: &Value,
    expires_at: DateTime<Utc>,
) -> bool {
    gate.community_id == params.community_id
        && gate.channel_id == params.channel_id
        && gate.workflow_id == params.workflow_id
        && gate.run_id == params.run_id
        && gate.definition_hash.as_slice() == params.definition_hash
        && gate.step_id == params.step_id
        && gate.step_index == params.step_index
        && gate.gate_generation == gate_generation
        && serde_json::to_value(&gate.policy).ok().as_ref() == Some(policy_json)
        && gate.expires_at == expires_at
}

async fn insert_or_load_request(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &CreateWorkflowApprovalGateParams<'_>,
    gate: &WorkflowApprovalGateRecord,
    gate_generation: i64,
    expires_at: DateTime<Utc>,
    dedupe_key: &str,
) -> Result<Option<WorkflowApprovalRequestRecord>> {
    let expected_payload = bound_request_payload(
        params,
        gate.approval_id,
        &gate.resolved_approvers,
        gate_generation,
        expires_at,
    )?;
    sqlx::query(
        r#"
        INSERT INTO workflow_approval_outbox
            (community_id, approval_id, class, payload, dedupe_key)
        VALUES ($1, $2, 'approval_requested', $3, $4)
        ON CONFLICT (community_id, dedupe_key) DO NOTHING
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(gate.approval_id)
    .bind(&expected_payload)
    .bind(dedupe_key)
    .execute(&mut **tx)
    .await?;

    let row = sqlx::query(
        r#"
        SELECT id, community_id, approval_id, class, payload, dedupe_key
        FROM workflow_approval_outbox
        WHERE community_id = $1 AND dedupe_key = $2
        FOR UPDATE
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(dedupe_key)
    .fetch_optional(&mut **tx)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let row_community_id: Uuid = row.try_get("community_id")?;
    let matches = CommunityId::from_uuid(row_community_id) == params.community_id
        && row.try_get::<Uuid, _>("approval_id")? == gate.approval_id
        && row.try_get::<String, _>("class")? == "approval_requested"
        && row.try_get::<Value, _>("payload")? == expected_payload
        && row.try_get::<String, _>("dedupe_key")? == dedupe_key;
    if !matches {
        return Ok(None);
    }

    Ok(Some(WorkflowApprovalRequestRecord {
        outbox_id: row.try_get("id")?,
        dedupe_key: dedupe_key.to_owned(),
    }))
}

fn bound_request_payload(
    params: &CreateWorkflowApprovalGateParams<'_>,
    approval_id: Uuid,
    resolved_approvers: &ResolvedApprovers,
    gate_generation: i64,
    expires_at: DateTime<Utc>,
) -> Result<Value> {
    let mut payload = params
        .request_payload
        .as_value()
        .as_object()
        .cloned()
        .unwrap_or_default();
    payload.insert(
        "approval_id".to_owned(),
        Value::String(approval_id.to_string()),
    );
    payload.insert(
        "community_id".to_owned(),
        Value::String(params.community_id.as_uuid().to_string()),
    );
    payload.insert(
        "channel_id".to_owned(),
        Value::String(params.channel_id.to_string()),
    );
    payload.insert(
        "workflow_id".to_owned(),
        Value::String(params.workflow_id.to_string()),
    );
    payload.insert(
        "run_id".to_owned(),
        Value::String(params.run_id.to_string()),
    );
    payload.insert(
        "definition_hash".to_owned(),
        Value::String(hex::encode(params.definition_hash)),
    );
    payload.insert(
        "step_id".to_owned(),
        Value::String(params.step_id.to_owned()),
    );
    payload.insert("step_index".to_owned(), Value::from(params.step_index));
    payload.insert("generation".to_owned(), Value::from(gate_generation));
    payload.insert(
        "action_summary".to_owned(),
        Value::String(params.action_summary.as_str().to_owned()),
    );
    payload.insert(
        "expires_at".to_owned(),
        Value::String(expires_at.to_rfc3339()),
    );
    payload.insert(
        "tags".to_owned(),
        Value::Array(
            std::iter::once(serde_json::json!(["h", params.channel_id.to_string()]))
                .chain(
                    resolved_approvers
                        .as_slice()
                        .iter()
                        .map(|pubkey| serde_json::json!(["p", hex::encode(pubkey)])),
                )
                .collect(),
        ),
    );
    let payload = Value::Object(payload);
    ApprovalRequestPayload::new(payload.clone())?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_resolved_approvers_are_canonical() {
        let first = vec![0x01; 32];
        let second = vec![0x02; 32];
        let policy = CanonicalApprovalPolicy::new(
            vec![second.clone(), first.clone(), first.clone()],
            vec![
                ApprovalRole::Admin,
                ApprovalRole::Owner,
                ApprovalRole::Admin,
            ],
        )
        .expect("canonical policy");
        assert_eq!(
            policy.exact_pubkeys(),
            &[hex::encode(&first), hex::encode(&second)]
        );
        assert_eq!(policy.roles(), &[ApprovalRole::Owner, ApprovalRole::Admin]);

        let resolved = ResolvedApprovers::new(vec![second.clone(), first.clone(), second])
            .expect("canonical resolved approvers");
        assert_eq!(resolved.as_slice(), &[first, vec![0x02; 32]]);
    }

    #[test]
    fn policy_rejects_empty_or_malformed_pubkeys() {
        assert!(CanonicalApprovalPolicy::new(vec![], vec![]).is_err());
        assert!(CanonicalApprovalPolicy::new(vec![vec![0x01; 31]], vec![]).is_err());
        assert!(ResolvedApprovers::new(vec![]).is_err());
    }

    #[test]
    fn action_summary_is_utf8_byte_bounded() {
        assert!(ApprovalActionSummary::new("review deploy").is_ok());
        assert!(ApprovalActionSummary::new("   ").is_err());
        assert!(ApprovalActionSummary::new("x".repeat(ACTION_SUMMARY_MAX_BYTES + 1)).is_err());
        assert!(ApprovalActionSummary::new("é".repeat(ACTION_SUMMARY_MAX_BYTES / 2)).is_ok());
        assert!(ApprovalActionSummary::new("é".repeat(ACTION_SUMMARY_MAX_BYTES / 2 + 1)).is_err());
    }

    #[test]
    fn request_payload_rejects_private_or_unbounded_data() {
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "approval_id": Uuid::new_v4(),
            "action_summary": "review deploy"
        }))
        .is_ok());
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "nested": {"approval_token": "raw"}
        }))
        .is_err());
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "step_outputs": {"secret": "value"}
        }))
        .is_err());
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "summary": "x".repeat(REQUEST_PAYLOAD_MAX_BYTES)
        }))
        .is_err());
    }

    #[test]
    fn run_gate_state_allows_only_fresh_or_exact_committed_replay() {
        assert_eq!(
            classify_run_gate_state(RunStatus::Running, 7, 7),
            RunGateState::Fresh { gate_generation: 8 }
        );
        assert_eq!(
            classify_run_gate_state(RunStatus::WaitingApproval, 8, 7),
            RunGateState::Replay { gate_generation: 8 }
        );
        assert_eq!(
            classify_run_gate_state(RunStatus::WaitingApproval, 7, 7),
            RunGateState::Conflict
        );
        assert_eq!(
            classify_run_gate_state(RunStatus::Running, 8, 7),
            RunGateState::Conflict
        );
        assert_eq!(
            classify_run_gate_state(RunStatus::Completed, 8, 7),
            RunGateState::Conflict
        );
    }

    #[test]
    fn request_dedupe_key_is_stable_per_run_step() {
        let run_id = Uuid::parse_str("6cb54514-bc14-47dc-a9e9-cbf0de5b243e").expect("static UUID");
        assert_eq!(
            request_dedupe_key(run_id, 4),
            "workflow-approval-request:6cb54514-bc14-47dc-a9e9-cbf0de5b243e:4"
        );
        assert_ne!(request_dedupe_key(run_id, 4), request_dedupe_key(run_id, 5));
    }

    #[test]
    fn bound_request_contains_safe_gate_bindings_and_channel_tags() {
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let channel_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let approval_id = Uuid::new_v4();
        let definition_hash = vec![0x42; 32];
        let policy =
            CanonicalApprovalPolicy::new(vec![], vec![ApprovalRole::Owner]).expect("policy");
        let approver = vec![0x21; 32];
        let approvers = ResolvedApprovers::new(vec![approver.clone()]).expect("approvers");
        let summary = ApprovalActionSummary::new("release candidate").expect("summary");
        let outputs = serde_json::json!({"build": {"private": "not published"}});
        let waiting = serde_json::json!({
            "step_id": "approve-release",
            "step_index": 2,
            "status": "waiting_approval"
        });
        let request = ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested"
        }))
        .expect("request");
        let params = CreateWorkflowApprovalGateParams {
            community_id,
            channel_id,
            workflow_id,
            run_id,
            definition_hash: &definition_hash,
            step_id: "approve-release",
            step_index: 2,
            expected_generation: 7,
            policy: &policy,
            action_summary: &summary,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            prior_step_outputs: &outputs,
            waiting_trace_entry: &waiting,
            request_payload: &request,
        };

        validate_params(&params).expect("valid gate params");
        let gate_generation = 8;
        let expires_at = DateTime::from_timestamp_micros(params.expires_at.timestamp_micros())
            .expect("normalized expiry");
        let payload = bound_request_payload(
            &params,
            approval_id,
            &approvers,
            gate_generation,
            expires_at,
        )
        .expect("bound payload");
        assert_eq!(payload["approval_id"], approval_id.to_string());
        assert_eq!(payload["generation"], 8);
        assert_eq!(
            payload["tags"],
            serde_json::json!([["h", channel_id.to_string()], ["p", hex::encode(approver)]])
        );
        let serialized = serde_json::to_string(&payload).expect("serialize payload");
        assert!(!serialized.contains("not published"));
        assert!(!serialized.to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn waiting_trace_must_bind_the_exact_gate_step() {
        let policy =
            CanonicalApprovalPolicy::new(vec![], vec![ApprovalRole::Admin]).expect("policy");
        let summary = ApprovalActionSummary::new("inspect change").expect("summary");
        let definition_hash = vec![0x41; 32];
        let outputs = serde_json::json!({});
        let wrong_waiting = serde_json::json!({
            "step_id": "other",
            "step_index": 1,
            "status": "waiting_approval"
        });
        let request = ApprovalRequestPayload::new(serde_json::json!({})).expect("request");
        let params = CreateWorkflowApprovalGateParams {
            community_id: CommunityId::from_uuid(Uuid::new_v4()),
            channel_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
            definition_hash: &definition_hash,
            step_id: "approve-gate",
            step_index: 1,
            expected_generation: 1,
            policy: &policy,
            action_summary: &summary,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            prior_step_outputs: &outputs,
            waiting_trace_entry: &wrong_waiting,
            request_payload: &request,
        };

        assert!(validate_params(&params).is_err());
    }
}
