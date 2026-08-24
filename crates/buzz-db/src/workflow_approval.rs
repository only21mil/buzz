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
const REQUEST_PAYLOAD_ALLOWED_FIELDS: [&str; 2] = ["class", "timeout_seconds"];
const DECISION_PAYLOAD_ALLOWED_FIELDS: [&str; 2] = ["decision", "note"];
const DECISION_NOTE_MAX_BYTES: usize = 2_000;

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
    /// Validate the exact caller-owned request fields.
    pub fn new(payload: Value) -> Result<Self> {
        validate_request_payload_fields(&payload)?;
        validate_request_payload_size(&payload)?;
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
    /// Complete display trace before this approval step.
    pub prior_execution_trace: &'a Value,
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

/// A signed decision applied to a pending workflow approval gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowApprovalDecision {
    /// Permit the frozen run to become eligible for a durable resume lease.
    Grant,
    /// Cancel the frozen run without executing any later workflow step.
    Deny,
}

impl WorkflowApprovalDecision {
    fn gate_status(self) -> &'static str {
        match self {
            Self::Grant => "granted",
            Self::Deny => "denied",
        }
    }
}

/// Strictly allowlisted decision content derived from the signed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionPayload {
    decision: WorkflowApprovalDecision,
    note: Option<String>,
}

impl ApprovalDecisionPayload {
    /// Validate a JSON object containing only `decision` and optional `note`.
    pub fn new(value: Value) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            DbError::InvalidData("approval decision payload must be a JSON object".to_owned())
        })?;
        if object.len() > DECISION_PAYLOAD_ALLOWED_FIELDS.len()
            || object
                .keys()
                .any(|field| !DECISION_PAYLOAD_ALLOWED_FIELDS.contains(&field.as_str()))
        {
            return Err(DbError::InvalidData(
                "approval decision payload contains an unknown field".to_owned(),
            ));
        }
        let decision = match object.get("decision").and_then(Value::as_str) {
            Some("grant") => WorkflowApprovalDecision::Grant,
            Some("deny") => WorkflowApprovalDecision::Deny,
            _ => {
                return Err(DbError::InvalidData(
                    "approval decision must be grant or deny".to_owned(),
                ))
            }
        };
        let note = match object.get("note") {
            None | Some(Value::Null) => None,
            Some(Value::String(note)) if !note.trim().is_empty() => {
                if note.len() > DECISION_NOTE_MAX_BYTES {
                    return Err(DbError::InvalidData(format!(
                        "approval decision note exceeds {DECISION_NOTE_MAX_BYTES} UTF-8 bytes"
                    )));
                }
                Some(note.clone())
            }
            Some(Value::String(_)) => None,
            Some(_) => {
                return Err(DbError::InvalidData(
                    "approval decision note must be text".to_owned(),
                ))
            }
        };
        if decision == WorkflowApprovalDecision::Deny && note.is_none() {
            return Err(DbError::InvalidData(
                "denial requires a non-empty note".to_owned(),
            ));
        }
        Ok(Self { decision, note })
    }

    /// The validated decision.
    pub fn decision(&self) -> WorkflowApprovalDecision {
        self.decision
    }

    /// The validated note, if supplied.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// Raw fields of a signature-verified decision event stored with the decision.
pub struct WorkflowApprovalDecisionEvent<'a> {
    /// Exact 32-byte Nostr event identifier.
    pub event_id: &'a [u8],
    /// Exact 32-byte signing pubkey. It must equal the decision actor.
    pub pubkey: &'a [u8],
    /// Signed Nostr creation time.
    pub created_at: DateTime<Utc>,
    /// Signed decision kind (`46030` grant or `46031` deny).
    pub kind: i32,
    /// Canonical serialized Nostr tags.
    pub tags: &'a Value,
    /// Signed event content.
    pub content: &'a str,
    /// Exact 64-byte Schnorr signature.
    pub signature: &'a [u8],
    /// Relay receipt time.
    pub received_at: DateTime<Utc>,
}

/// Inputs to the atomic signed-actor decision transaction.
pub struct DecideWorkflowApprovalGateParams<'a> {
    /// Server-resolved tenant.
    pub community_id: CommunityId,
    /// Public, non-authorizing gate identifier.
    pub approval_id: Uuid,
    /// Signature-verified actor pubkey.
    pub actor_pubkey: &'a [u8],
    /// Evidence-only actor kind (`human`, `agent`, `bot`, or `unknown`).
    pub actor_kind: &'a str,
    /// Strictly allowlisted decision payload.
    pub payload: &'a ApprovalDecisionPayload,
    /// Signature-verified event persisted atomically with the decision.
    pub event: WorkflowApprovalDecisionEvent<'a>,
}

/// Result of attempting to decide a workflow approval gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum WorkflowApprovalDecisionOutcome {
    /// The pending gate and waiting run transitioned atomically.
    Applied {
        /// Frozen run affected by the decision.
        run_id: Uuid,
        /// New run generation after the decision.
        generation: i64,
    },
    /// An exact signed-event replay found the already committed decision.
    Reused {
        /// Frozen run affected by the original decision.
        run_id: Uuid,
        /// Generation immediately after the original decision.
        generation: i64,
    },
    /// The actor is not a current active member satisfying the frozen policy.
    Unauthorized,
    /// Database time has reached or passed the gate expiry.
    Expired,
    /// A tenant, binding, state, generation, event, or replay fence failed.
    Conflict,
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
/// channel membership, creates the immutable gate, stores `current_step =
/// step_index`, `next_step = step_index + 1`, prior outputs, and the complete
/// prior trace plus one waiting item, advances the run generation, and inserts
/// one request outbox row.
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
               run.generation, run.current_step, run.next_step, run.step_outputs,
               run.execution_trace,
               clock_timestamp() AS database_now
        FROM workflow_runs AS run
        JOIN workflows AS workflow
          ON workflow.community_id = run.community_id
         AND workflow.id = run.workflow_id
        WHERE run.community_id = $1
          AND run.id = $2
          AND workflow.channel_id = $3
          AND workflow.deleted_at IS NULL
        FOR UPDATE OF run, workflow
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
                current_step = $1,
                next_step = $2,
                step_outputs = $3,
                execution_trace = $4::jsonb || jsonb_build_array($5::jsonb),
                generation = generation + 1
            WHERE community_id = $6
              AND id = $7
              AND workflow_id = $8
              AND status = 'running'
              AND generation = $9
              AND definition_hash = $10
            RETURNING generation
            "#,
        )
        .bind(params.step_index)
        .bind(next_step)
        .bind(params.prior_step_outputs)
        .bind(params.prior_execution_trace)
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
            let stored_current_step: i32 = run.try_get("current_step")?;
            let stored_next_step: i32 = run.try_get("next_step")?;
            let stored_outputs: Value = run.try_get("step_outputs")?;
            let stored_trace: Value = run.try_get("execution_trace")?;
            let expected_trace = expected_execution_trace(&params)?;
            if stored_current_step != params.step_index
                || stored_next_step != next_step
                || stored_outputs != *params.prior_step_outputs
                || stored_trace != expected_trace
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

/// Locate a gate inside one tenant without treating its public UUID as authority.
pub async fn lookup_workflow_approval_gate(
    pool: &PgPool,
    community_id: CommunityId,
    approval_id: Uuid,
) -> Result<Option<WorkflowApprovalGateRecord>> {
    let row = sqlx::query(
        r#"
        SELECT id, community_id, channel_id, workflow_id, run_id,
               definition_hash, step_id, step_index, generation,
               policy_snapshot, resolved_approver_set, expires_at, created_at
        FROM workflow_approval_gates
        WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(approval_id)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_gate).transpose()
}

/// Apply or exactly reuse a signed grant/deny decision in one transaction.
///
/// The gate UUID only locates immutable state. Authorization is re-evaluated
/// from current active channel membership against the frozen policy while the
/// membership advisory lock is held. The signed event, gate evidence, run
/// transition, and two lifecycle outbox rows commit atomically.
pub async fn decide_workflow_approval_gate(
    pool: &PgPool,
    params: DecideWorkflowApprovalGateParams<'_>,
) -> Result<WorkflowApprovalDecisionOutcome> {
    validate_decision_params(&params)?;
    let Some(locator) =
        lookup_workflow_approval_gate(pool, params.community_id, params.approval_id).await?
    else {
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    };

    let mut tx = pool.begin().await?;
    acquire_workflow_approval_channel_lock(&mut tx, params.community_id, locator.channel_id)
        .await?;

    let run = sqlx::query(
        r#"
        SELECT run.status::text AS status, run.definition_hash, run.generation,
               run.current_step, run.next_step, workflow.owner_pubkey,
               workflow.channel_id, workflow.deleted_at,
               clock_timestamp() AS database_now
        FROM workflow_runs AS run
        JOIN workflows AS workflow
          ON workflow.community_id = run.community_id
         AND workflow.id = run.workflow_id
        WHERE run.community_id = $1 AND run.id = $2 AND run.workflow_id = $3
        FOR UPDATE OF run, workflow
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(locator.run_id)
    .bind(locator.workflow_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(run) = run else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    };

    let gate = sqlx::query(
        r#"
        SELECT id, channel_id, workflow_id, run_id, definition_hash,
               step_index, generation, policy_snapshot, status,
               decision_actor_pubkey, decision_actor_role::text AS decision_actor_role,
               decision_actor_kind, actor_is_definition_owner, matched_policy,
               note, decision_event_id, expires_at, deleted_at
        FROM workflow_approval_gates
        WHERE community_id = $1 AND id = $2
        FOR UPDATE
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(params.approval_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(gate) = gate else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    };

    let gate_channel: Uuid = gate.try_get("channel_id")?;
    let gate_workflow: Uuid = gate.try_get("workflow_id")?;
    let gate_run: Uuid = gate.try_get("run_id")?;
    let gate_hash: Vec<u8> = gate.try_get("definition_hash")?;
    let gate_step: i32 = gate.try_get("step_index")?;
    let gate_generation: i64 = gate.try_get("generation")?;
    let gate_status: String = gate.try_get("status")?;
    let gate_deleted_at: Option<DateTime<Utc>> = gate.try_get("deleted_at")?;
    let run_channel: Option<Uuid> = run.try_get("channel_id")?;
    let run_deleted_at: Option<DateTime<Utc>> = run.try_get("deleted_at")?;
    let run_hash: Vec<u8> = run.try_get("definition_hash")?;
    let run_generation: i64 = run.try_get("generation")?;
    let database_now: DateTime<Utc> = run.try_get("database_now")?;
    let expires_at: DateTime<Utc> = gate.try_get("expires_at")?;

    if gate_channel != locator.channel_id
        || gate_workflow != locator.workflow_id
        || gate_run != locator.run_id
        || gate_hash != locator.definition_hash
        || gate_generation != locator.gate_generation
        || run_channel != Some(locator.channel_id)
        || run_deleted_at.is_some()
        || gate_deleted_at.is_some()
    {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    }

    let next_generation = gate_generation.checked_add(1).ok_or_else(|| {
        DbError::InvalidData("workflow run generation cannot advance past i64::MAX".to_owned())
    })?;
    if gate_status != "pending" {
        let replay = exact_decision_replay(&gate, &params)?
            && exact_decision_event_replay(&mut tx, &params, locator.channel_id).await?;
        tx.rollback().await?;
        return Ok(if replay {
            WorkflowApprovalDecisionOutcome::Reused {
                run_id: locator.run_id,
                generation: next_generation,
            }
        } else {
            WorkflowApprovalDecisionOutcome::Conflict
        });
    }

    if database_now >= expires_at {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Expired);
    }

    let expected_next_step = gate_step.checked_add(1).ok_or_else(|| {
        DbError::InvalidData("workflow approval step cannot advance past i32::MAX".to_owned())
    })?;
    let run_status: RunStatus = run.try_get::<String, _>("status")?.parse()?;
    let run_current_step: i32 = run.try_get("current_step")?;
    let run_next_step: i32 = run.try_get("next_step")?;
    if run_status != RunStatus::WaitingApproval
        || run_generation != gate_generation
        || run_hash != gate_hash
        || run_current_step != gate_step
        || run_next_step != expected_next_step
    {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    }

    let member = sqlx::query(
        r#"
        SELECT member.role::text AS role, user_row.agent_type
        FROM channel_members AS member
        JOIN channels AS channel
          ON channel.community_id = member.community_id
         AND channel.id = member.channel_id
         AND channel.deleted_at IS NULL
        JOIN users AS user_row
          ON user_row.community_id = member.community_id
         AND user_row.pubkey = member.pubkey
         AND user_row.deactivated_at IS NULL
        WHERE member.community_id = $1 AND member.channel_id = $2
          AND member.pubkey = $3 AND member.removed_at IS NULL
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(locator.channel_id)
    .bind(params.actor_pubkey)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(member) = member else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Unauthorized);
    };
    let actor_role: String = member.try_get("role")?;
    let policy: CanonicalApprovalPolicy = serde_json::from_value(gate.try_get("policy_snapshot")?)?;
    policy.validate_canonical()?;
    let actor_hex = hex::encode(params.actor_pubkey);
    let matched_policy = if policy.exact_pubkeys().binary_search(&actor_hex).is_ok() {
        serde_json::json!({"kind": "exact_pubkey", "value": actor_hex})
    } else if policy
        .roles()
        .iter()
        .any(|role| role.as_str() == actor_role)
    {
        serde_json::json!({"kind": "role", "value": actor_role})
    } else {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Unauthorized);
    };
    let owner_pubkey: Vec<u8> = run.try_get("owner_pubkey")?;
    let actor_is_definition_owner = owner_pubkey.as_slice() == params.actor_pubkey;
    let actor_kind = if params.actor_kind == "unknown" {
        member
            .try_get::<Option<String>, _>("agent_type")?
            .map_or("human", |_| "agent")
    } else {
        params.actor_kind
    };

    let run_status = match params.payload.decision() {
        WorkflowApprovalDecision::Grant => "resume_pending",
        WorkflowApprovalDecision::Deny => "cancelled",
    };
    let completed_at = if params.payload.decision() == WorkflowApprovalDecision::Deny {
        Some(database_now)
    } else {
        None
    };
    let error_message = if params.payload.decision() == WorkflowApprovalDecision::Deny {
        Some("workflow cancelled: approval denied")
    } else {
        None
    };
    let advanced = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE workflow_runs
        SET status = $1::run_status, generation = generation + 1,
            completed_at = $2, error_message = $3
        WHERE community_id = $4 AND id = $5 AND workflow_id = $6
          AND status = 'waiting_approval' AND generation = $7
          AND definition_hash = $8 AND current_step = $9 AND next_step = $10
        RETURNING generation
        "#,
    )
    .bind(run_status)
    .bind(completed_at)
    .bind(error_message)
    .bind(params.community_id.as_uuid())
    .bind(locator.run_id)
    .bind(locator.workflow_id)
    .bind(gate_generation)
    .bind(&gate_hash)
    .bind(gate_step)
    .bind(expected_next_step)
    .fetch_optional(&mut *tx)
    .await?;
    if advanced != Some(next_generation) {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    }

    let decided = sqlx::query(
        r#"
        UPDATE workflow_approval_gates
        SET status = $1, decision_actor_pubkey = $2,
            decision_actor_role = $3::member_role, decision_actor_kind = $4,
            actor_is_definition_owner = $5, matched_policy = $6,
            note = $7, decision_event_id = $8, decided_at = $9, resolved_at = $9
        WHERE community_id = $10 AND id = $11 AND status = 'pending'
          AND generation = $12 AND deleted_at IS NULL
        "#,
    )
    .bind(params.payload.decision().gate_status())
    .bind(params.actor_pubkey)
    .bind(&actor_role)
    .bind(actor_kind)
    .bind(actor_is_definition_owner)
    .bind(&matched_policy)
    .bind(params.payload.note())
    .bind(params.event.event_id)
    .bind(database_now)
    .bind(params.community_id.as_uuid())
    .bind(params.approval_id)
    .bind(gate_generation)
    .execute(&mut *tx)
    .await?;
    if decided.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(WorkflowApprovalDecisionOutcome::Conflict);
    }

    insert_decision_event(&mut tx, &params, locator.channel_id).await?;
    insert_decision_outbox(&mut tx, &params, &locator, next_generation).await?;
    tx.commit().await?;
    Ok(WorkflowApprovalDecisionOutcome::Applied {
        run_id: locator.run_id,
        generation: next_generation,
    })
}

fn validate_decision_params(params: &DecideWorkflowApprovalGateParams<'_>) -> Result<()> {
    validate_pubkey(params.actor_pubkey)?;
    validate_pubkey(params.event.pubkey)?;
    if params.actor_pubkey != params.event.pubkey {
        return Err(DbError::InvalidData(
            "approval decision actor does not match event signer".to_owned(),
        ));
    }
    if params.event.event_id.len() != 32 || params.event.signature.len() != 64 {
        return Err(DbError::InvalidData(
            "approval decision event identity or signature has the wrong length".to_owned(),
        ));
    }
    if !matches!(params.actor_kind, "human" | "agent" | "bot" | "unknown") {
        return Err(DbError::InvalidData(
            "approval decision actor kind is invalid".to_owned(),
        ));
    }
    let expected_kind = match params.payload.decision() {
        WorkflowApprovalDecision::Grant => 46_030,
        WorkflowApprovalDecision::Deny => 46_031,
    };
    if params.event.kind != expected_kind {
        return Err(DbError::InvalidData(
            "approval decision event does not match the validated decision".to_owned(),
        ));
    }
    let signed_payload = serde_json::from_str(params.event.content)
        .map_err(|_| {
            DbError::InvalidData("approval decision event content must be JSON".to_owned())
        })
        .and_then(ApprovalDecisionPayload::new)?;
    if signed_payload != *params.payload {
        return Err(DbError::InvalidData(
            "approval decision event content does not match the validated decision".to_owned(),
        ));
    }
    let tags = params.event.tags.as_array().ok_or_else(|| {
        DbError::InvalidData("approval decision event tags must be an array".to_owned())
    })?;
    let d_tags: Vec<&str> = tags
        .iter()
        .filter_map(|tag| tag.as_array())
        .filter(|tag| tag.first().and_then(Value::as_str) == Some("d"))
        .filter_map(|tag| tag.get(1).and_then(Value::as_str))
        .collect();
    let expected_id = params.approval_id.to_string();
    if d_tags.as_slice() != [expected_id.as_str()] {
        return Err(DbError::InvalidData(
            "approval decision event must contain exactly one canonical gate ID".to_owned(),
        ));
    }
    Ok(())
}

fn exact_decision_replay(
    gate: &sqlx::postgres::PgRow,
    params: &DecideWorkflowApprovalGateParams<'_>,
) -> Result<bool> {
    Ok(
        gate.try_get::<String, _>("status")? == params.payload.decision().gate_status()
            && gate
                .try_get::<Option<Vec<u8>>, _>("decision_actor_pubkey")?
                .as_deref()
                == Some(params.actor_pubkey)
            && gate
                .try_get::<Option<Vec<u8>>, _>("decision_event_id")?
                .as_deref()
                == Some(params.event.event_id)
            && gate.try_get::<Option<String>, _>("note")?.as_deref() == params.payload.note(),
    )
}

async fn exact_decision_event_replay(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &DecideWorkflowApprovalGateParams<'_>,
    channel_id: Uuid,
) -> Result<bool> {
    let Some(existing) = lookup_decision_event(tx, params).await? else {
        return Ok(false);
    };
    decision_event_matches(&existing, params, channel_id)
}

async fn lookup_decision_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &DecideWorkflowApprovalGateParams<'_>,
) -> Result<Option<sqlx::postgres::PgRow>> {
    sqlx::query(
        r#"
        SELECT pubkey, created_at, kind, tags, content, sig, channel_id, d_tag
        FROM events
        WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(params.event.event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(Into::into)
}

fn decision_event_matches(
    existing: &sqlx::postgres::PgRow,
    params: &DecideWorkflowApprovalGateParams<'_>,
    channel_id: Uuid,
) -> Result<bool> {
    Ok(
        existing.try_get::<Vec<u8>, _>("pubkey")?.as_slice() == params.event.pubkey
            && existing.try_get::<DateTime<Utc>, _>("created_at")? == params.event.created_at
            && existing.try_get::<i32, _>("kind")? == params.event.kind
            && existing.try_get::<Value, _>("tags")? == *params.event.tags
            && existing.try_get::<String, _>("content")? == params.event.content
            && existing.try_get::<Vec<u8>, _>("sig")?.as_slice() == params.event.signature
            && existing.try_get::<Option<Uuid>, _>("channel_id")? == Some(channel_id)
            && existing.try_get::<Option<String>, _>("d_tag")?.as_deref()
                == Some(params.approval_id.to_string().as_str()),
    )
}

async fn insert_decision_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &DecideWorkflowApprovalGateParams<'_>,
    channel_id: Uuid,
) -> Result<()> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO events
            (community_id, id, pubkey, created_at, kind, tags, content, sig,
             received_at, channel_id, d_tag)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(params.community_id.as_uuid())
    .bind(params.event.event_id)
    .bind(params.event.pubkey)
    .bind(params.event.created_at)
    .bind(params.event.kind)
    .bind(params.event.tags)
    .bind(params.event.content)
    .bind(params.event.signature)
    .bind(params.event.received_at)
    .bind(channel_id)
    .bind(params.approval_id.to_string())
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        let existing = lookup_decision_event(tx, params).await?;
        let Some(existing) = existing else {
            return Err(DbError::InvalidData(
                "approval decision event ID conflicts with hidden event state".to_owned(),
            ));
        };
        if !decision_event_matches(&existing, params, channel_id)? {
            return Err(DbError::InvalidData(
                "approval decision event ID conflicts with different event data".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn insert_decision_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: &DecideWorkflowApprovalGateParams<'_>,
    gate: &WorkflowApprovalGateRecord,
    generation: i64,
) -> Result<()> {
    let (approval_class, run_class) = match params.payload.decision() {
        WorkflowApprovalDecision::Grant => ("approval_granted", "workflow_resume_pending"),
        WorkflowApprovalDecision::Deny => ("approval_denied", "workflow_cancelled"),
    };
    let payload = serde_json::json!({
        "approval_id": gate.approval_id,
        "channel_id": gate.channel_id,
        "workflow_id": gate.workflow_id,
        "run_id": gate.run_id,
        "generation": generation,
        "decision": params.payload.decision().gate_status(),
    });
    validate_request_payload_size(&payload)?;
    for (class, suffix) in [(approval_class, "decision"), (run_class, "run")] {
        let dedupe_key = format!(
            "workflow-approval-{suffix}:{}:{}",
            gate.approval_id,
            params.payload.decision().gate_status()
        );
        sqlx::query(
            r#"
            INSERT INTO workflow_approval_outbox
                (community_id, approval_id, class, payload, dedupe_key)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(params.community_id.as_uuid())
        .bind(gate.approval_id)
        .bind(class)
        .bind(&payload)
        .bind(&dedupe_key)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
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
    if !params.prior_execution_trace.is_array() {
        return Err(DbError::InvalidData(
            "prior workflow execution trace must be a JSON array".to_owned(),
        ));
    }
    validate_waiting_trace_entry(params)?;
    Ok(())
}

fn expected_execution_trace(params: &CreateWorkflowApprovalGateParams<'_>) -> Result<Value> {
    let Some(mut trace) = params.prior_execution_trace.as_array().cloned() else {
        return Err(DbError::InvalidData(
            "prior workflow execution trace must be a JSON array".to_owned(),
        ));
    };
    trace.push(params.waiting_trace_entry.clone());
    Ok(Value::Array(trace))
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
        || entry.len() != 3
        || entry
            .keys()
            .any(|key| !matches!(key.as_str(), "step_id" | "step_index" | "status"))
    {
        return Err(DbError::InvalidData(
            "waiting trace entry must contain only the exact step and waiting_approval status"
                .to_owned(),
        ));
    }
    Ok(())
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

fn validate_request_payload_fields(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(DbError::InvalidData(
            "approval request payload must be a JSON object".to_owned(),
        ));
    };
    if object.len() != REQUEST_PAYLOAD_ALLOWED_FIELDS.len()
        || REQUEST_PAYLOAD_ALLOWED_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(DbError::InvalidData(
            "approval request payload must contain exactly class and timeout_seconds".to_owned(),
        ));
    }
    for key in object.keys() {
        if !REQUEST_PAYLOAD_ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(DbError::InvalidData(format!(
                "approval request payload contains unsupported field '{key}'"
            )));
        }
    }
    if object.get("class").and_then(Value::as_str) != Some("approval_requested") {
        return Err(DbError::InvalidData(
            "approval request payload class is invalid".to_owned(),
        ));
    }
    if object
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .is_none_or(|seconds| seconds == 0)
    {
        return Err(DbError::InvalidData(
            "approval request payload timeout_seconds must be a positive integer".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_payload_size(value: &Value) -> Result<()> {
    let size = serde_json::to_vec(value)?.len();
    if size > REQUEST_PAYLOAD_MAX_BYTES {
        return Err(DbError::InvalidData(format!(
            "approval request payload exceeds {REQUEST_PAYLOAD_MAX_BYTES} serialized bytes"
        )));
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
    validate_request_payload_size(&payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::ensure_user;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    struct PostgresGateFixture {
        pool: PgPool,
        community_id: CommunityId,
        channel_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        definition_hash: Vec<u8>,
        policy: CanonicalApprovalPolicy,
        expires_at: DateTime<Utc>,
    }

    impl PostgresGateFixture {
        async fn new(initial_execution_trace: &Value) -> Self {
            let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| TEST_DB_URL.to_owned());
            let pool = PgPool::connect(&database_url)
                .await
                .expect("connect to test DB");
            crate::migration::run_migrations(&pool)
                .await
                .expect("run migrations");

            let community_id = CommunityId::from_uuid(Uuid::new_v4());
            let channel_id = Uuid::new_v4();
            let workflow_id = Uuid::new_v4();
            let run_id = Uuid::new_v4();
            let owner = vec![0x71; 32];
            let approver = vec![0x72; 32];
            let definition_hash = vec![0x73; 32];
            let definition = serde_json::json!({
                "trigger": {"on": "message_posted"},
                "steps": [
                    {"id": "prepare", "run": "prepare"},
                    {"id": "optional", "run": "optional"},
                    {"id": "approve-release", "approval": {"role": "owner"}}
                ]
            });

            sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
                .bind(community_id.as_uuid())
                .bind(format!(
                    "approval-trace-{}.test",
                    community_id.as_uuid().simple()
                ))
                .execute(&pool)
                .await
                .expect("insert community");
            ensure_user(&pool, community_id, &owner)
                .await
                .expect("insert owner");
            ensure_user(&pool, community_id, &approver)
                .await
                .expect("insert approver");
            sqlx::query(
                "INSERT INTO channels (community_id, id, name, created_by) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(community_id.as_uuid())
            .bind(channel_id)
            .bind(format!("approval-trace-{}", channel_id.simple()))
            .bind(&owner)
            .execute(&pool)
            .await
            .expect("insert channel");
            sqlx::query(
                "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
                 VALUES ($1, $2, $3, 'owner'), ($1, $2, $4, 'admin')",
            )
            .bind(community_id.as_uuid())
            .bind(channel_id)
            .bind(&owner)
            .bind(&approver)
            .execute(&pool)
            .await
            .expect("insert channel members");
            sqlx::query(
                "INSERT INTO workflows \
                 (community_id, id, name, owner_pubkey, channel_id, definition, definition_hash) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(community_id.as_uuid())
            .bind(workflow_id)
            .bind(format!("approval-trace-{}", workflow_id.simple()))
            .bind(&owner)
            .bind(channel_id)
            .bind(&definition)
            .bind(&definition_hash)
            .execute(&pool)
            .await
            .expect("insert workflow");
            sqlx::query(
                "INSERT INTO workflow_runs \
                 (community_id, id, workflow_id, definition_snapshot, definition_hash, generation, \
                  status, current_step, next_step, step_outputs, execution_trace) \
                 VALUES ($1, $2, $3, $4, $5, 7, 'running', 0, 0, '{}'::jsonb, $6)",
            )
            .bind(community_id.as_uuid())
            .bind(run_id)
            .bind(workflow_id)
            .bind(&definition)
            .bind(&definition_hash)
            .bind(initial_execution_trace)
            .execute(&pool)
            .await
            .expect("insert workflow run");

            Self {
                pool,
                community_id,
                channel_id,
                workflow_id,
                run_id,
                definition_hash,
                policy: CanonicalApprovalPolicy::new(vec![approver], vec![ApprovalRole::Owner])
                    .expect("approval policy"),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            }
        }

        fn params<'a>(
            &'a self,
            summary: &'a ApprovalActionSummary,
            outputs: &'a Value,
            prior_trace: &'a Value,
            waiting: &'a Value,
            request: &'a ApprovalRequestPayload,
        ) -> CreateWorkflowApprovalGateParams<'a> {
            CreateWorkflowApprovalGateParams {
                community_id: self.community_id,
                channel_id: self.channel_id,
                workflow_id: self.workflow_id,
                run_id: self.run_id,
                definition_hash: &self.definition_hash,
                step_id: "approve-release",
                step_index: 2,
                expected_generation: 7,
                policy: &self.policy,
                action_summary: summary,
                expires_at: self.expires_at,
                prior_step_outputs: outputs,
                prior_execution_trace: prior_trace,
                waiting_trace_entry: waiting,
                request_payload: request,
            }
        }
    }

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
    fn request_payload_accepts_only_the_exact_caller_fields() {
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested",
            "timeout_seconds": 3_600
        }))
        .is_ok());
        for field in [
            "password",
            "authorization",
            "cookie",
            "api_key",
            "private_key",
            "approval_token",
            "definition_snapshot",
            "step_outputs",
        ] {
            let mut payload = serde_json::json!({
                "class": "approval_requested",
                "timeout_seconds": 3_600
            })
            .as_object()
            .cloned()
            .expect("request payload object");
            payload.insert(field.to_owned(), Value::String("private".to_owned()));
            assert!(
                ApprovalRequestPayload::new(Value::Object(payload)).is_err(),
                "unexpectedly accepted {field}"
            );
        }
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"class": "approval_requested"}),
            serde_json::json!({"timeout_seconds": 3_600}),
            serde_json::json!({
                "class": "wrong",
                "timeout_seconds": 3_600
            }),
            serde_json::json!({
                "class": "approval_requested",
                "timeout_seconds": "3600"
            }),
        ] {
            assert!(ApprovalRequestPayload::new(payload).is_err());
        }
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "class": {"password": "private"},
            "timeout_seconds": 3_600
        }))
        .is_err());
        assert!(ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested",
            "timeout_seconds": 0
        }))
        .is_err());
    }

    #[test]
    fn decision_payload_accepts_only_decision_and_bounded_note() {
        assert!(ApprovalDecisionPayload::new(serde_json::json!({
            "decision": "grant"
        }))
        .is_ok());
        assert!(ApprovalDecisionPayload::new(serde_json::json!({
            "decision": "deny",
            "note": "needs revision"
        }))
        .is_ok());
        assert!(ApprovalDecisionPayload::new(serde_json::json!({
            "decision": "deny"
        }))
        .is_err());
        assert!(ApprovalDecisionPayload::new(serde_json::json!({
            "decision": "deny",
            "note": "   "
        }))
        .is_err());
        assert!(ApprovalDecisionPayload::new(serde_json::json!({
            "decision": "grant",
            "note": "x".repeat(DECISION_NOTE_MAX_BYTES + 1)
        }))
        .is_err());
        for field in [
            "token",
            "authorization",
            "cookie",
            "api_key",
            "private_key",
            "definition_snapshot",
            "step_outputs",
        ] {
            let mut payload = serde_json::json!({"decision": "grant"})
                .as_object()
                .cloned()
                .expect("decision payload object");
            payload.insert(field.to_owned(), Value::String("private".to_owned()));
            assert!(
                ApprovalDecisionPayload::new(Value::Object(payload)).is_err(),
                "unexpectedly accepted {field}"
            );
        }
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
        let prior_trace = serde_json::json!([]);
        let waiting = serde_json::json!({
            "step_id": "approve-release",
            "step_index": 2,
            "status": "waiting_approval"
        });
        let request = ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested",
            "timeout_seconds": 3_600
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
            prior_execution_trace: &prior_trace,
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

        assert_eq!(
            expected_execution_trace(&params).expect("expected execution trace"),
            serde_json::json!([waiting])
        );
        let invalid_trace = serde_json::json!({});
        let invalid_params = CreateWorkflowApprovalGateParams {
            prior_execution_trace: &invalid_trace,
            ..params
        };
        assert!(validate_params(&invalid_params).is_err());
    }

    #[test]
    fn waiting_trace_must_bind_the_exact_gate_step() {
        let policy =
            CanonicalApprovalPolicy::new(vec![], vec![ApprovalRole::Admin]).expect("policy");
        let summary = ApprovalActionSummary::new("inspect change").expect("summary");
        let definition_hash = vec![0x41; 32];
        let outputs = serde_json::json!({});
        let prior_trace = serde_json::json!([]);
        let wrong_waiting = serde_json::json!({
            "step_id": "other",
            "step_index": 1,
            "status": "waiting_approval"
        });
        let request = ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested",
            "timeout_seconds": 3_600
        }))
        .expect("request");
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
            prior_execution_trace: &prior_trace,
            waiting_trace_entry: &wrong_waiting,
            request_payload: &request,
        };

        assert!(validate_params(&params).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn prior_trace_is_persisted_once_and_replay_does_not_append() {
        let fixture = PostgresGateFixture::new(&serde_json::json!([])).await;
        let summary = ApprovalActionSummary::new("release candidate").expect("summary");
        let outputs = serde_json::json!({"prepare": {"artifact": "candidate"}});
        let prior_trace = serde_json::json!([
            {"step_id": "prepare", "step_index": 0, "status": "completed"},
            {"step_id": "optional", "step_index": 1, "status": "skipped"}
        ]);
        let waiting = serde_json::json!({
            "step_id": "approve-release",
            "step_index": 2,
            "status": "waiting_approval"
        });
        let expected_trace = serde_json::json!([
            {"step_id": "prepare", "step_index": 0, "status": "completed"},
            {"step_id": "optional", "step_index": 1, "status": "skipped"},
            {"step_id": "approve-release", "step_index": 2, "status": "waiting_approval"}
        ]);
        let request = ApprovalRequestPayload::new(serde_json::json!({
            "class": "approval_requested",
            "timeout_seconds": 3_600
        }))
        .expect("request");

        let created = create_workflow_approval_gate(
            &fixture.pool,
            fixture.params(&summary, &outputs, &prior_trace, &waiting, &request),
        )
        .await
        .expect("create gate");
        let (approval_id, outbox_id) = match created {
            WorkflowApprovalGateCreationOutcome::Created { gate, request } => {
                (gate.approval_id, request.outbox_id)
            }
            other => panic!("expected Created, got {other:?}"),
        };

        let replayed = create_workflow_approval_gate(
            &fixture.pool,
            fixture.params(&summary, &outputs, &prior_trace, &waiting, &request),
        )
        .await
        .expect("replay gate");
        match replayed {
            WorkflowApprovalGateCreationOutcome::Reused { gate, request } => {
                assert_eq!(gate.approval_id, approval_id);
                assert_eq!(request.outbox_id, outbox_id);
            }
            other => panic!("expected Reused, got {other:?}"),
        }

        let row = sqlx::query(
            "SELECT status::text AS status, generation, current_step, next_step, \
                    step_outputs, execution_trace \
             FROM workflow_runs WHERE community_id = $1 AND id = $2",
        )
        .bind(fixture.community_id.as_uuid())
        .bind(fixture.run_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("read workflow run");
        assert_eq!(
            row.try_get::<String, _>("status").expect("status"),
            "waiting_approval"
        );
        assert_eq!(row.try_get::<i64, _>("generation").expect("generation"), 8);
        assert_eq!(
            row.try_get::<i32, _>("current_step").expect("current step"),
            2
        );
        assert_eq!(row.try_get::<i32, _>("next_step").expect("next step"), 3);
        assert_eq!(
            row.try_get::<Value, _>("step_outputs")
                .expect("step outputs"),
            outputs
        );
        assert_eq!(
            row.try_get::<Value, _>("execution_trace")
                .expect("execution trace"),
            expected_trace
        );
    }
}
