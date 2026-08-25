//! Relay-owned recovery for durable workflow approval continuations.

use std::sync::Arc;
use std::time::Duration;

use buzz_core::CommunityId;
use buzz_db::workflow::RunStatus;
use buzz_db::{Db, WorkflowRunTransitionOutcome};
use futures_util::future::join_all;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const RECOVERY_BATCH_LIMIT: i64 = 100;
const MINIMUM_LEASE_DURATION: Duration = Duration::from_secs(60);

/// Result of one generation-fenced continuation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum WorkflowResumeDriveOutcome {
    /// This caller claimed and drove the run.
    Applied {
        /// Generation owned during execution.
        generation: i64,
    },
    /// Another caller owns the run or it is no longer recoverable.
    Conflict,
}

/// Counts returned by one bounded recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct WorkflowResumeSweepOutcome {
    /// Candidate rows returned by the bounded database scan.
    pub found: usize,
    /// Candidates whose generation fence this pass acquired.
    pub claimed: usize,
}

fn lease_duration(sweep_interval: Duration) -> Duration {
    sweep_interval.saturating_mul(3).max(MINIMUM_LEASE_DURATION)
}

fn duration_secs_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

async fn fail_claimed_run(
    db: &Db,
    community_id: CommunityId,
    run_id: Uuid,
    generation: i64,
    current_step: i32,
    trace: &serde_json::Value,
    error_message: &str,
) {
    match db
        .fail_running_workflow_run(
            community_id,
            run_id,
            generation,
            current_step,
            trace,
            error_message,
        )
        .await
    {
        Ok(WorkflowRunTransitionOutcome::Applied { .. }) => {}
        Ok(WorkflowRunTransitionOutcome::Conflict) => {
            debug!(%run_id, generation, "workflow resume failure lost its generation fence");
        }
        Err(error) => {
            error!(%run_id, generation, "workflow resume failure could not be persisted: {error}");
        }
    }
}

fn spawn_lease_renewer(
    db: Db,
    community_id: CommunityId,
    run_id: Uuid,
    generation: i64,
    lease: Duration,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let renew_every = (lease / 3).max(Duration::from_secs(1));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(renew_every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = interval.tick() => {
                    match db.renew_workflow_resume_lease(
                        community_id,
                        run_id,
                        generation,
                        duration_secs_i64(lease),
                    ).await {
                        Ok(true) => {}
                        Ok(false) => {
                            debug!(%run_id, generation, "workflow resume lease lost its generation fence");
                            return;
                        }
                        Err(error) => {
                            warn!(%run_id, generation, "workflow resume lease renewal failed: {error}");
                        }
                    }
                }
            }
        }
    })
}

/// Claim and execute one approved run through the shared durable driver.
///
/// `minimum_generation` is the generation returned by the grant transaction or
/// observed by a sweep. A replay may encounter a later expired running
/// generation; the database claim still fences the exact row read here.
pub async fn drive_workflow_resume(
    engine: Arc<buzz_workflow::WorkflowEngine>,
    db: Db,
    community_id: CommunityId,
    run_id: Uuid,
    minimum_generation: i64,
    sweep_interval: Duration,
) -> Result<WorkflowResumeDriveOutcome, String> {
    let run = db
        .get_workflow_run(community_id, run_id)
        .await
        .map_err(|error| format!("run lookup failed: {error}"))?;
    if run.generation < minimum_generation
        || !matches!(run.status, RunStatus::ResumePending | RunStatus::Running)
    {
        return Ok(WorkflowResumeDriveOutcome::Conflict);
    }

    let lease = lease_duration(sweep_interval);
    let claimed_generation = match db
        .claim_workflow_resume(
            community_id,
            run_id,
            run.status.clone(),
            run.generation,
            duration_secs_i64(lease),
        )
        .await
        .map_err(|error| format!("resume claim failed: {error}"))?
    {
        WorkflowRunTransitionOutcome::Conflict => return Ok(WorkflowResumeDriveOutcome::Conflict),
        WorkflowRunTransitionOutcome::Applied { generation } => generation,
    };

    let cancel = CancellationToken::new();
    let renewer = spawn_lease_renewer(
        db.clone(),
        community_id,
        run_id,
        claimed_generation,
        lease,
        cancel.clone(),
    );

    let prepared = (|| {
        let start_index = usize::try_from(run.next_step)
            .map_err(|_| "persisted workflow resume cursor is invalid".to_owned())?;
        let definition: buzz_workflow::WorkflowDef =
            serde_json::from_value(run.definition_snapshot.clone())
                .map_err(|error| format!("frozen workflow definition is invalid: {error}"))?;
        if start_index > definition.steps.len() {
            return Err(
                "persisted workflow resume cursor exceeds the frozen definition".to_owned(),
            );
        }
        let step_outputs = serde_json::from_value(run.step_outputs.clone())
            .map_err(|error| format!("persisted workflow step outputs are invalid: {error}"))?;
        let trigger_context = run
            .trigger_context
            .as_ref()
            .ok_or_else(|| "frozen workflow trigger context is missing".to_owned())
            .and_then(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|error| format!("frozen workflow trigger context is invalid: {error}"))
            })?;
        let existing_trace = run
            .execution_trace
            .as_array()
            .cloned()
            .ok_or_else(|| "persisted workflow execution trace is invalid".to_owned())?;
        Ok((
            start_index,
            definition,
            step_outputs,
            trigger_context,
            existing_trace,
        ))
    })();

    let (start_index, definition, step_outputs, trigger_context, existing_trace) = match prepared {
        Ok(prepared) => prepared,
        Err(message) => {
            fail_claimed_run(
                &db,
                community_id,
                run_id,
                claimed_generation,
                run.current_step,
                &run.execution_trace,
                &message,
            )
            .await;
            cancel.cancel();
            let _ = renewer.await;
            return Err(message);
        }
    };

    let result = buzz_workflow::executor::execute_claimed_from_step(
        &engine,
        community_id,
        run_id,
        &definition,
        &trigger_context,
        buzz_workflow::executor::ClaimedResume {
            start_index,
            step_outputs,
            generation: claimed_generation,
        },
    )
    .await;
    engine
        .finalize_claimed_run(
            community_id,
            run_id,
            claimed_generation,
            result,
            existing_trace,
        )
        .await;

    cancel.cancel();
    let _ = renewer.await;
    Ok(WorkflowResumeDriveOutcome::Applied {
        generation: claimed_generation,
    })
}

/// Run one bounded recovery pass and wait for every claimed continuation.
pub async fn run_workflow_resume_sweep_once(
    engine: Arc<buzz_workflow::WorkflowEngine>,
    db: Db,
    sweep_interval: Duration,
    resume_pending_age: Duration,
) -> Result<WorkflowResumeSweepOutcome, String> {
    let candidates = db
        .list_recoverable_workflow_resumes(
            duration_secs_i64(resume_pending_age),
            RECOVERY_BATCH_LIMIT,
        )
        .await
        .map_err(|error| format!("recovery scan failed: {error}"))?;
    let found = candidates.len();
    let attempts = candidates.into_iter().map(|candidate| {
        drive_workflow_resume(
            Arc::clone(&engine),
            db.clone(),
            candidate.community_id,
            candidate.run_id,
            candidate.generation,
            sweep_interval,
        )
    });
    let mut claimed = 0;
    for result in join_all(attempts).await {
        match result {
            Ok(WorkflowResumeDriveOutcome::Applied { .. }) => claimed += 1,
            Ok(WorkflowResumeDriveOutcome::Conflict) => {}
            Err(error) => warn!("workflow resume recovery attempt failed: {error}"),
        }
    }
    Ok(WorkflowResumeSweepOutcome { found, claimed })
}

/// Start the relay-owned startup pass and periodic recovery sweep.
pub async fn run_workflow_resume_worker(
    engine: Arc<buzz_workflow::WorkflowEngine>,
    db: Db,
    sweep_interval: Duration,
    resume_pending_age: Duration,
) {
    info!(
        sweep_interval_secs = sweep_interval.as_secs(),
        resume_pending_age_secs = resume_pending_age.as_secs(),
        "workflow resume recovery worker started"
    );
    loop {
        match run_workflow_resume_sweep_once(
            Arc::clone(&engine),
            db.clone(),
            sweep_interval,
            resume_pending_age,
        )
        .await
        {
            Ok(outcome) if outcome.claimed > 0 => {
                info!(
                    found = outcome.found,
                    claimed = outcome.claimed,
                    "workflow resume recovery pass completed"
                );
            }
            Ok(_) => {}
            Err(error) => error!("workflow resume recovery pass failed: {error}"),
        }
        tokio::time::sleep(sweep_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::channel::{ChannelType, ChannelVisibility};
    use buzz_db::{
        ApprovalDecisionPayload, CreateCommunityWithOwnerResult, DecideWorkflowApprovalGateParams,
        WorkflowApprovalDecisionEvent, WorkflowApprovalDecisionOutcome,
    };
    use buzz_workflow::action_sink::{ActionEffectContext, ActionSink, ActionSinkError};
    use buzz_workflow::executor::{ClaimedResume, TriggerContext};
    use chrono::{DateTime, Utc};
    use nostr::Keys;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    const RECOVERY_YAML: &str = r#"
name: Approval recovery contract
trigger:
  on: webhook
steps:
  - id: approve
    action: request_approval
    from: owner
    message: Approve the continuation
  - id: execute
    action: extract
    from: trigger.text
    matchers:
      first_word: wf_word
"#;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MessageCall {
        effect: ActionEffectContext,
        text: String,
        mentioned_pubkeys: Vec<String>,
    }

    #[derive(Default)]
    struct RecordingActionSink {
        messages: Mutex<Vec<MessageCall>>,
        resolved_mentions: Mutex<Vec<String>>,
        mention_resolution_fails: Mutex<bool>,
    }

    impl RecordingActionSink {
        fn messages(&self) -> Vec<MessageCall> {
            self.messages
                .lock()
                .expect("recording action sink lock")
                .clone()
        }

        fn set_resolved_mentions(&self, pubkeys: Vec<String>) {
            *self
                .resolved_mentions
                .lock()
                .expect("resolved mentions lock") = pubkeys;
        }

        fn fail_mention_resolution(&self) {
            *self
                .mention_resolution_fails
                .lock()
                .expect("mention resolution failure lock") = true;
        }
    }

    impl ActionSink for RecordingActionSink {
        fn resolve_message_mentions(
            &self,
            _community_id: CommunityId,
            _channel_id: &str,
            _text: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, ActionSinkError>> + Send + '_>>
        {
            if *self
                .mention_resolution_fails
                .lock()
                .expect("mention resolution failure lock")
            {
                return Box::pin(async {
                    Err(ActionSinkError::Database(
                        "forced mention resolution failure".to_owned(),
                    ))
                });
            }
            let pubkeys = self
                .resolved_mentions
                .lock()
                .expect("resolved mentions lock")
                .clone();
            Box::pin(async move { Ok(pubkeys) })
        }

        fn send_message(
            &self,
            effect: ActionEffectContext,
            _community_id: CommunityId,
            _channel_id: &str,
            text: &str,
            _author_pubkey: &str,
            mentioned_pubkeys: &[String],
        ) -> Pin<Box<dyn Future<Output = Result<String, ActionSinkError>> + Send + '_>> {
            self.messages
                .lock()
                .expect("recording action sink lock")
                .push(MessageCall {
                    effect,
                    text: text.to_owned(),
                    mentioned_pubkeys: mentioned_pubkeys.to_owned(),
                });
            Box::pin(async move { Ok(format!("event-{}", effect.idempotency_key)) })
        }

        fn add_reaction(
            &self,
            _effect: ActionEffectContext,
            _community_id: CommunityId,
            _channel_id: &str,
            _target_event_id: &str,
            _emoji: &str,
            _author_pubkey: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, ActionSinkError>> + Send + '_>>
        {
            Box::pin(async { unreachable!("reaction is not part of recovery fixtures") })
        }
    }

    struct RecoveryFixture {
        pool: PgPool,
        db: Db,
        engine: Arc<buzz_workflow::WorkflowEngine>,
        community_id: CommunityId,
        run_id: Uuid,
        approval_id: Uuid,
        owner: Vec<u8>,
        decision_time: DateTime<Utc>,
        sink: Arc<RecordingActionSink>,
    }

    async fn recovery_fixture() -> RecoveryFixture {
        recovery_fixture_with_yaml(RECOVERY_YAML).await
    }

    async fn recovery_fixture_with_yaml(yaml: &str) -> RecoveryFixture {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect to test database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("apply test database migrations");
        let db = Db::from_pool(pool.clone());
        let owner = Keys::generate();
        let owner_bytes = owner.public_key().to_bytes().to_vec();
        let host = format!("resume-recovery-{}.example", Uuid::new_v4().simple());
        let community_id = match db
            .create_community_with_owner(&host, &owner.public_key().to_hex())
            .await
            .expect("create recovery test community")
        {
            CreateCommunityWithOwnerResult::Created(community) => community.id,
            other => panic!("expected a fresh recovery community, got {other:?}"),
        };
        db.ensure_user(community_id, &owner_bytes)
            .await
            .expect("insert workflow owner");
        let channel = db
            .create_channel(
                community_id,
                "resume-recovery",
                ChannelType::Stream,
                ChannelVisibility::Private,
                None,
                &owner_bytes,
                None,
            )
            .await
            .expect("create recovery test channel");

        let (definition, definition_json) =
            buzz_workflow::WorkflowEngine::parse_yaml(yaml).expect("parse recovery workflow");
        let definition_value =
            serde_json::from_str(&definition_json).expect("parse recovery definition JSON");
        let definition_hash = Sha256::digest(definition_json.as_bytes()).to_vec();
        let workflow_id = Uuid::new_v4();
        db.upsert_workflow(
            community_id,
            workflow_id,
            Some(channel.id),
            &owner_bytes,
            "Approval recovery contract",
            &definition_json,
            &definition_hash,
            true,
        )
        .await
        .expect("insert recovery workflow");
        let trigger_context = TriggerContext {
            text: "execute exactly once".to_owned(),
            channel_id: channel.id.to_string(),
            author: owner.public_key().to_hex(),
            ..TriggerContext::default()
        };
        let trigger_json =
            serde_json::to_value(&trigger_context).expect("serialize recovery trigger");
        let run_id = db
            .create_workflow_run(
                community_id,
                workflow_id,
                None,
                Some(&trigger_json),
                &definition_value,
                &definition_hash,
            )
            .await
            .expect("create recovery workflow run");
        let engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let sink = Arc::new(RecordingActionSink::default());
        engine.set_action_sink(sink.clone());
        let suspended = buzz_workflow::executor::execute_from_step(
            &engine,
            community_id,
            run_id,
            &definition,
            &trigger_context,
            0,
            None,
        )
        .await;
        engine
            .finalize_run(community_id, run_id, suspended, None)
            .await;
        let waiting = db
            .get_workflow_run(community_id, run_id)
            .await
            .expect("read waiting recovery run");
        assert_eq!(waiting.status, RunStatus::WaitingApproval);
        let approval_id = sqlx::query_scalar(
            "SELECT id FROM workflow_approval_gates \
             WHERE community_id = $1 AND run_id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .expect("read recovery approval gate");

        RecoveryFixture {
            pool,
            db,
            engine,
            community_id,
            run_id,
            approval_id,
            owner: owner_bytes,
            decision_time: DateTime::from_timestamp(Utc::now().timestamp(), 0)
                .expect("current timestamp is representable"),
            sink,
        }
    }

    async fn grant(fixture: &RecoveryFixture) -> WorkflowApprovalDecisionOutcome {
        let decision_json = serde_json::json!({"decision": "grant", "note": null});
        let content = decision_json.to_string();
        let payload = ApprovalDecisionPayload::new(decision_json).expect("validate grant payload");
        let tags = serde_json::json!([["d", fixture.approval_id.to_string()]]);
        let event_id = [0xd1_u8; 32];
        let signature = [0xd2_u8; 64];
        fixture
            .db
            .decide_workflow_approval_gate(DecideWorkflowApprovalGateParams {
                community_id: fixture.community_id,
                approval_id: fixture.approval_id,
                actor_pubkey: &fixture.owner,
                actor_kind: "human",
                payload: &payload,
                event: WorkflowApprovalDecisionEvent {
                    event_id: &event_id,
                    pubkey: &fixture.owner,
                    created_at: fixture.decision_time,
                    kind: buzz_core::kind::KIND_APPROVAL_GRANT as i32,
                    tags: &tags,
                    content: &content,
                    signature: &signature,
                    received_at: fixture.decision_time,
                },
            })
            .await
            .expect("grant recovery approval")
    }

    async fn claim_resume(fixture: &RecoveryFixture, generation: i64) -> i64 {
        let claimed_generation = match fixture
            .db
            .claim_workflow_resume(
                fixture.community_id,
                fixture.run_id,
                RunStatus::ResumePending,
                generation,
                300,
            )
            .await
            .expect("claim recovery run before simulated crash")
        {
            WorkflowRunTransitionOutcome::Applied { generation } => generation,
            WorkflowRunTransitionOutcome::Conflict => panic!("initial recovery claim conflicted"),
        };
        claimed_generation
    }

    async fn expire_claim(fixture: &RecoveryFixture, claimed_generation: i64) {
        let affected = sqlx::query(
            "UPDATE workflow_runs SET resume_lease_expires_at = clock_timestamp() \
             - INTERVAL '1 second' WHERE community_id = $1 AND id = $2 \
             AND status = 'running' AND generation = $3",
        )
        .bind(fixture.community_id.as_uuid())
        .bind(fixture.run_id)
        .bind(claimed_generation)
        .execute(&fixture.pool)
        .await
        .expect("expire simulated crashed worker lease")
        .rows_affected();
        assert_eq!(affected, 1);
    }

    async fn claim_then_expire(fixture: &RecoveryFixture, generation: i64) -> i64 {
        let claimed_generation = claim_resume(fixture, generation).await;
        expire_claim(fixture, claimed_generation).await;
        claimed_generation
    }

    async fn execute_claim_without_finalizing(fixture: &RecoveryFixture, claimed_generation: i64) {
        let run = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read claimed workflow run");
        let definition = serde_json::from_value(run.definition_snapshot)
            .expect("parse claimed workflow definition");
        let trigger_context = serde_json::from_value(
            run.trigger_context
                .expect("claimed workflow trigger context"),
        )
        .expect("parse claimed workflow trigger context");
        let step_outputs =
            serde_json::from_value(run.step_outputs).expect("parse claimed workflow outputs");
        let start_index = usize::try_from(run.next_step).expect("non-negative resume cursor");
        let result = buzz_workflow::executor::execute_claimed_from_step(
            &fixture.engine,
            fixture.community_id,
            fixture.run_id,
            &definition,
            &trigger_context,
            ClaimedResume {
                start_index,
                step_outputs,
                generation: claimed_generation,
            },
        )
        .await;
        assert!(result.is_ok(), "claimed execution should succeed");
    }

    async fn assert_completed_once(fixture: &RecoveryFixture) {
        let run = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read recovered workflow run");
        assert_eq!(run.status, RunStatus::Completed);
        let trace = run
            .execution_trace
            .as_array()
            .expect("recovered trace is an array");
        assert_eq!(trace.len(), 2, "continuation must execute exactly once");
        assert_eq!(trace[0]["step_id"], "approve");
        assert_eq!(trace[0]["status"], "waiting_approval");
        assert_eq!(trace[1]["step_id"], "execute");
        assert_eq!(trace[1]["status"], "completed");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn recovery_sweep_completes_grant_when_inline_continuation_never_starts() {
        let fixture = recovery_fixture().await;
        assert!(matches!(
            grant(&fixture).await,
            WorkflowApprovalDecisionOutcome::Applied { .. }
        ));

        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("recover resume_pending run");
        assert_eq!(outcome.claimed, 1);
        assert_completed_once(&fixture).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn recovery_sweep_reclaims_expired_running_generation() {
        let fixture = recovery_fixture().await;
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        let stale_generation = claim_then_expire(&fixture, generation).await;

        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("reclaim expired running run");
        assert_eq!(outcome.claimed, 1);
        let completed = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read reclaimed run");
        assert!(completed.generation > stale_generation);
        assert_completed_once(&fixture).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn inline_driver_and_recovery_sweep_race_on_one_generation_fence() {
        let fixture = recovery_fixture().await;
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };

        let inline = drive_workflow_resume(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            fixture.community_id,
            fixture.run_id,
            generation,
            Duration::from_secs(1),
        );
        let sweep = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        );
        let (inline, sweep) = tokio::join!(inline, sweep);
        let inline_claimed = usize::from(matches!(
            inline.expect("run inline recovery driver"),
            WorkflowResumeDriveOutcome::Applied { .. }
        ));
        let sweep_claimed = sweep.expect("run racing recovery sweep").claimed;
        assert_eq!(inline_claimed + sweep_claimed, 1);
        assert_completed_once(&fixture).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn replay_reclaims_expired_run_then_conflicts_without_double_execution() {
        let fixture = recovery_fixture().await;
        let original_generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        claim_then_expire(&fixture, original_generation).await;
        let replay_generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Reused { generation, .. } => generation,
            other => panic!("expected exact grant replay, got {other:?}"),
        };
        assert_eq!(replay_generation, original_generation);

        assert!(matches!(
            drive_workflow_resume(
                Arc::clone(&fixture.engine),
                fixture.db.clone(),
                fixture.community_id,
                fixture.run_id,
                replay_generation,
                Duration::from_secs(1),
            )
            .await
            .expect("replay must reclaim the expired running generation"),
            WorkflowResumeDriveOutcome::Applied { .. }
        ));
        let second_replay_generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Reused { generation, .. } => generation,
            other => panic!("expected completed grant replay, got {other:?}"),
        };
        assert_eq!(
            drive_workflow_resume(
                Arc::clone(&fixture.engine),
                fixture.db.clone(),
                fixture.community_id,
                fixture.run_id,
                second_replay_generation,
                Duration::from_secs(1),
            )
            .await
            .expect("completed replay returns a typed conflict"),
            WorkflowResumeDriveOutcome::Conflict
        );
        assert_completed_once(&fixture).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn effect_recovery_skips_fired_message_after_crash_before_finalize() {
        let yaml = r#"
name: Fired effect recovery
trigger:
  on: webhook
steps:
  - id: approve
    action: request_approval
    from: owner
    message: Approve delivery
  - id: execute
    action: send_message
    text: recovered message
"#;
        let fixture = recovery_fixture_with_yaml(yaml).await;
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        let claimed_generation = claim_resume(&fixture, generation).await;
        execute_claim_without_finalizing(&fixture, claimed_generation).await;
        assert_eq!(fixture.sink.messages().len(), 1);

        expire_claim(&fixture, claimed_generation).await;
        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("recover fired message effect");
        assert_eq!(outcome.claimed, 1);
        assert_eq!(
            fixture.sink.messages().len(),
            1,
            "a fired claim must bypass the sink after reclaim"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn effect_recovery_fires_unfired_claim_once_with_same_identity() {
        let yaml = r#"
name: Unfired effect recovery
trigger:
  on: webhook
steps:
  - id: approve
    action: request_approval
    from: owner
    message: Approve delivery
  - id: execute
    action: send_message
    text: claimed message
"#;
        let fixture = recovery_fixture_with_yaml(yaml).await;
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        let claimed_generation = claim_resume(&fixture, generation).await;
        let run = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read claimed workflow run");
        let definition: buzz_workflow::WorkflowDef =
            serde_json::from_value(run.definition_snapshot).expect("parse workflow definition");
        let effect_spec =
            serde_json::to_value(&definition.steps[1].action).expect("serialize message action");
        let effect_payload = serde_json::json!({
            "channel_id": "00000000-0000-0000-0000-000000000001",
            "text": "claimed message",
            "author_pubkey": hex::encode(&fixture.owner),
            "mentioned_pubkeys": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        });
        let claim = fixture
            .db
            .claim_workflow_effect(
                fixture.community_id,
                fixture.run_id,
                claimed_generation,
                "execute",
                0,
                "send_message",
                &effect_spec,
                &effect_payload,
            )
            .await
            .expect("claim message before firing");
        let buzz_db::WorkflowEffectClaimOutcome::Ready(claim) = claim else {
            panic!("new message claim must be ready");
        };
        assert!(fixture.sink.messages().is_empty());
        fixture.sink.set_resolved_mentions(vec![
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        ]);

        expire_claim(&fixture, claimed_generation).await;
        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("recover unfired message effect");
        assert_eq!(outcome.claimed, 1);
        let calls = fixture.sink.messages();
        assert_eq!(calls.len(), 1, "an unfired claim must reach the sink once");
        assert_eq!(calls[0].effect.idempotency_key, claim.idempotency_key);
        assert_eq!(calls[0].effect.claimed_at, claim.claimed_at);
        assert_eq!(
            calls[0].mentioned_pubkeys,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "recovery must fire the mention pubkeys pinned before live resolution changed"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn effect_recovery_uses_pinned_message_when_live_resolution_fails() {
        let yaml = r#"
name: Pinned message recovery
trigger:
  on: webhook
steps:
  - id: approve
    action: request_approval
    from: owner
    message: Approve delivery
  - id: execute
    action: send_message
    text: pinned message
"#;
        let fixture = recovery_fixture_with_yaml(yaml).await;
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        let claimed_generation = claim_resume(&fixture, generation).await;
        let run = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read claimed workflow run");
        let definition: buzz_workflow::WorkflowDef =
            serde_json::from_value(run.definition_snapshot).expect("parse workflow definition");
        let effect_spec =
            serde_json::to_value(&definition.steps[1].action).expect("serialize message action");
        let effect_payload = serde_json::json!({
            "channel_id": "00000000-0000-0000-0000-000000000001",
            "text": "pinned message",
            "author_pubkey": hex::encode(&fixture.owner),
            "mentioned_pubkeys": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        });
        let claim = fixture
            .db
            .claim_workflow_effect(
                fixture.community_id,
                fixture.run_id,
                claimed_generation,
                "execute",
                0,
                "send_message",
                &effect_spec,
                &effect_payload,
            )
            .await
            .expect("persist pinned message claim");
        assert!(matches!(
            claim,
            buzz_db::WorkflowEffectClaimOutcome::Ready(_)
        ));
        fixture.sink.fail_mention_resolution();

        expire_claim(&fixture, claimed_generation).await;
        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("recover pinned message despite failed resolution");

        assert_eq!(outcome.claimed, 1);
        let calls = fixture.sink.messages();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].mentioned_pubkeys,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        let run = fixture
            .db
            .get_workflow_run(fixture.community_id, fixture.run_id)
            .await
            .expect("read completed workflow run");
        assert_eq!(run.status, RunStatus::Completed);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn effect_recovery_reclaimed_run_does_not_refire_prior_message() {
        let yaml = r#"
name: Prior effect recovery
trigger:
  on: webhook
steps:
  - id: before
    action: send_message
    text: before approval
  - id: approve
    action: request_approval
    from: owner
    message: Approve delivery
  - id: after
    action: send_message
    text: after approval
"#;
        let fixture = recovery_fixture_with_yaml(yaml).await;
        assert_eq!(
            fixture
                .sink
                .messages()
                .iter()
                .map(|call| call.text.as_str())
                .collect::<Vec<_>>(),
            vec!["before approval"]
        );
        let generation = match grant(&fixture).await {
            WorkflowApprovalDecisionOutcome::Applied { generation, .. } => generation,
            other => panic!("expected applied grant, got {other:?}"),
        };
        claim_then_expire(&fixture, generation).await;

        let outcome = run_workflow_resume_sweep_once(
            Arc::clone(&fixture.engine),
            fixture.db.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .expect("recover run after prior message");
        assert_eq!(outcome.claimed, 1);
        assert_eq!(
            fixture
                .sink
                .messages()
                .iter()
                .map(|call| call.text.as_str())
                .collect::<Vec<_>>(),
            vec!["before approval", "after approval"]
        );
    }
}
