//! Durable ingest index for signed Buzz-native CI events.

use std::collections::{BTreeMap, BTreeSet};

use buzz_core::ci::{
    CiEvidenceFinalizedEnvelope, CiJobState, CiJobStatusEnvelope, CiRequestEnvelope, CiRequestType,
    CiRunState, CiSkipPolicy, CiTeardownAttestationEnvelope, ValidatedCiEnvelope,
};
use buzz_core::kind::{
    KIND_CI_ARTIFACT_REFERENCE, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
};
use buzz_core::{CommunityId, StoredEvent};
use chrono::{DateTime, Utc};
use nostr::Event;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{event, DbError, Result};

const MAX_SAFE_CURSOR: i64 = 9_007_199_254_740_991;
const MAX_REDUCER_EVENTS: i64 = 10_000;

/// One canonical signed CI event and its durable per-run acceptance cursor.
#[derive(Debug, Clone)]
pub struct CiStoredEvent {
    /// Strictly increasing storage order within the run.
    pub watch_cursor: i64,
    /// Database acceptance time.
    pub accepted_at: DateTime<Utc>,
    /// Canonical event row from the ordinary event store.
    pub stored_event: StoredEvent,
}

/// Events loaded in the exact shape consumed by the relay selected-graph reducer.
#[derive(Debug, Clone)]
pub struct CiReducerEvents {
    /// Accepted initial and rerun request events in storage order.
    pub request_events: Vec<Event>,
    /// Accepted job-status events in storage order.
    pub job_status_events: Vec<Event>,
}

/// Result of atomically storing a canonical event row and its CI index row.
#[derive(Debug, Clone)]
pub enum StoreCiEventOutcome {
    /// A new event and index row committed together.
    Stored(CiStoredEvent),
    /// The exact event was already present in both stores.
    Reused(CiStoredEvent),
}

#[derive(Debug)]
struct Projection {
    kind: i32,
    run_id: Uuid,
    request_event_id: Option<Vec<u8>>,
    attempt: i32,
    job_id: Option<String>,
    sequence: Option<i64>,
    status_state: Option<&'static str>,
}

impl Projection {
    fn from_envelope(envelope: &ValidatedCiEnvelope) -> Result<Self> {
        let (kind, run_id, request_event_id, attempt, job_id, sequence, status_state) =
            match envelope {
                ValidatedCiEnvelope::Request(value) => (
                    KIND_CI_REQUEST,
                    value.run_id.as_str(),
                    None,
                    value.attempt,
                    (value.request_type == CiRequestType::Rerun).then(|| value.job_ids[0].clone()),
                    None,
                    None,
                ),
                ValidatedCiEnvelope::RunStatus(value) => (
                    KIND_CI_RUN_STATUS,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    None,
                    Some(value.sequence),
                    Some(run_state_text(value.state)),
                ),
                ValidatedCiEnvelope::JobStatus(value) => (
                    KIND_CI_JOB_STATUS,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    Some(value.job_id.clone()),
                    Some(value.sequence),
                    Some(job_state_text(value.state)),
                ),
                ValidatedCiEnvelope::LogReference(value) => (
                    KIND_CI_LOG_REFERENCE,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    Some(value.job_id.clone()),
                    None,
                    None,
                ),
                ValidatedCiEnvelope::ArtifactReference(value) => (
                    KIND_CI_ARTIFACT_REFERENCE,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    Some(value.job_id.clone()),
                    None,
                    None,
                ),
                ValidatedCiEnvelope::EvidenceFinalized(value) => (
                    KIND_CI_EVIDENCE_FINALIZED,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    None,
                    None,
                    None,
                ),
                ValidatedCiEnvelope::TeardownAttestation(value) => (
                    KIND_CI_TEARDOWN_ATTESTATION,
                    value.run_id.as_str(),
                    Some(value.request_event_id.as_str()),
                    value.attempt,
                    None,
                    None,
                    None,
                ),
            };
        Ok(Self {
            kind: i32::try_from(kind)
                .map_err(|_| DbError::InvalidData("CI kind exceeds i32".into()))?,
            run_id: Uuid::parse_str(run_id)
                .map_err(|_| DbError::InvalidData("CI run ID is not a UUID".into()))?,
            request_event_id: request_event_id.map(decode_event_id).transpose()?,
            attempt: i32::try_from(attempt)
                .map_err(|_| DbError::InvalidData("CI attempt exceeds i32".into()))?,
            job_id,
            sequence: sequence
                .map(i64::try_from)
                .transpose()
                .map_err(|_| DbError::InvalidData("CI sequence exceeds i64".into()))?,
            status_state,
        })
    }
}

/// Atomically store one validated CI event in the canonical event log and CI index.
pub async fn store_ci_event(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    event: &Event,
    envelope: &ValidatedCiEnvelope,
) -> Result<StoreCiEventOutcome> {
    if channel_id.is_nil() {
        return Err(DbError::InvalidData("CI channel ID cannot be nil".into()));
    }
    let projection = Projection::from_envelope(envelope)?;
    if i32::from(event.kind.as_u16()) != projection.kind {
        return Err(DbError::InvalidData(
            "CI event kind does not match validated envelope".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    let (stored_event, inserted) = event::insert_event_with_thread_metadata_tx(
        &mut tx,
        community_id,
        event,
        Some(channel_id),
        None,
    )
    .await?;

    if !inserted {
        let existing =
            load_ci_event_by_id_tx(&mut tx, community_id, channel_id, event.id.as_bytes())
                .await?
                .ok_or_else(|| {
                    DbError::InvalidData(
                        "canonical CI event exists without its required CI index row".into(),
                    )
                })?;
        if existing.stored_event.event != *event {
            return Err(DbError::InvalidData("CI event ID conflict".into()));
        }
        tx.commit().await?;
        return Ok(StoreCiEventOutcome::Reused(existing));
    }

    let request_event_id = match envelope {
        ValidatedCiEnvelope::Request(request) => {
            prepare_request(&mut tx, community_id, channel_id, event, request).await?;
            event.id.as_bytes().to_vec()
        }
        _ => {
            let request_event_id = projection
                .request_event_id
                .as_deref()
                .ok_or_else(|| DbError::InvalidData("CI event has no request link".into()))?;
            prepare_linked_event(
                &mut tx,
                community_id,
                channel_id,
                envelope,
                &projection,
                request_event_id,
            )
            .await?;
            request_event_id.to_vec()
        }
    };

    let cursor = next_watch_cursor(&mut tx, community_id, projection.run_id).await?;
    let event_created_at = DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .ok_or_else(|| DbError::InvalidData("CI event timestamp is invalid".into()))?;
    let accepted_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        r#"
        INSERT INTO ci_run_events
            (community_id,run_id,watch_cursor,event_id,event_created_at,
             request_event_id,event_kind,attempt,job_id,status_state,sequence)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT DO NOTHING
        RETURNING accepted_at
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(projection.run_id)
    .bind(cursor)
    .bind(event.id.as_bytes().as_slice())
    .bind(event_created_at)
    .bind(&request_event_id)
    .bind(projection.kind)
    .bind(projection.attempt)
    .bind(projection.job_id.as_deref())
    .bind(projection.status_state)
    .bind(projection.sequence)
    .fetch_optional(&mut *tx)
    .await?;
    let accepted_at = accepted_at.ok_or_else(|| {
        DbError::InvalidData("CI event conflicts with stored run identity or stream order".into())
    })?;
    tx.commit().await?;
    Ok(StoreCiEventOutcome::Stored(CiStoredEvent {
        watch_cursor: cursor,
        accepted_at,
        stored_event,
    }))
}

/// Load the immutable initial kind-46100 request for a run.
pub async fn get_ci_run_request(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    run_id: Uuid,
) -> Result<Option<CiStoredEvent>> {
    let row = sqlx::query(
        r#"
        SELECT index.watch_cursor,index.accepted_at,index.event_kind,
               stored.id,stored.pubkey,stored.created_at,stored.kind,stored.tags,
               stored.content,stored.sig,stored.received_at,stored.channel_id
        FROM ci_run_events AS index
        JOIN ci_runs AS run
          ON run.community_id=index.community_id AND run.run_id=index.run_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND run.channel_id=$2 AND index.run_id=$3
          AND index.event_kind=$4 AND index.attempt=1
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(run_id)
    .bind(KIND_CI_REQUEST as i32)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_ci_stored_event).transpose()
}

/// List accepted CI events after an exclusive per-run cursor.
pub async fn list_ci_run_events(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    run_id: Uuid,
    after_cursor: i64,
    limit: u32,
) -> Result<Vec<CiStoredEvent>> {
    if !(0..=MAX_SAFE_CURSOR).contains(&after_cursor) {
        return Err(DbError::InvalidData(
            "CI watch cursor is outside the safe integer range".into(),
        ));
    }
    let rows = sqlx::query(
        r#"
        SELECT index.watch_cursor,index.accepted_at,index.event_kind,
               stored.id,stored.pubkey,stored.created_at,stored.kind,stored.tags,
               stored.content,stored.sig,stored.received_at,stored.channel_id
        FROM ci_run_events AS index
        JOIN ci_runs AS run
          ON run.community_id=index.community_id AND run.run_id=index.run_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND run.channel_id=$2 AND index.run_id=$3
          AND index.watch_cursor>$4
        ORDER BY index.watch_cursor LIMIT $5
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(run_id)
    .bind(after_cursor)
    .bind(i64::from(limit.clamp(1, 1_000)))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_ci_stored_event).collect()
}

/// Load the accepted request and job-status events needed by the selected-graph reducer.
pub async fn load_ci_reducer_events(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    run_id: Uuid,
) -> Result<CiReducerEvents> {
    let rows = sqlx::query(
        r#"
        SELECT index.watch_cursor,index.accepted_at,index.event_kind,
               stored.id,stored.pubkey,stored.created_at,stored.kind,stored.tags,
               stored.content,stored.sig,stored.received_at,stored.channel_id
        FROM ci_run_events AS index
        JOIN ci_runs AS run
          ON run.community_id=index.community_id AND run.run_id=index.run_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND run.channel_id=$2 AND index.run_id=$3
          AND index.event_kind IN ($4,$5)
        ORDER BY index.watch_cursor LIMIT $6
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(run_id)
    .bind(KIND_CI_REQUEST as i32)
    .bind(KIND_CI_JOB_STATUS as i32)
    .bind(MAX_REDUCER_EVENTS + 1)
    .fetch_all(pool)
    .await?;
    if rows.len() > MAX_REDUCER_EVENTS as usize {
        return Err(DbError::InvalidData(
            "CI reducer input exceeds the bounded event limit".into(),
        ));
    }
    let mut request_events = Vec::new();
    let mut job_status_events = Vec::new();
    for row in rows {
        let kind: i32 = row.try_get("event_kind")?;
        let event = row_to_ci_stored_event(row)?.stored_event.event;
        if kind == KIND_CI_REQUEST as i32 {
            request_events.push(event);
        } else {
            job_status_events.push(event);
        }
    }
    Ok(CiReducerEvents {
        request_events,
        job_status_events,
    })
}

async fn prepare_request(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    event: &Event,
    request: &CiRequestEnvelope,
) -> Result<()> {
    let run_id = Uuid::parse_str(&request.run_id)
        .map_err(|_| DbError::InvalidData("CI run ID is not a UUID".into()))?;
    let digest = hex::decode(&request.workflow_digest)
        .map_err(|_| DbError::InvalidData("CI workflow digest is not hexadecimal".into()))?;
    let tuple_digest = immutable_tuple_digest(request)?;
    if request.request_type == CiRequestType::Run {
        let inserted = sqlx::query(
            r#"
            INSERT INTO ci_runs
                (community_id,channel_id,run_id,initial_request_event_id,target_repo_a,
                 tip_oid,base_oid,workflow_id,workflow_digest,immutable_tuple_digest)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .bind(run_id)
        .bind(event.id.as_bytes().as_slice())
        .bind(&request.target_repo_a)
        .bind(&request.tip_oid)
        .bind(&request.base_oid)
        .bind(&request.workflow_id)
        .bind(digest)
        .bind(tuple_digest)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(DbError::InvalidData(
                "CI run ID or initial request event ID already exists".into(),
            ));
        }
        return Ok(());
    }

    let run = lock_run(tx, community_id, channel_id, run_id).await?;
    if run.try_get::<String, _>("target_repo_a")? != request.target_repo_a
        || run.try_get::<String, _>("tip_oid")? != request.tip_oid
        || run.try_get::<String, _>("base_oid")? != request.base_oid
        || run.try_get::<String, _>("workflow_id")? != request.workflow_id
        || run.try_get::<Vec<u8>, _>("workflow_digest")? != digest
        || run.try_get::<Vec<u8>, _>("immutable_tuple_digest")? != tuple_digest
    {
        return Err(DbError::InvalidData(
            "CI rerun changed immutable run coordinates".into(),
        ));
    }
    let initial = load_initial_request_tx(tx, community_id, run_id).await?;
    let job_id = &request.job_ids[0];
    if !initial.job_ids.contains(job_id) {
        return Err(DbError::InvalidData(
            "CI rerun selected an unknown initial job".into(),
        ));
    }
    let parent_attempt = i32::try_from(request.parent_attempt.unwrap_or(0))
        .map_err(|_| DbError::InvalidData("CI parent attempt exceeds i32".into()))?;
    let parent_state: Option<String> = sqlx::query_scalar(
        r#"
        SELECT status_state FROM ci_run_events
        WHERE community_id=$1 AND run_id=$2 AND event_kind=$3
          AND job_id=$4 AND attempt=$5
        ORDER BY sequence DESC LIMIT 1
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(KIND_CI_JOB_STATUS as i32)
    .bind(job_id)
    .bind(parent_attempt)
    .fetch_optional(&mut **tx)
    .await?;
    if parent_state.as_deref() != Some("failure") {
        return Err(DbError::InvalidData(
            "CI rerun parent job is not a selected terminal failure".into(),
        ));
    }
    Ok(())
}

async fn prepare_linked_event(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    envelope: &ValidatedCiEnvelope,
    projection: &Projection,
    request_event_id: &[u8],
) -> Result<()> {
    lock_run(tx, community_id, channel_id, projection.run_id).await?;
    let request =
        load_linked_request_tx(tx, community_id, projection.run_id, request_event_id).await?;
    if projection.attempt
        != i32::try_from(request.attempt)
            .map_err(|_| DbError::InvalidData("CI request attempt exceeds i32".into()))?
    {
        return Err(DbError::InvalidData(
            "CI event attempt does not match its request".into(),
        ));
    }
    if !coordinates_match(envelope, &request) {
        return Err(DbError::InvalidData(
            "CI event changed immutable request coordinates".into(),
        ));
    }
    if let Some(job_id) = projection.job_id.as_deref() {
        let initial = load_initial_request_tx(tx, community_id, projection.run_id).await?;
        if !initial.job_ids.iter().any(|candidate| candidate == job_id) {
            return Err(DbError::InvalidData(
                "CI event references a job outside the initial request".into(),
            ));
        }
    }
    validate_status_sequence(tx, community_id, envelope, projection).await?;
    match envelope {
        ValidatedCiEnvelope::EvidenceFinalized(evidence) => {
            validate_evidence_finalized(tx, community_id, projection.run_id, evidence).await?;
        }
        ValidatedCiEnvelope::TeardownAttestation(teardown) => {
            validate_teardown_attestation(tx, community_id, projection.run_id, teardown).await?;
        }
        _ => {}
    }
    if matches!(
        envelope,
        ValidatedCiEnvelope::RunStatus(status) if status.state == CiRunState::Success
    ) {
        validate_terminal_success(tx, community_id, projection.run_id).await?;
    }
    Ok(())
}

async fn validate_terminal_success(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
) -> Result<()> {
    let evidence: CiEvidenceFinalizedEnvelope =
        load_terminal_fact(tx, community_id, run_id, KIND_CI_EVIDENCE_FINALIZED).await?;
    validate_evidence_finalized(tx, community_id, run_id, &evidence).await?;

    let teardown: CiTeardownAttestationEnvelope =
        load_terminal_fact(tx, community_id, run_id, KIND_CI_TEARDOWN_ATTESTATION).await?;
    validate_teardown_attestation(tx, community_id, run_id, &teardown).await
}

async fn validate_evidence_finalized(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    evidence: &CiEvidenceFinalizedEnvelope,
) -> Result<()> {
    let (request_event_id, request) =
        load_initial_request_identity_tx(tx, community_id, run_id).await?;
    if evidence.request_event_id != request_event_id
        || evidence.run_id != request.run_id
        || evidence.workflow_id != request.workflow_id
        || evidence.target_repo_a != request.target_repo_a
        || evidence.tip_oid != request.tip_oid
    {
        return Err(DbError::InvalidData(
            "CI evidence provenance does not match the accepted run".into(),
        ));
    }

    let selected =
        load_selected_terminal_jobs(tx, community_id, run_id, &request_event_id, &request).await?;
    let max_attempt = selected
        .iter()
        .map(|status| status.attempt)
        .max()
        .ok_or_else(|| DbError::InvalidData("CI selected job graph is empty".into()))?;
    if evidence.attempt != max_attempt || evidence.finalized_job_attempts.len() != selected.len() {
        return Err(DbError::InvalidData(
            "CI evidence does not exactly match selected job attempts".into(),
        ));
    }

    let finalized = evidence
        .finalized_job_attempts
        .iter()
        .map(|job| (job.job_id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    for status in &selected {
        let fact = finalized.get(status.job_id.as_str()).ok_or_else(|| {
            DbError::InvalidData("CI evidence omits a selected job attempt".into())
        })?;
        if fact.attempt != status.attempt
            || status.log_ref.as_deref() != Some(fact.log_ref.as_str())
            || status.artifact_refs != fact.artifact_refs
        {
            return Err(DbError::InvalidData(
                "CI evidence references do not match the selected terminal job status".into(),
            ));
        }
        require_stored_reference(
            tx,
            community_id,
            run_id,
            &fact.log_ref,
            KIND_CI_LOG_REFERENCE,
            &status.job_id,
            status.attempt,
        )
        .await?;
        for artifact_ref in &fact.artifact_refs {
            require_stored_reference(
                tx,
                community_id,
                run_id,
                artifact_ref,
                KIND_CI_ARTIFACT_REFERENCE,
                &status.job_id,
                status.attempt,
            )
            .await?;
        }
    }
    Ok(())
}

async fn validate_teardown_attestation(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    teardown: &CiTeardownAttestationEnvelope,
) -> Result<()> {
    let (request_event_id, request) =
        load_initial_request_identity_tx(tx, community_id, run_id).await?;
    let selected =
        load_selected_terminal_jobs(tx, community_id, run_id, &request_event_id, &request).await?;
    let selected_attempts = selected
        .into_iter()
        .map(|status| (status.job_id, status.attempt))
        .collect::<Vec<_>>();
    teardown
        .validate_context(&request_event_id, &request, &selected_attempts)
        .map_err(|error| DbError::InvalidData(format!("invalid CI teardown binding: {error}")))
}

async fn load_selected_terminal_jobs(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    initial_request_event_id: &str,
    initial: &CiRequestEnvelope,
) -> Result<Vec<CiJobStatusEnvelope>> {
    let request_rows = sqlx::query(
        r#"
        SELECT encode(index.event_id, 'hex') AS event_id,stored.content
        FROM ci_run_events AS index
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND index.run_id=$2 AND index.event_kind=$3
        ORDER BY index.watch_cursor
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(KIND_CI_REQUEST as i32)
    .fetch_all(&mut **tx)
    .await?;
    let mut requests = Vec::with_capacity(request_rows.len());
    for row in request_rows {
        let event_id: String = row.try_get("event_id")?;
        let envelope: CiRequestEnvelope = serde_json::from_str(row.try_get("content")?)
            .map_err(|_| DbError::InvalidData("stored CI request content is invalid".into()))?;
        requests.push((event_id, envelope));
    }
    if requests.first().is_none_or(|(event_id, request)| {
        event_id != initial_request_event_id || request != initial
    }) {
        return Err(DbError::InvalidData(
            "CI selected graph has no canonical initial request".into(),
        ));
    }

    let rows = sqlx::query(
        r#"
        SELECT stored.content
        FROM ci_run_events AS index
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND index.run_id=$2 AND index.event_kind=$3
        ORDER BY index.job_id,index.attempt,index.sequence
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(KIND_CI_JOB_STATUS as i32)
    .fetch_all(&mut **tx)
    .await?;
    let mut histories = BTreeMap::new();
    for row in rows {
        let status: CiJobStatusEnvelope = serde_json::from_str(row.try_get("content")?)
            .map_err(|_| DbError::InvalidData("stored CI job status content is invalid".into()))?;
        histories.insert(
            (
                status.request_event_id.clone(),
                status.job_id.clone(),
                status.attempt,
            ),
            status,
        );
    }

    let mut selected_attempts = BTreeMap::new();
    let mut selected_states = BTreeMap::new();
    let mut selected_request_ids = BTreeMap::new();
    let mut consumed = BTreeSet::new();
    for job_id in &initial.job_ids {
        let key = (initial_request_event_id.to_string(), job_id.clone(), 1);
        let status = histories.get(&key).ok_or_else(|| {
            DbError::InvalidData(format!("CI selected job {job_id} has no status history"))
        })?;
        if !status.state.is_terminal() {
            return Err(DbError::InvalidData(format!(
                "CI selected job {job_id} is not terminal"
            )));
        }
        selected_attempts.insert(job_id.clone(), 1);
        selected_states.insert(job_id.clone(), status.state);
        selected_request_ids.insert(job_id.clone(), initial_request_event_id.to_string());
        consumed.insert(key);
    }

    for (request_event_id, request) in requests.iter().skip(1) {
        if request.request_type != CiRequestType::Rerun {
            return Err(DbError::InvalidData(
                "CI selected graph contains a second initial request".into(),
            ));
        }
        let selected_job = &request.job_ids[0];
        let parent_attempt = request.parent_attempt.ok_or_else(|| {
            DbError::InvalidData("CI rerun is missing its selected parent attempt".into())
        })?;
        if selected_attempts.get(selected_job) != Some(&parent_attempt)
            || selected_states.get(selected_job) != Some(&CiJobState::Failure)
        {
            return Err(DbError::InvalidData(
                "CI rerun does not advance the selected failed parent".into(),
            ));
        }
        let primary_key = (
            request_event_id.clone(),
            selected_job.clone(),
            request.attempt,
        );
        let primary = histories.get(&primary_key).ok_or_else(|| {
            DbError::InvalidData("CI rerun selected job has no terminal status stream".into())
        })?;
        let mut advanced = BTreeSet::from([selected_job.clone()]);
        advanced.extend(primary.also_reruns.iter().cloned());
        for job_id in advanced {
            let key = (request_event_id.clone(), job_id.clone(), request.attempt);
            let status = histories.get(&key).ok_or_else(|| {
                DbError::InvalidData(
                    "CI rerun fan-out job has no matching terminal status stream".into(),
                )
            })?;
            if !status.state.is_terminal() || status.parent_attempt != Some(parent_attempt) {
                return Err(DbError::InvalidData(
                    "CI rerun job status is non-terminal or has wrong parent attempt".into(),
                ));
            }
            selected_attempts.insert(job_id.clone(), request.attempt);
            selected_states.insert(job_id.clone(), status.state);
            selected_request_ids.insert(job_id, request_event_id.clone());
            consumed.insert(key);
        }
    }

    if consumed.len() != histories.len() {
        return Err(DbError::InvalidData(
            "CI status history contains an unselected job attempt".into(),
        ));
    }

    let mut selected = Vec::with_capacity(initial.job_ids.len());
    for job_id in &initial.job_ids {
        let attempt = selected_attempts[job_id];
        let request_event_id = &selected_request_ids[job_id];
        let status = histories
            .get(&(request_event_id.clone(), job_id.clone(), attempt))
            .cloned()
            .ok_or_else(|| DbError::InvalidData("CI selected terminal status is missing".into()))?;
        if status.required
            && status.state != CiJobState::Success
            && !(status.state == CiJobState::Skipped && status.skip_policy == CiSkipPolicy::Allow)
        {
            return Err(DbError::InvalidData(format!(
                "CI selected required job {job_id} is not terminal-good"
            )));
        }
        selected.push(status);
    }
    Ok(selected)
}

async fn require_stored_reference(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    event_id: &str,
    event_kind: u32,
    job_id: &str,
    attempt: u32,
) -> Result<()> {
    let event_id = decode_event_id(event_id)?;
    let attempt = i32::try_from(attempt)
        .map_err(|_| DbError::InvalidData("CI evidence attempt exceeds i32".into()))?;
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ci_run_events
            WHERE community_id=$1 AND run_id=$2 AND event_id=$3
              AND event_kind=$4 AND job_id=$5 AND attempt=$6
        )
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(event_id)
    .bind(event_kind as i32)
    .bind(job_id)
    .bind(attempt)
    .fetch_one(&mut **tx)
    .await?;
    if !exists {
        return Err(DbError::InvalidData(
            "CI evidence reference does not resolve to the selected run/job/attempt".into(),
        ));
    }
    Ok(())
}

async fn load_terminal_fact<T: serde::de::DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    event_kind: u32,
) -> Result<T> {
    let content: String = sqlx::query_scalar(
        r#"
        SELECT stored.content
        FROM ci_run_events AS index
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND index.run_id=$2 AND index.event_kind=$3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(event_kind as i32)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        DbError::InvalidData(
            "CI terminal success requires stored evidence and teardown facts".into(),
        )
    })?;
    serde_json::from_str(&content)
        .map_err(|_| DbError::InvalidData("stored CI terminal fact content is invalid".into()))
}

async fn validate_status_sequence(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    envelope: &ValidatedCiEnvelope,
    projection: &Projection,
) -> Result<()> {
    let Some(sequence) = projection.sequence else {
        return Ok(());
    };
    let previous = sqlx::query(
        r#"
        SELECT index.sequence,index.status_state,stored.content
        FROM ci_run_events AS index
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND index.run_id=$2 AND index.event_kind=$3
          AND index.attempt=$4 AND index.job_id IS NOT DISTINCT FROM $5
        ORDER BY index.sequence DESC LIMIT 1
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(projection.run_id)
    .bind(projection.kind)
    .bind(projection.attempt)
    .bind(projection.job_id.as_deref())
    .fetch_optional(&mut **tx)
    .await?;
    let expected = previous
        .as_ref()
        .map(|row| row.try_get::<i64, _>("sequence"))
        .transpose()?
        .unwrap_or(0)
        + 1;
    if sequence != expected {
        return Err(DbError::InvalidData(
            "CI status sequence is duplicate or has a gap".into(),
        ));
    }
    match envelope {
        ValidatedCiEnvelope::RunStatus(status) => {
            let valid = match previous.as_ref() {
                None => status.state == CiRunState::Queued,
                Some(row) => {
                    parse_run_state(row.try_get("status_state")?)?.can_transition_to(status.state)
                }
            };
            if !valid {
                return Err(DbError::InvalidData(
                    "CI run status transition is invalid".into(),
                ));
            }
            let initial = load_initial_request_tx(tx, community_id, projection.run_id).await?;
            if status.job_ids != initial.job_ids {
                return Err(DbError::InvalidData(
                    "CI run status changed the signed initial job set".into(),
                ));
            }
        }
        ValidatedCiEnvelope::JobStatus(status) => {
            let valid = match previous.as_ref() {
                None => status.state == CiJobState::Queued,
                Some(row) => {
                    parse_job_state(row.try_get("status_state")?)?.can_transition_to(status.state)
                }
            };
            if !valid {
                return Err(DbError::InvalidData(
                    "CI job status transition is invalid".into(),
                ));
            }
            if let Some(row) = previous {
                let prior: CiJobStatusEnvelope = serde_json::from_str(row.try_get("content")?)
                    .map_err(|_| {
                        DbError::InvalidData("stored CI job status content is invalid".into())
                    })?;
                if prior.name != status.name
                    || prior.required != status.required
                    || prior.skip_policy != status.skip_policy
                    || prior.selected_job_instance != status.selected_job_instance
                    || prior.also_reruns != status.also_reruns
                {
                    return Err(DbError::InvalidData(
                        "CI job status stream changed signed manifest fields".into(),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn lock_run(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    run_id: Uuid,
) -> Result<sqlx::postgres::PgRow> {
    sqlx::query(
        r#"
        SELECT target_repo_a,tip_oid,base_oid,workflow_id,workflow_digest,
               immutable_tuple_digest,initial_request_event_id
        FROM ci_runs
        WHERE community_id=$1 AND channel_id=$2 AND run_id=$3
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(run_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DbError::NotFound(format!("CI run {run_id}")))
}

async fn next_watch_cursor(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
) -> Result<i64> {
    sqlx::query_scalar(
        r#"
        UPDATE ci_runs SET last_watch_cursor=last_watch_cursor+1
        WHERE community_id=$1 AND run_id=$2 AND last_watch_cursor<$3
        RETURNING last_watch_cursor
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(MAX_SAFE_CURSOR)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("CI watch cursor exhausted".into()))
}

async fn load_initial_request_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
) -> Result<CiRequestEnvelope> {
    load_initial_request_identity_tx(tx, community_id, run_id)
        .await
        .map(|(_, request)| request)
}

async fn load_initial_request_identity_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
) -> Result<(String, CiRequestEnvelope)> {
    let row = sqlx::query(
        r#"
        SELECT encode(run.initial_request_event_id, 'hex') AS request_event_id,
               stored.content
        FROM ci_runs AS run
        JOIN ci_run_events AS index
          ON index.community_id=run.community_id
         AND index.event_id=run.initial_request_event_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE run.community_id=$1 AND run.run_id=$2
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("CI initial request is missing".into()))?;
    let request_event_id = row.try_get("request_event_id")?;
    let content: String = row.try_get("content")?;
    let request = serde_json::from_str(&content)
        .map_err(|_| DbError::InvalidData("stored CI request content is invalid".into()))?;
    Ok((request_event_id, request))
}

async fn load_linked_request_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    run_id: Uuid,
    request_event_id: &[u8],
) -> Result<CiRequestEnvelope> {
    let content: String = sqlx::query_scalar(
        r#"
        SELECT stored.content
        FROM ci_run_events AS index
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND index.run_id=$2
          AND index.event_kind=$3 AND index.event_id=$4
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(KIND_CI_REQUEST as i32)
    .bind(request_event_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("CI request link does not resolve".into()))?;
    serde_json::from_str(&content)
        .map_err(|_| DbError::InvalidData("stored CI request content is invalid".into()))
}

async fn load_ci_event_by_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    event_id: &[u8],
) -> Result<Option<CiStoredEvent>> {
    let row = sqlx::query(
        r#"
        SELECT index.watch_cursor,index.accepted_at,index.event_kind,
               stored.id,stored.pubkey,stored.created_at,stored.kind,stored.tags,
               stored.content,stored.sig,stored.received_at,stored.channel_id
        FROM ci_run_events AS index
        JOIN ci_runs AS run
          ON run.community_id=index.community_id AND run.run_id=index.run_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND run.channel_id=$2 AND index.event_id=$3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(row_to_ci_stored_event).transpose()
}

fn row_to_ci_stored_event(row: sqlx::postgres::PgRow) -> Result<CiStoredEvent> {
    let watch_cursor = row.try_get("watch_cursor")?;
    let accepted_at = row.try_get("accepted_at")?;
    let stored_event = event::row_to_stored_event(row)?.ok_or_else(|| {
        DbError::InvalidData("canonical CI event row could not be reconstructed".into())
    })?;
    Ok(CiStoredEvent {
        watch_cursor,
        accepted_at,
        stored_event,
    })
}

fn coordinates_match(envelope: &ValidatedCiEnvelope, request: &CiRequestEnvelope) -> bool {
    match envelope {
        ValidatedCiEnvelope::Request(value) => value == request,
        ValidatedCiEnvelope::RunStatus(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
                && value.base_oid == request.base_oid
        }
        ValidatedCiEnvelope::JobStatus(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
                && value.base_oid == request.base_oid
        }
        ValidatedCiEnvelope::LogReference(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
        }
        ValidatedCiEnvelope::ArtifactReference(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
        }
        ValidatedCiEnvelope::EvidenceFinalized(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
        }
        ValidatedCiEnvelope::TeardownAttestation(value) => {
            value.run_id == request.run_id
                && value.workflow_id == request.workflow_id
                && value.target_repo_a == request.target_repo_a
                && value.tip_oid == request.tip_oid
                && value.base_oid == request.base_oid
                && value.workflow_digest == request.workflow_digest
        }
    }
}

fn immutable_tuple_digest(request: &CiRequestEnvelope) -> Result<Vec<u8>> {
    let canonical = serde_json::to_vec(&(
        &request.target_repo_a,
        &request.pr_root_event_id,
        request.pr_update_event_id.as_deref(),
        &request.source_clone_url,
        &request.immutable_source_ref,
        &request.tip_oid,
        &request.source_branch,
        &request.base_ref,
        &request.base_oid,
        &request.workflow_id,
        &request.workflow_digest,
        &request.trigger_event_id,
    ))?;
    Ok(Sha256::digest(canonical).to_vec())
}

fn decode_event_id(value: &str) -> Result<Vec<u8>> {
    let decoded = hex::decode(value)
        .map_err(|_| DbError::InvalidData("CI request event ID is not hexadecimal".into()))?;
    if decoded.len() != 32 {
        return Err(DbError::InvalidData(
            "CI request event ID must be 32 bytes".into(),
        ));
    }
    Ok(decoded)
}

fn run_state_text(value: CiRunState) -> &'static str {
    match value {
        CiRunState::Queued => "queued",
        CiRunState::Running => "running",
        CiRunState::Success => "success",
        CiRunState::Failure => "failure",
        CiRunState::Cancelled => "cancelled",
        CiRunState::TimedOut => "timed_out",
        CiRunState::InfrastructureFailure => "infrastructure_failure",
    }
}

fn job_state_text(value: CiJobState) -> &'static str {
    match value {
        CiJobState::Queued => "queued",
        CiJobState::Running => "running",
        CiJobState::Success => "success",
        CiJobState::Failure => "failure",
        CiJobState::Cancelled => "cancelled",
        CiJobState::TimedOut => "timed_out",
        CiJobState::Skipped => "skipped",
    }
}

fn parse_run_state(value: Option<String>) -> Result<CiRunState> {
    match value.as_deref() {
        Some("queued") => Ok(CiRunState::Queued),
        Some("running") => Ok(CiRunState::Running),
        Some("success") => Ok(CiRunState::Success),
        Some("failure") => Ok(CiRunState::Failure),
        Some("cancelled") => Ok(CiRunState::Cancelled),
        Some("timed_out") => Ok(CiRunState::TimedOut),
        Some("infrastructure_failure") => Ok(CiRunState::InfrastructureFailure),
        _ => Err(DbError::InvalidData(
            "stored CI run state is invalid".into(),
        )),
    }
}

fn parse_job_state(value: Option<String>) -> Result<CiJobState> {
    match value.as_deref() {
        Some("queued") => Ok(CiJobState::Queued),
        Some("running") => Ok(CiJobState::Running),
        Some("success") => Ok(CiJobState::Success),
        Some("failure") => Ok(CiJobState::Failure),
        Some("cancelled") => Ok(CiJobState::Cancelled),
        Some("timed_out") => Ok(CiJobState::TimedOut),
        Some("skipped") => Ok(CiJobState::Skipped),
        _ => Err(DbError::InvalidData(
            "stored CI job state is invalid".into(),
        )),
    }
}
