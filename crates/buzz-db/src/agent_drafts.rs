//! Atomic immutable draft intake and owner decision CAS on the writer.
use crate::{Db, DbError, Result};
use buzz_core::{
    agent_drafts::{validate_decision, validate_request, DecisionState},
    event::StoredEvent,
    kind::KIND_AGENT_DRAFT,
    tenant::CommunityId,
};
use nostr::Event;
use sqlx::Row;

impl Db {
    /// Store the request identity and signed event atomically, or advance one owner CAS.
    /// Exact retries return their original result; UUID/content conflicts never replace it.
    pub async fn store_agent_draft(
        &self,
        community: CommunityId,
        event: &Event,
    ) -> Result<(StoredEvent, bool)> {
        let invalid = DbError::InvalidData;
        let mut tx = self.pool.begin().await?;
        let id = event.id.as_bytes().as_slice();
        let is_request = u32::from(event.kind.as_u16()) == KIND_AGENT_DRAFT;
        if is_request {
            let route = validate_request(event).map_err(invalid)?;
            // Serialize quota checks per owner; exact UUID retries remain accepted.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!(
                    "agent_drafts:{}:{}",
                    community.as_uuid(),
                    route.owner.to_hex()
                ))
                .execute(&mut *tx)
                .await?;
            let full:bool=sqlx::query_scalar("SELECT (SELECT count(*) FROM agent_drafts WHERE community_id=$1 AND owner=$2 AND state IN ('pending','applying')) >= 10000 AND NOT EXISTS (SELECT 1 FROM agent_drafts WHERE community_id=$1 AND owner=$2 AND agent=$3 AND request_id=$4)")
                .bind(community.as_uuid()).bind(route.owner.as_bytes().as_slice()).bind(route.agent.as_bytes().as_slice()).bind(route.request_id).fetch_one(&mut *tx).await?;
            if full {
                return Err(DbError::Conflict(
                    "owner pending draft quota reached; existing drafts retained".into(),
                ));
            }
            sqlx::query("INSERT INTO agent_drafts (community_id, owner, agent, request_id, request_event_id, channel_id, head_event_id) VALUES ($1,$2,$3,$4,$5,$6,$5) ON CONFLICT DO NOTHING")
                .bind(community.as_uuid()).bind(route.owner.as_bytes().as_slice()).bind(route.agent.as_bytes().as_slice()).bind(route.request_id).bind(id).bind(route.channel).execute(&mut *tx).await?;
            let stored: Vec<u8> = sqlx::query_scalar("SELECT request_event_id FROM agent_drafts WHERE community_id=$1 AND owner=$2 AND agent=$3 AND request_id=$4 FOR UPDATE")
                .bind(community.as_uuid()).bind(route.owner.as_bytes().as_slice()).bind(route.agent.as_bytes().as_slice()).bind(route.request_id).fetch_one(&mut *tx).await?;
            if stored != id {
                return Err(DbError::Conflict(
                    "request UUID already binds different signed bytes".into(),
                ));
            }
        } else {
            let decision = validate_decision(event).map_err(invalid)?;
            let row = sqlx::query("SELECT owner, head_event_id, generation, state FROM agent_drafts WHERE community_id=$1 AND request_event_id=$2 FOR UPDATE")
                .bind(community.as_uuid()).bind(decision.request_event.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or_else(|| DbError::AccessDenied("draft unavailable".into()))?;
            let owner: Vec<u8> = row.try_get("owner")?;
            if owner != decision.owner.as_bytes() {
                return Err(DbError::AccessDenied("draft unavailable".into()));
            }
            // A previously accepted intermediate claim remains an idempotent retry
            // even after a terminal outcome advanced the head.
            let duplicate: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM events WHERE community_id=$1 AND id=$2)",
            )
            .bind(community.as_uuid())
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if !duplicate {
                let head: Vec<u8> = row.try_get("head_event_id")?;
                let generation: i64 = row.try_get("generation")?;
                let state: String = row.try_get("state")?;
                let valid_transition = (state == "pending"
                    && matches!(
                        decision.state,
                        DecisionState::Applying | DecisionState::Rejected
                    ))
                    || (state == "applying" && decision.state == DecisionState::Applied);
                if !valid_transition
                    || head != decision.predecessor.as_bytes()
                    || generation + 1 != decision.generation as i64
                {
                    return Err(DbError::Conflict(
                        "draft decision predecessor already advanced; inspect winning claim".into(),
                    ));
                }
                let next = match decision.state {
                    DecisionState::Applying => "applying",
                    DecisionState::Applied => "applied",
                    DecisionState::Rejected => "rejected",
                };
                sqlx::query("UPDATE agent_drafts SET head_event_id=$3,generation=$4,state=$5 WHERE community_id=$1 AND request_event_id=$2")
                    .bind(community.as_uuid()).bind(decision.request_event.as_bytes().as_slice()).bind(id).bind(decision.generation as i64).bind(next).execute(&mut *tx).await?;
            }
        }
        let created = chrono::DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
            .ok_or(DbError::InvalidTimestamp(event.created_at.as_secs() as i64))?;
        let received = chrono::Utc::now();
        let inserted = sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags,content,sig,received_at,channel_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL) ON CONFLICT DO NOTHING")
            .bind(community.as_uuid()).bind(id).bind(event.pubkey.as_bytes().as_slice()).bind(created).bind(i32::from(event.kind.as_u16())).bind(serde_json::to_value(&event.tags)?).bind(&event.content).bind(event.sig.serialize().as_slice()).bind(received).execute(&mut *tx).await?.rows_affected() > 0;
        let owner = buzz_core::agent_drafts::exact_tag(event, "p").map_err(DbError::InvalidData)?;
        sqlx::query("INSERT INTO event_mentions (community_id,pubkey_hex,event_id,event_created_at,event_kind) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(community.as_uuid()).bind(owner).bind(id).bind(created).bind(i32::from(event.kind.as_u16())).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok((
            StoredEvent::with_received_at(event.clone(), received, None, true),
            inserted,
        ))
    }
}
