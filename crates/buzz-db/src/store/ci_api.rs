//! Compatibility methods for fork CI persistence.
use crate::{ci, ci_grants, ci_landing, ci_merge_bypass, git_merge_gate, CommunityId, Db, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;
impl Db {
    /// Restored fork CI persistence operation.
    pub async fn consume_ci_merge_bypass(
        &self,
        community_id: CommunityId,
        event_id: &[u8],
        decision_id: Uuid,
    ) -> Result<bool> {
        async {
            ci_merge_bypass::consume_ci_merge_bypass(
                &self.pool,
                community_id,
                event_id,
                decision_id,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn find_merge_gate_allow(
        &self,
        community_id: CommunityId,
        target_repo_a: &str,
        ref_name: &str,
        old_oid: &str,
        new_oid: &str,
        pusher: &str,
        not_before: DateTime<Utc>,
    ) -> Result<Option<git_merge_gate::MergeGateAllowRecord>> {
        async {
            git_merge_gate::find_merge_gate_allow(
                &self.pool,
                community_id,
                target_repo_a,
                ref_name,
                old_oid,
                new_oid,
                pusher,
                not_before,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn get_active_ci_signers(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        target_repo_a: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        async {
            ci_grants::get_active_ci_signers(
                &self.pool,
                community_id,
                channel_id,
                target_repo_a,
                now,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn get_ci_run_member_channel(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        pubkey: &[u8],
    ) -> Result<Option<Uuid>> {
        async { ci::get_ci_run_member_channel(&self.pool, community_id, run_id, pubkey).await }
            .await
    }
    /// Restored fork CI persistence operation.
    pub async fn get_ci_run_request(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        run_id: Uuid,
    ) -> Result<Option<ci::CiStoredEvent>> {
        async { ci::get_ci_run_request(&self.pool, community_id, channel_id, run_id).await }.await
    }
    /// Restored fork CI persistence operation.
    pub async fn insert_ci_merge_bypass(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        event_id: &[u8],
        issuer_pubkey: &str,
        envelope: &buzz_core::ci::CiMergeBypassEnvelope,
    ) -> Result<bool> {
        async {
            ci_merge_bypass::insert_ci_merge_bypass(
                &self.pool,
                community_id,
                channel_id,
                event_id,
                issuer_pubkey,
                envelope,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn insert_merge_gate_decision(
        &self,
        community_id: CommunityId,
        insert: &git_merge_gate::MergeGateDecisionInsert,
    ) -> Result<Uuid> {
        async { git_merge_gate::insert_merge_gate_decision(&self.pool, community_id, insert).await }
            .await
    }
    /// Restored fork CI persistence operation.
    pub async fn list_ci_merge_bypasses(
        &self,
        community_id: CommunityId,
        target_repo_a: &str,
        ref_name: &str,
        old_oid: &str,
        new_oid: &str,
    ) -> Result<Vec<ci_merge_bypass::CiMergeBypassRecord>> {
        async {
            ci_merge_bypass::list_ci_merge_bypasses(
                &self.pool,
                community_id,
                target_repo_a,
                ref_name,
                old_oid,
                new_oid,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn list_ci_run_checks(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        run_id: Uuid,
    ) -> Result<Vec<ci::CiStoredEvent>> {
        async { ci_landing::list_ci_run_checks(&self.pool, community_id, channel_id, run_id).await }
            .await
    }
    /// Restored fork CI persistence operation.
    pub async fn list_ci_run_events(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        run_id: Uuid,
        after_cursor: i64,
        limit: u32,
    ) -> Result<Vec<ci::CiStoredEvent>> {
        async {
            ci::list_ci_run_events(
                &self.pool,
                community_id,
                channel_id,
                run_id,
                after_cursor,
                limit,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn list_ci_runs_for_tip(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        target_repo_a: &str,
        tip_oid: &str,
        workflow_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ci_landing::CiRunRecord>> {
        async {
            ci_landing::list_ci_runs_for_tip(
                &self.pool,
                community_id,
                channel_id,
                target_repo_a,
                tip_oid,
                workflow_id,
                limit,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn list_merge_gate_decisions(
        &self,
        community_id: CommunityId,
        target_repo_a: &str,
        ref_name: &str,
        new_oid: &str,
        old_oid: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ci_landing::MergeGateDecisionRecord>> {
        async {
            ci_landing::list_merge_gate_decisions(
                &self.pool,
                community_id,
                target_repo_a,
                ref_name,
                new_oid,
                old_oid,
                limit,
            )
            .await
        }
        .await
    }
    /// Restored fork CI persistence operation.
    pub async fn load_ci_check(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
        check_event_id: &[u8],
    ) -> Result<Option<ci::CiStoredEvent>> {
        async { ci::load_ci_check(&self.pool, community_id, run_id, check_event_id).await }.await
    }
    /// Restored fork CI persistence operation.
    pub async fn store_ci_event(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        event: &nostr::Event,
        envelope: &buzz_core::ci::ValidatedCiEnvelope,
    ) -> Result<ci::StoreCiEventOutcome> {
        async { ci::store_ci_event(&self.pool, community_id, channel_id, event, envelope).await }
            .await
    }
    /// Restored fork CI persistence operation.
    pub async fn upsert_ci_grant(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        target_repo_a: &str,
        signer_pubkey: &str,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        granted_by: &str,
    ) -> Result<()> {
        async {
            ci_grants::upsert_ci_grant(
                &self.pool,
                community_id,
                channel_id,
                target_repo_a,
                signer_pubkey,
                valid_from,
                valid_until,
                granted_by,
            )
            .await
        }
        .await
    }
}
