//! Merge gate tests: pure rules without a database (`unit`), and the git
//! transport harness of design section 5 (`harness`, Postgres + MinIO +
//! git, `#[ignore]`).

use super::*;
use buzz_core::ci::{
    CiConcurrencyGroup, CiEvidenceFinalizedEnvelope, CiFinalizedJobAttempt, CiJobStatusEnvelope,
    CiLogReferenceEnvelope, CiRequestType, CiRunStatusEnvelope, CiSkipPolicy,
    CiTeardownAttestationEnvelope, CiTeardownLease, CI_SCHEMA_VERSION,
};

const SIGNER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// A synthetic run history over `jobs` for one attempt, mirroring the
/// reducer's own `green_events` fixture but parameterized by job set and
/// terminal outcome. Event ids are `format!("{n:064x}")`.
mod synthetic {
    use super::*;

    pub(super) fn id(value: u64) -> String {
        format!("{value:064x}")
    }

    pub(super) fn request(
        jobs: &[&str],
        candidate: &str,
        base: &str,
        digest: &str,
    ) -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            pr_root_event_id: "1".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/buzz.git".into(),
            immutable_source_ref: "refs/buzz/pr/1".into(),
            tip_oid: candidate.into(),
            source_branch: "feature".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: base.into(),
            workflow_id: "ci".into(),
            workflow_digest: digest.into(),
            job_ids: jobs.iter().map(|j| (*j).to_string()).collect(),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "1".repeat(64),
            actor: "f".repeat(64),
            timeout_seconds: 600,
            idempotency_key: "idempotency".into(),
            issued_at: 1,
            expires_at: 601,
        }
    }

    /// Terminal outcome of the synthetic run.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Outcome {
        /// Every job succeeds, terminal facts and a success check follow.
        Green,
        /// Every job succeeds but no check is accepted yet.
        GreenNoCheck,
        /// The last job fails; run status failure and a failure check follow.
        Red,
        /// The last job never reaches a terminal state.
        Pending,
    }

    pub(super) struct History {
        pub(super) request_event_id: String,
        pub(super) request: CiRequestEnvelope,
        pub(super) events: Vec<AcceptedCiEnvelope>,
        pub(super) check_event_id: Option<String>,
    }

    pub(super) fn history(
        jobs: &[&str],
        candidate: &str,
        base: &str,
        digest: &str,
        outcome: Outcome,
    ) -> History {
        let request = request(jobs, candidate, base, digest);
        let request_event_id = id(1);
        // The request itself carries the fixed request id at cursor 1.
        let mut events = vec![AcceptedCiEnvelope {
            event_id: request_event_id.clone(),
            watch_cursor: 1,
            envelope: ValidatedCiEnvelope::Request(request.clone()),
        }];
        let push = |events: &mut Vec<AcceptedCiEnvelope>, envelope: ValidatedCiEnvelope| {
            let cursor = events.len() as u64 + 1;
            let event_id = id(100 + cursor);
            events.push(AcceptedCiEnvelope {
                event_id: event_id.clone(),
                watch_cursor: cursor,
                envelope,
            });
            event_id
        };

        let run_status = |sequence: u64, state: CiRunState| CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_event_id.clone(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            attempt: 1,
            sequence,
            state,
            conclusion: state.is_terminal().then(|| format!("{state:?}")),
            reason: None,
            started_at: (state != CiRunState::Queued).then_some(10),
            finished_at: state.is_terminal().then_some(40),
            job_ids: request.job_ids.clone(),
            relay_signer: SIGNER.into(),
        };
        let job_status =
            |job_id: &str, sequence: u64, state: CiJobState, log_ref: Option<String>| {
                CiJobStatusEnvelope {
                    schema_version: CI_SCHEMA_VERSION,
                    request_event_id: request_event_id.clone(),
                    run_id: request.run_id.clone(),
                    workflow_id: request.workflow_id.clone(),
                    target_repo_a: request.target_repo_a.clone(),
                    tip_oid: request.tip_oid.clone(),
                    base_oid: request.base_oid.clone(),
                    job_id: job_id.into(),
                    name: job_id.into(),
                    attempt: 1,
                    parent_attempt: None,
                    sequence,
                    state,
                    conclusion: state.is_terminal().then(|| format!("{state:?}")),
                    reason: None,
                    required: true,
                    skip_policy: CiSkipPolicy::Forbid,
                    selected_job_instance: job_id.into(),
                    also_reruns: Vec::new(),
                    started_at: (state != CiJobState::Queued).then_some(10),
                    finished_at: state.is_terminal().then_some(20),
                    log_ref,
                    artifact_refs: Vec::new(),
                    relay_signer: SIGNER.into(),
                }
            };

        push(
            &mut events,
            ValidatedCiEnvelope::RunStatus(run_status(1, CiRunState::Queued)),
        );
        push(
            &mut events,
            ValidatedCiEnvelope::RunStatus(run_status(2, CiRunState::Running)),
        );

        // Log references are pushed after the job streams (like the reducer
        // fixture); their ids are pre-assigned so job statuses can name them.
        let log_ids: Vec<String> = (0..jobs.len()).map(|i| id(50 + i as u64)).collect();
        let last = jobs.len() - 1;
        for (index, job_id) in jobs.iter().enumerate() {
            push(
                &mut events,
                ValidatedCiEnvelope::JobStatus(job_status(job_id, 1, CiJobState::Queued, None)),
            );
            push(
                &mut events,
                ValidatedCiEnvelope::JobStatus(job_status(job_id, 2, CiJobState::Running, None)),
            );
            let terminal = match outcome {
                Outcome::Red if index == last => Some(CiJobState::Failure),
                Outcome::Pending if index == last => None,
                _ => Some(CiJobState::Success),
            };
            if let Some(state) = terminal {
                push(
                    &mut events,
                    ValidatedCiEnvelope::JobStatus(job_status(
                        job_id,
                        3,
                        state,
                        Some(log_ids[index].clone()),
                    )),
                );
            }
        }
        for (index, job_id) in jobs.iter().enumerate() {
            if outcome == Outcome::Pending && index == last {
                continue;
            }
            push(
                &mut events,
                ValidatedCiEnvelope::LogReference(CiLogReferenceEnvelope {
                    schema_version: CI_SCHEMA_VERSION,
                    request_event_id: request_event_id.clone(),
                    run_id: request.run_id.clone(),
                    workflow_id: request.workflow_id.clone(),
                    target_repo_a: request.target_repo_a.clone(),
                    tip_oid: request.tip_oid.clone(),
                    job_id: (*job_id).into(),
                    attempt: 1,
                    log_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .into(),
                    byte_length: 0,
                    cap_bytes: 1024,
                    truncated: false,
                    url: None,
                    inline: Some(String::new()),
                    created_at: 21,
                    relay_signer: SIGNER.into(),
                }),
            );
            let n = events.len() - 1;
            events[n].event_id = log_ids[index].clone();
        }

        let mut check_event_id = None;
        match outcome {
            Outcome::Pending => {}
            Outcome::Red => {
                let terminal_id = push(
                    &mut events,
                    ValidatedCiEnvelope::RunStatus(run_status(3, CiRunState::Failure)),
                );
                let check = CiCheckEnvelope {
                    schema_version: CI_SCHEMA_VERSION,
                    request_event_id: request_event_id.clone(),
                    run_id: request.run_id.clone(),
                    workflow_id: request.workflow_id.clone(),
                    target_repo_a: request.target_repo_a.clone(),
                    tip_oid: request.tip_oid.clone(),
                    base_oid: request.base_oid.clone(),
                    attempt: 1,
                    conclusion: CiRunState::Failure,
                    reason: None,
                    run_status_event_id: terminal_id,
                    evidence_finalized_event_id: None,
                    teardown_attestation_event_id: None,
                    concurrency_group: CiConcurrencyGroup::of(&request).key,
                    published_at: 32,
                    relay_signer: SIGNER.into(),
                };
                check_event_id = Some(push(&mut events, ValidatedCiEnvelope::Check(check)));
            }
            Outcome::Green | Outcome::GreenNoCheck => {
                let evidence_id = push(
                    &mut events,
                    ValidatedCiEnvelope::EvidenceFinalized(CiEvidenceFinalizedEnvelope {
                        schema_version: CI_SCHEMA_VERSION,
                        request_event_id: request_event_id.clone(),
                        run_id: request.run_id.clone(),
                        workflow_id: request.workflow_id.clone(),
                        target_repo_a: request.target_repo_a.clone(),
                        tip_oid: request.tip_oid.clone(),
                        attempt: 1,
                        finalized_job_attempts: jobs
                            .iter()
                            .enumerate()
                            .map(|(index, job_id)| CiFinalizedJobAttempt {
                                job_id: (*job_id).into(),
                                attempt: 1,
                                log_ref: log_ids[index].clone(),
                                artifact_refs: Vec::new(),
                            })
                            .collect(),
                        finalized_at: 30,
                        relay_signer: SIGNER.into(),
                    }),
                );
                let teardown_id = push(
                    &mut events,
                    ValidatedCiEnvelope::TeardownAttestation(CiTeardownAttestationEnvelope {
                        schema_version: CI_SCHEMA_VERSION,
                        request_event_id: request_event_id.clone(),
                        run_id: request.run_id.clone(),
                        workflow_id: request.workflow_id.clone(),
                        target_repo_a: request.target_repo_a.clone(),
                        tip_oid: request.tip_oid.clone(),
                        base_oid: request.base_oid.clone(),
                        workflow_digest: request.workflow_digest.clone(),
                        attempt: 1,
                        leases: jobs
                            .iter()
                            .map(|job_id| CiTeardownLease {
                                job_id: (*job_id).into(),
                                attempt: 1,
                                lease_id: format!("lease-{job_id}"),
                            })
                            .collect(),
                        lease_empty: true,
                        teardown_at: 31,
                        relay_signer: SIGNER.into(),
                    }),
                );
                let terminal_id = push(
                    &mut events,
                    ValidatedCiEnvelope::RunStatus(run_status(3, CiRunState::Success)),
                );
                if outcome == Outcome::Green {
                    let check = CiCheckEnvelope {
                        schema_version: CI_SCHEMA_VERSION,
                        request_event_id: request_event_id.clone(),
                        run_id: request.run_id.clone(),
                        workflow_id: request.workflow_id.clone(),
                        target_repo_a: request.target_repo_a.clone(),
                        tip_oid: request.tip_oid.clone(),
                        base_oid: request.base_oid.clone(),
                        attempt: 1,
                        conclusion: CiRunState::Success,
                        reason: None,
                        run_status_event_id: terminal_id,
                        evidence_finalized_event_id: Some(evidence_id),
                        teardown_attestation_event_id: Some(teardown_id),
                        concurrency_group: CiConcurrencyGroup::of(&request).key,
                        published_at: 32,
                        relay_signer: SIGNER.into(),
                    };
                    check_event_id = Some(push(&mut events, ValidatedCiEnvelope::Check(check)));
                }
            }
        }
        History {
            request_event_id,
            request,
            events,
            check_event_id,
        }
    }

    pub(super) fn loaded(history: &History, base: &str, digest: &str) -> LoadedRun {
        LoadedRun {
            run_id: Uuid::parse_str(&history.request.run_id).expect("run id"),
            base_oid: base.into(),
            workflow_digest: digest.into(),
            request_event_id: history.request_event_id.clone(),
            request: history.request.clone(),
            events: history.events.clone(),
        }
    }
}

mod unit {
    use super::synthetic::{self, Outcome};
    use super::*;

    const CANDIDATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BASE: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const DIGEST: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn update(
        parents: &[&str],
        tree: &str,
        parent_trees: &[&str],
        is_ancestor: bool,
        second: bool,
    ) -> HookRefUpdate {
        HookRefUpdate {
            old_oid: BASE.into(),
            new_oid: "1".repeat(40),
            ref_name: "refs/heads/main".into(),
            is_ancestor,
            parents: parents.iter().map(|p| (*p).to_string()).collect(),
            tree: tree.into(),
            parent_trees: parent_trees.iter().map(|t| (*t).to_string()).collect(),
            old_in_second_parent: second,
        }
    }

    fn pinned(jobs: &[&str]) -> BTreeSet<String> {
        jobs.iter().map(|j| (*j).to_string()).collect()
    }

    #[test]
    fn fast_forward_candidate_is_new_oid() {
        let ff = update(
            &[BASE],
            &"3".repeat(40),
            &["4".repeat(40).as_str()],
            true,
            false,
        );
        assert_eq!(
            classify_update(&ff),
            Ok((Classification::FastForward, "1".repeat(40)))
        );
    }

    #[test]
    fn two_parent_merge_candidate_is_second_parent() {
        let tree = "3".repeat(40);
        let merge = update(
            &[BASE, CANDIDATE],
            &tree,
            &["4".repeat(40).as_str(), tree.as_str()],
            true,
            true,
        );
        assert_eq!(
            classify_update(&merge),
            Ok((Classification::Merge, CANDIDATE.into()))
        );
    }

    #[test]
    fn three_parents_wrong_first_parent_and_empty_facts_are_parent_shape() {
        let tree = "3".repeat(40);
        let octopus = update(&[BASE, CANDIDATE, &"9".repeat(40)], &tree, &[], true, false);
        assert_eq!(
            classify_update(&octopus).unwrap_err().code,
            RefusalCode::ParentShape
        );

        let wrong_first = update(
            &[CANDIDATE, BASE],
            &tree,
            &[tree.as_str(), "4".repeat(40).as_str()],
            true,
            true,
        );
        assert_eq!(
            classify_update(&wrong_first).unwrap_err().code,
            RefusalCode::ParentShape
        );

        let wrong_single = update(&[CANDIDATE], &tree, &[tree.as_str()], false, false);
        assert_eq!(
            classify_update(&wrong_single).unwrap_err().code,
            RefusalCode::ParentShape
        );

        let tag_or_missing = update(&[], "", &[], true, false);
        assert_eq!(
            classify_update(&tag_or_missing).unwrap_err().code,
            RefusalCode::ParentShape
        );
    }

    #[test]
    fn merge_without_base_in_candidate_is_not_descendant() {
        let tree = "3".repeat(40);
        let merge = update(
            &[BASE, CANDIDATE],
            &tree,
            &["4".repeat(40).as_str(), tree.as_str()],
            true,
            false,
        );
        assert_eq!(
            classify_update(&merge).unwrap_err().code,
            RefusalCode::NotDescendant
        );
    }

    #[test]
    fn merge_with_a_different_tree_is_tree_mismatch() {
        let merge = update(
            &[BASE, CANDIDATE],
            &"3".repeat(40),
            &["4".repeat(40).as_str(), "5".repeat(40).as_str()],
            true,
            true,
        );
        assert_eq!(
            classify_update(&merge).unwrap_err().code,
            RefusalCode::TreeMismatch
        );
    }

    #[test]
    fn green_run_over_the_pinned_jobs_passes_history_checks() {
        let history =
            synthetic::history(&["lint", "unit"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        let run = synthetic::loaded(&history, BASE, DIGEST);
        let reduction =
            evaluate_run_history(&pinned(&["lint", "unit"]), CANDIDATE, BASE, DIGEST, &run)
                .expect("green");
        assert_eq!(reduction.state, CiReducedState::Green);
        assert_eq!(
            reduction.check.map(|c| c.event_id),
            history.check_event_id,
            "the selected check is the accepted success check"
        );
    }

    #[test]
    fn green_run_over_a_subset_of_pinned_jobs_is_required_jobs_missing() {
        let history = synthetic::history(&["lint"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        let run = synthetic::loaded(&history, BASE, DIGEST);
        let refusal =
            evaluate_run_history(&pinned(&["lint", "unit"]), CANDIDATE, BASE, DIGEST, &run)
                .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::RequiredJobsMissing);
        assert!(refusal.detail.contains("\"unit\""), "{}", refusal.detail);
    }

    #[test]
    fn run_against_another_base_is_base_moved() {
        let history = synthetic::history(&["lint"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        let run = synthetic::loaded(&history, BASE, DIGEST);
        let moved = "9".repeat(40);
        let refusal =
            evaluate_run_history(&pinned(&["lint"]), CANDIDATE, &moved, DIGEST, &run).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::BaseMoved);
    }

    #[test]
    fn run_with_another_workflow_digest_is_workflow_digest_mismatch() {
        let history = synthetic::history(&["lint"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        let run = synthetic::loaded(&history, BASE, &"f".repeat(64));
        let refusal =
            evaluate_run_history(&pinned(&["lint"]), CANDIDATE, BASE, DIGEST, &run).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::WorkflowDigestMismatch);
    }

    #[test]
    fn pending_red_and_missing_check_map_to_their_codes() {
        for (outcome, code) in [
            (Outcome::Pending, RefusalCode::CheckPending),
            (Outcome::Red, RefusalCode::CheckNotSuccess),
            (Outcome::GreenNoCheck, RefusalCode::NoCheck),
        ] {
            let history = synthetic::history(&["lint", "unit"], CANDIDATE, BASE, DIGEST, outcome);
            let run = synthetic::loaded(&history, BASE, DIGEST);
            let refusal =
                evaluate_run_history(&pinned(&["lint", "unit"]), CANDIDATE, BASE, DIGEST, &run)
                    .unwrap_err();
            assert_eq!(refusal.code, code, "{}", refusal.detail);
        }
    }

    #[test]
    fn inconsistent_history_is_reducer_disagrees() {
        let history = synthetic::history(&["lint"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        let mut run = synthetic::loaded(&history, BASE, DIGEST);
        // Duplicate the last cursor: the reducer refuses the history.
        let last = run.events.len() - 1;
        run.events[last].watch_cursor = run.events[last - 1].watch_cursor;
        let refusal =
            evaluate_run_history(&pinned(&["lint"]), CANDIDATE, BASE, DIGEST, &run).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::ReducerDisagrees);
    }

    fn success_check() -> CiCheckEnvelope {
        let history = synthetic::history(&["lint"], CANDIDATE, BASE, DIGEST, Outcome::Green);
        history
            .events
            .iter()
            .find_map(|event| match &event.envelope {
                ValidatedCiEnvelope::Check(check) => Some(check.clone()),
                _ => None,
            })
            .expect("check")
    }

    fn union() -> HashSet<String> {
        HashSet::from([SIGNER.to_string()])
    }

    #[test]
    fn fresh_bound_check_from_the_union_verifies() {
        let now = Utc::now();
        assert_eq!(
            verify_check(
                &success_check(),
                &synthetic::id(9),
                SIGNER,
                now,
                now,
                86_400,
                CANDIDATE,
                BASE,
                &union()
            ),
            Ok(())
        );
    }

    #[test]
    fn check_older_than_the_window_by_accepted_at_is_expired_even_with_a_later_published_at() {
        let now = Utc::now();
        let mut check = success_check();
        check.published_at = u64::try_from(now.timestamp()).unwrap() + 3_600; // signer-chosen, ignored
        let accepted = now - chrono::Duration::seconds(86_401);
        let refusal = verify_check(
            &check,
            &synthetic::id(9),
            SIGNER,
            accepted,
            now,
            86_400,
            CANDIDATE,
            BASE,
            &union(),
        )
        .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::CheckExpired);
        let accepted = now - chrono::Duration::seconds(86_400);
        assert!(verify_check(
            &check,
            &synthetic::id(9),
            SIGNER,
            accepted,
            now,
            86_400,
            CANDIDATE,
            BASE,
            &union()
        )
        .is_ok());
    }

    #[test]
    fn check_signed_outside_the_union_is_signer_unauthorized() {
        let now = Utc::now();
        let other = "1".repeat(64);
        let refusal = verify_check(
            &success_check(),
            &synthetic::id(9),
            SIGNER,
            now,
            now,
            86_400,
            CANDIDATE,
            BASE,
            &HashSet::from([other.clone()]),
        )
        .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::SignerUnauthorized);
        let refusal = verify_check(
            &success_check(),
            &synthetic::id(9),
            &other,
            now,
            now,
            86_400,
            CANDIDATE,
            BASE,
            &union(),
        )
        .unwrap_err();
        assert_eq!(
            refusal.code,
            RefusalCode::SignerUnauthorized,
            "event signer must equal relay_signer"
        );
    }

    #[test]
    fn check_bound_to_another_tip_or_base_is_refused() {
        let now = Utc::now();
        let refusal = verify_check(
            &success_check(),
            &synthetic::id(9),
            SIGNER,
            now,
            now,
            86_400,
            &"7".repeat(40),
            BASE,
            &union(),
        )
        .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::ReducerDisagrees);
        let refusal = verify_check(
            &success_check(),
            &synthetic::id(9),
            SIGNER,
            now,
            now,
            86_400,
            CANDIDATE,
            &"7".repeat(40),
            &union(),
        )
        .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::BaseMoved);
        let mut failed = success_check();
        failed.conclusion = CiRunState::Failure;
        let refusal = verify_check(
            &failed,
            &synthetic::id(9),
            SIGNER,
            now,
            now,
            86_400,
            CANDIDATE,
            BASE,
            &union(),
        )
        .unwrap_err();
        assert_eq!(refusal.code, RefusalCode::CheckNotSuccess);
    }

    fn bypass(event: u8, issued_at: DateTime<Utc>, consumed: bool) -> CiMergeBypassRecord {
        CiMergeBypassRecord {
            event_id: vec![event; 32],
            channel_id: Uuid::nil(),
            issuer_pubkey: "a".repeat(64),
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            ref_name: "refs/heads/main".into(),
            old_oid: BASE.into(),
            new_oid: "1".repeat(40),
            reason: "override".into(),
            issued_at,
            expires_at: issued_at + chrono::Duration::seconds(600),
            consumed_by: consumed.then(Uuid::new_v4),
            accepted_at: issued_at,
        }
    }

    #[test]
    fn bypass_selection_requires_a_live_unconsumed_record() {
        let now = Utc::now();
        assert_eq!(select_bypass(&[], now), BypassSelection::None);

        let live = bypass(1, now - chrono::Duration::seconds(10), false);
        assert_eq!(
            select_bypass(std::slice::from_ref(&live), now),
            BypassSelection::Usable(live.clone())
        );

        let expired = bypass(2, now - chrono::Duration::seconds(700), false);
        assert_eq!(
            select_bypass(std::slice::from_ref(&expired), now),
            BypassSelection::Unusable(expired.clone())
        );

        let future = bypass(3, now + chrono::Duration::seconds(60), false);
        assert_eq!(
            select_bypass(std::slice::from_ref(&future), now),
            BypassSelection::Unusable(future.clone())
        );

        let consumed = bypass(4, now - chrono::Duration::seconds(10), true);
        assert_eq!(
            select_bypass(std::slice::from_ref(&consumed), now),
            BypassSelection::Unusable(consumed.clone())
        );

        // A consumed record does not hide a later live one.
        assert_eq!(
            select_bypass(&[consumed, live.clone()], now),
            BypassSelection::Usable(live)
        );
    }

    #[test]
    fn refusal_codes_match_the_decision_table_grammar() {
        for code in [
            RefusalCode::NoCheck,
            RefusalCode::CheckPending,
            RefusalCode::CheckNotSuccess,
            RefusalCode::ReducerDisagrees,
            RefusalCode::BaseMoved,
            RefusalCode::NotDescendant,
            RefusalCode::ParentShape,
            RefusalCode::TreeMismatch,
            RefusalCode::WorkflowDigestMismatch,
            RefusalCode::RequiredJobsMissing,
            RefusalCode::SignerUnauthorized,
            RefusalCode::CheckExpired,
            RefusalCode::BypassInvalid,
            RefusalCode::GateMisconfigured,
        ] {
            assert!(
                buzz_db::git_merge_gate::MERGE_GATE_DECISION_CODES.contains(&code.as_str()),
                "{}",
                code.as_str()
            );
        }
    }

    #[test]
    fn pusher_message_shortens_identifiers_to_twelve_hex() {
        let detail = format!(
            "run {} tested candidate {CANDIDATE} against base {BASE}.",
            "a".repeat(64)
        );
        let shortened = shorten_oids(&detail);
        assert_eq!(
            shortened,
            format!(
                "run {} tested candidate {} against base {}.",
                "a".repeat(12),
                "b".repeat(12),
                "c".repeat(12)
            )
        );
    }
}

/// Git transport harness of design section 5: a real relay listener on
/// 127.0.0.1, the git and policy routers, a real `git push` through the
/// NIP-98 credential helper, Postgres and MinIO. Run with an isolated
/// `BUZZ_TEST_DATABASE_URL` and the local MinIO from `.env.example`:
///
/// ```text
/// cargo build -p git-credential-nostr
/// BUZZ_TEST_DATABASE_URL=postgres://... cargo test -p buzz-relay --lib \
///   api::git::merge_gate::tests::harness -- --ignored --test-threads=1
/// ```
mod harness {
    use super::*;
    use crate::api::git::cas_publish::ParentState;
    use crate::api::git::hydrate::hydrate_for_write;
    use crate::api::git::policy::tests::policy_test_state_with;
    use crate::api::git::transport::{finalize_push, PackOutput, PushContext};
    use crate::api::git::{git_policy_router, git_router};
    use crate::config::{Config, MergeGateMode};
    use buzz_core::channel::MemberRole;
    use buzz_core::ci::{
        check_tags, evidence_finalized_tags, job_status_tags, log_reference_tags, request_tags,
        run_status_tags, teardown_attestation_tags, CiEvidenceFinalizedEnvelope,
        CiFinalizedJobAttempt, CiJobStatusEnvelope, CiLogReferenceEnvelope, CiMergeBypassEnvelope,
        CiRequestType, CiRunStatusEnvelope, CiSkipPolicy, CiTeardownAttestationEnvelope,
        CiTeardownLease, CI_SCHEMA_VERSION,
    };
    use buzz_core::kind::{
        KIND_CI_CHECK, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS, KIND_CI_LOG_REFERENCE,
        KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
    };
    use nostr::{Event, EventBuilder, Keys, Kind, Tag};
    use sha2::{Digest as _, Sha256};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    const PINNED: &[&str] = &["lint", "unit"];
    const RULE: &str = "require-check:ci:lint+unit";
    const WORKFLOW_V1: &str = "name: ci\non: [push]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps: []\n  unit:\n    runs-on: ubuntu-latest\n    steps: []\n";
    const WORKFLOW_V2: &str = "name: ci\non: [push]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps: []\n  unit:\n    runs-on: ubuntu-latest\n    steps: []\n  docs:\n    runs-on: ubuntu-latest\n    required: false\n    steps: []\n";
    const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";

    fn digest(bytes: &str) -> String {
        hex::encode(Sha256::digest(bytes.as_bytes()))
    }

    /// The compiled `git-credential-nostr`; built on demand when absent.
    fn credential_helper() -> PathBuf {
        if let Ok(path) = std::env::var("GIT_CREDENTIAL_NOSTR_BIN") {
            return PathBuf::from(path);
        }
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root");
        for profile in ["debug", "release"] {
            let candidate = workspace
                .join("target")
                .join(profile)
                .join("git-credential-nostr");
            if candidate.is_file() {
                return candidate;
            }
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", "git-credential-nostr"])
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo build for git-credential-nostr");
        assert!(
            status.success(),
            "cargo build -p git-credential-nostr failed"
        );
        workspace.join("target/debug/git-credential-nostr")
    }

    /// Terminal outcome of a seeded run.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Seed {
        Green,
        Pending,
    }

    struct Harness {
        state: Arc<AppState>,
        pool: sqlx::PgPool,
        _git_storage: tempfile::TempDir,
        _server: tokio::task::JoinHandle<()>,
        port: u16,
        community: CommunityId,
        tenant: TenantContext,
        channel: Uuid,
        owner: Keys,
        control: Keys,
        repo_id: String,
        coordinate: String,
        clone: tempfile::TempDir,
        helper: PathBuf,
    }

    impl Harness {
        async fn start(configure: impl FnOnce(&mut Config)) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let port = listener.local_addr().expect("addr").port();
            let control = Keys::generate();
            let control_hex = control.public_key().to_hex();
            let (state, git_storage, pool) = policy_test_state_with(|config| {
                config.bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
                config.relay_url = format!("ws://127.0.0.1:{port}");
                config.ci_status_signer_pubkeys = HashSet::from([control_hex.clone()]);
                configure(config);
            })
            .await;
            buzz_db::migration::run_migrations(&pool)
                .await
                .expect("apply migrations");
            let app = git_router(state.clone()).merge(git_policy_router(state.clone()));
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .expect("serve git routers");
            });

            let host = format!("127.0.0.1:{port}");
            let community = state
                .db
                .ensure_configured_community(&host)
                .await
                .expect("community")
                .id;
            let tenant = TenantContext::resolved(community, host);

            let owner = Keys::generate();
            let creator = Keys::generate();
            let creator_pk = creator.public_key().to_bytes().to_vec();
            let owner_pk = owner.public_key().to_bytes().to_vec();
            state
                .db
                .ensure_user(community, &creator_pk)
                .await
                .expect("creator");
            state
                .db
                .ensure_user(community, &owner_pk)
                .await
                .expect("owner");
            let channel = Uuid::new_v4();
            state
                .db
                .create_channel_with_id(
                    community,
                    channel,
                    &format!("merge-gate-{}", channel.simple()),
                    buzz_db::channel::ChannelType::Stream,
                    buzz_db::channel::ChannelVisibility::Open,
                    None,
                    &creator_pk,
                    None,
                )
                .await
                .expect("channel");
            state
                .db
                .add_member(
                    community,
                    channel,
                    &owner_pk,
                    MemberRole::Member,
                    Some(&creator_pk),
                )
                .await
                .expect("owner membership");

            let repo_id = format!("gate-{}", Uuid::new_v4().simple());
            let announcement = EventBuilder::new(Kind::Custom(30617), "")
                .tags(vec![
                    Tag::parse(["d", &repo_id]).unwrap(),
                    Tag::parse(["buzz-channel", &channel.to_string()]).unwrap(),
                    Tag::parse(["buzz-protect", "refs/heads/main", RULE]).unwrap(),
                ])
                .sign_with_keys(&owner)
                .expect("sign 30617");
            state
                .db
                .insert_event(community, &announcement, None)
                .await
                .expect("insert 30617");
            let owner_hex = owner.public_key().to_hex();
            crate::handlers::side_effects::seed_manifest_pointer(
                &state, &tenant, &owner_hex, &repo_id,
            )
            .await
            .expect("seed empty pointer");

            let coordinate = format!("30617:{owner_hex}:{repo_id}");
            let clone = tempfile::tempdir().expect("clone dir");
            let harness = Self {
                state,
                pool,
                _git_storage: git_storage,
                _server: server,
                port,
                community,
                tenant,
                channel,
                owner,
                control,
                repo_id,
                coordinate,
                clone,
                helper: credential_helper(),
            };
            harness.git_ok(&["init", "-q", "-b", "main"]);
            harness.git_ok(&["remote", "add", "origin", &harness.url()]);
            harness.commit_file(WORKFLOW_PATH, WORKFLOW_V1, "ci workflow");
            harness
                .push("main:refs/heads/main")
                .expect("initial push creates main");
            harness
        }

        fn url(&self) -> String {
            format!(
                "http://127.0.0.1:{}/git/{}/{}",
                self.port,
                self.owner.public_key().to_hex(),
                self.repo_id
            )
        }

        fn owner_hex(&self) -> String {
            self.owner.public_key().to_hex()
        }

        fn git(&self, args: &[&str]) -> Output {
            Command::new("git")
                .args([
                    "-c",
                    "credential.useHttpPath=true",
                    "-c",
                    &format!("credential.helper={}", self.helper.display()),
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "tag.gpgsign=false",
                    "-c",
                    "user.name=Gate",
                    "-c",
                    "user.email=gate@example.com",
                    "-c",
                    "protocol.file.allow=always",
                ])
                .args(args)
                .current_dir(self.clone.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env_remove("GIT_CONFIG_COUNT")
                .env("NOSTR_PRIVATE_KEY", self.owner.secret_key().to_secret_hex())
                .output()
                .expect("spawn git")
        }

        fn git_ok(&self, args: &[&str]) -> String {
            let out = self.git(args);
            assert!(
                out.status.success(),
                "git {args:?} failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        /// `git push origin <refspec>`; `Err` carries stderr so callers can
        /// assert the refusal code the pusher sees.
        fn push(&self, refspec: &str) -> Result<(), String> {
            let out = self.git(&["push", "origin", refspec]);
            if out.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ))
            }
        }

        fn rev_parse(&self, spec: &str) -> String {
            self.git_ok(&["rev-parse", "--verify", spec])
        }

        /// Commit `content` at `path` on the current HEAD; returns the new OID.
        fn commit_file(&self, path: &str, content: &str, message: &str) -> String {
            let full = self.clone.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, content).unwrap();
            self.git_ok(&["add", "-A"]);
            self.git_ok(&["commit", "-q", "--allow-empty", "-m", message]);
            self.rev_parse("HEAD")
        }

        /// A candidate commit on top of `base` touching `path`.
        fn candidate(&self, base: &str, path: &str, content: &str, message: &str) -> String {
            self.git_ok(&["checkout", "-q", "--detach", base]);
            self.commit_file(path, content, message)
        }

        /// A commit with `tree` and `parents`, made with `git commit-tree`.
        fn commit_tree(&self, tree: &str, parents: &[&str], message: &str) -> String {
            let mut args = vec!["commit-tree", tree, "-m", message];
            for parent in parents {
                args.push("-p");
                args.push(parent);
            }
            self.git_ok(&args)
        }

        fn main_oid_on_relay(&self) -> String {
            self.git_ok(&["ls-remote", "origin", "refs/heads/main"])
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        }

        async fn decisions(&self) -> Vec<(String, String, Option<Vec<u8>>, Uuid)> {
            use sqlx::Row as _;
            sqlx::query(
                "SELECT code, classification, bypass_event_id, id FROM git_merge_gate_decisions \
                 WHERE community_id = $1 ORDER BY decided_at",
            )
            .bind(self.community.as_uuid())
            .fetch_all(&self.pool)
            .await
            .expect("decisions")
            .into_iter()
            .map(|row| {
                (
                    row.get::<String, _>("code"),
                    row.get::<String, _>("classification"),
                    row.get::<Option<Vec<u8>>, _>("bypass_event_id"),
                    row.get::<Uuid, _>("id"),
                )
            })
            .collect()
        }

        async fn last_decision(&self) -> (String, String, Option<Vec<u8>>, Uuid) {
            self.decisions()
                .await
                .pop()
                .expect("a decision was recorded")
        }

        fn sign(&self, kind: u32, content: &str, tags: Vec<Tag>, keys: &Keys) -> Event {
            EventBuilder::new(Kind::Custom(kind as u16), content)
                .tags(tags)
                .sign_with_keys(keys)
                .expect("sign CI event")
        }

        async fn store(&self, event: &Event, authorized: &HashSet<String>) {
            let validated = validate_signed_ci_event(event, &self.channel.to_string(), authorized)
                .expect("validate CI event");
            self.state
                .db
                .store_ci_event(self.community, self.channel, event, &validated)
                .await
                .expect("store CI event");
        }

        /// Seed one run over `jobs` for `candidate` against `base` with the
        /// given workflow digest, signed by the harness control key, and
        /// return `(run_id, check event id)`.
        async fn seed_run(
            &self,
            jobs: &[&str],
            candidate: &str,
            base: &str,
            workflow_digest: &str,
            seed: Seed,
        ) -> (Uuid, Option<Vec<u8>>) {
            let channel = self.channel.to_string();
            let authorized = HashSet::from([self.control.public_key().to_hex()]);
            let signer = self.control.public_key().to_hex();
            let run_id = Uuid::new_v4();
            let request = CiRequestEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_type: CiRequestType::Run,
                target_repo_a: self.coordinate.clone(),
                pr_root_event_id: "11".repeat(32),
                pr_update_event_id: None,
                source_clone_url: self.url(),
                immutable_source_ref: "refs/buzz/objects/candidate".into(),
                tip_oid: candidate.into(),
                source_branch: "candidate".into(),
                base_ref: "refs/heads/main".into(),
                base_oid: base.into(),
                workflow_id: "ci".into(),
                workflow_digest: workflow_digest.into(),
                job_ids: jobs.iter().map(|j| (*j).to_string()).collect(),
                run_id: run_id.to_string(),
                attempt: 1,
                parent_attempt: None,
                parent_run_id: None,
                trigger_event_id: "11".repeat(32),
                actor: self.owner_hex(),
                timeout_seconds: 300,
                idempotency_key: Uuid::new_v4().to_string(),
                issued_at: 1_800_000_000,
                expires_at: 1_800_000_600,
            };
            let request_event = self.sign(
                KIND_CI_REQUEST,
                &serde_json::to_string(&request).unwrap(),
                request_tags(&channel, &request).expect("request tags"),
                &self.owner,
            );
            self.store(&request_event, &authorized).await;
            let request_event_id = request_event.id.to_hex();

            let run_status = |sequence: u64, state: CiRunState| CiRunStatusEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: request_event_id.clone(),
                run_id: request.run_id.clone(),
                workflow_id: request.workflow_id.clone(),
                target_repo_a: request.target_repo_a.clone(),
                tip_oid: request.tip_oid.clone(),
                base_oid: request.base_oid.clone(),
                attempt: 1,
                sequence,
                state,
                conclusion: state
                    .is_terminal()
                    .then(|| format!("{state:?}").to_lowercase()),
                reason: None,
                started_at: (state != CiRunState::Queued).then_some(1_800_000_010),
                finished_at: state.is_terminal().then_some(1_800_000_040),
                job_ids: request.job_ids.clone(),
                relay_signer: signer.clone(),
            };
            for (sequence, state) in [(1, CiRunState::Queued), (2, CiRunState::Running)] {
                let envelope = run_status(sequence, state);
                let event = self.sign(
                    KIND_CI_RUN_STATUS,
                    &serde_json::to_string(&envelope).unwrap(),
                    run_status_tags(&channel, &envelope).expect("run status tags"),
                    &self.control,
                );
                self.store(&event, &authorized).await;
            }

            let job_status =
                |job_id: &str, sequence: u64, state: CiJobState, log_ref: Option<String>| {
                    CiJobStatusEnvelope {
                        schema_version: CI_SCHEMA_VERSION,
                        request_event_id: request_event_id.clone(),
                        run_id: request.run_id.clone(),
                        workflow_id: request.workflow_id.clone(),
                        target_repo_a: request.target_repo_a.clone(),
                        tip_oid: request.tip_oid.clone(),
                        base_oid: request.base_oid.clone(),
                        job_id: job_id.into(),
                        name: job_id.into(),
                        attempt: 1,
                        parent_attempt: None,
                        sequence,
                        state,
                        conclusion: state.is_terminal().then(|| "success".to_string()),
                        reason: None,
                        required: true,
                        skip_policy: CiSkipPolicy::Forbid,
                        selected_job_instance: job_id.into(),
                        also_reruns: Vec::new(),
                        started_at: (state != CiJobState::Queued).then_some(1_800_000_010),
                        finished_at: state.is_terminal().then_some(1_800_000_020),
                        log_ref,
                        artifact_refs: Vec::new(),
                        relay_signer: signer.clone(),
                    }
                };
            let mut logs = Vec::new();
            let last = jobs.len() - 1;
            for (index, job_id) in jobs.iter().enumerate() {
                for (sequence, state) in [(1, CiJobState::Queued), (2, CiJobState::Running)] {
                    let envelope = job_status(job_id, sequence, state, None);
                    let event = self.sign(
                        KIND_CI_JOB_STATUS,
                        &serde_json::to_string(&envelope).unwrap(),
                        job_status_tags(&channel, &envelope).expect("job status tags"),
                        &self.control,
                    );
                    self.store(&event, &authorized).await;
                }
                if seed == Seed::Pending && index == last {
                    continue;
                }
                let log = CiLogReferenceEnvelope {
                    schema_version: CI_SCHEMA_VERSION,
                    request_event_id: request_event_id.clone(),
                    run_id: request.run_id.clone(),
                    workflow_id: request.workflow_id.clone(),
                    target_repo_a: request.target_repo_a.clone(),
                    tip_oid: request.tip_oid.clone(),
                    job_id: (*job_id).into(),
                    attempt: 1,
                    log_sha256: "55".repeat(32),
                    byte_length: 3,
                    cap_bytes: 1024,
                    truncated: false,
                    url: Some("https://example.com/log".into()),
                    inline: None,
                    created_at: 1_800_000_020,
                    relay_signer: signer.clone(),
                };
                let log_event = self.sign(
                    KIND_CI_LOG_REFERENCE,
                    &serde_json::to_string(&log).unwrap(),
                    log_reference_tags(&channel, &log).expect("log tags"),
                    &self.control,
                );
                self.store(&log_event, &authorized).await;
                let terminal =
                    job_status(job_id, 3, CiJobState::Success, Some(log_event.id.to_hex()));
                let event = self.sign(
                    KIND_CI_JOB_STATUS,
                    &serde_json::to_string(&terminal).unwrap(),
                    job_status_tags(&channel, &terminal).expect("job status tags"),
                    &self.control,
                );
                self.store(&event, &authorized).await;
                logs.push(((*job_id).to_string(), log_event.id.to_hex()));
            }
            if seed == Seed::Pending {
                return (run_id, None);
            }

            let evidence = CiEvidenceFinalizedEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: request_event_id.clone(),
                run_id: request.run_id.clone(),
                workflow_id: request.workflow_id.clone(),
                target_repo_a: request.target_repo_a.clone(),
                tip_oid: request.tip_oid.clone(),
                attempt: 1,
                finalized_job_attempts: logs
                    .iter()
                    .map(|(job_id, log_ref)| CiFinalizedJobAttempt {
                        job_id: job_id.clone(),
                        attempt: 1,
                        log_ref: log_ref.clone(),
                        artifact_refs: Vec::new(),
                    })
                    .collect(),
                finalized_at: 1_800_000_030,
                relay_signer: signer.clone(),
            };
            let evidence_event = self.sign(
                KIND_CI_EVIDENCE_FINALIZED,
                &serde_json::to_string(&evidence).unwrap(),
                evidence_finalized_tags(&channel, &evidence).expect("evidence tags"),
                &self.control,
            );
            self.store(&evidence_event, &authorized).await;
            let teardown = CiTeardownAttestationEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: request_event_id.clone(),
                run_id: request.run_id.clone(),
                workflow_id: request.workflow_id.clone(),
                target_repo_a: request.target_repo_a.clone(),
                tip_oid: request.tip_oid.clone(),
                base_oid: request.base_oid.clone(),
                workflow_digest: request.workflow_digest.clone(),
                attempt: 1,
                leases: jobs
                    .iter()
                    .map(|job_id| CiTeardownLease {
                        job_id: (*job_id).into(),
                        attempt: 1,
                        lease_id: Uuid::new_v4().to_string(),
                    })
                    .collect(),
                lease_empty: true,
                teardown_at: 1_800_000_035,
                relay_signer: signer.clone(),
            };
            let teardown_event = self.sign(
                KIND_CI_TEARDOWN_ATTESTATION,
                &serde_json::to_string(&teardown).unwrap(),
                teardown_attestation_tags(&channel, &teardown).expect("teardown tags"),
                &self.control,
            );
            self.store(&teardown_event, &authorized).await;
            let success = run_status(3, CiRunState::Success);
            let success_event = self.sign(
                KIND_CI_RUN_STATUS,
                &serde_json::to_string(&success).unwrap(),
                run_status_tags(&channel, &success).expect("run status tags"),
                &self.control,
            );
            self.store(&success_event, &authorized).await;
            let check = CiCheckEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: request_event_id.clone(),
                run_id: request.run_id.clone(),
                workflow_id: request.workflow_id.clone(),
                target_repo_a: request.target_repo_a.clone(),
                tip_oid: request.tip_oid.clone(),
                base_oid: request.base_oid.clone(),
                attempt: 1,
                conclusion: CiRunState::Success,
                reason: None,
                run_status_event_id: success_event.id.to_hex(),
                evidence_finalized_event_id: Some(evidence_event.id.to_hex()),
                teardown_attestation_event_id: Some(teardown_event.id.to_hex()),
                concurrency_group: CiConcurrencyGroup::of(&request).key,
                published_at: 1_800_000_050,
                relay_signer: signer.clone(),
            };
            let check_event = self.sign(
                KIND_CI_CHECK,
                &serde_json::to_string(&check).unwrap(),
                check_tags(&channel, &check).expect("check tags"),
                &self.control,
            );
            self.store(&check_event, &authorized).await;
            (run_id, Some(check_event.id.as_bytes().to_vec()))
        }

        async fn backdate_acceptance(&self, event_id: &[u8], seconds: i64) {
            sqlx::query(
                "UPDATE ci_run_events SET accepted_at = accepted_at - make_interval(secs => $3) \
                 WHERE community_id = $1 AND event_id = $2",
            )
            .bind(self.community.as_uuid())
            .bind(event_id)
            .bind(seconds as f64)
            .execute(&self.pool)
            .await
            .expect("backdate accepted_at");
        }

        async fn insert_bypass(
            &self,
            old_oid: &str,
            new_oid: &str,
            issued_at: i64,
            window: u64,
        ) -> Vec<u8> {
            let envelope = CiMergeBypassEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                target_repo_a: self.coordinate.clone(),
                ref_name: "refs/heads/main".into(),
                old_oid: old_oid.into(),
                new_oid: new_oid.into(),
                reason: "harness override".into(),
                issued_at: issued_at as u64,
                expires_at: issued_at as u64 + window,
            };
            let event_id: Vec<u8> = Uuid::new_v4()
                .as_bytes()
                .iter()
                .chain(Uuid::new_v4().as_bytes().iter())
                .copied()
                .collect();
            assert!(
                self.state
                    .db
                    .insert_ci_merge_bypass(
                        self.community,
                        self.channel,
                        &event_id,
                        &self.owner_hex(),
                        &envelope
                    )
                    .await
                    .expect("insert bypass"),
                "bypass stored"
            );
            event_id
        }

        async fn bypass_consumed_by(&self, event_id: &[u8]) -> Option<Uuid> {
            use sqlx::Row as _;
            sqlx::query("SELECT consumed_by FROM ci_merge_bypasses WHERE community_id = $1 AND event_id = $2")
                .bind(self.community.as_uuid())
                .bind(event_id)
                .fetch_one(&self.pool)
                .await
                .expect("bypass row")
                .get::<Option<Uuid>, _>("consumed_by")
        }

        /// Commit facts for `old -> new` as the hook would compute them from
        /// the clone (every object is local here).
        fn facts(&self, old_oid: &str, new_oid: &str) -> HookRefUpdate {
            let parents: Vec<String> = self
                .git_ok(&["rev-list", "--parents", "-n", "1", new_oid])
                .split_whitespace()
                .skip(1)
                .map(str::to_string)
                .collect();
            let parent_trees = if parents.len() <= 2 {
                parents
                    .iter()
                    .map(|parent| self.rev_parse(&format!("{parent}^{{tree}}")))
                    .collect()
            } else {
                Vec::new()
            };
            let is_ancestor = self
                .git(&["merge-base", "--is-ancestor", old_oid, new_oid])
                .status
                .success();
            let old_in_second_parent = parents.len() == 2
                && self
                    .git(&["merge-base", "--is-ancestor", old_oid, &parents[1]])
                    .status
                    .success();
            HookRefUpdate {
                old_oid: old_oid.into(),
                new_oid: new_oid.into(),
                ref_name: "refs/heads/main".into(),
                is_ancestor,
                parents,
                tree: self.rev_parse(&format!("{new_oid}^{{tree}}")),
                parent_trees,
                old_in_second_parent,
            }
        }

        /// Run the gate directly (no git) for one update, as the hook
        /// callback would after `evaluate_push`.
        async fn gate(&self, update: HookRefUpdate) -> Vec<Denial> {
            let rules = buzz_core::git_perms::parse_protection_tag(&["refs/heads/main", RULE])
                .expect("rule");
            evaluate_push_gate(
                &self.state,
                &GatePushContext {
                    community: self.community,
                    repo_owner: &self.owner_hex(),
                    repo_id: &self.repo_id,
                    channel_id: self.channel,
                    pusher: &self.owner_hex(),
                    rules: std::slice::from_ref(&rules),
                    ref_updates: std::slice::from_ref(&update),
                },
                tokio::time::Instant::now() + EVALUATION_TIMEOUT,
            )
            .await
        }
    }

    fn assert_refused(result: Result<(), String>, code: &str) {
        let stderr = result.expect_err("push must be refused");
        assert!(
            stderr.contains(&format!("merge gate: {code}")),
            "expected refusal {code}, got:\n{stderr}"
        );
        assert!(
            stderr.contains("pre-receive hook declined"),
            "refusal is a hook decline:\n{stderr}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres and git"]
    async fn audit_write_deadline_preserves_shadow_and_refuses_enforce() {
        for mode in [MergeGateMode::Shadow, MergeGateMode::Enforce] {
            let h = Harness::start(|config| config.ci.merge_gate.mode = mode).await;
            let base = h.main_oid_on_relay();
            let candidate = h.candidate(&base, "timeout.txt", "deadline\n", "deadline");
            h.seed_run(PINNED, &candidate, &base, &digest(WORKFLOW_V1), Seed::Green)
                .await;
            // The candidate is green, but the audit write cannot finish. Hold
            // this lock until the real hook has returned, past the gate budget.
            let mut lock = h.pool.begin().await.expect("audit lock transaction");
            sqlx::query("LOCK TABLE git_merge_gate_decisions IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *lock)
                .await
                .expect("lock audit table");
            let started = std::time::Instant::now();
            let result = h.push(&format!("{candidate}:refs/heads/main"));
            let elapsed = started.elapsed();
            lock.rollback().await.expect("release audit lock");
            assert!(
                elapsed >= EVALUATION_TIMEOUT,
                "the gate must reach its deadline"
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "hook must return before curl times out: {elapsed:?}"
            );
            if mode == MergeGateMode::Shadow {
                result.expect("shadow must allow despite a stalled audit write");
                assert_eq!(h.main_oid_on_relay(), candidate);
            } else {
                assert_refused(result, "gate_misconfigured");
                assert_eq!(h.main_oid_on_relay(), base);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres and git"]
    async fn callback_authorization_spends_gate_deadline() {
        use crate::api::git::policy::{generate_hook_hmac, hook_policy_check, HookCallbackRequest};
        use axum::{extract::State, http::StatusCode, Json};
        for mode in [MergeGateMode::Shadow, MergeGateMode::Enforce] {
            let h = Harness::start(|config| config.ci.merge_gate.mode = mode).await;
            let base = h.main_oid_on_relay();
            let candidate = h.candidate(&base, "auth.txt", "authorization\n", "authorization");
            h.seed_run(PINNED, &candidate, &base, &digest(WORKFLOW_V1), Seed::Green)
                .await;
            let mut req = HookCallbackRequest {
                repo_id: h.repo_id.clone(),
                repo_owner: h.owner_hex(),
                community_id: h.community.as_uuid().to_string(),
                pusher_pubkey: h.owner_hex(),
                ref_updates: vec![h.facts(&base, &candidate)],
                timestamp: Utc::now().timestamp() as u64,
                signature: String::new(),
            };
            req.signature = generate_hook_hmac(
                h.state.config.git_hook_hmac_secret.as_bytes(),
                &req.repo_id,
                &req.repo_owner,
                &req.community_id,
                &req.pusher_pubkey,
                &req.ref_updates,
                req.timestamp,
            );
            let mut audit_lock = h.pool.begin().await.expect("audit transaction");
            sqlx::query("LOCK TABLE git_merge_gate_decisions IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *audit_lock)
                .await
                .expect("lock audit writes");
            let mut auth_lock = h.pool.begin().await.expect("authorization transaction");
            sqlx::query("LOCK TABLE channel_members IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *auth_lock)
                .await
                .expect("lock authorization reads");
            let release_auth = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(4)).await;
                auth_lock
                    .rollback()
                    .await
                    .expect("release authorization reads");
            });
            let started = std::time::Instant::now();
            // Drive the signed callback directly so transport authorization
            // before the hook cannot consume the controlled four-second delay.
            let response = hook_policy_check(State(h.state.clone()), Json(req)).await;
            let elapsed = started.elapsed();
            audit_lock.rollback().await.expect("release audit writes");
            release_auth.await.expect("authorization release task");
            assert!(elapsed >= EVALUATION_TIMEOUT);
            assert!(
                elapsed < Duration::from_secs(8),
                "callback reset the budget after authorization: {elapsed:?}"
            );
            let (status, body) = crate::api::git::policy::tests::body_string(response).await;
            if mode == MergeGateMode::Shadow {
                assert_eq!(status, StatusCode::OK, "{body}");
                assert!(body.contains("\"allowed\":true"), "{body}");
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
                assert!(
                    body.contains("gate_misconfigured: evaluation deadline exceeded"),
                    "{body}"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres and git"]
    async fn newest_run_mismatch_supersedes_older_green() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Enforce).await;
        let base = h.main_oid_on_relay();
        let v1 = digest(WORKFLOW_V1);
        for (name, newer_base, newer_digest, code) in [
            ("base", "7".repeat(40), v1.clone(), "base_moved"),
            (
                "digest",
                base.clone(),
                "8".repeat(64),
                "workflow_digest_mismatch",
            ),
        ] {
            let candidate = h.candidate(&base, "order.txt", name, name);
            h.seed_run(PINNED, &candidate, &base, &v1, Seed::Green)
                .await;
            // Requests are accepted in separate committed transactions, so
            // the second run is newer without mutating immutable run identity.
            h.seed_run(PINNED, &candidate, &newer_base, &newer_digest, Seed::Green)
                .await;
            assert_refused(h.push(&format!("{candidate}:refs/heads/main")), code);
            assert_eq!(h.last_decision().await.0, code);
            assert_eq!(h.main_oid_on_relay(), base);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres and git"]
    async fn require_check_alone_blocks_delete_recreate() {
        // Harness announcements deliberately contain require-check alone.
        for mode in [
            MergeGateMode::Off,
            MergeGateMode::Shadow,
            MergeGateMode::Enforce,
        ] {
            let h = Harness::start(|config| config.ci.merge_gate.mode = mode).await;
            let base = h.main_oid_on_relay();
            let stderr = h
                .push(":refs/heads/main")
                .expect_err("deletion must be refused");
            assert!(
                stderr.contains("ref deletion denied: no-delete is set"),
                "{stderr}"
            );
            assert!(stderr.contains("pre-receive hook declined"), "{stderr}");
            assert_eq!(h.main_oid_on_relay(), base);
        }
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn off_mode_ignores_gated_refs() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Off).await;
        let main0 = h.main_oid_on_relay();
        let candidate = h.candidate(&main0, "a.txt", "a\n", "candidate without a run");
        h.push(&format!("{candidate}:refs/heads/main"))
            .expect("off mode ignores the rule");
        assert_eq!(h.main_oid_on_relay(), candidate);
        assert!(h.decisions().await.is_empty(), "off evaluates nothing");
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn shadow_mode_allows_and_records() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Shadow).await;
        let main0 = h.main_oid_on_relay();
        let no_run = h.candidate(&main0, "a.txt", "a\n", "no run");
        h.push(&format!("{no_run}:refs/heads/main"))
            .expect("shadow never refuses");
        let (code, classification, _, _) = h.last_decision().await;
        assert_eq!(
            (code.as_str(), classification.as_str()),
            ("no_check", "fast_forward")
        );

        let green = h.candidate(&no_run, "b.txt", "b\n", "green");
        h.seed_run(PINNED, &green, &no_run, &digest(WORKFLOW_V1), Seed::Green)
            .await;
        h.push(&format!("{green}:refs/heads/main"))
            .expect("shadow allows");
        let (code, classification, bypass, _) = h.last_decision().await;
        assert_eq!(
            (code.as_str(), classification.as_str()),
            ("allow", "fast_forward")
        );
        assert!(bypass.is_none());
        assert_eq!(h.decisions().await.len(), 2);
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn enforce_refuses_each_refusal_code() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Enforce).await;
        let main0 = h.main_oid_on_relay();
        let v1 = digest(WORKFLOW_V1);

        // Ungated run: nothing seeded.
        let no_run = h.candidate(&main0, "a.txt", "a\n", "no run");
        assert_refused(h.push(&format!("{no_run}:refs/heads/main")), "no_check");
        assert_eq!(h.last_decision().await.0, "no_check");

        // Green over a subset of the pinned jobs.
        let subset = h.candidate(&main0, "a.txt", "subset\n", "subset");
        h.seed_run(&["lint"], &subset, &main0, &v1, Seed::Green)
            .await;
        assert_refused(
            h.push(&format!("{subset}:refs/heads/main")),
            "required_jobs_missing",
        );
        assert_eq!(h.last_decision().await.0, "required_jobs_missing");

        // Green but tested against another base.
        let wrong_base = h.candidate(&main0, "a.txt", "wrong base\n", "wrong base");
        h.seed_run(PINNED, &wrong_base, &"7".repeat(40), &v1, Seed::Green)
            .await;
        assert_refused(
            h.push(&format!("{wrong_base}:refs/heads/main")),
            "base_moved",
        );
        assert_eq!(h.last_decision().await.0, "base_moved");

        // Still running.
        let pending = h.candidate(&main0, "a.txt", "pending\n", "pending");
        h.seed_run(PINNED, &pending, &main0, &v1, Seed::Pending)
            .await;
        assert_refused(
            h.push(&format!("{pending}:refs/heads/main")),
            "check_pending",
        );

        // Expired by relay accepted_at, one second past the window.
        let expired = h.candidate(&main0, "a.txt", "expired\n", "expired");
        let (_, check_id) = h.seed_run(PINNED, &expired, &main0, &v1, Seed::Green).await;
        let max_age = h.state.config.ci.merge_gate.check_max_age_seconds as i64;
        h.backdate_acceptance(&check_id.expect("check"), max_age + 1)
            .await;
        assert_refused(
            h.push(&format!("{expired}:refs/heads/main")),
            "check_expired",
        );
        assert_eq!(h.last_decision().await.0, "check_expired");

        // Land a green candidate so main moves, then build bad merges.
        let landed = h.candidate(&main0, "a.txt", "landed\n", "landed");
        h.seed_run(PINNED, &landed, &main0, &v1, Seed::Green).await;
        h.push(&format!("{landed}:refs/heads/main"))
            .expect("green lands");
        assert_eq!(h.main_oid_on_relay(), landed);

        // A candidate branched from the old main, merged with its own tree:
        // the merge cannot prove it keeps `landed`.
        let stale = h.candidate(&main0, "c.txt", "c\n", "stale candidate");
        let stale_tree = h.rev_parse(&format!("{stale}^{{tree}}"));
        let not_descendant = h.commit_tree(&stale_tree, &[&landed, &stale], "merge stale");
        assert_refused(
            h.push(&format!("{not_descendant}:refs/heads/main")),
            "not_descendant",
        );
        assert_eq!(h.last_decision().await.0, "not_descendant");

        // A candidate on top of main merged with a tree that is not its own
        // (a conflict resolution).
        let fresh = h.candidate(&landed, "d.txt", "d\n", "fresh candidate");
        let landed_tree = h.rev_parse(&format!("{landed}^{{tree}}"));
        let tree_mismatch = h.commit_tree(&landed_tree, &[&landed, &fresh], "merge with edits");
        assert_refused(
            h.push(&format!("{tree_mismatch}:refs/heads/main")),
            "tree_mismatch",
        );
        assert_eq!(h.last_decision().await.0, "tree_mismatch");

        // Nothing but the green candidate landed.
        assert_eq!(h.main_oid_on_relay(), landed);
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn enforce_refuses_a_check_signed_outside_the_union() {
        let outsider = Keys::generate().public_key().to_hex();
        let h = Harness::start(|config| {
            config.ci.merge_gate.mode = MergeGateMode::Enforce;
            config.ci_status_signer_pubkeys = HashSet::from([outsider]);
        })
        .await;
        let main0 = h.main_oid_on_relay();
        let candidate = h.candidate(&main0, "a.txt", "a\n", "signed by a revoked key");
        h.seed_run(
            PINNED,
            &candidate,
            &main0,
            &digest(WORKFLOW_V1),
            Seed::Green,
        )
        .await;
        assert_refused(
            h.push(&format!("{candidate}:refs/heads/main")),
            "signer_unauthorized",
        );
        assert_eq!(h.last_decision().await.0, "signer_unauthorized");
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn enforce_allows_a_green_run_by_fast_forward_and_by_merge() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Enforce).await;
        let main0 = h.main_oid_on_relay();
        let v1 = digest(WORKFLOW_V1);

        let ff = h.candidate(&main0, "a.txt", "a\n", "fast-forward candidate");
        h.seed_run(PINNED, &ff, &main0, &v1, Seed::Green).await;
        h.push(&format!("{ff}:refs/heads/main"))
            .expect("fast-forward lands");
        assert_eq!(h.main_oid_on_relay(), ff);
        let (code, classification, _, _) = h.last_decision().await;
        assert_eq!(
            (code.as_str(), classification.as_str()),
            ("allow", "fast_forward")
        );

        let candidate = h.candidate(&ff, "b.txt", "b\n", "merge candidate");
        h.seed_run(PINNED, &candidate, &ff, &v1, Seed::Green).await;
        let tree = h.rev_parse(&format!("{candidate}^{{tree}}"));
        let merge = h.commit_tree(&tree, &[&ff, &candidate], "Merge pull request #1");
        h.push(&format!("{merge}:refs/heads/main"))
            .expect("merge landing lands");
        assert_eq!(h.main_oid_on_relay(), merge);
        let (code, classification, _, _) = h.last_decision().await;
        assert_eq!((code.as_str(), classification.as_str()), ("allow", "merge"));
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn bypass_allows_once_and_survives_a_simulated_cas_loss() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Enforce).await;
        let main0 = h.main_oid_on_relay();
        let now = Utc::now().timestamp();

        // Finalize fence with no decision at all: refused before any CAS.
        let orphan = h.candidate(&main0, "z.txt", "z\n", "orphan");
        let (repo, parent_state) = h.hydrate_for_write().await;
        h.install_candidate(repo.path(), &orphan);
        let response = finalize_push(&h.state, h.push_context(repo, parent_state, &orphan)).await;
        let (status, body) = crate::api::git::policy::tests::body_string(response).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
        assert!(
            body.contains("gate_misconfigured") && body.contains("no allow decision"),
            "{body}"
        );
        assert_eq!(h.main_oid_on_relay(), main0);

        // A bypass lands a candidate with no run, once.
        let first = h.candidate(&main0, "a.txt", "a\n", "bypassed");
        let bypass = h.insert_bypass(&main0, &first, now - 10, 600).await;
        h.push(&format!("{first}:refs/heads/main"))
            .expect("bypass allows");
        assert_eq!(h.main_oid_on_relay(), first);
        let (code, classification, decision_bypass, decision_id) = h.last_decision().await;
        assert_eq!(
            (code.as_str(), classification.as_str()),
            ("allow", "bypass")
        );
        assert_eq!(decision_bypass.as_deref(), Some(bypass.as_slice()));
        assert_eq!(
            h.bypass_consumed_by(&bypass).await,
            Some(decision_id),
            "consumed after the CAS won"
        );

        // Reuse of the consumed bypass for the same update is bypass_invalid.
        let denials = h.gate(h.facts(&main0, &first)).await;
        assert_eq!(denials.len(), 1);
        assert!(
            denials[0].reason.starts_with("merge gate: bypass_invalid"),
            "{}",
            denials[0].reason
        );
        assert_eq!(h.last_decision().await.0, "bypass_invalid");

        // Simulated CAS loss: a workspace hydrated at `first`, then main
        // advances by another bypassed push, then the stale workspace
        // finalizes with its own allowing bypass decision.
        let stale_candidate = h.candidate(&first, "b.txt", "stale\n", "stale");
        let (repo, stale_parent) = h.hydrate_for_write().await;
        h.install_candidate(repo.path(), &stale_candidate);

        let winner = h.candidate(&first, "c.txt", "winner\n", "winner");
        let winner_bypass = h.insert_bypass(&first, &winner, now - 10, 600).await;
        h.push(&format!("{winner}:refs/heads/main"))
            .expect("winner lands");
        assert_eq!(h.main_oid_on_relay(), winner);
        assert!(h.bypass_consumed_by(&winner_bypass).await.is_some());

        let loser_bypass = h
            .insert_bypass(&first, &stale_candidate, now - 10, 600)
            .await;
        let denials = h.gate(h.facts(&first, &stale_candidate)).await;
        assert!(denials.is_empty(), "{denials:?}");
        assert_eq!(h.last_decision().await.0, "allow");
        assert!(
            h.bypass_consumed_by(&loser_bypass).await.is_none(),
            "hook time consumes nothing"
        );

        let response = finalize_push(
            &h.state,
            h.push_context(repo, stale_parent, &stale_candidate),
        )
        .await;
        let (status, body) = crate::api::git::policy::tests::body_string(response).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
        assert!(
            h.bypass_consumed_by(&loser_bypass).await.is_none(),
            "a CAS loser leaves its bypass usable"
        );
        assert_eq!(h.main_oid_on_relay(), winner);
    }

    // Multi-threaded: the test thread blocks on `git push` while the relay
    // listener must keep serving on other workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires Postgres, MinIO and git"]
    async fn candidate_editing_the_workflow_lands_and_governs_the_next_candidate() {
        let h = Harness::start(|config| config.ci.merge_gate.mode = MergeGateMode::Enforce).await;
        let main0 = h.main_oid_on_relay();
        let v1 = digest(WORKFLOW_V1);
        let v2 = digest(WORKFLOW_V2);

        // The edit is tested under the base's workflow (v1) and lands.
        let edit = h.candidate(&main0, WORKFLOW_PATH, WORKFLOW_V2, "edit ci.yml");
        h.seed_run(PINNED, &edit, &main0, &v1, Seed::Green).await;
        h.push(&format!("{edit}:refs/heads/main"))
            .expect("workflow edit lands under v1");
        assert_eq!(h.main_oid_on_relay(), edit);

        // The next candidate must be tested under v2: a v1 run is refused.
        let next = h.candidate(&edit, "a.txt", "a\n", "next candidate");
        h.seed_run(PINNED, &next, &edit, &v1, Seed::Green).await;
        assert_refused(
            h.push(&format!("{next}:refs/heads/main")),
            "workflow_digest_mismatch",
        );
        assert_eq!(h.last_decision().await.0, "workflow_digest_mismatch");

        // A newer v2 run for the same candidate decides.
        h.seed_run(PINNED, &next, &edit, &v2, Seed::Green).await;
        h.push(&format!("{next}:refs/heads/main"))
            .expect("v2 run lands");
        assert_eq!(h.main_oid_on_relay(), next);
        assert_eq!(h.last_decision().await.0, "allow");
    }

    impl Harness {
        async fn hydrate_for_write(&self) -> (HydratedRepo, ParentState) {
            hydrate_for_write(
                &self.state.git_store,
                &self.tenant,
                &self.owner_hex(),
                &self.repo_id,
                HydrationOptions {
                    pack_cache: &self.state.git_pack_cache,
                    scratch_dir: &self.state.config.git_repo_path,
                    max_pack_bytes: self.state.config.git_max_pack_bytes,
                    max_repo_bytes: self.state.config.git_max_repo_bytes,
                },
            )
            .await
            .expect("hydrate for write")
        }

        /// Bring `candidate` into the hydrated workspace and point main at it,
        /// standing in for the receive-pack subprocess.
        fn install_candidate(&self, workspace: &Path, candidate: &str) {
            let clone = self.clone.path().display().to_string();
            let out = Command::new("git")
                .args(["fetch", "-q", &clone, candidate])
                .current_dir(workspace)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git fetch into workspace");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let out = Command::new("git")
                .args(["update-ref", "refs/heads/main", candidate])
                .current_dir(workspace)
                .output()
                .expect("git update-ref");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        fn push_context(
            &self,
            repo: HydratedRepo,
            parent_state: ParentState,
            _candidate: &str,
        ) -> PushContext {
            PushContext {
                pack: PackOutput {
                    stdout: Vec::new(),
                    ok: true,
                },
                parent_state,
                owner: self.owner_hex(),
                repo: self.repo_id.clone(),
                repo_id: self.repo_id.clone(),
                pusher: self.owner.public_key(),
                tenant: self.tenant.clone(),
                repo_handle: repo,
            }
        }
    }
}
