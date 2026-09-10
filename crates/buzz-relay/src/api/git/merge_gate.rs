//! Relay merge gate (`docs/ci/BUZZ_MERGE_GATE_DESIGN.md`, section 1).
//!
//! `hook_policy_check` calls [`evaluate_push_gate`] after `evaluate_push`
//! allows a push. For every ref update whose effective `buzz-protect` rules
//! pin a `require-check`, the gate:
//!
//! 1. classifies the update from the hook's quarantine-computed commit facts
//!    (fast-forward or two-parent merge landing, [`classify_update`]);
//! 2. resolves the workflow blob at the base through the published state
//!    (`hydrate_for_read` + `resolve_workflow_at_base`);
//! 3. selects the latest `ci_runs` row for the candidate whose base and
//!    workflow digest match, reads only that run's events, validates them
//!    against the live signer union, and reduces them with
//!    `buzz_core::ci::reducer` ([`evaluate_run_history`]);
//! 4. requires the pinned jobs green and the selected kind-46108 check
//!    success, bound, signed by the union, and fresh by relay `accepted_at`
//!    ([`verify_check`]);
//! 5. falls back to a live, unconsumed kind-46109 bypass for exactly
//!    `(ref, old, new)` ([`select_bypass`]);
//! 6. appends one `git_merge_gate_decisions` row.
//!
//! `shadow` records and never refuses; `enforce` refuses on every refusal
//! code and on any error of its own (`gate_misconfigured`); `off` evaluates
//! nothing and logs gated refs as skipped. `finalize_push` adds the second
//! fence ([`finalize_fence`]) and consumes a bypass only after the CAS
//! publish wins ([`consume_bypasses`]).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{error, info, warn};
use uuid::Uuid;

use buzz_core::ci::reducer::{reduce_verdict, AcceptedCiEnvelope, CiReducedState, CiReduction};
use buzz_core::ci::{
    validate_signed_ci_event, CiCheckEnvelope, CiJobState, CiRequestEnvelope, CiRunState,
    ValidatedCiEnvelope,
};
use buzz_core::git_perms::{Denial, EffectiveRules, ProtectionRule};
use buzz_core::{CommunityId, TenantContext};
use buzz_db::ci_merge_bypass::CiMergeBypassRecord;
use buzz_db::git_merge_gate::MergeGateDecisionInsert;
use buzz_db::EventQuery;

use super::hydrate::{hydrate_for_read, HydratedRepo, HydrationOptions};
use super::policy::HookRefUpdate;
use crate::config::MergeGateMode;
use crate::state::AppState;

const ZERO_OID: &str = "0000000000000000000000000000000000000000";
/// Page size for `list_ci_run_events` (its clamp ceiling).
const RUN_EVENT_PAGE: u32 = 1_000;
/// The CLI's bounded reducer window; a longer history is `gate_misconfigured`.
const MAX_RUN_EVENTS: usize = 10_000;
/// Rows read per `(repo, tip, workflow)` when selecting a run.
const MAX_RUNS_FOR_TIP: u32 = 100;
/// Budget for hydrating the published state inside the hook callback.
const HYDRATE_TIMEOUT: Duration = Duration::from_secs(8);

/// Refusal codes of design section 1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalCode {
    NoCheck,
    CheckPending,
    CheckNotSuccess,
    ReducerDisagrees,
    BaseMoved,
    NotDescendant,
    ParentShape,
    TreeMismatch,
    WorkflowDigestMismatch,
    RequiredJobsMissing,
    SignerUnauthorized,
    CheckExpired,
    BypassInvalid,
    GateMisconfigured,
}

impl RefusalCode {
    /// Canonical snake_case code, also the `git_merge_gate_decisions.code` value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoCheck => "no_check",
            Self::CheckPending => "check_pending",
            Self::CheckNotSuccess => "check_not_success",
            Self::ReducerDisagrees => "reducer_disagrees",
            Self::BaseMoved => "base_moved",
            Self::NotDescendant => "not_descendant",
            Self::ParentShape => "parent_shape",
            Self::TreeMismatch => "tree_mismatch",
            Self::WorkflowDigestMismatch => "workflow_digest_mismatch",
            Self::RequiredJobsMissing => "required_jobs_missing",
            Self::SignerUnauthorized => "signer_unauthorized",
            Self::CheckExpired => "check_expired",
            Self::BypassInvalid => "bypass_invalid",
            Self::GateMisconfigured => "gate_misconfigured",
        }
    }
}

/// A refusal with its human-readable detail (full identifiers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: RefusalCode,
    pub(crate) detail: String,
}

impl Refusal {
    fn new(code: RefusalCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// How a gated ref update was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Classification {
    /// `parents == [old]` and old is an ancestor of new; candidate is new.
    FastForward,
    /// `parents == [old, candidate]`, candidate contains old, tree equals the
    /// candidate's tree; candidate is the second parent.
    Merge,
}

impl Classification {
    fn as_str(self) -> &'static str {
        match self {
            Self::FastForward => "fast_forward",
            Self::Merge => "merge",
        }
    }
}

/// Classify a gated update from the hook's commit facts (design 1.3).
pub(crate) fn classify_update(update: &HookRefUpdate) -> Result<(Classification, String), Refusal> {
    let parents = &update.parents;
    match parents.len() {
        1 => {
            if parents[0] != update.old_oid {
                return Err(Refusal::new(
                    RefusalCode::ParentShape,
                    format!(
                        "new {} has parent {} but the ref was at {}",
                        update.new_oid, parents[0], update.old_oid
                    ),
                ));
            }
            if !update.is_ancestor {
                return Err(Refusal::new(
                    RefusalCode::ParentShape,
                    format!(
                        "new {} names {} as parent but is not its descendant",
                        update.new_oid, update.old_oid
                    ),
                ));
            }
            Ok((Classification::FastForward, update.new_oid.clone()))
        }
        2 => {
            if parents[0] != update.old_oid {
                return Err(Refusal::new(
                    RefusalCode::ParentShape,
                    format!(
                        "merge {} has first parent {} but the ref was at {}",
                        update.new_oid, parents[0], update.old_oid
                    ),
                ));
            }
            let candidate = parents[1].clone();
            if !update.old_in_second_parent {
                return Err(Refusal::new(
                    RefusalCode::NotDescendant,
                    format!(
                        "candidate {candidate} does not contain base {}",
                        update.old_oid
                    ),
                ));
            }
            let candidate_tree = update.parent_trees.get(1);
            if candidate_tree.is_none_or(|tree| *tree != update.tree) {
                return Err(Refusal::new(
                    RefusalCode::TreeMismatch,
                    format!(
                        "merge {} tree {} differs from candidate {candidate} tree {}",
                        update.new_oid,
                        update.tree,
                        candidate_tree.map(String::as_str).unwrap_or("unknown")
                    ),
                ));
            }
            Ok((Classification::Merge, candidate))
        }
        0 => Err(Refusal::new(
            RefusalCode::ParentShape,
            format!(
                "new {} is not a root-less commit with parents (tag object or missing facts)",
                update.new_oid
            ),
        )),
        n => Err(Refusal::new(
            RefusalCode::ParentShape,
            format!(
                "new {} has {n} parents; only fast-forward or two-parent merge lands",
                update.new_oid
            ),
        )),
    }
}

/// One `ci_runs` row with its validated history, ready for reduction.
#[derive(Debug, Clone)]
pub(crate) struct LoadedRun {
    pub(crate) run_id: Uuid,
    pub(crate) base_oid: String,
    /// Hex SHA-256 of the workflow bytes the request named.
    pub(crate) workflow_digest: String,
    pub(crate) request_event_id: String,
    pub(crate) request: CiRequestEnvelope,
    pub(crate) events: Vec<AcceptedCiEnvelope>,
}

fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// Steps 1 to 5 of design 1.3 over an already loaded run: base, workflow
/// digest, reduction to `Green`, pinned job coverage, and a selected
/// success check bound to the candidate and base. Returns the reduction so
/// the caller can load the check by id.
pub(crate) fn evaluate_run_history(
    pinned_jobs: &BTreeSet<String>,
    candidate: &str,
    base: &str,
    base_workflow_digest: &str,
    run: &LoadedRun,
) -> Result<CiReduction, Refusal> {
    if run.base_oid != base {
        return Err(Refusal::new(
            RefusalCode::BaseMoved,
            format!(
                "run {} tested candidate {candidate} against base {} but the ref is at {base}",
                run.run_id, run.base_oid
            ),
        ));
    }
    if run.workflow_digest != base_workflow_digest {
        return Err(Refusal::new(
            RefusalCode::WorkflowDigestMismatch,
            format!(
                "run {} used workflow digest {} but the workflow at base {base} digests to {base_workflow_digest}",
                run.run_id, run.workflow_digest
            ),
        ));
    }
    let reduction = reduce_verdict(
        &run.request_event_id,
        &run.request,
        &run.events,
        candidate,
        false,
    )
    .map_err(|error| {
        Refusal::new(
            RefusalCode::ReducerDisagrees,
            format!("run {}: {error}", run.run_id),
        )
    })?;
    match reduction.state {
        CiReducedState::Green => {}
        CiReducedState::Pending => {
            return Err(Refusal::new(
                RefusalCode::CheckPending,
                format!(
                    "run {} attempt {} is pending ({}/{} jobs terminal)",
                    run.run_id, reduction.attempt, reduction.jobs_terminal, reduction.jobs_total
                ),
            ));
        }
        CiReducedState::Red => {
            return Err(Refusal::new(
                RefusalCode::CheckNotSuccess,
                format!(
                    "run {} attempt {} is red: required jobs failing {:?}{}",
                    run.run_id,
                    reduction.attempt,
                    reduction.required_failing,
                    reduction
                        .reason
                        .as_deref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default()
                ),
            ));
        }
        CiReducedState::InfrastructureFailure => {
            return Err(Refusal::new(
                RefusalCode::ReducerDisagrees,
                format!(
                    "run {} attempt {} reduced to infrastructure_failure{}",
                    run.run_id,
                    reduction.attempt,
                    reduction
                        .reason
                        .as_deref()
                        .map(|reason| format!(": {reason}"))
                        .unwrap_or_default()
                ),
            ));
        }
    }

    let missing: Vec<&str> = pinned_jobs
        .iter()
        .map(String::as_str)
        .filter(|job_id| {
            let requested = run.request.job_ids.iter().any(|id| id == job_id);
            let green = reduction.jobs.iter().any(|job| {
                job.job_id == *job_id
                    && job.required == Some(true)
                    && job.state == Some(CiJobState::Success)
            });
            !(requested && green)
        })
        .collect();
    if !missing.is_empty() {
        return Err(Refusal::new(
            RefusalCode::RequiredJobsMissing,
            format!(
                "run {} is green over {:?} but the pinned jobs {:?} are not requested, required and successful",
                run.run_id, run.request.job_ids, missing
            ),
        ));
    }

    let check = reduction.check.as_ref().ok_or_else(|| {
        Refusal::new(
            RefusalCode::NoCheck,
            format!(
                "run {} attempt {} has no accepted kind-46108 check yet",
                run.run_id, reduction.attempt
            ),
        )
    })?;
    if check.conclusion != CiRunState::Success {
        return Err(Refusal::new(
            RefusalCode::CheckNotSuccess,
            format!(
                "check {} for run {} concludes {:?}",
                check.event_id, run.run_id, check.conclusion
            ),
        ));
    }
    if check.sha != candidate {
        return Err(Refusal::new(
            RefusalCode::ReducerDisagrees,
            format!(
                "check {} names sha {} but the candidate is {candidate}",
                check.event_id, check.sha
            ),
        ));
    }
    Ok(reduction)
}

/// Steps 5 to 7 of design 1.3 on the stored check the reduction selected:
/// binding to candidate and base, signer in the live union, and freshness
/// by relay `accepted_at` (never `published_at`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_check(
    check: &CiCheckEnvelope,
    check_event_id: &str,
    event_signer: &str,
    accepted_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_age_seconds: u64,
    candidate: &str,
    base: &str,
    signer_union: &HashSet<String>,
) -> Result<(), Refusal> {
    if check.conclusion != CiRunState::Success {
        return Err(Refusal::new(
            RefusalCode::CheckNotSuccess,
            format!("check {check_event_id} concludes {:?}", check.conclusion),
        ));
    }
    if check.tip_oid != candidate {
        return Err(Refusal::new(
            RefusalCode::ReducerDisagrees,
            format!(
                "check {check_event_id} is about tip {} but the candidate is {candidate}",
                check.tip_oid
            ),
        ));
    }
    if check.base_oid != base {
        return Err(Refusal::new(
            RefusalCode::BaseMoved,
            format!(
                "check {check_event_id} names base {} but the ref is at {base}",
                check.base_oid
            ),
        ));
    }
    if event_signer != check.relay_signer || !signer_union.contains(event_signer) {
        return Err(Refusal::new(
            RefusalCode::SignerUnauthorized,
            format!("check {check_event_id} signer {event_signer} is not in the live signer union"),
        ));
    }
    let age = now.signed_duration_since(accepted_at).num_seconds();
    if age < 0 || u64::try_from(age).is_ok_and(|age| age > max_age_seconds) {
        return Err(Refusal::new(
            RefusalCode::CheckExpired,
            format!(
                "check {check_event_id} was accepted {age}s ago; the gate allows {max_age_seconds}s"
            ),
        ));
    }
    Ok(())
}

/// Outcome of consulting the stored bypasses for one exact update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BypassSelection {
    /// No bypass names this update.
    None,
    /// The first usable bypass, oldest accepted first.
    Usable(CiMergeBypassRecord),
    /// Bypasses exist but every one is consumed or outside its window.
    Unusable(CiMergeBypassRecord),
}

/// Pick a live, unconsumed bypass among the records the repository
/// coordinate lookup returned.
pub(crate) fn select_bypass(
    records: &[CiMergeBypassRecord],
    now: DateTime<Utc>,
) -> BypassSelection {
    if let Some(usable) = records.iter().find(|record| record.is_usable_at(now)) {
        return BypassSelection::Usable(usable.clone());
    }
    match records.last() {
        Some(latest) => BypassSelection::Unusable(latest.clone()),
        None => BypassSelection::None,
    }
}

/// Everything the hook callback resolved before the gate runs.
pub(crate) struct GatePushContext<'a> {
    pub(crate) community: CommunityId,
    pub(crate) repo_owner: &'a str,
    pub(crate) repo_id: &'a str,
    pub(crate) channel_id: Uuid,
    pub(crate) pusher: &'a str,
    pub(crate) rules: &'a [ProtectionRule],
    pub(crate) ref_updates: &'a [HookRefUpdate],
}

/// A decision ready to be recorded.
#[derive(Debug, Clone)]
struct Decision {
    classification: String,
    candidate: Option<String>,
    run_id: Option<Uuid>,
    check_event_id: Option<Vec<u8>>,
    signer: Option<String>,
    bypass_event_id: Option<Vec<u8>>,
    /// `None` is an allow.
    refusal: Option<Refusal>,
}

impl Decision {
    fn code(&self) -> &'static str {
        self.refusal.as_ref().map_or("allow", |r| r.code.as_str())
    }
}

/// Repository coordinate the gate keys every lookup on: the kind-30617
/// announcement `hook_policy_check` resolved, never a client-supplied value.
fn repo_coordinate(owner: &str, repo_id: &str) -> String {
    format!("30617:{owner}:{repo_id}")
}

/// Evaluate the merge gate for every gated ref update of a push and record
/// each decision. Returns the denials `enforce` mode produces; `shadow`
/// and `off` always return an empty list.
pub(crate) async fn evaluate_push_gate(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
) -> Vec<Denial> {
    let mode = state.config.ci.merge_gate.mode;
    let gated: Vec<(&HookRefUpdate, EffectiveRules)> = ctx
        .ref_updates
        .iter()
        .filter(|update| update.old_oid != ZERO_OID && update.new_oid != ZERO_OID)
        .filter_map(|update| {
            let effective = EffectiveRules::for_ref(&update.ref_name, ctx.rules);
            effective.is_gated().then_some((update, effective))
        })
        .collect();
    if gated.is_empty() {
        return Vec::new();
    }
    if mode == MergeGateMode::Off {
        for (update, effective) in &gated {
            warn!(
                repo = %ctx.repo_id,
                ref_name = %update.ref_name,
                workflows = ?effective.require_checks.keys().collect::<Vec<_>>(),
                "require-check rule skipped: BUZZ_MERGE_GATE_MODE=off"
            );
        }
        return Vec::new();
    }

    let coordinate = repo_coordinate(ctx.repo_owner, ctx.repo_id);
    let mut denials = Vec::new();
    let mut hydrated: Option<HydratedRepo> = None;
    for (update, effective) in &gated {
        let decision =
            evaluate_update(state, ctx, &coordinate, update, effective, &mut hydrated).await;
        let insert = MergeGateDecisionInsert {
            target_repo_a: coordinate.clone(),
            ref_name: update.ref_name.clone(),
            old_oid: update.old_oid.clone(),
            new_oid: update.new_oid.clone(),
            candidate_oid: decision.candidate.clone(),
            classification: decision.classification.clone(),
            run_id: decision.run_id,
            check_event_id: decision.check_event_id.clone(),
            signer: decision.signer.clone(),
            code: decision.code().to_string(),
            mode: mode.as_str().to_string(),
            pusher: ctx.pusher.to_string(),
            bypass_event_id: decision.bypass_event_id.clone(),
        };
        let recorded = state
            .db
            .insert_merge_gate_decision(ctx.community, &insert)
            .await;
        let verdict = if decision.refusal.is_none() {
            "allow"
        } else {
            "refuse"
        };
        match &recorded {
            Ok(id) => info!(
                repo = %ctx.repo_id,
                ref_name = %update.ref_name,
                old = %update.old_oid,
                new = %update.new_oid,
                candidate = decision.candidate.as_deref().unwrap_or(""),
                run_id = ?decision.run_id,
                check_event_id = decision.check_event_id.as_deref().map(hex::encode).unwrap_or_default(),
                bypass_event_id = decision.bypass_event_id.as_deref().map(hex::encode).unwrap_or_default(),
                decision_id = %id,
                mode = mode.as_str(),
                detail = decision.refusal.as_ref().map(|r| r.detail.as_str()).unwrap_or(""),
                "merge_gate decision={verdict} code={}",
                decision.code()
            ),
            Err(e) => error!(
                repo = %ctx.repo_id,
                ref_name = %update.ref_name,
                error = %e,
                mode = mode.as_str(),
                "merge_gate decision={verdict} code={} (decision row NOT recorded)",
                decision.code()
            ),
        }
        if mode != MergeGateMode::Enforce {
            continue;
        }
        if recorded.is_err() {
            denials.push(Denial {
                ref_name: update.ref_name.clone(),
                reason: format!(
                    "merge gate: {}: decision record unavailable",
                    RefusalCode::GateMisconfigured.as_str()
                ),
            });
            continue;
        }
        if let Some(refusal) = &decision.refusal {
            denials.push(Denial {
                ref_name: update.ref_name.clone(),
                reason: format!(
                    "merge gate: {}: {}",
                    refusal.code.as_str(),
                    shorten_oids(&refusal.detail)
                ),
            });
        }
    }
    denials
}

/// Replace every 40- or 64-hex identifier in `detail` with its 12-hex prefix
/// for the message the pusher sees; the log keeps the complete detail.
fn shorten_oids(detail: &str) -> String {
    detail
        .split(' ')
        .map(|word| {
            let trimmed = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if (trimmed.len() == 40 || trimmed.len() == 64)
                && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
            {
                word.replacen(trimmed, short(trimmed), 1)
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn evaluate_update(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
    coordinate: &str,
    update: &HookRefUpdate,
    effective: &EffectiveRules,
    hydrated: &mut Option<HydratedRepo>,
) -> Decision {
    let mut decision = Decision {
        classification: "unclassified".into(),
        candidate: None,
        run_id: None,
        check_event_id: None,
        signer: None,
        bypass_event_id: None,
        refusal: None,
    };
    let refusal = match evaluate_candidate(
        state,
        ctx,
        coordinate,
        update,
        effective,
        hydrated,
        &mut decision,
    )
    .await
    {
        Ok(()) => return decision,
        Err(refusal) => refusal,
    };

    // Owner override: a live, unconsumed kind-46109 for exactly this update
    // of this repository coordinate allows regardless of the refusal.
    let now = Utc::now();
    match state
        .db
        .list_ci_merge_bypasses(
            ctx.community,
            coordinate,
            &update.ref_name,
            &update.old_oid,
            &update.new_oid,
        )
        .await
    {
        Ok(records) => match select_bypass(&records, now) {
            BypassSelection::None => decision.refusal = Some(refusal),
            BypassSelection::Usable(record) => {
                if record.issuer_pubkey != ctx.repo_owner {
                    decision.bypass_event_id = Some(record.event_id.clone());
                    decision.refusal = Some(Refusal::new(
                        RefusalCode::BypassInvalid,
                        format!(
                            "bypass {} was issued by {} but the repository owner is {}",
                            hex::encode(&record.event_id),
                            record.issuer_pubkey,
                            ctx.repo_owner
                        ),
                    ));
                } else {
                    info!(
                        repo = %ctx.repo_id,
                        ref_name = %update.ref_name,
                        bypass = %hex::encode(&record.event_id),
                        overridden_code = refusal.code.as_str(),
                        "merge gate bypass covers this update"
                    );
                    decision.classification = "bypass".into();
                    decision.bypass_event_id = Some(record.event_id);
                    decision.refusal = None;
                }
            }
            BypassSelection::Unusable(record) => {
                let why = if record.consumed_by.is_some() {
                    "already consumed".to_string()
                } else {
                    format!(
                        "outside its window ({} to {}, now {})",
                        record.issued_at.timestamp(),
                        record.expires_at.timestamp(),
                        now.timestamp()
                    )
                };
                decision.bypass_event_id = Some(record.event_id.clone());
                decision.refusal = Some(Refusal::new(
                    RefusalCode::BypassInvalid,
                    format!(
                        "bypass {} is {why}; without it: {}: {}",
                        hex::encode(&record.event_id),
                        refusal.code.as_str(),
                        refusal.detail
                    ),
                ));
            }
        },
        Err(e) => {
            decision.refusal = Some(Refusal::new(
                RefusalCode::GateMisconfigured,
                format!(
                    "bypass lookup failed: {e}; without it: {}: {}",
                    refusal.code.as_str(),
                    refusal.detail
                ),
            ));
        }
    }
    decision
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_candidate(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
    coordinate: &str,
    update: &HookRefUpdate,
    effective: &EffectiveRules,
    hydrated: &mut Option<HydratedRepo>,
    decision: &mut Decision,
) -> Result<(), Refusal> {
    let (classification, candidate) = classify_update(update)?;
    decision.classification = classification.as_str().into();
    decision.candidate = Some(candidate.clone());
    let base = update.old_oid.as_str();

    let repo = match hydrated {
        Some(repo) => repo,
        None => {
            let repo = hydrate_published(state, ctx).await?;
            hydrated.insert(repo)
        }
    };
    let now = Utc::now();
    let signer_union = signer_union(state, ctx, coordinate, now).await?;
    let max_age = state.config.ci.merge_gate.check_max_age_seconds;

    let base_workflow = crate::api::ci::resolve_workflow_at_base(repo.path(), base)
        .await
        .map_err(|(status, body)| {
            Refusal::new(
                RefusalCode::GateMisconfigured,
                format!(
                    "workflow at base {base} unresolvable ({}): {}",
                    status.as_u16(),
                    body.0
                ),
            )
        })?;

    for (workflow_id, pinned_jobs) in &effective.require_checks {
        let run = select_run(
            state,
            ctx,
            coordinate,
            &candidate,
            base,
            workflow_id,
            &base_workflow.workflow_digest,
            &signer_union,
        )
        .await?;
        decision.run_id = Some(run.run_id);
        let reduction = evaluate_run_history(
            pinned_jobs,
            &candidate,
            base,
            &base_workflow.workflow_digest,
            &run,
        )?;
        let check = reduction.check.as_ref().ok_or_else(|| {
            Refusal::new(
                RefusalCode::NoCheck,
                format!("run {} has no check", run.run_id),
            )
        })?;
        let check_id_bytes = hex::decode(&check.event_id).map_err(|_| {
            Refusal::new(
                RefusalCode::ReducerDisagrees,
                format!("check id {} is not hex", check.event_id),
            )
        })?;
        decision.check_event_id = Some(check_id_bytes.clone());
        let stored = state
            .db
            .load_ci_check(ctx.community, run.run_id, &check_id_bytes)
            .await
            .map_err(|e| {
                Refusal::new(
                    RefusalCode::GateMisconfigured,
                    format!("check {} unavailable: {e}", check.event_id),
                )
            })?
            .ok_or_else(|| {
                Refusal::new(
                    RefusalCode::NoCheck,
                    format!(
                        "check {} selected for run {} is not stored",
                        check.event_id, run.run_id
                    ),
                )
            })?;
        let event_signer = stored.stored_event.event.pubkey.to_hex();
        decision.signer = Some(event_signer.clone());
        let envelope = match validate_signed_ci_event(
            &stored.stored_event.event,
            &ctx.channel_id.to_string(),
            &signer_union,
        ) {
            Ok(ValidatedCiEnvelope::Check(envelope)) => envelope,
            Ok(_) => {
                return Err(Refusal::new(
                    RefusalCode::ReducerDisagrees,
                    format!("stored event {} is not a kind-46108 check", check.event_id),
                ))
            }
            Err(error) => {
                return Err(Refusal::new(
                    RefusalCode::SignerUnauthorized,
                    format!("check {} failed validation: {error}", check.event_id),
                ))
            }
        };
        verify_check(
            &envelope,
            &check.event_id,
            &event_signer,
            stored.accepted_at,
            now,
            max_age,
            &candidate,
            base,
            &signer_union,
        )?;
    }
    Ok(())
}

async fn hydrate_published(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
) -> Result<HydratedRepo, Refusal> {
    let host = state
        .db
        .lookup_community_host(ctx.community)
        .await
        .map_err(|e| {
            Refusal::new(
                RefusalCode::GateMisconfigured,
                format!("community host lookup failed: {e}"),
            )
        })?
        .ok_or_else(|| {
            Refusal::new(
                RefusalCode::GateMisconfigured,
                "community has no host".to_string(),
            )
        })?;
    let tenant = TenantContext::resolved(ctx.community, host);
    let hydration = hydrate_for_read(
        &state.git_store,
        &tenant,
        ctx.repo_owner,
        ctx.repo_id,
        HydrationOptions {
            pack_cache: &state.git_pack_cache,
            scratch_dir: &state.config.git_repo_path,
            max_pack_bytes: state.config.git_max_pack_bytes,
            max_repo_bytes: state.config.git_max_repo_bytes,
        },
    );
    match tokio::time::timeout(HYDRATE_TIMEOUT, hydration).await {
        Ok(Ok(Some(repo))) => Ok(repo),
        Ok(Ok(None)) => Err(Refusal::new(
            RefusalCode::GateMisconfigured,
            "published repository state is missing".to_string(),
        )),
        Ok(Err(e)) => Err(Refusal::new(
            RefusalCode::GateMisconfigured,
            format!("published repository state unavailable: {e}"),
        )),
        Err(_) => Err(Refusal::new(
            RefusalCode::GateMisconfigured,
            "published repository hydration timed out".to_string(),
        )),
    }
}

async fn signer_union(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
    coordinate: &str,
    now: DateTime<Utc>,
) -> Result<HashSet<String>, Refusal> {
    let mut signers = state.config.ci_status_signer_pubkeys.clone();
    signers.extend(
        state
            .db
            .get_active_ci_signers(ctx.community, ctx.channel_id, coordinate, now)
            .await
            .map_err(|e| {
                Refusal::new(
                    RefusalCode::GateMisconfigured,
                    format!("signer grants unavailable: {e}"),
                )
            })?,
    );
    if signers.is_empty() {
        return Err(Refusal::new(
            RefusalCode::GateMisconfigured,
            "the CI signer union is empty".to_string(),
        ));
    }
    Ok(signers)
}

/// Select the latest run for `(repository, candidate, workflow)` whose base
/// and workflow digest match the push, and load only its history.
#[allow(clippy::too_many_arguments)]
async fn select_run(
    state: &Arc<AppState>,
    ctx: &GatePushContext<'_>,
    coordinate: &str,
    candidate: &str,
    base: &str,
    workflow_id: &str,
    base_workflow_digest: &str,
    signer_union: &HashSet<String>,
) -> Result<LoadedRun, Refusal> {
    let runs = state
        .db
        .list_ci_runs_for_tip(
            ctx.community,
            coordinate,
            candidate,
            workflow_id,
            MAX_RUNS_FOR_TIP,
        )
        .await
        .map_err(|e| {
            Refusal::new(
                RefusalCode::GateMisconfigured,
                format!("run lookup failed: {e}"),
            )
        })?;
    let runs: Vec<_> = runs
        .into_iter()
        .filter(|run| run.channel_id == ctx.channel_id)
        .collect();
    let Some(latest) = runs.first() else {
        return Err(Refusal::new(
            RefusalCode::NoCheck,
            format!("no {workflow_id} run for candidate {candidate}"),
        ));
    };
    let selected = runs
        .iter()
        .find(|run| run.base_oid == base && run.workflow_digest == base_workflow_digest);
    let Some(selected) = selected else {
        // Report why the newest run does not qualify.
        if latest.base_oid != base {
            return Err(Refusal::new(
                RefusalCode::BaseMoved,
                format!(
                    "latest {workflow_id} run {} tested candidate {candidate} against base {} but the ref is at {base}",
                    latest.run_id, latest.base_oid
                ),
            ));
        }
        return Err(Refusal::new(
            RefusalCode::WorkflowDigestMismatch,
            format!(
                "latest {workflow_id} run {} used workflow digest {} but the workflow at base {base} digests to {base_workflow_digest}",
                latest.run_id, latest.workflow_digest
            ),
        ));
    };

    let channel = ctx.channel_id.to_string();
    let request_stored = state
        .db
        .get_ci_run_request(ctx.community, ctx.channel_id, selected.run_id)
        .await
        .map_err(|e| {
            Refusal::new(
                RefusalCode::GateMisconfigured,
                format!("run {} request unavailable: {e}", selected.run_id),
            )
        })?
        .ok_or_else(|| {
            Refusal::new(
                RefusalCode::ReducerDisagrees,
                format!("run {} has no stored initial request", selected.run_id),
            )
        })?;
    let request = match validate_signed_ci_event(
        &request_stored.stored_event.event,
        &channel,
        signer_union,
    ) {
        Ok(ValidatedCiEnvelope::Request(request)) => request,
        Ok(_) => {
            return Err(Refusal::new(
                RefusalCode::ReducerDisagrees,
                format!("run {} initial event is not a request", selected.run_id),
            ))
        }
        Err(error) => {
            return Err(Refusal::new(
                RefusalCode::ReducerDisagrees,
                format!("run {} request failed validation: {error}", selected.run_id),
            ))
        }
    };

    let mut events = Vec::new();
    let mut after_cursor = 0_i64;
    loop {
        let page = state
            .db
            .list_ci_run_events(
                ctx.community,
                ctx.channel_id,
                selected.run_id,
                after_cursor,
                RUN_EVENT_PAGE,
            )
            .await
            .map_err(|e| {
                Refusal::new(
                    RefusalCode::GateMisconfigured,
                    format!("run {} history unavailable: {e}", selected.run_id),
                )
            })?;
        let page_len = page.len();
        if events.len().saturating_add(page_len) > MAX_RUN_EVENTS {
            return Err(Refusal::new(
                RefusalCode::GateMisconfigured,
                format!(
                    "run {} history exceeds the {MAX_RUN_EVENTS}-event reducer window",
                    selected.run_id
                ),
            ));
        }
        for stored in page {
            let event = &stored.stored_event.event;
            let envelope = validate_signed_ci_event(event, &channel, signer_union)
                .map_err(|error| history_signer_refusal(selected.run_id, event, error))?;
            let watch_cursor = u64::try_from(stored.watch_cursor).map_err(|_| {
                Refusal::new(
                    RefusalCode::ReducerDisagrees,
                    format!("run {} has a negative watch cursor", selected.run_id),
                )
            })?;
            after_cursor = stored.watch_cursor;
            events.push(AcceptedCiEnvelope {
                event_id: stored.stored_event.event.id.to_hex(),
                watch_cursor,
                envelope,
            });
        }
        if page_len < RUN_EVENT_PAGE as usize {
            break;
        }
    }

    Ok(LoadedRun {
        run_id: selected.run_id,
        base_oid: selected.base_oid.clone(),
        workflow_digest: selected.workflow_digest.clone(),
        request_event_id: request_stored.stored_event.event.id.to_hex(),
        request,
        events,
    })
}

/// A stored run event that no longer validates against the live signer
/// union: a revoked signer's history stops counting.
fn history_signer_refusal(
    run_id: Uuid,
    event: &nostr::Event,
    error: buzz_core::ci::CiValidationError,
) -> Refusal {
    Refusal::new(
        RefusalCode::SignerUnauthorized,
        format!(
            "run {run_id} event {} failed validation against the live signer union: {error}",
            event.id.to_hex()
        ),
    )
}

/// An allowing decision the finalize fence matched to a changed gated ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FenceClaim {
    pub(crate) ref_name: String,
    pub(crate) decision_id: Uuid,
    pub(crate) bypass_event_id: Option<Vec<u8>>,
}

/// Second fence of design 1.7, `enforce` mode only: every gated ref that
/// changed between the parent manifest and the workspace needs an `allow`
/// row for exactly `(ref, old, new, pusher)` decided inside the window.
/// Returns the claims to consume after the CAS wins, or the refusal detail.
pub(crate) async fn finalize_fence(
    state: &Arc<AppState>,
    community: CommunityId,
    repo_owner: &str,
    repo_id: &str,
    pusher: &str,
    parent_refs: &BTreeMap<String, String>,
    workspace_refs: &BTreeMap<String, String>,
) -> Result<Vec<FenceClaim>, String> {
    if state.config.ci.merge_gate.mode != MergeGateMode::Enforce {
        return Ok(Vec::new());
    }
    let owner_bytes =
        hex::decode(repo_owner).map_err(|_| "invalid repository owner".to_string())?;
    let query = EventQuery {
        kinds: Some(vec![30617]),
        pubkey: Some(owner_bytes),
        d_tag: Some(repo_id.to_string()),
        global_only: true,
        limit: Some(1),
        ..EventQuery::for_community(community)
    };
    let announcement = state
        .db
        .query_events(&query)
        .await
        .map_err(|e| format!("repository lookup failed: {e}"))?
        .pop()
        .ok_or_else(|| "repository announcement not found".to_string())?;
    let tags: Vec<Vec<String>> = announcement
        .event
        .tags
        .iter()
        .map(|t| t.as_slice().to_vec())
        .collect();
    let rules = buzz_core::git_perms::parse_protection_tags(&tags)
        .map_err(|e| format!("malformed protection rules: {e}"))?
        .rules;
    let coordinate = repo_coordinate(repo_owner, repo_id);
    let window =
        i64::try_from(state.config.ci.merge_gate.decision_window_seconds).unwrap_or(i64::MAX);
    let not_before = Utc::now() - chrono::Duration::seconds(window);

    let mut claims = Vec::new();
    for (ref_name, new_oid) in workspace_refs {
        let Some(old_oid) = parent_refs.get(ref_name) else {
            continue; // create: not gated
        };
        if old_oid == new_oid {
            continue;
        }
        if !EffectiveRules::for_ref(ref_name, &rules).is_gated() {
            continue;
        }
        let allow = state
            .db
            .find_merge_gate_allow(
                community,
                &coordinate,
                ref_name,
                old_oid,
                new_oid,
                pusher,
                not_before,
            )
            .await
            .map_err(|e| format!("decision lookup failed: {e}"))?
            .ok_or_else(|| {
                format!(
                    "no allow decision for {ref_name} {} -> {} by {} within {window}s",
                    short(old_oid),
                    short(new_oid),
                    short(pusher)
                )
            })?;
        claims.push(FenceClaim {
            ref_name: ref_name.clone(),
            decision_id: allow.id,
            bypass_event_id: allow.bypass_event_id,
        });
    }
    Ok(claims)
}

/// Consume every bypass the fence claimed. Called only after `cas_publish`
/// returned `Won`, so a CAS loser leaves its bypass usable.
pub(crate) async fn consume_bypasses(
    state: &Arc<AppState>,
    community: CommunityId,
    claims: &[FenceClaim],
) {
    for claim in claims {
        let Some(bypass_event_id) = &claim.bypass_event_id else {
            continue;
        };
        match state
            .db
            .consume_ci_merge_bypass(community, bypass_event_id, claim.decision_id)
            .await
        {
            Ok(true) => info!(
                ref_name = %claim.ref_name,
                bypass = %hex::encode(bypass_event_id),
                decision_id = %claim.decision_id,
                "merge gate bypass consumed after publish"
            ),
            Ok(false) => warn!(
                ref_name = %claim.ref_name,
                bypass = %hex::encode(bypass_event_id),
                decision_id = %claim.decision_id,
                "merge gate bypass was already consumed"
            ),
            Err(e) => error!(
                ref_name = %claim.ref_name,
                bypass = %hex::encode(bypass_event_id),
                error = %e,
                "merge gate bypass consumption failed; the push is already published"
            ),
        }
    }
}

#[cfg(test)]
#[path = "merge_gate_tests.rs"]
mod tests;
