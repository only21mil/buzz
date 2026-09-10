//! `buzz ci landing`: the Buzz-native landing verifier
//! (`docs/ci/BUZZ_MERGE_GATE_DESIGN.md` section 2).
//!
//! The verifier proves, from the relay and a local checkout, that a commit on
//! relay `main` is the reviewed candidate landed on the reviewed base with a
//! green Buzz-native run behind it. Every proof is a named check with a
//! refusal code; the receipt lists all of them, retains the complete run
//! history hash-bound, and is `PASS` only when every gating check passes.
//! `buzz ci landing validate` replays the retained bodies offline and can
//! repeat the live reads with `--reverify`.
//!
//! This command grants nothing: it reads the relay, it never pushes, and it
//! does not replace the protected-ci scripts until the cutover step in
//! `docs/delivery-lifecycle.md` makes it authoritative.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use buzz_core::ci::{
    validate_signed_ci_event, CiJobState, CiRequestEnvelope, CiRunState, CiSkipPolicy,
    ValidatedCiEnvelope,
};
use buzz_core::git_perms::{parse_protection_tags, EffectiveRules};
use chrono::{DateTime, Utc};
use nostr::Event;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::BuzzClient;
use crate::commands::ci::dispatch::{
    fetch_ci_run_request, validate_ci_request_history, ValidatedCiRequest, CI_RUN_EVENT_PAGE_LIMIT,
};
use crate::commands::ci::reducer::{
    reduce_verdict, AcceptedCiEnvelope, CiReducedState, CiReduction,
};
use crate::commands::ci::run::RunTrustedContext;
use crate::commands::repo_sync::{auth_from_client, GitHubAuth, GitRepo, RemoteAuth};
use crate::error::CliError;

/// Receipt policy identifier.
pub const LANDING_POLICY: &str = "buzz-native-landing-v1";
/// Receipt schema version.
pub const LANDING_SCHEMA_VERSION: u32 = 1;
/// Default freshness bound for the selected check, matching the relay's
/// `BUZZ_MERGE_GATE_CHECK_MAX_AGE_SECONDS` default.
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 86_400;
/// Upper bound on a receipt, as `protected-ci-receipt.py` enforces.
pub const MAX_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
/// The one workflow path the relay preflight resolves at the trusted base.
pub const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
/// The gated ref.
pub const MAIN_REF: &str = "refs/heads/main";
/// The maintained desktop identity gate the verifier executes.
pub const DESKTOP_VERIFIER: &str = "scripts/desktop_release.py";
/// The metadata blob `desktop_release.py` keys the candidate identity on.
pub const DESKTOP_METADATA: &str = ".release/desktop-candidate.json";
const MAX_CI_RUN_EVENTS: usize = 10_000;
const MAX_SAFE_CURSOR: u64 = (1_u64 << 53) - 1;

/// Inputs of `buzz ci landing`.
#[derive(clap::Args, Debug, Clone)]
pub struct LandingVerifyArgs {
    /// Repository owner public key (hex)
    #[arg(long)]
    pub repo_owner: String,
    /// Repository identifier (`d` tag)
    #[arg(long)]
    pub repo_id: String,
    /// Full reviewed candidate commit
    #[arg(long)]
    pub candidate: String,
    /// Full reviewed base commit
    #[arg(long)]
    pub base: String,
    /// Full commit relay main must name
    #[arg(long)]
    pub landed: String,
    /// Local checkout holding the landed, candidate, and base objects
    #[arg(long, default_value = ".")]
    pub checkout: PathBuf,
    /// Absolute receipt path; its parent must be a caller-owned mode-0700 directory and the file must not exist
    #[arg(long)]
    pub output: PathBuf,
    /// GitHub mirror (`owner/repo`) for the non-gating parity read
    #[arg(long)]
    pub github_mirror: Option<String>,
    /// Accept a merge-gate decision recorded in `shadow` mode
    #[arg(long)]
    pub allow_shadow: bool,
    /// Longest age of the selected check by relay `accepted_at`, in seconds
    #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECONDS)]
    pub max_age_seconds: u64,
}

/// Nested `buzz ci landing` subcommands.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum LandingCmd {
    /// Re-verify a landing receipt offline, optionally repeating the live reads
    Validate {
        /// Absolute receipt path
        #[arg(long)]
        receipt: PathBuf,
        /// Repeat the relay main, run listing, and merge-gate reads live
        #[arg(long)]
        reverify: bool,
        /// Longest age of the receipt itself, in seconds
        #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECONDS)]
        max_age_seconds: u64,
    },
}

// ── Receipt ──

/// Outcome of one named check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    /// The proof holds.
    Pass,
    /// The proof failed with the recorded refusal code.
    Refused,
    /// A non-gating read disagreed or was unavailable.
    Warn,
}

/// One named proof in the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandingCheck {
    /// Stable check name; per-workflow checks carry `:<workflow_id>`.
    pub name: String,
    /// Whether a refusal fails the landing.
    pub gating: bool,
    /// Outcome.
    pub result: CheckResult,
    /// Refusal code when refused or warned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One relay `main` read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayMainRead {
    /// Read time.
    pub read_at: DateTime<Utc>,
    /// Object ID relay main named, when the read succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// Read failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One retained run event body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedEvent {
    /// Signed event ID.
    pub event_id: String,
    /// Relay acceptance cursor.
    pub watch_cursor: u64,
    /// Relay clock acceptance time.
    pub accepted_at: DateTime<Utc>,
    /// SHA-256 of the retained bytes.
    pub sha256: String,
    /// Base64 of the signed event JSON exactly as retained.
    pub base64: String,
}

/// Reduced state summary of the selected run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionSummary {
    /// Aggregate state.
    pub state: CiReducedState,
    /// Greatest accepted attempt.
    pub attempt: u32,
    /// Terminal jobs.
    pub jobs_terminal: usize,
    /// Selected jobs.
    pub jobs_total: usize,
    /// Required jobs whose selected attempt did not succeed.
    pub required_failing: Vec<String>,
}

/// The selected kind-46108 check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSummary {
    /// Accepted event ID.
    pub event_id: String,
    /// Relay acceptance cursor.
    pub watch_cursor: u64,
    /// Relay clock acceptance time, the freshness authority.
    pub accepted_at: DateTime<Utc>,
    /// Control-plane signer.
    pub signer: String,
    /// Terminal conclusion.
    pub conclusion: CiRunState,
    /// Head the check is about.
    pub tip_oid: String,
    /// Base the check names.
    pub base_oid: String,
    /// Signer-chosen publication time, recorded and never trusted.
    pub published_at: u64,
}

/// Evidence for one gated workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEvidence {
    /// Workflow the rule pins.
    pub workflow_id: String,
    /// Job IDs the rule pins.
    pub pinned_jobs: Vec<String>,
    /// Workflow path digested at the base.
    pub workflow_path: String,
    /// SHA-256 of the workflow blob at the base, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_workflow_digest: Option<String>,
    /// Selected run, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Selected run's initial request event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_id: Option<String>,
    /// Selected run's base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_base_oid: Option<String>,
    /// Selected run's workflow digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_workflow_digest: Option<String>,
    /// Reduced state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction: Option<ReductionSummary>,
    /// Selected check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<CheckSummary>,
    /// Complete retained run history in cursor order.
    #[serde(default)]
    pub retained_events: Vec<RetainedEvent>,
    /// SHA-256 over the concatenated retained `sha256` values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_sha256: Option<String>,
}

/// One merge-gate decision row as read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRow {
    /// Row identifier.
    pub id: String,
    /// Old object ID.
    pub old_oid: String,
    /// New object ID.
    pub new_oid: String,
    /// Candidate the gate resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_oid: Option<String>,
    /// Push classification.
    pub classification: String,
    /// Selected run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Selected check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_event_id: Option<String>,
    /// Selected check's signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// `allow` or a refusal code.
    pub code: String,
    /// Gate mode at decision time.
    pub mode: String,
    /// Pusher.
    pub pusher: String,
    /// Bypass evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_event_id: Option<String>,
    /// Decision time.
    pub decided_at: DateTime<Utc>,
}

/// Merge-gate decision evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionEvidence {
    /// Relay merge-gate mode at read time, when the read succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Whether the decision gated this verification.
    pub gating: bool,
    /// Rows read for `(main, base, landed)`, newest first.
    #[serde(default)]
    pub decisions: Vec<DecisionRow>,
    /// Read failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// GitHub mirror parity evidence (non-gating).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorEvidence {
    /// `owner/repo`.
    pub repository: String,
    /// Read time.
    pub read_at: DateTime<Utc>,
    /// Mirror main, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// Whether the mirror named the landed commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agrees: Option<bool>,
    /// Read failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Trusted context the receipt records so offline validation replays it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedContextRecord {
    /// Repository channel.
    pub channel_id: String,
    /// Authorized status signers, sorted.
    pub status_signers: Vec<String>,
}

/// Repository identity the receipt is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryRecord {
    /// `30617:<owner>:<repo>`.
    pub target_repo_a: String,
    /// Relay base URL.
    pub relay_url: String,
    /// Relay git URL read for `main`.
    pub git_url: String,
    /// Announcement event that carried the rule, when found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement_event_id: Option<String>,
}

/// The receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandingReceipt {
    /// `buzz-native-landing-v1`.
    pub policy: String,
    /// `1`.
    pub schema_version: u32,
    /// Repository identity.
    pub repository: RepositoryRecord,
    /// Commit relay main must name.
    pub landed: String,
    /// Reviewed candidate.
    pub candidate: String,
    /// Reviewed base.
    pub base: String,
    /// `merge`, `fast_forward`, or `unknown`.
    pub classification: String,
    /// Checkout the git object reads used.
    pub checkout: String,
    /// Relay main reads around the relay reads.
    pub relay_main: Vec<RelayMainRead>,
    /// Effective `require-check` rule for `refs/heads/main`.
    pub require_checks: BTreeMap<String, Vec<String>>,
    /// Trusted context used to validate events.
    pub trusted: TrustedContextRecord,
    /// Freshness bound applied.
    pub max_age_seconds: u64,
    /// Whether a `shadow` decision was accepted.
    pub allow_shadow: bool,
    /// Per-workflow evidence.
    pub runs: Vec<RunEvidence>,
    /// Merge-gate decision evidence.
    pub gate_decision: GateDecisionEvidence,
    /// Mirror parity evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorEvidence>,
    /// Every check.
    pub landing_checks: Vec<LandingCheck>,
    /// `PASS` or `REFUSED`.
    pub verdict: String,
    /// Verification time.
    pub timestamp: DateTime<Utc>,
}

impl LandingReceipt {
    /// Whether every gating check passed.
    pub fn all_gating_pass(&self) -> bool {
        all_gating_pass(&self.landing_checks)
    }
}

fn all_gating_pass(checks: &[LandingCheck]) -> bool {
    checks
        .iter()
        .all(|check| !check.gating || check.result == CheckResult::Pass)
}

// ── Ledger ──

/// A refusal with its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Machine-readable code.
    pub code: String,
    /// Detail.
    pub detail: String,
}

impl Refusal {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Default)]
struct Ledger {
    checks: Vec<LandingCheck>,
}

impl Ledger {
    fn gate<T>(&mut self, name: &str, outcome: Result<(T, String), Refusal>) -> Option<T> {
        match outcome {
            Ok((value, detail)) => {
                self.checks.push(LandingCheck {
                    name: name.to_owned(),
                    gating: true,
                    result: CheckResult::Pass,
                    code: None,
                    detail: Some(detail),
                });
                Some(value)
            }
            Err(refusal) => {
                self.checks.push(LandingCheck {
                    name: name.to_owned(),
                    gating: true,
                    result: CheckResult::Refused,
                    code: Some(refusal.code),
                    detail: Some(refusal.detail),
                });
                None
            }
        }
    }

    fn record(&mut self, name: &str, gating: bool, outcome: Result<String, Refusal>) {
        let check = match outcome {
            Ok(detail) => LandingCheck {
                name: name.to_owned(),
                gating,
                result: CheckResult::Pass,
                code: None,
                detail: Some(detail),
            },
            Err(refusal) => LandingCheck {
                name: name.to_owned(),
                gating,
                result: if gating {
                    CheckResult::Refused
                } else {
                    CheckResult::Warn
                },
                code: Some(refusal.code),
                detail: Some(refusal.detail),
            },
        };
        self.checks.push(check);
    }

    fn refuse(&mut self, name: &str, refusal: Refusal) {
        self.record(name, true, Err(refusal));
    }
}

// ── Git ──

fn git_output(checkout: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| format!("git {} could not start: {error}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git {} failed (exit {}): {}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    Ok(output.stdout)
}

fn git_line(checkout: &Path, args: &[&str]) -> Result<String, String> {
    let stdout = git_output(checkout, args)?;
    let text = String::from_utf8(stdout).map_err(|_| "git returned non-UTF-8 output".to_owned())?;
    Ok(text.trim().to_owned())
}

fn is_full_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Push classification from `git rev-list --parents -n 1 <landed>`.
///
/// `merge`: parents are exactly `[base, candidate]`. `fast_forward`: the one
/// parent is `base` and `landed == candidate`. Anything else is
/// `parent_shape`.
pub fn classify_parents(
    landed: &str,
    candidate: &str,
    base: &str,
    rev_list_line: &str,
) -> Result<&'static str, Refusal> {
    let tokens: Vec<&str> = rev_list_line.split_whitespace().collect();
    if tokens.first().copied() != Some(landed) {
        return Err(Refusal::new(
            "parent_shape",
            format!("rev-list named {:?}, not the landed commit", tokens.first()),
        ));
    }
    match &tokens[1..] {
        [first, second] if *first == base && *second == candidate => Ok("merge"),
        [first] if *first == base && landed == candidate => Ok("fast_forward"),
        parents => Err(Refusal::new(
            "parent_shape",
            format!(
                "landed parents {parents:?} are not [base, candidate] or a fast-forward of the base"
            ),
        )),
    }
}

fn relay_git_url(relay_url: &str, owner: &str, repo_id: &str) -> String {
    format!("{}/git/{owner}/{repo_id}", relay_url.trim_end_matches('/'))
}

fn read_relay_main(git: &GitRepo, url: &str) -> RelayMainRead {
    let auth = if url.starts_with("http://") || url.starts_with("https://") {
        RemoteAuth::Buzz
    } else {
        RemoteAuth::None
    };
    let read_at = Utc::now();
    match git.remote_ref(url, auth, "buzz", MAIN_REF) {
        Ok(sha) => RelayMainRead {
            read_at,
            sha,
            error: None,
        },
        Err(error) => RelayMainRead {
            read_at,
            sha: None,
            error: Some(error.to_string()),
        },
    }
}

/// Both reads must name the landed commit.
pub fn evaluate_relay_main(reads: &[RelayMainRead], landed: &str) -> Result<String, Refusal> {
    for (index, read) in reads.iter().enumerate() {
        match (&read.sha, &read.error) {
            (Some(sha), _) if sha == landed => {}
            (Some(sha), _) => {
                return Err(Refusal::new(
                    "relay_main_mismatch",
                    format!("relay main read {} named {sha}, not {landed}", index + 1),
                ));
            }
            (None, Some(error)) => {
                return Err(Refusal::new(
                    "relay_main_unavailable",
                    format!("relay main read {} failed: {error}", index + 1),
                ));
            }
            (None, None) => {
                return Err(Refusal::new(
                    "relay_main_mismatch",
                    format!("relay main read {} found no refs/heads/main", index + 1),
                ));
            }
        }
    }
    Ok(format!(
        "relay {MAIN_REF} named {landed} on {} reads",
        reads.len()
    ))
}

// ── Relay reads ──

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEventResponse {
    watch_cursor: u64,
    accepted_at: DateTime<Utc>,
    event: Event,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiChecksRunResponse {
    run_id: String,
    request_event_id: String,
    workflow_id: String,
    workflow_digest: String,
    tip_oid: String,
    base_oid: String,
    #[serde(rename = "created_at")]
    _created_at: DateTime<Utc>,
    checks: Vec<StoredEventResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiChecksResponse {
    target_repo_a: String,
    tip_oid: String,
    runs: Vec<CiChecksRunResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiRunEventsResponse {
    run_id: String,
    request_event_id: String,
    events: Vec<StoredEventResponse>,
    next_cursor: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeGateDecisionsResponse {
    target_repo_a: String,
    #[serde(rename = "ref")]
    ref_name: String,
    new_oid: String,
    mode: String,
    #[serde(rename = "check_max_age_seconds")]
    _check_max_age_seconds: u64,
    decisions: Vec<DecisionRow>,
}

/// One stored run event with its relay acceptance metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRunEvent {
    /// Relay acceptance cursor.
    pub watch_cursor: u64,
    /// Relay clock acceptance time.
    pub accepted_at: DateTime<Utc>,
    /// Signed event.
    pub event: Event,
}

/// Complete run history as the relay exported it.
#[derive(Debug, Clone)]
pub struct RunHistory {
    /// Immutable initial request event ID.
    pub request_event_id: String,
    /// Immutable initial request.
    pub request: CiRequestEnvelope,
    /// Every stored event in cursor order.
    pub stored: Vec<StoredRunEvent>,
    /// Every stored event validated against the trusted context.
    pub accepted: Vec<AcceptedCiEnvelope>,
}

fn relay_error(context: &str, error: CliError) -> Refusal {
    match error {
        CliError::Relay { status: 404, body } => Refusal::new(
            "relay_route_unavailable",
            format!("{context}: relay answered 404: {body}"),
        ),
        other => Refusal::new("relay_unavailable", format!("{context}: {other}")),
    }
}

async fn fetch_checks_for_tip(
    client: &BuzzClient,
    target_repo_a: &str,
    tip_oid: &str,
    workflow_id: &str,
) -> Result<CiChecksResponse, Refusal> {
    let path = format!(
        "/ci/checks?target_repo_a={target_repo_a}&tip_oid={tip_oid}&workflow_id={workflow_id}"
    );
    let raw = client
        .get_authed(&path)
        .await
        .map_err(|error| relay_error("run listing", error))?;
    let response: CiChecksResponse = serde_json::from_str(&raw).map_err(|error| {
        Refusal::new(
            "relay_unavailable",
            format!("invalid run listing response: {error}"),
        )
    })?;
    if response.target_repo_a != target_repo_a || response.tip_oid != tip_oid {
        return Err(Refusal::new(
            "relay_unavailable",
            "run listing answered for another repository or tip",
        ));
    }
    Ok(response)
}

/// Validate every stored event and bind the pages to the request identity,
/// exactly as `fetch_ci_run_snapshot` does, while keeping the raw bodies.
fn validate_stored_history(
    request: &ValidatedCiRequest,
    stored: &[StoredRunEvent],
    trusted: &RunTrustedContext,
) -> Result<Vec<AcceptedCiEnvelope>, CliError> {
    let mut previous = 0_u64;
    let mut accepted = Vec::with_capacity(stored.len());
    for event in stored {
        let expected = previous.checked_add(1).ok_or_else(|| {
            CliError::Other("CI events exporter cursor overflowed the safe range".into())
        })?;
        if event.watch_cursor != expected || event.watch_cursor > MAX_SAFE_CURSOR {
            return Err(CliError::Other(
                "CI events exporter returned a non-contiguous cursor page".into(),
            ));
        }
        previous = event.watch_cursor;
        let envelope =
            validate_signed_ci_event(&event.event, &trusted.channel_id, &trusted.status_signers)
                .map_err(|error| CliError::Other(format!("invalid signed CI event: {error}")))?;
        accepted.push(AcceptedCiEnvelope {
            event_id: event.event.id.to_hex(),
            watch_cursor: event.watch_cursor,
            envelope,
        });
    }
    validate_ci_request_history(request, &accepted)?;
    Ok(accepted)
}

async fn fetch_run_history(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<RunHistory, CliError> {
    let request = fetch_ci_run_request(client, run_id, trusted).await?;
    let mut after_cursor = 0_u64;
    let mut stored: Vec<StoredRunEvent> = Vec::new();
    loop {
        let path = format!(
            "/ci/runs/{run_id}/events?after={after_cursor}&limit={CI_RUN_EVENT_PAGE_LIMIT}"
        );
        let raw = client.get_authed(&path).await?;
        let response: CiRunEventsResponse = serde_json::from_str(&raw)
            .map_err(|error| CliError::Other(format!("invalid CI events response: {error}")))?;
        if response.run_id != run_id
            || response.request_event_id != request.request_event_id
            || response.next_cursor > MAX_SAFE_CURSOR
        {
            return Err(CliError::Other(
                "CI events exporter returned conflicting page identity".into(),
            ));
        }
        let page_len = response.events.len();
        if page_len > CI_RUN_EVENT_PAGE_LIMIT as usize {
            return Err(CliError::Other(
                "CI events exporter exceeded the requested page limit".into(),
            ));
        }
        if stored.len().saturating_add(page_len) > MAX_CI_RUN_EVENTS {
            return Err(CliError::Other(
                "CI run history exceeds the bounded reducer window".into(),
            ));
        }
        let expected_next = response
            .events
            .last()
            .map_or(after_cursor, |event| event.watch_cursor);
        if response.next_cursor != expected_next {
            return Err(CliError::Other(
                "CI events exporter next cursor does not match the accepted page".into(),
            ));
        }
        stored.extend(response.events.into_iter().map(|event| StoredRunEvent {
            watch_cursor: event.watch_cursor,
            accepted_at: event.accepted_at,
            event: event.event,
        }));
        after_cursor = response.next_cursor;
        if page_len < CI_RUN_EVENT_PAGE_LIMIT as usize {
            break;
        }
    }
    let accepted = validate_stored_history(&request, &stored, trusted)?;
    Ok(RunHistory {
        request_event_id: request.request_event_id,
        request: request.request,
        stored,
        accepted,
    })
}

async fn fetch_gate_decisions(
    client: &BuzzClient,
    target_repo_a: &str,
    base: &str,
    landed: &str,
) -> Result<MergeGateDecisionsResponse, Refusal> {
    let path = format!(
        "/ci/merge-gate/decisions?target_repo_a={target_repo_a}&ref={MAIN_REF}&new_oid={landed}&old_oid={base}"
    );
    let raw = client
        .get_authed(&path)
        .await
        .map_err(|error| relay_error("merge gate decisions", error))?;
    let response: MergeGateDecisionsResponse = serde_json::from_str(&raw).map_err(|error| {
        Refusal::new(
            "relay_unavailable",
            format!("invalid merge gate decisions response: {error}"),
        )
    })?;
    if response.target_repo_a != target_repo_a
        || response.ref_name != MAIN_REF
        || response.new_oid != landed
    {
        return Err(Refusal::new(
            "relay_unavailable",
            "merge gate decisions answered for another update",
        ));
    }
    Ok(response)
}

/// Fetch the repository's announcement and resolve the effective
/// `require-check` rule for `refs/heads/main`.
async fn fetch_require_checks(
    client: &BuzzClient,
    owner: &str,
    repo_id: &str,
) -> Result<(String, BTreeMap<String, Vec<String>>), Refusal> {
    let filter = serde_json::json!({
        "kinds": [30617],
        "authors": [owner],
        "#d": [repo_id],
    });
    let raw = client
        .query(&filter)
        .await
        .map_err(|error| relay_error("announcement read", error))?;
    let events: Vec<Event> = serde_json::from_str(&raw).map_err(|error| {
        Refusal::new(
            "relay_unavailable",
            format!("invalid announcement response: {error}"),
        )
    })?;
    let announcement = events
        .into_iter()
        .filter(|event| {
            event.kind.as_u16() == 30617
                && event.pubkey.to_hex() == owner
                && event.tags.iter().any(|tag| {
                    tag.as_slice().len() >= 2
                        && tag.as_slice()[0] == "d"
                        && tag.as_slice()[1] == repo_id
                })
        })
        .max_by_key(|event| (event.created_at.as_secs(), event.id.to_hex()))
        .ok_or_else(|| {
            Refusal::new(
                "gate_misconfigured",
                "no kind-30617 announcement for the repository",
            )
        })?;
    announcement.verify().map_err(|_| {
        Refusal::new(
            "gate_misconfigured",
            "announcement signature does not verify",
        )
    })?;
    resolve_require_checks(&announcement).map(|rules| (announcement.id.to_hex(), rules))
}

/// The effective `require-check` rule of an announcement for `refs/heads/main`.
pub fn resolve_require_checks(
    announcement: &Event,
) -> Result<BTreeMap<String, Vec<String>>, Refusal> {
    let raw_tags: Vec<Vec<String>> = announcement
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect();
    let parsed = parse_protection_tags(&raw_tags).map_err(|error| {
        Refusal::new(
            "gate_misconfigured",
            format!("announcement protection rules do not parse: {error}"),
        )
    })?;
    let effective = EffectiveRules::for_ref(MAIN_REF, &parsed.rules);
    if !effective.is_gated() {
        return Err(Refusal::new(
            "gate_misconfigured",
            format!("announcement carries no require-check rule for {MAIN_REF}"),
        ));
    }
    Ok(effective
        .require_checks
        .into_iter()
        .map(|(workflow_id, jobs)| (workflow_id, jobs.into_iter().collect()))
        .collect())
}

// ── History evaluation (shared by verify and validate) ──

/// Everything the history rules need.
pub struct HistoryContext<'a> {
    /// Workflow the rule pins.
    pub workflow_id: &'a str,
    /// Job IDs the rule pins.
    pub pinned_jobs: &'a [String],
    /// Reviewed candidate.
    pub candidate: &'a str,
    /// Reviewed base.
    pub base: &'a str,
    /// Trusted context.
    pub trusted: &'a RunTrustedContext,
    /// Run history.
    pub history: &'a RunHistory,
    /// Clock for the freshness rule.
    pub now: DateTime<Utc>,
    /// Freshness bound.
    pub max_age_seconds: u64,
}

/// Outcome of the history rules.
#[derive(Debug, Default)]
pub struct HistoryOutcome {
    /// Reduced state, when the reducer ran.
    pub reduction: Option<ReductionSummary>,
    /// Selected check, when bound.
    pub check: Option<CheckSummary>,
}

fn summarize(reduction: &CiReduction) -> ReductionSummary {
    ReductionSummary {
        state: reduction.state,
        attempt: reduction.attempt,
        jobs_terminal: reduction.jobs_terminal,
        jobs_total: reduction.jobs_total,
        required_failing: reduction.required_failing.clone(),
    }
}

fn terminal_good(state: CiJobState, skip_policy: CiSkipPolicy) -> bool {
    matches!(state, CiJobState::Success)
        || matches!(
            (state, skip_policy),
            (CiJobState::Skipped, CiSkipPolicy::Allow)
        )
}

/// Apply rules 3 to 7 of design section 1.3 to one run history and record
/// each as a named check. Returns the reduction and the bound check when
/// they exist so the receipt can carry them.
fn evaluate_history(context: &HistoryContext<'_>, ledger: &mut Ledger) -> HistoryOutcome {
    let suffix = context.workflow_id;
    let history = context.history;
    let mut outcome = HistoryOutcome::default();

    // Rule 3: the accepted events reduce to Green for the candidate.
    let reduction = match reduce_verdict(
        &history.request_event_id,
        &history.request,
        &history.accepted,
        context.candidate,
        false,
    ) {
        Ok(reduction) => reduction,
        Err(error) => {
            ledger.refuse(
                &format!("run_history:{suffix}"),
                Refusal::new("reducer_disagrees", error.to_string()),
            );
            return outcome;
        }
    };
    outcome.reduction = Some(summarize(&reduction));
    let green = match reduction.state {
        CiReducedState::Green => Ok((
            (),
            format!(
                "attempt {} reduced Green with {}/{} jobs terminal",
                reduction.attempt, reduction.jobs_terminal, reduction.jobs_total
            ),
        )),
        CiReducedState::Pending => Err(Refusal::new(
            "check_pending",
            format!(
                "attempt {} is Pending with {}/{} jobs terminal",
                reduction.attempt, reduction.jobs_terminal, reduction.jobs_total
            ),
        )),
        CiReducedState::Red => Err(Refusal::new(
            "check_not_success",
            format!(
                "attempt {} reduced Red; required failing: {}",
                reduction.attempt,
                reduction.required_failing.join(",")
            ),
        )),
        CiReducedState::InfrastructureFailure => Err(Refusal::new(
            "reducer_disagrees",
            reduction
                .reason
                .clone()
                .unwrap_or_else(|| "infrastructure failure".into()),
        )),
    };
    ledger.gate(&format!("run_history:{suffix}"), green);

    // Rule 4: every pinned job is requested, required, and terminal-good at
    // its selected attempt.
    let mut missing = Vec::new();
    for job_id in context.pinned_jobs {
        if !history.request.job_ids.contains(job_id) {
            missing.push(format!("{job_id} (not requested)"));
            continue;
        }
        let Some(reduced) = reduction.jobs.iter().find(|job| &job.job_id == job_id) else {
            missing.push(format!("{job_id} (not reduced)"));
            continue;
        };
        if reduced.required != Some(true) {
            missing.push(format!("{job_id} (not required)"));
            continue;
        }
        let selected = history
            .accepted
            .iter()
            .rev()
            .find_map(|event| match &event.envelope {
                ValidatedCiEnvelope::JobStatus(status)
                    if status.job_id == *job_id && status.attempt == reduced.attempt =>
                {
                    Some(status)
                }
                _ => None,
            });
        match selected {
            Some(status) if status.required && terminal_good(status.state, status.skip_policy) => {}
            Some(status) => missing.push(format!(
                "{job_id} ({:?} at attempt {})",
                status.state, status.attempt
            )),
            None => missing.push(format!(
                "{job_id} (no status at attempt {})",
                reduced.attempt
            )),
        }
    }
    ledger.gate(
        &format!("required_jobs:{suffix}"),
        if missing.is_empty() {
            Ok((
                (),
                format!(
                    "pinned jobs terminal-good: {}",
                    context.pinned_jobs.join(",")
                ),
            ))
        } else {
            Err(Refusal::new(
                "required_jobs_missing",
                format!("pinned jobs not satisfied: {}", missing.join("; ")),
            ))
        },
    );

    // Rule 5: the selected check is a success bound to candidate and base.
    let bound = (|| {
        let check = reduction
            .check
            .as_ref()
            .ok_or_else(|| Refusal::new("no_check", "no kind-46108 check for the final request"))?;
        if check.conclusion != CiRunState::Success {
            return Err(Refusal::new(
                "check_not_success",
                format!("check {} concludes {:?}", check.event_id, check.conclusion),
            ));
        }
        let stored = history
            .stored
            .iter()
            .find(|event| event.event.id.to_hex() == check.event_id)
            .ok_or_else(|| {
                Refusal::new(
                    "reducer_disagrees",
                    "selected check is missing from the retained history",
                )
            })?;
        let envelope = history
            .accepted
            .iter()
            .find_map(|event| match &event.envelope {
                ValidatedCiEnvelope::Check(envelope) if event.event_id == check.event_id => {
                    Some(envelope)
                }
                _ => None,
            })
            .ok_or_else(|| {
                Refusal::new(
                    "reducer_disagrees",
                    "selected check did not validate as a kind-46108 envelope",
                )
            })?;
        if envelope.tip_oid != context.candidate {
            return Err(Refusal::new(
                "reducer_disagrees",
                format!("check names tip {}, not the candidate", envelope.tip_oid),
            ));
        }
        if envelope.base_oid != context.base {
            return Err(Refusal::new(
                "base_moved",
                format!(
                    "check names base {}, not {}",
                    envelope.base_oid, context.base
                ),
            ));
        }
        if envelope.relay_signer != stored.event.pubkey.to_hex() {
            return Err(Refusal::new(
                "signer_unauthorized",
                "check relay_signer differs from the event signer",
            ));
        }
        Ok((
            CheckSummary {
                event_id: check.event_id.clone(),
                watch_cursor: stored.watch_cursor,
                accepted_at: stored.accepted_at,
                signer: envelope.relay_signer.clone(),
                conclusion: envelope.conclusion,
                tip_oid: envelope.tip_oid.clone(),
                base_oid: envelope.base_oid.clone(),
                published_at: envelope.published_at,
            },
            format!(
                "check {} success for candidate on base, accepted at cursor {}",
                check.event_id, stored.watch_cursor
            ),
        ))
    })();
    let Some(summary) = ledger.gate(&format!("check_bound:{suffix}"), bound) else {
        return outcome;
    };

    // Rule 6: the signer is in the trusted status-signer set.
    ledger.gate(
        &format!("check_signer:{suffix}"),
        if context.trusted.status_signers.contains(&summary.signer) {
            Ok(((), format!("signer {} is trusted", summary.signer)))
        } else {
            Err(Refusal::new(
                "signer_unauthorized",
                format!("signer {} is not in BUZZ_CI_STATUS_SIGNERS", summary.signer),
            ))
        },
    );

    // Rule 7: fresh by the relay clock.
    let age = context
        .now
        .signed_duration_since(summary.accepted_at)
        .num_seconds();
    ledger.gate(
        &format!("check_fresh:{suffix}"),
        if age <= i64::try_from(context.max_age_seconds).unwrap_or(i64::MAX) {
            Ok((
                (),
                format!(
                    "check accepted {age}s before the verification clock (limit {}s)",
                    context.max_age_seconds
                ),
            ))
        } else {
            Err(Refusal::new(
                "check_expired",
                format!(
                    "check accepted {age}s ago, over the {}s limit",
                    context.max_age_seconds
                ),
            ))
        },
    );
    outcome.check = Some(summary);
    outcome
}

fn retain_history(history: &RunHistory) -> Result<(Vec<RetainedEvent>, String), CliError> {
    let mut retained = Vec::with_capacity(history.stored.len());
    let mut digest = Sha256::new();
    for event in &history.stored {
        let bytes = serde_json::to_vec(&event.event)
            .map_err(|error| CliError::Other(format!("failed to serialize event: {error}")))?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        digest.update(sha256.as_bytes());
        retained.push(RetainedEvent {
            event_id: event.event.id.to_hex(),
            watch_cursor: event.watch_cursor,
            accepted_at: event.accepted_at,
            sha256,
            base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        });
    }
    Ok((retained, hex::encode(digest.finalize())))
}

/// Decode retained bodies, recompute every hash, and rebuild the history.
pub fn restore_history(
    evidence: &RunEvidence,
    trusted: &RunTrustedContext,
) -> Result<RunHistory, Refusal> {
    let mut stored = Vec::with_capacity(evidence.retained_events.len());
    let mut digest = Sha256::new();
    for retained in &evidence.retained_events {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&retained.base64)
            .map_err(|_| {
                Refusal::new(
                    "retained_body_invalid",
                    format!("event {} is not valid base64", retained.event_id),
                )
            })?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        if sha256 != retained.sha256 {
            return Err(Refusal::new(
                "retained_body_tampered",
                format!(
                    "event {} bytes do not match the recorded sha256",
                    retained.event_id
                ),
            ));
        }
        digest.update(sha256.as_bytes());
        let event: Event = serde_json::from_slice(&bytes).map_err(|_| {
            Refusal::new(
                "retained_body_invalid",
                format!("event {} is not a signed event", retained.event_id),
            )
        })?;
        if event.id.to_hex() != retained.event_id {
            return Err(Refusal::new(
                "retained_body_tampered",
                format!(
                    "retained body names {}, not {}",
                    event.id.to_hex(),
                    retained.event_id
                ),
            ));
        }
        stored.push(StoredRunEvent {
            watch_cursor: retained.watch_cursor,
            accepted_at: retained.accepted_at,
            event,
        });
    }
    let history_sha256 = hex::encode(digest.finalize());
    if evidence.history_sha256.as_deref() != Some(history_sha256.as_str()) {
        return Err(Refusal::new(
            "retained_body_tampered",
            "history digest does not match the retained bodies",
        ));
    }
    let request_event_id = evidence
        .request_event_id
        .clone()
        .ok_or_else(|| Refusal::new("retained_body_invalid", "receipt names no request event"))?;
    let request_event = stored
        .iter()
        .find(|event| event.event.id.to_hex() == request_event_id)
        .ok_or_else(|| {
            Refusal::new(
                "retained_body_invalid",
                "retained history omits the request event",
            )
        })?;
    let request = match validate_signed_ci_event(
        &request_event.event,
        &trusted.channel_id,
        &trusted.status_signers,
    ) {
        Ok(ValidatedCiEnvelope::Request(request)) => request,
        Ok(_) => {
            return Err(Refusal::new(
                "retained_body_invalid",
                "recorded request event is not a kind-46100 request",
            ))
        }
        Err(error) => {
            return Err(Refusal::new(
                "retained_body_invalid",
                format!("recorded request does not validate: {error}"),
            ))
        }
    };
    if Some(request.run_id.as_str()) != evidence.run_id.as_deref() {
        return Err(Refusal::new(
            "retained_body_invalid",
            "recorded request names another run",
        ));
    }
    let validated = ValidatedCiRequest {
        request_event_id: request_event_id.clone(),
        request: request.clone(),
        watch_cursor: request_event.watch_cursor,
    };
    let accepted = validate_stored_history(&validated, &stored, trusted)
        .map_err(|error| Refusal::new("retained_body_invalid", error.to_string()))?;
    Ok(RunHistory {
        request_event_id,
        request,
        stored,
        accepted,
    })
}

// ── Gate decision, mirror, desktop ──

/// Apply the decision rule to the rows read for `(main, base, landed)`.
pub fn evaluate_gate_decision(
    response_mode: &str,
    decisions: &[DecisionRow],
    allow_shadow: bool,
) -> (bool, Result<String, Refusal>) {
    if response_mode == "off" {
        return (
            false,
            Ok(format!(
                "merge gate mode is off; {} decision rows recorded, none required",
                decisions.len()
            )),
        );
    }
    let Some(latest) = decisions.first() else {
        return (
            true,
            Err(Refusal::new(
                "no_decision",
                format!(
                    "merge gate mode is {response_mode} and no decision row exists for the update"
                ),
            )),
        );
    };
    if latest.code != "allow" {
        return (
            true,
            Err(Refusal::new(
                &latest.code,
                format!("latest decision {} refused with {}", latest.id, latest.code),
            )),
        );
    }
    if latest.mode == "shadow" && !allow_shadow {
        return (
            true,
            Err(Refusal::new(
                "gate_shadow",
                format!(
                    "latest allow decision {} was recorded in shadow mode; pass --allow-shadow during the mixed period",
                    latest.id
                ),
            )),
        );
    }
    let bypass = latest
        .bypass_event_id
        .as_deref()
        .map_or(String::new(), |id| format!(" via bypass {id}"));
    (
        true,
        Ok(format!(
            "decision {} allowed in {} mode{bypass}",
            latest.id, latest.mode
        )),
    )
}

/// Non-gating mirror parity from a `gh api` read of the mirror's main.
pub fn evaluate_mirror(
    repository: &str,
    landed: &str,
    read: Result<String, String>,
) -> (MirrorEvidence, Result<String, Refusal>) {
    let read_at = Utc::now();
    match read {
        Ok(sha) if sha == landed => (
            MirrorEvidence {
                repository: repository.to_owned(),
                read_at,
                sha: Some(sha),
                agrees: Some(true),
                error: None,
            },
            Ok(format!("mirror {repository} main names {landed}")),
        ),
        Ok(sha) => (
            MirrorEvidence {
                repository: repository.to_owned(),
                read_at,
                sha: Some(sha.clone()),
                agrees: Some(false),
                error: None,
            },
            Err(Refusal::new(
                "mirror_lag",
                format!(
                    "mirror {repository} main names {sha}, not {landed}; the mirror timer lags"
                ),
            )),
        ),
        Err(error) => (
            MirrorEvidence {
                repository: repository.to_owned(),
                read_at,
                sha: None,
                agrees: None,
                error: Some(error.clone()),
            },
            Err(Refusal::new(
                "mirror_unavailable",
                format!("mirror {repository} read failed: {error}"),
            )),
        ),
    }
}

fn read_mirror_main(repository: &str) -> Result<String, String> {
    let output = Command::new("gh")
        .args([
            "api",
            &format!("repos/{repository}/git/ref/heads/main"),
            "--jq",
            ".object.sha",
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| format!("gh could not start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !is_full_oid(&sha) {
        return Err(format!("gh api returned a non-OID: {sha:?}"));
    }
    Ok(sha)
}

/// Whether the desktop candidate identity differs between `landed` and its
/// first parent: the metadata blob `desktop_release.py` keys its identity
/// on. A changed blob puts `verify-main` in release mode, which queries the
/// pull request on the GitHub repository it is given.
fn desktop_identity_changed(checkout: &Path, landed: &str) -> Result<bool, Refusal> {
    let entry = |commit: &str| {
        git_line(checkout, &["ls-tree", commit, "--", DESKTOP_METADATA])
            .map_err(|error| Refusal::new("desktop_verify_main_failed", error))
    };
    let current = entry(landed)?;
    let parent = entry(&format!("{landed}^1"))?;
    Ok(current != parent)
}

/// Run the maintained desktop identity gate on the landed commit after
/// proving the checkout's verifier bytes equal the landed tree's.
fn desktop_verify_main(
    checkout: &Path,
    landed: &str,
    mirror: Option<&str>,
) -> Result<String, Refusal> {
    let committed = git_output(checkout, &["show", &format!("{landed}:{DESKTOP_VERIFIER}")])
        .map_err(|error| Refusal::new("desktop_verifier_source_differs", error))?;
    let local = std::fs::read(checkout.join(DESKTOP_VERIFIER)).map_err(|error| {
        Refusal::new(
            "desktop_verifier_source_differs",
            format!("cannot read {DESKTOP_VERIFIER} in the checkout: {error}"),
        )
    })?;
    if committed != local {
        return Err(Refusal::new(
            "desktop_verifier_source_differs",
            format!("{DESKTOP_VERIFIER} in the checkout differs from the landed tree"),
        ));
    }
    if mirror.is_none() && desktop_identity_changed(checkout, landed)? {
        return Err(Refusal::new(
            "desktop_release_repo_unset",
            format!(
                "{DESKTOP_METADATA} changed between {landed} and its first parent, so verify-main \
                 needs the release pull request; pass --github-mirror owner/repo"
            ),
        ));
    }
    // -I isolates the interpreter from the checkout's `scripts/` directory and
    // the caller's PYTHON* environment, so an untracked module cannot shadow
    // the standard library the maintained gate imports.
    let mut command = Command::new("python3");
    command
        .args(["-I", DESKTOP_VERIFIER])
        .args(["verify-main", "--commit", landed]);
    if let Some(mirror) = mirror {
        command.args(["--repo", mirror]);
    }
    command
        .current_dir(checkout)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_TERMINAL_PROMPT", "0");
    for name in ["HOME", "LANG", "GH_TOKEN", "GITHUB_TOKEN"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let output = command.output().map_err(|error| {
        Refusal::new(
            "desktop_verify_main_failed",
            format!("python3 could not start: {error}"),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(Refusal::new(
            "desktop_verify_main_failed",
            format!(
                "verify-main exited {}: {} {}",
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            ),
        ));
    }
    Ok(format!(
        "{DESKTOP_VERIFIER} verify-main passed for {landed}: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

// ── Receipt files ──

fn parent_of(path: &Path) -> Result<&Path, CliError> {
    if !path.is_absolute() {
        return Err(CliError::Usage("receipt path must be absolute".into()));
    }
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) if !name.is_empty() && name != "." && name != ".." && !name.starts_with('.') => {
        }
        _ => return Err(CliError::Usage("receipt basename is invalid".into())),
    }
    path.parent()
        .ok_or_else(|| CliError::Usage("receipt path has no parent".into()))
}

fn check_private_parent(parent: &Path) -> Result<std::fs::Metadata, CliError> {
    let info = std::fs::symlink_metadata(parent)
        .map_err(|error| CliError::Usage(format!("cannot stat receipt parent: {error}")))?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err(CliError::Usage(
            "receipt parent must be a non-symlink directory".into(),
        ));
    }
    let canonical = parent
        .canonicalize()
        .map_err(|error| CliError::Usage(format!("receipt parent is not canonical: {error}")))?;
    if canonical != parent {
        return Err(CliError::Usage(
            "receipt parent path must be canonical".into(),
        ));
    }
    let euid = nix::unistd::geteuid().as_raw();
    if info.uid() != euid || info.mode() & 0o7777 != 0o700 {
        return Err(CliError::Usage(
            "receipt parent must be owned by the caller with mode 0700".into(),
        ));
    }
    Ok(info)
}

/// Publish a receipt create-only: a mode-0600 temporary in the mode-0700
/// parent, fsync, byte read-back, then a hard link to the final name (which
/// fails when the name exists) and removal of the temporary.
pub fn publish_receipt(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = parent_of(path)?;
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(CliError::Other("receipt exceeds the size limit".into()));
    }
    let parent_info = check_private_parent(parent)?;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(CliError::Usage("receipt output already exists".into()));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CliError::Usage("receipt basename is invalid".into()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| CliError::Other(format!("cannot create receipt: {error}")))?;
        let initial = file
            .metadata()
            .map_err(|error| CliError::Other(format!("cannot stat receipt: {error}")))?;
        if !initial.is_file()
            || initial.mode() & 0o7777 != 0o600
            || initial.nlink() != 1
            || initial.uid() != parent_info.uid()
        {
            return Err(CliError::Other(
                "temporary receipt metadata mismatch".into(),
            ));
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| CliError::Other(format!("cannot write receipt: {error}")))?;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|error| CliError::Other(format!("cannot read receipt back: {error}")))?;
        let mut readback = Vec::with_capacity(bytes.len());
        file.take(MAX_RECEIPT_BYTES as u64 + 1)
            .read_to_end(&mut readback)
            .map_err(|error| CliError::Other(format!("cannot read receipt back: {error}")))?;
        if readback != bytes {
            return Err(CliError::Other(
                "temporary receipt readback mismatch".into(),
            ));
        }
        std::fs::hard_link(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CliError::Usage("receipt output already exists".into())
            } else {
                CliError::Other(format!("cannot publish receipt: {error}"))
            }
        })?;
        std::fs::remove_file(&temporary).map_err(|error| {
            CliError::Other(format!("cannot remove temporary receipt: {error}"))
        })?;
        let published = std::fs::symlink_metadata(path)
            .map_err(|error| CliError::Other(format!("cannot stat published receipt: {error}")))?;
        if !published.is_file()
            || (published.dev(), published.ino()) != (initial.dev(), initial.ino())
            || published.mode() & 0o7777 != 0o600
            || published.nlink() != 1
            || published.len() != bytes.len() as u64
        {
            return Err(CliError::Other(
                "published receipt metadata mismatch".into(),
            ));
        }
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| CliError::Other(format!("cannot sync receipt parent: {error}")))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Read a receipt under the same parent rule, refusing symlinks, foreign
/// owners, extra links, and oversized files.
pub fn read_receipt(path: &Path) -> Result<Vec<u8>, CliError> {
    let parent = parent_of(path)?;
    let parent_info = check_private_parent(parent)?;
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| CliError::Usage(format!("cannot stat receipt: {error}")))?;
    if !before.is_file()
        || before.uid() != parent_info.uid()
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() > MAX_RECEIPT_BYTES as u64
    {
        return Err(CliError::Usage(
            "receipt must be a caller-owned mode-0600 regular file with one link under the size limit".into(),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|error| CliError::Usage(format!("cannot open receipt: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| CliError::Usage(format!("cannot stat receipt: {error}")))?;
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
        return Err(CliError::Usage(
            "receipt identity changed during read".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(MAX_RECEIPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::Usage(format!("cannot read receipt: {error}")))?;
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(CliError::Usage("receipt exceeds the size limit".into()));
    }
    Ok(bytes)
}

// ── Verify ──

/// Run every proof against the relay at `client` and the git remote at
/// `git_url`, publish the receipt, and return it.
pub async fn verify_landing(
    client: &BuzzClient,
    args: &LandingVerifyArgs,
    trusted: &RunTrustedContext,
    git_url: &str,
) -> Result<LandingReceipt, CliError> {
    for (flag, value) in [
        ("--candidate", &args.candidate),
        ("--base", &args.base),
        ("--landed", &args.landed),
    ] {
        if !is_full_oid(value) {
            return Err(CliError::Usage(format!(
                "{flag} must be a full lowercase hex object ID"
            )));
        }
    }
    crate::validate::validate_hex64(&args.repo_owner)?;
    if args.repo_id.is_empty() || args.repo_id.contains(['/', ':']) {
        return Err(CliError::Usage(
            "--repo-id must be a bare repository id".into(),
        ));
    }
    let parent = parent_of(&args.output)?;
    check_private_parent(parent)?;
    if std::fs::symlink_metadata(&args.output).is_ok() {
        return Err(CliError::Usage("receipt output already exists".into()));
    }
    let checkout = args.checkout.canonicalize().map_err(|error| {
        CliError::Usage(format!("--checkout is not a readable directory: {error}"))
    })?;

    let target_repo_a = format!("30617:{}:{}", args.repo_owner, args.repo_id);
    let git = GitRepo::new(auth_from_client(client), GitHubAuth::absent())?;
    let now = Utc::now();
    let mut ledger = Ledger::default();
    let mut relay_main = vec![read_relay_main(&git, git_url)];

    // Objects, parents, tree, ancestry.
    let mut objects = Vec::new();
    for (what, oid) in [
        ("landed", &args.landed),
        ("candidate", &args.candidate),
        ("base", &args.base),
    ] {
        if let Err(error) = git_output(&checkout, &["cat-file", "-e", &format!("{oid}^{{commit}}")])
        {
            objects.push(format!("{what} {oid}: {error}"));
        }
    }
    let objects_present = ledger
        .gate(
            "objects_present",
            if objects.is_empty() {
                Ok((
                    (),
                    "landed, candidate, and base commits are present".to_owned(),
                ))
            } else {
                Err(Refusal::new("object_missing", objects.join("; ")))
            },
        )
        .is_some();
    let mut classification = "unknown";
    if objects_present {
        let shape = git_line(
            &checkout,
            &["rev-list", "--parents", "-n", "1", &args.landed],
        )
        .map_err(|error| Refusal::new("parent_shape", error))
        .and_then(|line| classify_parents(&args.landed, &args.candidate, &args.base, &line))
        .map(|class| (class, format!("landed is a {class} of base and candidate")));
        if let Some(class) = ledger.gate("parent_shape", shape) {
            classification = class;
        }
        let trees = git_line(
            &checkout,
            &["rev-parse", &format!("{}^{{tree}}", args.landed)],
        )
        .and_then(|landed_tree| {
            git_line(
                &checkout,
                &["rev-parse", &format!("{}^{{tree}}", args.candidate)],
            )
            .map(|candidate_tree| (landed_tree, candidate_tree))
        })
        .map_err(|error| Refusal::new("tree_mismatch", error))
        .and_then(|(landed_tree, candidate_tree)| {
            if landed_tree == candidate_tree {
                Ok(((), format!("landed and candidate share tree {landed_tree}")))
            } else {
                Err(Refusal::new(
                    "tree_mismatch",
                    format!(
                        "landed tree {landed_tree} differs from candidate tree {candidate_tree}"
                    ),
                ))
            }
        });
        ledger.gate("tree_match", trees);
        let ancestry = match git_output(
            &checkout,
            &["merge-base", "--is-ancestor", &args.base, &args.candidate],
        ) {
            Ok(_) => Ok(((), "base is an ancestor of the candidate".to_owned())),
            Err(error) => Err(Refusal::new("not_descendant", error)),
        };
        ledger.gate("base_ancestry", ancestry);
    } else {
        for name in ["parent_shape", "tree_match", "base_ancestry"] {
            ledger.refuse(
                name,
                Refusal::new("object_missing", "commit objects are missing"),
            );
        }
    }

    // The owner-signed rule.
    let mut announcement_event_id = None;
    let mut require_checks = BTreeMap::new();
    match fetch_require_checks(client, &args.repo_owner, &args.repo_id).await {
        Ok((event_id, rules)) => {
            announcement_event_id = Some(event_id);
            require_checks = rules;
            let rendered: Vec<String> = require_checks
                .iter()
                .map(|(workflow, jobs)| format!("{workflow}:{}", jobs.join("+")))
                .collect();
            ledger.record(
                "require_check_rule",
                true,
                Ok(format!("{MAIN_REF} requires {}", rendered.join(" "))),
            );
        }
        Err(refusal) => ledger.refuse("require_check_rule", refusal),
    }

    // Per workflow: latest run, digest, history, check.
    let mut runs = Vec::new();
    for (workflow_id, pinned_jobs) in &require_checks {
        let mut evidence = RunEvidence {
            workflow_id: workflow_id.clone(),
            pinned_jobs: pinned_jobs.clone(),
            workflow_path: WORKFLOW_PATH.to_owned(),
            base_workflow_digest: None,
            run_id: None,
            request_event_id: None,
            run_base_oid: None,
            run_workflow_digest: None,
            reduction: None,
            check: None,
            retained_events: Vec::new(),
            history_sha256: None,
        };
        let base_digest = if objects_present {
            git_output(
                &checkout,
                &["show", &format!("{}:{WORKFLOW_PATH}", args.base)],
            )
            .map(|bytes| hex::encode(Sha256::digest(&bytes)))
            .ok()
        } else {
            None
        };
        evidence.base_workflow_digest = base_digest.clone();

        let listing =
            fetch_checks_for_tip(client, &target_repo_a, &args.candidate, workflow_id).await;
        let selected = listing.and_then(|listing| {
            let run = listing.runs.into_iter().next().ok_or_else(|| {
                Refusal::new(
                    "no_check",
                    format!(
                        "no run for workflow {workflow_id} tests candidate {}",
                        args.candidate
                    ),
                )
            })?;
            if run.workflow_id != *workflow_id || run.tip_oid != args.candidate {
                return Err(Refusal::new(
                    "relay_unavailable",
                    "run listing returned a run for another workflow or tip",
                ));
            }
            Ok(run)
        });
        let Some(run) = ledger.gate(
            &format!("run_selected:{workflow_id}"),
            selected.map(|run| {
                let detail = format!(
                    "latest run {} requested at base {}",
                    run.run_id, run.base_oid
                );
                (run, detail)
            }),
        ) else {
            for name in [
                "run_base",
                "workflow_digest",
                "run_history",
                "required_jobs",
                "check_bound",
                "check_signer",
                "check_fresh",
                "check_listed",
            ] {
                ledger.refuse(
                    &format!("{name}:{workflow_id}"),
                    Refusal::new("no_check", "no run was selected"),
                );
            }
            runs.push(evidence);
            continue;
        };
        evidence.run_id = Some(run.run_id.clone());
        evidence.request_event_id = Some(run.request_event_id.clone());
        evidence.run_base_oid = Some(run.base_oid.clone());
        evidence.run_workflow_digest = Some(run.workflow_digest.clone());

        ledger.gate(
            &format!("run_base:{workflow_id}"),
            if run.base_oid == args.base {
                Ok((
                    (),
                    format!("run base {} equals the reviewed base", run.base_oid),
                ))
            } else {
                Err(Refusal::new(
                    "base_moved",
                    format!(
                        "run base {} is not the reviewed base {}",
                        run.base_oid, args.base
                    ),
                ))
            },
        );
        ledger.gate(
            &format!("workflow_digest:{workflow_id}"),
            match &base_digest {
                Some(digest) if *digest == run.workflow_digest => Ok((
                    (),
                    format!("run workflow digest equals sha256({WORKFLOW_PATH} at base) {digest}"),
                )),
                Some(digest) => Err(Refusal::new(
                    "workflow_digest_mismatch",
                    format!(
                        "run digest {} differs from the base workflow digest {digest}",
                        run.workflow_digest
                    ),
                )),
                None => Err(Refusal::new(
                    "gate_misconfigured",
                    format!("{WORKFLOW_PATH} is not readable at base {}", args.base),
                )),
            },
        );

        match fetch_run_history(client, &run.run_id, trusted).await {
            Ok(history) => {
                if history.request_event_id != run.request_event_id {
                    ledger.refuse(
                        &format!("run_history:{workflow_id}"),
                        Refusal::new(
                            "reducer_disagrees",
                            "run listing and run request name different request events",
                        ),
                    );
                    runs.push(evidence);
                    continue;
                }
                let (retained, history_sha256) = retain_history(&history)?;
                evidence.retained_events = retained;
                evidence.history_sha256 = Some(history_sha256);
                let outcome = evaluate_history(
                    &HistoryContext {
                        workflow_id,
                        pinned_jobs,
                        candidate: &args.candidate,
                        base: &args.base,
                        trusted,
                        history: &history,
                        now,
                        max_age_seconds: args.max_age_seconds,
                    },
                    &mut ledger,
                );
                evidence.reduction = outcome.reduction;
                if let Some(check) = &outcome.check {
                    let listed = run
                        .checks
                        .iter()
                        .find(|stored| stored.event.id.to_hex() == check.event_id);
                    ledger.gate(
                        &format!("check_listed:{workflow_id}"),
                        match listed {
                            Some(stored)
                                if stored.accepted_at == check.accepted_at
                                    && stored.watch_cursor == check.watch_cursor
                                    && stored.event
                                        == history.stored[check.watch_cursor as usize - 1]
                                            .event =>
                            {
                                Ok((
                                    (),
                                    format!(
                                        "run listing stores check {} with the same accepted_at",
                                        check.event_id
                                    ),
                                ))
                            }
                            Some(_) => Err(Refusal::new(
                                "reducer_disagrees",
                                "run listing stores the check with different acceptance metadata",
                            )),
                            None => Err(Refusal::new(
                                "no_check",
                                format!("run listing does not store check {}", check.event_id),
                            )),
                        },
                    );
                }
                evidence.check = outcome.check;
            }
            Err(error) => {
                ledger.refuse(
                    &format!("run_history:{workflow_id}"),
                    Refusal::new("history_unavailable", error.to_string()),
                );
            }
        }
        runs.push(evidence);
    }

    // Merge-gate decision.
    let gate_decision =
        match fetch_gate_decisions(client, &target_repo_a, &args.base, &args.landed).await {
            Ok(response) => {
                let (gating, outcome) =
                    evaluate_gate_decision(&response.mode, &response.decisions, args.allow_shadow);
                ledger.record("gate_decision", gating, outcome);
                GateDecisionEvidence {
                    mode: Some(response.mode),
                    gating,
                    decisions: response.decisions,
                    error: None,
                }
            }
            Err(refusal) => {
                let detail = refusal.detail.clone();
                ledger.refuse("gate_decision", refusal);
                GateDecisionEvidence {
                    mode: None,
                    gating: true,
                    decisions: Vec::new(),
                    error: Some(detail),
                }
            }
        };

    // Relay main again, after every relay read.
    relay_main.push(read_relay_main(&git, git_url));
    ledger.record(
        "relay_main",
        true,
        evaluate_relay_main(&relay_main, &args.landed),
    );

    // Mirror parity, non-gating.
    let mirror = args.github_mirror.as_deref().map(|repository| {
        let (evidence, outcome) =
            evaluate_mirror(repository, &args.landed, read_mirror_main(repository));
        if let Err(refusal) = &outcome {
            eprintln!("warning: {}", refusal.detail);
        }
        ledger.record("github_mirror", false, outcome);
        evidence
    });

    // Desktop identity.
    if objects_present {
        ledger.record(
            "desktop_verify_main",
            true,
            desktop_verify_main(&checkout, &args.landed, args.github_mirror.as_deref()),
        );
    } else {
        ledger.refuse(
            "desktop_verify_main",
            Refusal::new("object_missing", "commit objects are missing"),
        );
    }

    let verdict = if all_gating_pass(&ledger.checks) {
        "PASS"
    } else {
        "REFUSED"
    };
    let mut status_signers: Vec<String> = trusted.status_signers.iter().cloned().collect();
    status_signers.sort();
    let receipt = LandingReceipt {
        policy: LANDING_POLICY.to_owned(),
        schema_version: LANDING_SCHEMA_VERSION,
        repository: RepositoryRecord {
            target_repo_a,
            relay_url: client.relay_url().to_owned(),
            git_url: git_url.to_owned(),
            announcement_event_id,
        },
        landed: args.landed.clone(),
        candidate: args.candidate.clone(),
        base: args.base.clone(),
        classification: classification.to_owned(),
        checkout: checkout.display().to_string(),
        relay_main,
        require_checks,
        trusted: TrustedContextRecord {
            channel_id: trusted.channel_id.clone(),
            status_signers,
        },
        max_age_seconds: args.max_age_seconds,
        allow_shadow: args.allow_shadow,
        runs,
        gate_decision,
        mirror,
        landing_checks: ledger.checks,
        verdict: verdict.to_owned(),
        timestamp: now,
    };
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|error| CliError::Other(format!("failed to serialize receipt: {error}")))?;
    publish_receipt(&args.output, &bytes)?;
    Ok(receipt)
}

fn refusals(checks: &[LandingCheck]) -> Vec<serde_json::Value> {
    checks
        .iter()
        .filter(|check| check.result != CheckResult::Pass)
        .map(|check| {
            serde_json::json!({
                "name": check.name,
                "gating": check.gating,
                "code": check.code,
            })
        })
        .collect()
}

/// `buzz ci landing` entry point.
pub async fn cmd_landing(
    client: &BuzzClient,
    args: &LandingVerifyArgs,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let git_url = relay_git_url(client.relay_url(), &args.repo_owner, &args.repo_id);
    cmd_landing_with_git_url(client, args, trusted, &git_url).await
}

async fn cmd_landing_with_git_url(
    client: &BuzzClient,
    args: &LandingVerifyArgs,
    trusted: &RunTrustedContext,
    git_url: &str,
) -> Result<(), CliError> {
    let receipt = verify_landing(client, args, trusted, git_url).await?;
    let summary = serde_json::json!({
        "receipt": args.output.display().to_string(),
        "policy": receipt.policy,
        "landed": receipt.landed,
        "candidate": receipt.candidate,
        "base": receipt.base,
        "classification": receipt.classification,
        "verdict": receipt.verdict,
        "checks": receipt.landing_checks.len(),
        "refusals": refusals(&receipt.landing_checks),
    });
    println!("{summary}");
    if receipt.verdict == "PASS" {
        Ok(())
    } else {
        let codes: Vec<String> = receipt
            .landing_checks
            .iter()
            .filter(|check| check.gating && check.result != CheckResult::Pass)
            .map(|check| {
                format!(
                    "{}={}",
                    check.name,
                    check.code.as_deref().unwrap_or("refused")
                )
            })
            .collect();
        Err(CliError::Usage(format!(
            "landing refused: {}",
            codes.join(" ")
        )))
    }
}

// ── Validate ──

/// Where offline validation anchors the receipt's recorded trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchor {
    /// `BUZZ_CI_CHANNEL` and `BUZZ_CI_STATUS_SIGNERS` were exported and the
    /// receipt's context is within them.
    Environment,
    /// No environment context; the live relay reads with `--reverify` anchor
    /// the recorded check instead.
    Relay,
    /// No environment context and no live reads: offline PASS proves the
    /// receipt is self-consistent, not that its signer set had authority.
    Unanchored,
}

/// Compare the receipt's recorded trust with the operator's exported context.
pub fn evaluate_trust_anchor(
    receipt: &LandingReceipt,
    anchor: Option<&RunTrustedContext>,
    reverify: bool,
) -> (TrustAnchor, bool, Result<String, Refusal>) {
    match anchor {
        Some(anchor) => {
            let foreign: Vec<&String> = receipt
                .trusted
                .status_signers
                .iter()
                .filter(|signer| !anchor.status_signers.contains(*signer))
                .collect();
            if receipt.trusted.channel_id != anchor.channel_id {
                (
                    TrustAnchor::Environment,
                    true,
                    Err(Refusal::new(
                        "trusted_context_mismatch",
                        format!(
                            "receipt channel {} is not BUZZ_CI_CHANNEL {}",
                            receipt.trusted.channel_id, anchor.channel_id
                        ),
                    )),
                )
            } else if !foreign.is_empty() {
                (
                    TrustAnchor::Environment,
                    true,
                    Err(Refusal::new(
                        "trusted_context_mismatch",
                        format!(
                            "receipt signers outside BUZZ_CI_STATUS_SIGNERS: {}",
                            foreign
                                .iter()
                                .map(|signer| signer.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    )),
                )
            } else {
                (
                    TrustAnchor::Environment,
                    true,
                    Ok(format!(
                        "receipt channel and {} signer(s) are within the exported trusted context",
                        receipt.trusted.status_signers.len()
                    )),
                )
            }
        }
        None if reverify => (
            TrustAnchor::Relay,
            false,
            Err(Refusal::new(
                "trusted_context_unanchored",
                "BUZZ_CI_CHANNEL and BUZZ_CI_STATUS_SIGNERS are unset; the live relay reads anchor the recorded check",
            )),
        ),
        None => (
            TrustAnchor::Unanchored,
            true,
            Err(Refusal::new(
                "trusted_context_unanchored",
                "BUZZ_CI_CHANNEL and BUZZ_CI_STATUS_SIGNERS are unset and --reverify was not given; \
                 offline validation cannot prove the recorded signer set had authority",
            )),
        ),
    }
}

/// Offline replay of a receipt: trust anchor, hashes, signatures, reducer,
/// and rules. `anchor` is the operator's exported trusted context; without
/// it, and without `reverify`, the replay refuses `trusted_context_unanchored`.
pub fn validate_receipt_offline(
    receipt: &LandingReceipt,
    max_age_seconds: u64,
    anchor: Option<&RunTrustedContext>,
    reverify: bool,
) -> (TrustAnchor, Vec<LandingCheck>) {
    let mut ledger = Ledger::default();
    let now = Utc::now();
    let (trust, gating, outcome) = evaluate_trust_anchor(receipt, anchor, reverify);
    ledger.record("trusted_context", gating, outcome);
    ledger.gate(
        "receipt_policy",
        if receipt.policy == LANDING_POLICY && receipt.schema_version == LANDING_SCHEMA_VERSION {
            Ok((
                (),
                format!("{} schema {}", receipt.policy, receipt.schema_version),
            ))
        } else {
            Err(Refusal::new(
                "receipt_policy_unknown",
                format!("{} schema {}", receipt.policy, receipt.schema_version),
            ))
        },
    );
    let age = now.signed_duration_since(receipt.timestamp).num_seconds();
    ledger.gate(
        "receipt_fresh",
        if age <= i64::try_from(max_age_seconds).unwrap_or(i64::MAX) {
            Ok((
                (),
                format!("receipt is {age}s old (limit {max_age_seconds}s)"),
            ))
        } else {
            Err(Refusal::new(
                "receipt_expired",
                format!("receipt is {age}s old, over the {max_age_seconds}s limit"),
            ))
        },
    );
    ledger.gate(
        "receipt_verdict",
        if receipt.all_gating_pass() == (receipt.verdict == "PASS") {
            Ok((
                (),
                format!(
                    "recorded verdict {} agrees with the recorded checks",
                    receipt.verdict
                ),
            ))
        } else {
            Err(Refusal::new(
                "receipt_inconsistent",
                "recorded verdict disagrees with the recorded gating checks",
            ))
        },
    );
    let trusted = RunTrustedContext {
        channel_id: receipt.trusted.channel_id.clone(),
        status_signers: receipt.trusted.status_signers.iter().cloned().collect(),
    };
    ledger.gate(
        "receipt_rule",
        if receipt.require_checks.is_empty() {
            Err(Refusal::new(
                "gate_misconfigured",
                "receipt records no require-check rule",
            ))
        } else if receipt
            .require_checks
            .keys()
            .all(|workflow| receipt.runs.iter().any(|run| &run.workflow_id == workflow))
        {
            Ok(((), "every pinned workflow has run evidence".to_owned()))
        } else {
            Err(Refusal::new(
                "receipt_inconsistent",
                "a pinned workflow has no run evidence",
            ))
        },
    );
    for evidence in &receipt.runs {
        let name = format!("retained_bodies:{}", evidence.workflow_id);
        let Some(history) = ledger.gate(
            &name,
            restore_history(evidence, &trusted).map(|history| {
                let detail = format!(
                    "{} retained bodies re-hash and re-validate",
                    history.stored.len()
                );
                (history, detail)
            }),
        ) else {
            continue;
        };
        let pinned = receipt
            .require_checks
            .get(&evidence.workflow_id)
            .cloned()
            .unwrap_or_default();
        let outcome = evaluate_history(
            &HistoryContext {
                workflow_id: &evidence.workflow_id,
                pinned_jobs: &pinned,
                candidate: &receipt.candidate,
                base: &receipt.base,
                trusted: &trusted,
                history: &history,
                now: receipt.timestamp,
                max_age_seconds: receipt.max_age_seconds,
            },
            &mut ledger,
        );
        ledger.gate(
            &format!("recorded_check:{}", evidence.workflow_id),
            if outcome.check == evidence.check && outcome.reduction == evidence.reduction {
                Ok((
                    (),
                    "replayed check and reduction equal the recorded ones".to_owned(),
                ))
            } else {
                Err(Refusal::new(
                    "receipt_inconsistent",
                    "replayed check or reduction differs from the recorded ones",
                ))
            },
        );
    }
    (trust, ledger.checks)
}

/// `buzz ci landing validate` entry point.
pub async fn cmd_landing_validate(
    client: &BuzzClient,
    receipt_path: &Path,
    reverify: bool,
    max_age_seconds: u64,
) -> Result<(), CliError> {
    let anchor = crate::commands::ci::dispatch::resolve_optional_trusted_context()?;
    let bytes = read_receipt(receipt_path)?;
    let receipt: LandingReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::Usage(format!("receipt is not a landing receipt: {error}")))?;
    let (trust, mut checks) =
        validate_receipt_offline(&receipt, max_age_seconds, anchor.as_ref(), reverify);
    if reverify {
        checks.extend(reverify_live(client, &receipt).await);
    }
    let valid = all_gating_pass(&checks);
    let summary = serde_json::json!({
        "receipt": receipt_path.display().to_string(),
        "policy": receipt.policy,
        "landed": receipt.landed,
        "recorded_verdict": receipt.verdict,
        "reverified": reverify,
        "trust": trust,
        "verdict": if valid && receipt.verdict == "PASS" { "PASS" } else { "REFUSED" },
        "checks": checks,
    });
    println!("{summary}");
    if valid && receipt.verdict == "PASS" {
        Ok(())
    } else {
        Err(CliError::Usage("receipt validation refused".into()))
    }
}

/// Repeat the relay main, run listing, and merge-gate reads live.
async fn reverify_live(client: &BuzzClient, receipt: &LandingReceipt) -> Vec<LandingCheck> {
    let mut ledger = Ledger::default();
    let live = match GitRepo::new(auth_from_client(client), GitHubAuth::absent()) {
        Ok(git) => {
            let reads = vec![read_relay_main(&git, &receipt.repository.git_url)];
            evaluate_relay_main(&reads, &receipt.landed)
        }
        Err(error) => Err(Refusal::new("relay_main_unavailable", error.to_string())),
    };
    ledger.record("reverify_relay_main", true, live);

    for evidence in &receipt.runs {
        let name = format!("reverify_run_selected:{}", evidence.workflow_id);
        let outcome = fetch_checks_for_tip(
            client,
            &receipt.repository.target_repo_a,
            &receipt.candidate,
            &evidence.workflow_id,
        )
        .await
        .and_then(|listing| {
            let run =
                listing.runs.into_iter().next().ok_or_else(|| {
                    Refusal::new("no_check", "no run tests the candidate any more")
                })?;
            if Some(run.run_id.as_str()) != evidence.run_id.as_deref() {
                return Err(Refusal::new(
                    "run_superseded",
                    format!("latest run is now {}, not the recorded run", run.run_id),
                ));
            }
            let listed = evidence.check.as_ref().is_some_and(|check| {
                run.checks.iter().any(|stored| {
                    stored.event.id.to_hex() == check.event_id
                        && stored.accepted_at == check.accepted_at
                })
            });
            if !listed {
                return Err(Refusal::new(
                    "no_check",
                    "the recorded check is no longer stored with the same accepted_at",
                ));
            }
            Ok(format!(
                "run {} is still the latest with its check stored",
                run.run_id
            ))
        });
        ledger.record(&name, true, outcome);
    }

    let decision = fetch_gate_decisions(
        client,
        &receipt.repository.target_repo_a,
        &receipt.base,
        &receipt.landed,
    )
    .await;
    match decision {
        Ok(response) => {
            let (gating, outcome) =
                evaluate_gate_decision(&response.mode, &response.decisions, receipt.allow_shadow);
            ledger.record("reverify_gate_decision", gating, outcome);
        }
        Err(refusal) => ledger.refuse("reverify_gate_decision", refusal),
    }
    ledger.checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::{Method, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use buzz_core::ci::{
        check_tags, evidence_finalized_tags, job_status_tags, log_reference_tags, request_tags,
        run_status_tags, teardown_attestation_tags, CiCheckEnvelope, CiConcurrencyGroup,
        CiEvidenceFinalizedEnvelope, CiFinalizedJobAttempt, CiJobStatusEnvelope,
        CiLogReferenceEnvelope, CiRequestType, CiRunStatusEnvelope, CiTeardownAttestationEnvelope,
        CiTeardownLease, CI_SCHEMA_VERSION,
    };
    use buzz_core::kind::{
        KIND_CI_CHECK, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS, KIND_CI_LOG_REFERENCE,
        KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
    };
    use nostr::{EventBuilder, Keys, Kind};
    use std::collections::{HashMap, HashSet};
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const CHANNEL: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const RUN_ID: &str = "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45";
    const OTHER_RUN_ID: &str = "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd46";

    // ── signed green-run fixture (mirrors buzz-core reducer `green_events`) ──

    struct Fixture {
        actor: Keys,
        control: Keys,
        target_repo_a: String,
        tip: String,
        base: String,
        workflow_digest: String,
        run_id: String,
        jobs: Vec<String>,
    }

    fn request_envelope(fx: &Fixture) -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: fx.target_repo_a.clone(),
            pr_root_event_id: "22".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://example.invalid/buzz.git".into(),
            immutable_source_ref: format!("refs/nostr/{}", "22".repeat(32)),
            tip_oid: fx.tip.clone(),
            source_branch: "feature/ci".into(),
            base_ref: MAIN_REF.into(),
            base_oid: fx.base.clone(),
            workflow_id: "ci".into(),
            workflow_digest: fx.workflow_digest.clone(),
            job_ids: fx.jobs.clone(),
            run_id: fx.run_id.clone(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "22".repeat(32),
            actor: fx.actor.public_key().to_hex(),
            timeout_seconds: 300,
            idempotency_key: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd47".into(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_600,
        }
    }

    fn sign<T: Serialize>(
        keys: &Keys,
        kind: u32,
        envelope: &T,
        tags: Vec<nostr::Tag>,
        created_at: u64,
    ) -> Event {
        EventBuilder::new(
            Kind::Custom(kind as u16),
            serde_json::to_string(envelope).unwrap(),
        )
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(created_at))
        .sign_with_keys(keys)
        .unwrap()
    }

    fn run_status(fx: &Fixture, request_id: &str, sequence: u64, state: CiRunState) -> Event {
        let request = request_envelope(fx);
        let terminal = state.is_terminal();
        let envelope = CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.into(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            attempt: 1,
            sequence,
            state,
            conclusion: terminal.then(|| format!("{state:?}").to_ascii_lowercase()),
            reason: None,
            started_at: (sequence >= 2).then_some(1_800_000_010),
            finished_at: terminal.then_some(1_800_000_040),
            job_ids: request.job_ids.clone(),
            relay_signer: fx.control.public_key().to_hex(),
        };
        let tags = run_status_tags(CHANNEL, &envelope).unwrap();
        sign(
            &fx.control,
            KIND_CI_RUN_STATUS,
            &envelope,
            tags,
            1_800_000_010 + sequence,
        )
    }

    fn job_status(
        fx: &Fixture,
        request_id: &str,
        job_id: &str,
        sequence: u64,
        state: CiJobState,
        log_ref: Option<String>,
    ) -> Event {
        let request = request_envelope(fx);
        let terminal = state.is_terminal();
        let envelope = CiJobStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.into(),
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
            conclusion: terminal.then(|| format!("{state:?}").to_ascii_lowercase()),
            reason: None,
            required: true,
            skip_policy: CiSkipPolicy::Forbid,
            selected_job_instance: job_id.into(),
            also_reruns: Vec::new(),
            started_at: (sequence >= 2).then_some(1_800_000_010),
            finished_at: terminal.then_some(1_800_000_020),
            log_ref,
            artifact_refs: Vec::new(),
            relay_signer: fx.control.public_key().to_hex(),
        };
        let tags = job_status_tags(CHANNEL, &envelope).unwrap();
        sign(
            &fx.control,
            KIND_CI_JOB_STATUS,
            &envelope,
            tags,
            1_800_000_010 + sequence,
        )
    }

    fn log_reference(fx: &Fixture, request_id: &str, job_id: &str) -> Event {
        let request = request_envelope(fx);
        let envelope = CiLogReferenceEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.into(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            job_id: job_id.into(),
            attempt: 1,
            log_sha256: "55".repeat(32),
            byte_length: 3,
            cap_bytes: 1024,
            truncated: false,
            url: Some("https://example.invalid/log".into()),
            inline: None,
            created_at: 1_800_000_020,
            relay_signer: fx.control.public_key().to_hex(),
        };
        let tags = log_reference_tags(CHANNEL, &envelope).unwrap();
        sign(
            &fx.control,
            KIND_CI_LOG_REFERENCE,
            &envelope,
            tags,
            1_800_000_020,
        )
    }

    struct History {
        request: CiRequestEnvelope,
        request_event: Event,
        events: Vec<Event>,
        check: Event,
    }

    /// A complete run history ending in a kind-46108 check: request, run
    /// stream, every job's stream with its log, the two terminal facts, the
    /// terminal run status, then the check. `failing` names a job that fails.
    fn build_history(fx: &Fixture, failing: Option<&str>) -> History {
        let request = request_envelope(fx);
        let request_event = sign(
            &fx.actor,
            KIND_CI_REQUEST,
            &request,
            request_tags(CHANNEL, &request).unwrap(),
            1_800_000_000,
        );
        let request_id = request_event.id.to_hex();
        let mut events = vec![request_event.clone()];
        events.push(run_status(fx, &request_id, 1, CiRunState::Queued));
        events.push(run_status(fx, &request_id, 2, CiRunState::Running));
        let mut finalized = Vec::new();
        let mut leases = Vec::new();
        for job_id in &fx.jobs {
            events.push(job_status(
                fx,
                &request_id,
                job_id,
                1,
                CiJobState::Queued,
                None,
            ));
            events.push(job_status(
                fx,
                &request_id,
                job_id,
                2,
                CiJobState::Running,
                None,
            ));
            let log = log_reference(fx, &request_id, job_id);
            let log_id = log.id.to_hex();
            events.push(log);
            let terminal = if failing == Some(job_id.as_str()) {
                CiJobState::Failure
            } else {
                CiJobState::Success
            };
            events.push(job_status(
                fx,
                &request_id,
                job_id,
                3,
                terminal,
                Some(log_id.clone()),
            ));
            finalized.push(CiFinalizedJobAttempt {
                job_id: job_id.clone(),
                attempt: 1,
                log_ref: log_id,
                artifact_refs: Vec::new(),
            });
            leases.push(CiTeardownLease {
                job_id: job_id.clone(),
                attempt: 1,
                lease_id: format!("lease-{job_id}"),
            });
        }
        let evidence = CiEvidenceFinalizedEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.clone(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            attempt: 1,
            finalized_job_attempts: finalized,
            finalized_at: 1_800_000_030,
            relay_signer: fx.control.public_key().to_hex(),
        };
        let evidence_event = sign(
            &fx.control,
            KIND_CI_EVIDENCE_FINALIZED,
            &evidence,
            evidence_finalized_tags(CHANNEL, &evidence).unwrap(),
            1_800_000_030,
        );
        let teardown = CiTeardownAttestationEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.clone(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            workflow_digest: request.workflow_digest.clone(),
            attempt: 1,
            leases,
            lease_empty: true,
            teardown_at: 1_800_000_031,
            relay_signer: fx.control.public_key().to_hex(),
        };
        let teardown_event = sign(
            &fx.control,
            KIND_CI_TEARDOWN_ATTESTATION,
            &teardown,
            teardown_attestation_tags(CHANNEL, &teardown).unwrap(),
            1_800_000_031,
        );
        events.push(evidence_event.clone());
        events.push(teardown_event.clone());
        let conclusion = if failing.is_some() {
            CiRunState::Failure
        } else {
            CiRunState::Success
        };
        let terminal = run_status(fx, &request_id, 3, conclusion);
        events.push(terminal.clone());
        let success = conclusion == CiRunState::Success;
        let check = CiCheckEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.clone(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            attempt: 1,
            conclusion,
            reason: None,
            run_status_event_id: terminal.id.to_hex(),
            evidence_finalized_event_id: success.then(|| evidence_event.id.to_hex()),
            teardown_attestation_event_id: success.then(|| teardown_event.id.to_hex()),
            concurrency_group: CiConcurrencyGroup::of(&request).key,
            published_at: 1_800_000_050,
            relay_signer: fx.control.public_key().to_hex(),
        };
        let check_event = sign(
            &fx.control,
            KIND_CI_CHECK,
            &check,
            check_tags(CHANNEL, &check).unwrap(),
            1_800_000_050,
        );
        events.push(check_event.clone());
        History {
            request,
            request_event,
            events,
            check: check_event,
        }
    }

    fn stored(history: &History, accepted_at: DateTime<Utc>) -> Vec<StoredRunEvent> {
        history
            .events
            .iter()
            .enumerate()
            .map(|(index, event)| StoredRunEvent {
                watch_cursor: index as u64 + 1,
                accepted_at,
                event: event.clone(),
            })
            .collect()
    }

    fn trusted_for(fx: &Fixture) -> RunTrustedContext {
        RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::from([fx.control.public_key().to_hex()]),
        }
    }

    fn run_history(fx: &Fixture, history: &History, accepted_at: DateTime<Utc>) -> RunHistory {
        let stored = stored(history, accepted_at);
        let validated = ValidatedCiRequest {
            request_event_id: history.request_event.id.to_hex(),
            request: history.request.clone(),
            watch_cursor: 1,
        };
        let accepted = validate_stored_history(&validated, &stored, &trusted_for(fx)).unwrap();
        RunHistory {
            request_event_id: history.request_event.id.to_hex(),
            request: history.request.clone(),
            stored,
            accepted,
        }
    }

    fn fixture(tip: &str, base: &str, workflow_digest: &str, jobs: &[&str]) -> Fixture {
        let actor = Keys::generate();
        Fixture {
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            actor,
            control: Keys::generate(),
            tip: tip.into(),
            base: base.into(),
            workflow_digest: workflow_digest.into(),
            run_id: RUN_ID.into(),
            jobs: jobs.iter().map(|job| job.to_string()).collect(),
        }
    }

    fn checks_named(checks: &[LandingCheck], name: &str) -> LandingCheck {
        checks
            .iter()
            .find(|check| check.name == name)
            .unwrap_or_else(|| panic!("check {name} recorded: {checks:#?}"))
            .clone()
    }

    fn assert_refused(checks: &[LandingCheck], name: &str, code: &str) {
        let check = checks_named(checks, name);
        assert_eq!(check.result, CheckResult::Refused, "{name}: {check:?}");
        assert_eq!(check.code.as_deref(), Some(code), "{name}: {check:?}");
        assert!(check.gating, "{name} gates");
    }

    fn assert_pass(checks: &[LandingCheck], name: &str) {
        let check = checks_named(checks, name);
        assert_eq!(check.result, CheckResult::Pass, "{name}: {check:?}");
    }

    // ── history rules over the fixture ──

    #[test]
    fn green_history_passes_every_history_rule() {
        let fx = fixture(
            &"b".repeat(40),
            &"c".repeat(40),
            &"e".repeat(64),
            &["lint", "unit"],
        );
        let history = build_history(&fx, None);
        let now = Utc::now();
        let run = run_history(&fx, &history, now - chrono::Duration::seconds(60));
        let mut ledger = Ledger::default();
        let outcome = evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        for name in [
            "run_history:ci",
            "required_jobs:ci",
            "check_bound:ci",
            "check_signer:ci",
            "check_fresh:ci",
        ] {
            assert_pass(&ledger.checks, name);
        }
        let check = outcome.check.expect("bound check");
        assert_eq!(check.event_id, history.check.id.to_hex());
        assert_eq!(check.watch_cursor, history.events.len() as u64);
        assert_eq!(check.signer, fx.control.public_key().to_hex());
        assert_eq!(outcome.reduction.unwrap().state, CiReducedState::Green);
    }

    #[test]
    fn red_run_refuses_check_not_success() {
        let fx = fixture(
            &"b".repeat(40),
            &"c".repeat(40),
            &"e".repeat(64),
            &["lint", "unit"],
        );
        let history = build_history(&fx, Some("unit"));
        let now = Utc::now();
        let run = run_history(&fx, &history, now);
        let mut ledger = Ledger::default();
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_refused(&ledger.checks, "run_history:ci", "check_not_success");
        assert_refused(&ledger.checks, "required_jobs:ci", "required_jobs_missing");
        assert_refused(&ledger.checks, "check_bound:ci", "check_not_success");
    }

    #[test]
    fn green_run_over_a_subset_of_the_pinned_jobs_refuses_required_jobs_missing() {
        let fx = fixture(&"b".repeat(40), &"c".repeat(40), &"e".repeat(64), &["unit"]);
        let history = build_history(&fx, None);
        let now = Utc::now();
        let run = run_history(&fx, &history, now);
        let pinned = vec!["lint".to_string(), "unit".to_string()];
        let mut ledger = Ledger::default();
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &pinned,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_pass(&ledger.checks, "run_history:ci");
        let check = checks_named(&ledger.checks, "required_jobs:ci");
        assert_eq!(check.code.as_deref(), Some("required_jobs_missing"));
        assert!(check.detail.unwrap().contains("lint (not requested)"));
        assert_pass(&ledger.checks, "check_bound:ci");
    }

    #[test]
    fn check_accepted_past_the_window_is_expired_while_published_at_is_ignored() {
        let fx = fixture(
            &"b".repeat(40),
            &"c".repeat(40),
            &"e".repeat(64),
            &["lint", "unit"],
        );
        let history = build_history(&fx, None);
        let now = Utc::now();
        let run = run_history(
            &fx,
            &history,
            now - chrono::Duration::seconds(DEFAULT_MAX_AGE_SECONDS as i64 + 1),
        );
        let mut ledger = Ledger::default();
        let outcome = evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_refused(&ledger.checks, "check_fresh:ci", "check_expired");
        // published_at (1_800_000_050, far in the past or future) is recorded, never consulted.
        assert_eq!(outcome.check.unwrap().published_at, 1_800_000_050);
        let mut ledger = Ledger::default();
        let fresh = run_history(
            &fx,
            &history,
            now - chrono::Duration::seconds(DEFAULT_MAX_AGE_SECONDS as i64),
        );
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &fresh,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_pass(&ledger.checks, "check_fresh:ci");
    }

    #[test]
    fn check_bound_to_another_base_is_base_moved_and_another_tip_disagrees() {
        let fx = fixture(
            &"b".repeat(40),
            &"c".repeat(40),
            &"e".repeat(64),
            &["lint", "unit"],
        );
        let history = build_history(&fx, None);
        let now = Utc::now();
        let run = run_history(&fx, &history, now);
        let mut ledger = Ledger::default();
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &"d".repeat(40),
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_refused(&ledger.checks, "check_bound:ci", "base_moved");
        let mut ledger = Ledger::default();
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &"f".repeat(40),
                base: &fx.base,
                trusted: &trusted_for(&fx),
                history: &run,
                now,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_refused(&ledger.checks, "run_history:ci", "reducer_disagrees");
    }

    #[test]
    fn signer_outside_the_trusted_set_never_validates() {
        let fx = fixture(
            &"b".repeat(40),
            &"c".repeat(40),
            &"e".repeat(64),
            &["lint", "unit"],
        );
        let history = build_history(&fx, None);
        let stored = stored(&history, Utc::now());
        let validated = ValidatedCiRequest {
            request_event_id: history.request_event.id.to_hex(),
            request: history.request.clone(),
            watch_cursor: 1,
        };
        let stranger = RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::from([Keys::generate().public_key().to_hex()]),
        };
        let error = validate_stored_history(&validated, &stored, &stranger).unwrap_err();
        assert!(
            error.to_string().contains("invalid signed CI event"),
            "{error}"
        );
        // With a trusted signer the same bytes validate and the explicit
        // signer rule then compares against the recorded set.
        let run = run_history(&fx, &history, Utc::now());
        let mut ledger = Ledger::default();
        let mut trusted = trusted_for(&fx);
        let outcome = evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted,
                history: &run,
                now: Utc::now(),
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_pass(&ledger.checks, "check_signer:ci");
        trusted.status_signers = HashSet::from([Keys::generate().public_key().to_hex()]);
        let mut ledger = Ledger::default();
        evaluate_history(
            &HistoryContext {
                workflow_id: "ci",
                pinned_jobs: &fx.jobs,
                candidate: &fx.tip,
                base: &fx.base,
                trusted: &trusted,
                history: &run,
                now: Utc::now(),
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            },
            &mut ledger,
        );
        assert_refused(&ledger.checks, "check_signer:ci", "signer_unauthorized");
        assert!(outcome.check.is_some());
    }

    // ── pure rules ──

    #[test]
    fn parent_classification_accepts_merge_and_fast_forward_only() {
        let (landed, candidate, base) = ("1".repeat(40), "2".repeat(40), "3".repeat(40));
        assert_eq!(
            classify_parents(
                &landed,
                &candidate,
                &base,
                &format!("{landed} {base} {candidate}")
            ),
            Ok("merge")
        );
        assert_eq!(
            classify_parents(
                &candidate,
                &candidate,
                &base,
                &format!("{candidate} {base}")
            ),
            Ok("fast_forward")
        );
        for line in [
            format!("{landed} {candidate} {base}"),
            format!("{landed} {base}"),
            format!("{landed} {base} {candidate} {base}"),
            format!("{base} {base} {candidate}"),
            String::new(),
        ] {
            assert_eq!(
                classify_parents(&landed, &candidate, &base, &line)
                    .unwrap_err()
                    .code,
                "parent_shape",
                "{line:?}"
            );
        }
    }

    #[test]
    fn relay_main_rule_needs_every_read_to_name_the_landed_commit() {
        let landed = "1".repeat(40);
        let read = |sha: Option<&str>, error: Option<&str>| RelayMainRead {
            read_at: Utc::now(),
            sha: sha.map(str::to_owned),
            error: error.map(str::to_owned),
        };
        assert!(evaluate_relay_main(
            &[read(Some(&landed), None), read(Some(&landed), None)],
            &landed
        )
        .is_ok());
        assert_eq!(
            evaluate_relay_main(
                &[read(Some(&landed), None), read(Some(&"2".repeat(40)), None)],
                &landed
            )
            .unwrap_err()
            .code,
            "relay_main_mismatch"
        );
        assert_eq!(
            evaluate_relay_main(&[read(None, Some("boom"))], &landed)
                .unwrap_err()
                .code,
            "relay_main_unavailable"
        );
        assert_eq!(
            evaluate_relay_main(&[read(None, None)], &landed)
                .unwrap_err()
                .code,
            "relay_main_mismatch"
        );
    }

    fn decision(code: &str, mode: &str, bypass: Option<&str>) -> DecisionRow {
        DecisionRow {
            id: uuid::Uuid::new_v4().to_string(),
            old_oid: "3".repeat(40),
            new_oid: "1".repeat(40),
            candidate_oid: Some("2".repeat(40)),
            classification: "merge".into(),
            run_id: Some(RUN_ID.into()),
            check_event_id: None,
            signer: None,
            code: code.into(),
            mode: mode.into(),
            pusher: "a".repeat(64),
            bypass_event_id: bypass.map(str::to_owned),
            decided_at: Utc::now(),
        }
    }

    #[test]
    fn gate_decision_rule_follows_mode_shadow_and_bypass() {
        let (gating, outcome) = evaluate_gate_decision("off", &[], false);
        assert!(!gating);
        assert!(outcome.is_ok());
        let (gating, outcome) = evaluate_gate_decision("enforce", &[], false);
        assert!(gating);
        assert_eq!(outcome.unwrap_err().code, "no_decision");
        let (_, outcome) = evaluate_gate_decision(
            "enforce",
            &[decision("check_pending", "enforce", None)],
            false,
        );
        assert_eq!(outcome.unwrap_err().code, "check_pending");
        let (_, outcome) =
            evaluate_gate_decision("shadow", &[decision("allow", "shadow", None)], false);
        assert_eq!(outcome.unwrap_err().code, "gate_shadow");
        let (_, outcome) =
            evaluate_gate_decision("shadow", &[decision("allow", "shadow", None)], true);
        assert!(outcome.is_ok());
        let (_, outcome) = evaluate_gate_decision(
            "enforce",
            &[
                decision("allow", "enforce", Some(&"9".repeat(64))),
                decision("check_pending", "enforce", None),
            ],
            false,
        );
        assert!(outcome.unwrap().contains("via bypass"));
    }

    #[test]
    fn mirror_parity_is_recorded_and_never_gates() {
        let landed = "1".repeat(40);
        let (evidence, outcome) = evaluate_mirror("only21mil/buzz", &landed, Ok(landed.clone()));
        assert_eq!(evidence.agrees, Some(true));
        assert!(outcome.is_ok());
        let (evidence, outcome) = evaluate_mirror("only21mil/buzz", &landed, Ok("2".repeat(40)));
        assert_eq!(evidence.agrees, Some(false));
        assert_eq!(outcome.unwrap_err().code, "mirror_lag");
        let (evidence, outcome) =
            evaluate_mirror("only21mil/buzz", &landed, Err("gh failed".into()));
        assert_eq!(evidence.agrees, None);
        assert_eq!(outcome.as_ref().unwrap_err().code, "mirror_unavailable");
        let mut ledger = Ledger::default();
        ledger.record("github_mirror", false, outcome);
        assert_eq!(ledger.checks[0].result, CheckResult::Warn);
        assert!(all_gating_pass(&ledger.checks));
    }

    #[test]
    fn require_check_rule_comes_from_the_announcement() {
        let owner = Keys::generate();
        let announce = |tags: Vec<Vec<&str>>| {
            EventBuilder::new(Kind::Custom(30617), "")
                .tags(tags.into_iter().map(|tag| nostr::Tag::parse(tag).unwrap()))
                .sign_with_keys(&owner)
                .unwrap()
        };
        let rules = resolve_require_checks(&announce(vec![
            vec!["d", "buzz"],
            vec![
                "buzz-protect",
                "refs/heads/main",
                "no-delete",
                "require-check:ci:unit+lint",
            ],
            vec!["buzz-protect", "refs/heads/*", "require-check:ci:web"],
        ]))
        .unwrap();
        assert_eq!(rules["ci"], vec!["lint", "unit", "web"]);
        assert_eq!(
            resolve_require_checks(&announce(vec![
                vec!["d", "buzz"],
                vec!["buzz-protect", "refs/heads/main", "no-delete"]
            ]))
            .unwrap_err()
            .code,
            "gate_misconfigured"
        );
        assert_eq!(
            resolve_require_checks(&announce(vec![
                vec!["d", "buzz"],
                vec![
                    "buzz-protect",
                    "refs/heads/main",
                    "require-check:ci:bad job"
                ]
            ]))
            .unwrap_err()
            .code,
            "gate_misconfigured"
        );
    }

    // ── receipt files ──

    fn private_dir() -> tempfile::TempDir {
        let base = std::env::temp_dir().canonicalize().unwrap();
        tempfile::Builder::new()
            .prefix("landing-receipt-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap()
    }

    #[test]
    fn receipt_publish_is_create_only_under_a_private_parent() {
        let dir = private_dir();
        let path = dir.path().join("receipt.json");
        publish_receipt(&path, b"{\"a\":1}").unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.nlink(), 1);
        assert_eq!(read_receipt(&path).unwrap(), b"{\"a\":1}");
        assert!(
            std::fs::read_dir(dir.path()).unwrap().count() == 1,
            "no temporary left behind"
        );
        // Existing destination.
        let error = publish_receipt(&path, b"{}").unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error}");
        assert_eq!(read_receipt(&path).unwrap(), b"{\"a\":1}");
        // Relative path and dotfile basename.
        assert!(publish_receipt(Path::new("relative.json"), b"{}").is_err());
        assert!(publish_receipt(&dir.path().join(".hidden.json"), b"{}").is_err());
        // Symlink destination is refused, not followed.
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(publish_receipt(&link, b"{}").is_err());
        assert!(!target.exists());
        // Oversized.
        assert!(publish_receipt(
            &dir.path().join("big.json"),
            &vec![b'x'; MAX_RECEIPT_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn receipt_parent_must_be_a_caller_owned_mode_0700_directory() {
        let dir = private_dir();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = publish_receipt(&open.join("receipt.json"), b"{}").unwrap_err();
        assert!(error.to_string().contains("mode 0700"), "{error}");
        assert!(!open.join("receipt.json").exists());
        std::fs::write(open.join("receipt.json"), b"{}").unwrap();
        assert!(read_receipt(&open.join("receipt.json")).is_err());
        // A symlinked parent is refused even when the target is private.
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(dir.path(), &linked).unwrap();
        assert!(publish_receipt(&linked.join("receipt.json"), b"{}").is_err());
    }

    #[test]
    fn receipt_read_refuses_symlinks_wrong_modes_and_extra_links() {
        let dir = private_dir();
        let path = dir.path().join("receipt.json");
        publish_receipt(&path, b"{}").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_receipt(&link).is_err());
        let extra = dir.path().join("extra.json");
        std::fs::hard_link(&path, &extra).unwrap();
        assert!(read_receipt(&path).is_err());
        std::fs::remove_file(&extra).unwrap();
        assert!(read_receipt(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_receipt(&path).is_err());
    }

    // ── full verify against a temp git history and a stub relay ──

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    const BASE_WORKFLOW: &str = "name: ci\non: [push]\njobs:\n  lint:\n    runs-on: x\n    steps: []\n  unit:\n    runs-on: x\n    steps: []\n";
    const CANDIDATE_WORKFLOW: &str = "name: ci\non: [push]\njobs:\n  lint:\n    runs-on: x\n    steps: []\n  unit:\n    runs-on: x\n    steps: [ {run: echo} ]\n";

    /// A checkout with `base`, `candidate` (branched from base, editing the
    /// workflow), a merge `landed` whose tree is the candidate's, and a bare
    /// relay remote whose main names `landed`. The committed
    /// `scripts/desktop_release.py` is a stub exiting with `verifier_exit`.
    struct GitFixture {
        _dir: tempfile::TempDir,
        checkout: PathBuf,
        relay: PathBuf,
        base: String,
        candidate: String,
        landed: String,
    }

    fn git_fixture(verifier_exit: i32) -> GitFixture {
        git_fixture_with(verifier_exit, false)
    }

    /// `candidate_metadata` adds `.release/desktop-candidate.json` in the
    /// candidate commit, so the landed commit's desktop identity differs from
    /// its first parent's.
    fn git_fixture_with(verifier_exit: i32, candidate_metadata: bool) -> GitFixture {
        let dir = private_dir();
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(checkout.join(".github/workflows")).unwrap();
        std::fs::create_dir_all(checkout.join("scripts")).unwrap();
        git(&checkout, &["init", "-q", "-b", "main"]);
        std::fs::write(checkout.join(".github/workflows/ci.yml"), BASE_WORKFLOW).unwrap();
        std::fs::write(
            checkout.join("scripts/desktop_release.py"),
            format!(
                "import json\nimport sys\nprint('stub verify-main', json.dumps(sys.argv[1:]))\nsys.exit({verifier_exit})\n"
            ),
        )
        .unwrap();
        std::fs::write(checkout.join("README.md"), "base\n").unwrap();
        git(&checkout, &["add", "."]);
        git(&checkout, &["commit", "-q", "-m", "base", "--no-gpg-sign"]);
        let base = git(&checkout, &["rev-parse", "HEAD"]);
        std::fs::write(
            checkout.join(".github/workflows/ci.yml"),
            CANDIDATE_WORKFLOW,
        )
        .unwrap();
        std::fs::write(checkout.join("README.md"), "candidate\n").unwrap();
        if candidate_metadata {
            std::fs::create_dir_all(checkout.join(".release")).unwrap();
            std::fs::write(
                checkout.join(DESKTOP_METADATA),
                "{\"version\":\"1.2.3\",\"tag\":\"desktop-v1.2.3\"}\n",
            )
            .unwrap();
            git(&checkout, &["add", DESKTOP_METADATA]);
        }
        git(
            &checkout,
            &["commit", "-q", "-am", "candidate", "--no-gpg-sign"],
        );
        let candidate = git(&checkout, &["rev-parse", "HEAD"]);
        let candidate_tree = git(&checkout, &["rev-parse", &format!("{candidate}^{{tree}}")]);
        let landed = git(
            &checkout,
            &[
                "commit-tree",
                &candidate_tree,
                "-p",
                &base,
                "-p",
                &candidate,
                "-m",
                "Merge pull request #1: candidate",
            ],
        );
        git(&checkout, &["update-ref", "refs/heads/main", &landed]);
        git(&checkout, &["checkout", "-q", "main"]);
        let relay = dir.path().join("relay.git");
        git(dir.path(), &["init", "-q", "--bare", "relay.git"]);
        git(
            &checkout,
            &[
                "push",
                "-q",
                relay.to_str().unwrap(),
                "main:refs/heads/main",
            ],
        );
        GitFixture {
            _dir: dir,
            checkout,
            relay,
            base,
            candidate,
            landed,
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    type Routes = HashMap<(Method, String), (StatusCode, String)>;

    async fn stub_relay(routes: Routes) -> String {
        async fn handle(
            State(routes): State<Arc<Mutex<Routes>>>,
            request: Request,
        ) -> Response<Body> {
            let method = request.method().clone();
            let path = request
                .uri()
                .path_and_query()
                .map(ToString::to_string)
                .unwrap_or_default();
            let routes = routes.lock().unwrap();
            let (status, body) = routes
                .get(&(method.clone(), path.clone()))
                .cloned()
                .unwrap_or((
                    StatusCode::NOT_FOUND,
                    format!("{{\"error\":\"no route {method} {path}\"}}"),
                ));
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        let app = Router::new()
            .fallback(handle)
            .with_state(Arc::new(Mutex::new(routes)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    struct Scenario {
        owner: Keys,
        git: GitFixture,
        fx: Fixture,
        history: History,
        accepted_at: DateTime<Utc>,
        gate_mode: &'static str,
        decisions: Vec<DecisionRow>,
        extra_runs: Vec<(Fixture, History)>,
        rule: &'static str,
    }

    impl Scenario {
        fn new(verifier_exit: i32) -> Self {
            let git = git_fixture(verifier_exit);
            let digest = sha256_hex(BASE_WORKFLOW.as_bytes());
            let fx = fixture(&git.candidate, &git.base, &digest, &["lint", "unit"]);
            let history = build_history(&fx, None);
            Self {
                owner: Keys::generate(),
                git,
                fx,
                history,
                accepted_at: Utc::now() - chrono::Duration::seconds(60),
                gate_mode: "off",
                decisions: Vec::new(),
                extra_runs: Vec::new(),
                rule: "require-check:ci:lint+unit",
            }
        }

        fn target_repo_a(&self) -> String {
            format!("30617:{}:buzz", self.owner.public_key().to_hex())
        }

        fn announcement(&self) -> Event {
            EventBuilder::new(Kind::Custom(30617), "")
                .tags([
                    nostr::Tag::parse(["d", "buzz"]).unwrap(),
                    nostr::Tag::parse(["buzz-channel", CHANNEL]).unwrap(),
                    nostr::Tag::parse(["buzz-protect", MAIN_REF, "no-delete", self.rule]).unwrap(),
                ])
                .sign_with_keys(&self.owner)
                .unwrap()
        }

        fn run_entry(&self, fx: &Fixture, history: &History) -> serde_json::Value {
            let cursor = history.events.len() as u64;
            serde_json::json!({
                "run_id": fx.run_id,
                "request_event_id": history.request_event.id.to_hex(),
                "workflow_id": "ci",
                "workflow_digest": fx.workflow_digest,
                "tip_oid": fx.tip,
                "base_oid": fx.base,
                "created_at": self.accepted_at,
                "checks": [{"watch_cursor": cursor, "accepted_at": self.accepted_at, "event": history.check}],
            })
        }

        fn routes(&self) -> Routes {
            let repo = self.target_repo_a();
            let mut routes = Routes::new();
            routes.insert(
                (Method::POST, "/query".into()),
                (
                    StatusCode::OK,
                    serde_json::json!([self.announcement()]).to_string(),
                ),
            );
            let mut runs: Vec<serde_json::Value> = self
                .extra_runs
                .iter()
                .map(|(fx, history)| self.run_entry(fx, history))
                .collect();
            runs.push(self.run_entry(&self.fx, &self.history));
            routes.insert(
                (Method::GET, format!("/ci/checks?target_repo_a={repo}&tip_oid={}&workflow_id=ci", self.git.candidate)),
                (StatusCode::OK, serde_json::json!({"target_repo_a": repo, "tip_oid": self.git.candidate, "runs": runs}).to_string()),
            );
            let all_runs: Vec<(&Fixture, &History)> = self
                .extra_runs
                .iter()
                .map(|(fx, history)| (fx, history))
                .chain(std::iter::once((&self.fx, &self.history)))
                .collect();
            for (fx, history) in all_runs {
                let events: Vec<serde_json::Value> = history
                    .events
                    .iter()
                    .enumerate()
                    .map(|(index, event)| serde_json::json!({"watch_cursor": index as u64 + 1, "accepted_at": self.accepted_at, "event": event}))
                    .collect();
                routes.insert(
                    (Method::GET, format!("/ci/runs/{}/request", fx.run_id)),
                    (
                        StatusCode::OK,
                        serde_json::json!({
                            "run_id": fx.run_id,
                            "request_event_id": history.request_event.id.to_hex(),
                            "watch_cursor": 1,
                            "accepted_at": self.accepted_at,
                            "event": history.request_event,
                        })
                        .to_string(),
                    ),
                );
                routes.insert(
                    (
                        Method::GET,
                        format!(
                            "/ci/runs/{}/events?after=0&limit={CI_RUN_EVENT_PAGE_LIMIT}",
                            fx.run_id
                        ),
                    ),
                    (
                        StatusCode::OK,
                        serde_json::json!({
                            "run_id": fx.run_id,
                            "request_event_id": history.request_event.id.to_hex(),
                            "events": events,
                            "next_cursor": history.events.len(),
                        })
                        .to_string(),
                    ),
                );
            }
            routes.insert(
                (Method::GET, format!("/ci/merge-gate/decisions?target_repo_a={repo}&ref={MAIN_REF}&new_oid={}&old_oid={}", self.git.landed, self.git.base)),
                (StatusCode::OK, serde_json::json!({
                    "target_repo_a": repo,
                    "ref": MAIN_REF,
                    "new_oid": self.git.landed,
                    "mode": self.gate_mode,
                    "check_max_age_seconds": 86_400,
                    "decisions": self.decisions,
                }).to_string()),
            );
            routes
        }

        fn args(&self, output: &Path) -> LandingVerifyArgs {
            LandingVerifyArgs {
                repo_owner: self.owner.public_key().to_hex(),
                repo_id: "buzz".into(),
                candidate: self.git.candidate.clone(),
                base: self.git.base.clone(),
                landed: self.git.landed.clone(),
                checkout: self.git.checkout.clone(),
                output: output.to_path_buf(),
                github_mirror: None,
                allow_shadow: false,
                max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            }
        }

        /// Run the verifier with a client whose relay URL is the stub and
        /// whose git reads go to the temp bare relay.
        async fn verify(&self, args: &LandingVerifyArgs) -> LandingReceipt {
            let url = stub_relay(self.routes()).await;
            let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();
            let trusted = trusted_for(&self.fx);
            verify_landing(&client, args, &trusted, self.git.relay.to_str().unwrap())
                .await
                .unwrap()
        }
    }

    #[tokio::test]
    async fn green_landing_passes_and_the_receipt_round_trips_offline() {
        let scenario = Scenario::new(0);
        let dir = private_dir();
        let output = dir.path().join("landing.json");
        let receipt = scenario.verify(&scenario.args(&output)).await;
        assert_eq!(receipt.verdict, "PASS", "{:#?}", receipt.landing_checks);
        assert_eq!(receipt.classification, "merge");
        for name in [
            "objects_present",
            "parent_shape",
            "tree_match",
            "base_ancestry",
            "require_check_rule",
            "run_selected:ci",
            "run_base:ci",
            "workflow_digest:ci",
            "run_history:ci",
            "required_jobs:ci",
            "check_bound:ci",
            "check_signer:ci",
            "check_fresh:ci",
            "check_listed:ci",
            "relay_main",
            "desktop_verify_main",
        ] {
            assert_pass(&receipt.landing_checks, name);
        }
        let gate = checks_named(&receipt.landing_checks, "gate_decision");
        assert!(!gate.gating);
        assert_eq!(gate.result, CheckResult::Pass);
        assert!(receipt.mirror.is_none());
        assert_eq!(receipt.runs.len(), 1);
        assert_eq!(
            receipt.runs[0].retained_events.len(),
            scenario.history.events.len()
        );
        assert_eq!(
            receipt.runs[0].check.as_ref().unwrap().event_id,
            scenario.history.check.id.to_hex()
        );
        assert_eq!(receipt.relay_main.len(), 2);

        // Round trip: the published bytes parse back to the same receipt and
        // validate offline.
        let bytes = read_receipt(&output).unwrap();
        let parsed: LandingReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, receipt);
        let anchor = trusted_for(&scenario.fx);
        let (trust, checks) =
            validate_receipt_offline(&parsed, DEFAULT_MAX_AGE_SECONDS, Some(&anchor), false);
        assert_eq!(trust, TrustAnchor::Environment);
        assert!(all_gating_pass(&checks), "{checks:#?}");
        assert_pass(&checks, "trusted_context");
        assert_pass(&checks, "retained_bodies:ci");
        assert_pass(&checks, "recorded_check:ci");

        // Without an exported context the offline replay is unanchored: it
        // refuses unless the live reads are requested, and then only warns.
        let (trust, checks) =
            validate_receipt_offline(&parsed, DEFAULT_MAX_AGE_SECONDS, None, false);
        assert_eq!(trust, TrustAnchor::Unanchored);
        assert_refused(&checks, "trusted_context", "trusted_context_unanchored");
        let (trust, checks) =
            validate_receipt_offline(&parsed, DEFAULT_MAX_AGE_SECONDS, None, true);
        assert_eq!(trust, TrustAnchor::Relay);
        let warned = checks_named(&checks, "trusted_context");
        assert_eq!(warned.result, CheckResult::Warn);
        assert!(!warned.gating);
        assert!(all_gating_pass(&checks));

        // One retained byte changed: the offline replay refuses.
        let mut tampered = parsed.clone();
        let body = &mut tampered.runs[0].retained_events[3];
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&body.base64)
            .unwrap();
        let position = raw.iter().position(|b| *b == b'r').unwrap();
        raw[position] = b'R';
        body.base64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let (_, checks) =
            validate_receipt_offline(&tampered, DEFAULT_MAX_AGE_SECONDS, Some(&anchor), false);
        assert_refused(&checks, "retained_bodies:ci", "retained_body_tampered");

        // A receipt whose verdict disagrees with its checks is inconsistent.
        let mut lying = parsed.clone();
        lying.landing_checks[0].result = CheckResult::Refused;
        let (_, checks) =
            validate_receipt_offline(&lying, DEFAULT_MAX_AGE_SECONDS, Some(&anchor), false);
        assert_refused(&checks, "receipt_verdict", "receipt_inconsistent");
    }

    #[tokio::test]
    async fn offline_validate_refuses_a_receipt_outside_the_exported_trusted_context() {
        let scenario = Scenario::new(0);
        let dir = private_dir();
        let output = dir.path().join("anchor.json");
        let receipt = scenario.verify(&scenario.args(&output)).await;
        assert_eq!(receipt.verdict, "PASS");

        // A forged receipt naming an attacker signer set is self-consistent:
        // rebuild the whole history under a stranger control key.
        let mut forged_scenario = Scenario::new(0);
        forged_scenario.fx.control = Keys::generate();
        forged_scenario.history = build_history(&forged_scenario.fx, None);
        let forged = forged_scenario
            .verify(&forged_scenario.args(&dir.path().join("forged.json")))
            .await;
        assert_eq!(
            forged.verdict, "PASS",
            "self-consistent under its own signer set"
        );

        // The operator's exported context anchors the replay: the genuine
        // receipt is within it, the forged one is not.
        let anchor = trusted_for(&scenario.fx);
        let (_, checks) =
            validate_receipt_offline(&receipt, DEFAULT_MAX_AGE_SECONDS, Some(&anchor), false);
        assert!(all_gating_pass(&checks), "{checks:#?}");
        let (_, checks) =
            validate_receipt_offline(&forged, DEFAULT_MAX_AGE_SECONDS, Some(&anchor), false);
        assert_refused(&checks, "trusted_context", "trusted_context_mismatch");
        assert!(checks_named(&checks, "trusted_context")
            .detail
            .unwrap()
            .contains("signers outside"));
        assert!(!all_gating_pass(&checks));
        // A superset environment still anchors; another channel refuses.
        let mut wider = anchor.clone();
        wider
            .status_signers
            .insert(Keys::generate().public_key().to_hex());
        let (_, checks) =
            validate_receipt_offline(&receipt, DEFAULT_MAX_AGE_SECONDS, Some(&wider), false);
        assert_pass(&checks, "trusted_context");
        let mut other_channel = anchor.clone();
        other_channel.channel_id = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee".into();
        let (_, checks) = validate_receipt_offline(
            &receipt,
            DEFAULT_MAX_AGE_SECONDS,
            Some(&other_channel),
            false,
        );
        assert_refused(&checks, "trusted_context", "trusted_context_mismatch");
        assert!(checks_named(&checks, "trusted_context")
            .detail
            .unwrap()
            .contains("channel"));
    }

    /// The validate entry through the real CLI grammar on a published receipt.
    #[tokio::test]
    async fn validate_cli_entry_anchors_to_the_environment() {
        let _guard = crate::commands::ci::CI_ENV_LOCK.lock().await;

        let scenario = Scenario::new(0);
        let dir = private_dir();
        let output = dir.path().join("cli.json");
        let receipt = scenario.verify(&scenario.args(&output)).await;
        assert_eq!(receipt.verdict, "PASS");
        let receipt_arg = output.display().to_string();
        let argv = |extra: &[&str]| -> Vec<String> {
            let mut args: Vec<String> = ["buzz", "ci", "landing", "validate", "--receipt"]
                .iter()
                .map(|arg| arg.to_string())
                .collect();
            args.push(receipt_arg.clone());
            args.extend(extra.iter().map(|arg| arg.to_string()));
            args
        };
        let signer = scenario.fx.control.public_key().to_hex();
        let stranger = Keys::generate().public_key().to_hex();
        let private_key = Keys::generate().secret_key().to_secret_hex();
        std::env::set_var("BUZZ_PRIVATE_KEY", &private_key);
        std::env::remove_var("BUZZ_AUTH_TAG");

        // Anchored to a matching environment: exit 0.
        std::env::set_var("BUZZ_CI_CHANNEL", CHANNEL);
        std::env::set_var("BUZZ_CI_STATUS_SIGNERS", &signer);
        assert_eq!(crate::run_from_args(argv(&[])).await, 0);
        // Superset signer set still anchors.
        std::env::set_var("BUZZ_CI_STATUS_SIGNERS", format!("{stranger},{signer}"));
        assert_eq!(crate::run_from_args(argv(&[])).await, 0);
        // A signer set that excludes the receipt's signer refuses (exit 1).
        std::env::set_var("BUZZ_CI_STATUS_SIGNERS", &stranger);
        assert_eq!(crate::run_from_args(argv(&[])).await, 1);
        // Another channel refuses.
        std::env::set_var("BUZZ_CI_STATUS_SIGNERS", &signer);
        std::env::set_var("BUZZ_CI_CHANNEL", "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        assert_eq!(crate::run_from_args(argv(&[])).await, 1);
        // Half an environment is a usage error; none is unanchored (exit 1).
        std::env::remove_var("BUZZ_CI_CHANNEL");
        assert_eq!(crate::run_from_args(argv(&[])).await, 1);
        std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
        assert_eq!(crate::run_from_args(argv(&[])).await, 1);
        // A tampered receipt refuses even inside a matching environment.
        std::env::set_var("BUZZ_CI_CHANNEL", CHANNEL);
        std::env::set_var("BUZZ_CI_STATUS_SIGNERS", &signer);
        let mut tampered: LandingReceipt =
            serde_json::from_slice(&read_receipt(&output).unwrap()).unwrap();
        tampered.runs[0].history_sha256 = Some("0".repeat(64));
        let tampered_path = dir.path().join("tampered.json");
        publish_receipt(&tampered_path, &serde_json::to_vec(&tampered).unwrap()).unwrap();
        let tampered_arg = tampered_path.display().to_string();
        assert_eq!(
            crate::run_from_args([
                "buzz",
                "ci",
                "landing",
                "validate",
                "--receipt",
                tampered_arg.as_str()
            ])
            .await,
            1
        );
        std::env::remove_var("BUZZ_CI_CHANNEL");
        std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
        std::env::remove_var("BUZZ_PRIVATE_KEY");
    }

    #[tokio::test]
    async fn relay_main_elsewhere_refuses_relay_main_mismatch() {
        let scenario = Scenario::new(0);
        git(
            &scenario.git.checkout,
            &[
                "push",
                "-q",
                "-f",
                scenario.git.relay.to_str().unwrap(),
                &format!("{}:refs/heads/main", scenario.git.candidate),
            ],
        );
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("r.json")))
            .await;
        assert_eq!(receipt.verdict, "REFUSED");
        assert_refused(&receipt.landing_checks, "relay_main", "relay_main_mismatch");
        assert_pass(&receipt.landing_checks, "parent_shape");
    }

    #[tokio::test]
    async fn reversed_parents_and_a_differing_tree_are_refused() {
        let scenario = Scenario::new(0);
        let checkout = &scenario.git.checkout.clone();
        let candidate_tree = git(
            checkout,
            &["rev-parse", &format!("{}^{{tree}}", scenario.git.candidate)],
        );
        let reversed = git(
            checkout,
            &[
                "commit-tree",
                &candidate_tree,
                "-p",
                &scenario.git.candidate,
                "-p",
                &scenario.git.base,
                "-m",
                "reversed",
            ],
        );
        git(
            checkout,
            &[
                "push",
                "-q",
                "-f",
                scenario.git.relay.to_str().unwrap(),
                &format!("{reversed}:refs/heads/main"),
            ],
        );
        let dir = private_dir();
        let mut args = scenario.args(&dir.path().join("reversed.json"));
        args.landed = reversed;
        let mut scenario_reversed = scenario;
        scenario_reversed.git.landed = args.landed.clone();
        let receipt = scenario_reversed.verify(&args).await;
        assert_refused(&receipt.landing_checks, "parent_shape", "parent_shape");
        assert_pass(&receipt.landing_checks, "tree_match");
        assert_eq!(receipt.classification, "unknown");

        let base_tree = git(
            checkout,
            &[
                "rev-parse",
                &format!("{}^{{tree}}", scenario_reversed.git.base),
            ],
        );
        let conflict = git(
            checkout,
            &[
                "commit-tree",
                &base_tree,
                "-p",
                &scenario_reversed.git.base,
                "-p",
                &scenario_reversed.git.candidate,
                "-m",
                "resolved",
            ],
        );
        git(
            checkout,
            &[
                "push",
                "-q",
                "-f",
                scenario_reversed.git.relay.to_str().unwrap(),
                &format!("{conflict}:refs/heads/main"),
            ],
        );
        let mut args = scenario_reversed.args(&dir.path().join("tree.json"));
        args.landed = conflict.clone();
        scenario_reversed.git.landed = conflict;
        let receipt = scenario_reversed.verify(&args).await;
        assert_pass(&receipt.landing_checks, "parent_shape");
        assert_refused(&receipt.landing_checks, "tree_match", "tree_mismatch");
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn candidate_off_the_base_lineage_is_not_descendant() {
        let mut scenario = Scenario::new(0);
        let checkout = scenario.git.checkout.clone();
        // An orphan candidate with the same tree as the reviewed candidate.
        let candidate_tree = git(
            &checkout,
            &["rev-parse", &format!("{}^{{tree}}", scenario.git.candidate)],
        );
        let orphan = git(&checkout, &["commit-tree", &candidate_tree, "-m", "orphan"]);
        let landed = git(
            &checkout,
            &[
                "commit-tree",
                &candidate_tree,
                "-p",
                &scenario.git.base,
                "-p",
                &orphan,
                "-m",
                "landed orphan",
            ],
        );
        git(
            &checkout,
            &[
                "push",
                "-q",
                "-f",
                scenario.git.relay.to_str().unwrap(),
                &format!("{landed}:refs/heads/main"),
            ],
        );
        scenario.git.candidate = orphan.clone();
        scenario.git.landed = landed;
        scenario.fx.tip = orphan;
        scenario.history = build_history(&scenario.fx, None);
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("orphan.json")))
            .await;
        assert_pass(&receipt.landing_checks, "parent_shape");
        assert_pass(&receipt.landing_checks, "tree_match");
        assert_refused(&receipt.landing_checks, "base_ancestry", "not_descendant");
        assert_pass(&receipt.landing_checks, "run_history:ci");
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn a_newer_red_run_decides_over_an_older_green_one() {
        let mut scenario = Scenario::new(0);
        let mut red = fixture(
            &scenario.git.candidate,
            &scenario.git.base,
            &scenario.fx.workflow_digest,
            &["lint", "unit"],
        );
        red.run_id = OTHER_RUN_ID.into();
        red.control = scenario.fx.control.clone();
        let red_history = build_history(&red, Some("unit"));
        // The listing is newest first: the red run precedes the green one.
        scenario.extra_runs.push((red, red_history));
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("red.json")))
            .await;
        assert_eq!(receipt.runs[0].run_id.as_deref(), Some(OTHER_RUN_ID));
        assert_refused(
            &receipt.landing_checks,
            "run_history:ci",
            "check_not_success",
        );
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn pinned_job_missing_from_a_green_run_is_refused() {
        let mut scenario = Scenario::new(0);
        scenario.fx.jobs = vec!["unit".into()];
        scenario.history = build_history(&scenario.fx, None);
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("subset.json")))
            .await;
        assert_pass(&receipt.landing_checks, "run_history:ci");
        assert_refused(
            &receipt.landing_checks,
            "required_jobs:ci",
            "required_jobs_missing",
        );
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn workflow_digested_from_the_candidate_tree_is_refused() {
        let mut scenario = Scenario::new(0);
        scenario.fx.workflow_digest = sha256_hex(CANDIDATE_WORKFLOW.as_bytes());
        scenario.history = build_history(&scenario.fx, None);
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("digest.json")))
            .await;
        assert_refused(
            &receipt.landing_checks,
            "workflow_digest:ci",
            "workflow_digest_mismatch",
        );
        assert_eq!(
            receipt.runs[0].base_workflow_digest.as_deref(),
            Some(sha256_hex(BASE_WORKFLOW.as_bytes()).as_str())
        );
        assert_pass(&receipt.landing_checks, "run_history:ci");
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn expired_check_and_moved_base_are_refused() {
        let mut scenario = Scenario::new(0);
        scenario.accepted_at =
            Utc::now() - chrono::Duration::seconds(DEFAULT_MAX_AGE_SECONDS as i64 + 5);
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("expired.json")))
            .await;
        assert_refused(&receipt.landing_checks, "check_fresh:ci", "check_expired");
        assert_eq!(receipt.verdict, "REFUSED");

        let mut moved = Scenario::new(0);
        moved.fx.base = "4".repeat(40);
        moved.history = build_history(&moved.fx, None);
        let receipt = moved
            .verify(&moved.args(&dir.path().join("moved.json")))
            .await;
        assert_refused(&receipt.landing_checks, "run_base:ci", "base_moved");
        assert_refused(&receipt.landing_checks, "check_bound:ci", "base_moved");
    }

    #[tokio::test]
    async fn signer_absent_from_the_trusted_set_refuses_the_history() {
        let scenario = Scenario::new(0);
        let url = stub_relay(scenario.routes()).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();
        let stranger = RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::from([Keys::generate().public_key().to_hex()]),
        };
        let dir = private_dir();
        let args = scenario.args(&dir.path().join("signer.json"));
        let receipt = verify_landing(
            &client,
            &args,
            &stranger,
            scenario.git.relay.to_str().unwrap(),
        )
        .await
        .unwrap();
        let check = checks_named(&receipt.landing_checks, "run_history:ci");
        assert_eq!(check.code.as_deref(), Some("history_unavailable"));
        assert!(check.detail.unwrap().contains("invalid signed CI event"));
        assert_eq!(receipt.verdict, "REFUSED");
    }

    #[tokio::test]
    async fn shadow_decision_needs_allow_shadow_and_enforce_needs_a_row() {
        let mut scenario = Scenario::new(0);
        scenario.gate_mode = "shadow";
        scenario.decisions = vec![decision("allow", "shadow", None)];
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("shadow.json")))
            .await;
        assert_refused(&receipt.landing_checks, "gate_decision", "gate_shadow");
        assert_eq!(receipt.verdict, "REFUSED");
        let mut args = scenario.args(&dir.path().join("shadow-ok.json"));
        args.allow_shadow = true;
        let receipt = scenario.verify(&args).await;
        assert_pass(&receipt.landing_checks, "gate_decision");
        assert_eq!(receipt.verdict, "PASS");

        scenario.gate_mode = "enforce";
        scenario.decisions = Vec::new();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("enforce.json")))
            .await;
        assert_refused(&receipt.landing_checks, "gate_decision", "no_decision");
        assert!(receipt.gate_decision.gating);
    }

    #[tokio::test]
    async fn missing_rule_and_missing_routes_are_refused_not_errors() {
        let mut scenario = Scenario::new(0);
        scenario.rule = "no-force-push";
        let dir = private_dir();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("rule.json")))
            .await;
        assert_refused(
            &receipt.landing_checks,
            "require_check_rule",
            "gate_misconfigured",
        );
        assert!(receipt.runs.is_empty());
        assert_eq!(receipt.verdict, "REFUSED");

        let scenario = Scenario::new(0);
        let mut routes = scenario.routes();
        routes.retain(|(_, path), _| {
            !path.starts_with("/ci/checks") && !path.starts_with("/ci/merge-gate")
        });
        let url = stub_relay(routes).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();
        let args = scenario.args(&dir.path().join("routes.json"));
        let receipt = verify_landing(
            &client,
            &args,
            &trusted_for(&scenario.fx),
            scenario.git.relay.to_str().unwrap(),
        )
        .await
        .unwrap();
        assert_refused(
            &receipt.landing_checks,
            "run_selected:ci",
            "relay_route_unavailable",
        );
        assert_refused(
            &receipt.landing_checks,
            "gate_decision",
            "relay_route_unavailable",
        );
    }

    #[tokio::test]
    async fn desktop_verify_main_stub_failure_refuses_and_exits_one() {
        let scenario = Scenario::new(1);
        let dir = private_dir();
        let output = dir.path().join("desktop.json");
        let receipt = scenario.verify(&scenario.args(&output)).await;
        assert_refused(
            &receipt.landing_checks,
            "desktop_verify_main",
            "desktop_verify_main_failed",
        );
        assert_eq!(receipt.verdict, "REFUSED");
        // The receipt is still published, and the command maps the refusal
        // to a usage error (exit code 1).
        assert!(output.exists());
        let url = stub_relay(scenario.routes()).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();
        let args = scenario.args(&dir.path().join("desktop-cmd.json"));
        let error = cmd_landing_with_git_url(
            &client,
            &args,
            &trusted_for(&scenario.fx),
            scenario.git.relay.to_str().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        assert_eq!(crate::error::exit_code(&error), 1);

        // A checkout whose verifier bytes differ from the landed tree refuses
        // before running anything.
        std::fs::write(
            scenario.git.checkout.join(DESKTOP_VERIFIER),
            "import sys\nsys.exit(0)\n",
        )
        .unwrap();
        let receipt = scenario
            .verify(&scenario.args(&dir.path().join("desktop-bytes.json")))
            .await;
        assert_refused(
            &receipt.landing_checks,
            "desktop_verify_main",
            "desktop_verifier_source_differs",
        );
    }

    #[tokio::test]
    async fn existing_output_is_refused_before_any_read() {
        let scenario = Scenario::new(0);
        let dir = private_dir();
        let output = dir.path().join("exists.json");
        std::fs::write(&output, b"{}").unwrap();
        let url = stub_relay(Routes::new()).await;
        let client = BuzzClient::new(url, Keys::generate(), None, None).unwrap();
        let error = verify_landing(
            &client,
            &scenario.args(&output),
            &trusted_for(&scenario.fx),
            scenario.git.relay.to_str().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error}");
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = verify_landing(
            &client,
            &scenario.args(&open.join("r.json")),
            &trusted_for(&scenario.fx),
            scenario.git.relay.to_str().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("mode 0700"), "{error}");
    }

    #[test]
    fn desktop_release_mode_needs_the_mirror_and_runs_python_isolated() {
        let unchanged = git_fixture(0);
        assert!(!desktop_identity_changed(&unchanged.checkout, &unchanged.landed).unwrap());
        assert!(desktop_verify_main(&unchanged.checkout, &unchanged.landed, None).is_ok());

        let changed = git_fixture_with(0, true);
        assert!(desktop_identity_changed(&changed.checkout, &changed.landed).unwrap());
        let refusal = desktop_verify_main(&changed.checkout, &changed.landed, None).unwrap_err();
        assert_eq!(refusal.code, "desktop_release_repo_unset");
        assert!(refusal.detail.contains("--github-mirror"));
        // With the mirror named, the maintained gate runs and receives --repo.
        let detail =
            desktop_verify_main(&changed.checkout, &changed.landed, Some("only21mil/buzz"))
                .unwrap();
        assert!(
            detail.contains("\"--repo\", \"only21mil/buzz\""),
            "{detail}"
        );

        // An untracked module in scripts/ must not shadow the standard
        // library. `json` is not a built-in module (unlike `sys`), so without
        // -I the interpreter would import this poisoned copy from the script
        // directory first and the stub would exit "shadowed stdlib".
        std::fs::write(
            unchanged.checkout.join("scripts/json.py"),
            "raise SystemExit('shadowed stdlib')\n",
        )
        .unwrap();
        let detail = desktop_verify_main(&unchanged.checkout, &unchanged.landed, None).unwrap();
        assert!(detail.contains("stub verify-main"), "{detail}");
    }
}
