//! Durable, network-free state core for the Buzz CI control service.
//!
//! This crate does not load signer material, connect to the relay or runner,
//! publish events, or execute workflow code. Service wiring must provide those
//! capabilities around the closed state and persistence contracts below.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const RUNNER_CONTROL_SOCKET_PATH: &str = "/run/buzzci/runner-control.sock";
pub const RUNNER_OUTPUT_ROOT: &str = "/var/lib/buzzci/runner-output";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const DEFAULT_LIVENESS_WINDOW: Duration = Duration::from_secs(300);
pub const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

/// Trusted process configuration. Paths cannot be selected by a runner request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControldConfig {
    signer_key_path: PathBuf,
    runner_socket_path: PathBuf,
    runner_output_root: PathBuf,
    poll_interval: Duration,
    liveness_window: Duration,
}

impl ControldConfig {
    /// Build the fixed Phase-1 runner configuration around one dedicated key file.
    pub fn phase1(signer_key_path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        Self::new(
            signer_key_path.into(),
            PathBuf::from(RUNNER_CONTROL_SOCKET_PATH),
            PathBuf::from(RUNNER_OUTPUT_ROOT),
            DEFAULT_POLL_INTERVAL,
            DEFAULT_LIVENESS_WINDOW,
        )
    }

    /// Build configuration for tests and future reviewed deployment profiles.
    pub fn new(
        signer_key_path: PathBuf,
        runner_socket_path: PathBuf,
        runner_output_root: PathBuf,
        poll_interval: Duration,
        liveness_window: Duration,
    ) -> Result<Self, ConfigError> {
        for path in [
            signer_key_path.as_path(),
            runner_socket_path.as_path(),
            runner_output_root.as_path(),
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::RelativePath);
            }
        }
        if signer_key_path == runner_socket_path || signer_key_path.starts_with(&runner_output_root)
        {
            return Err(ConfigError::UnsafeSignerPath);
        }
        if poll_interval.is_zero()
            || liveness_window.is_zero()
            || poll_interval >= liveness_window
        {
            return Err(ConfigError::InvalidTiming);
        }
        Ok(Self {
            signer_key_path,
            runner_socket_path,
            runner_output_root,
            poll_interval,
            liveness_window,
        })
    }

    pub fn signer_key_path(&self) -> &Path {
        &self.signer_key_path
    }

    pub fn runner_socket_path(&self) -> &Path {
        &self.runner_socket_path
    }

    pub fn runner_output_root(&self) -> &Path {
        &self.runner_output_root
    }

    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub const fn liveness_window(&self) -> Duration {
        self.liveness_window
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("controld paths must be absolute")]
    RelativePath,
    #[error("the signer key path overlaps an untrusted runner path")]
    UnsafeSignerPath,
    #[error("poll and liveness durations must be nonzero, with poll shorter than liveness")]
    InvalidTiming,
}

/// Immutable identity for one accepted request attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunIdentity {
    request_event_id: String,
    run_id: Uuid,
    attempt: u32,
    target_repo_a: String,
    tip_oid: String,
    workflow_id: String,
}

impl RunIdentity {
    pub fn new(
        request_event_id: String,
        run_id: Uuid,
        attempt: u32,
        target_repo_a: String,
        tip_oid: String,
        workflow_id: String,
    ) -> Result<Self, StateError> {
        if !is_lower_hex(&request_event_id, 64)
            || attempt == 0
            || target_repo_a.is_empty()
            || (!is_lower_hex(&tip_oid, 40) && !is_lower_hex(&tip_oid, 64))
            || workflow_id.is_empty()
        {
            return Err(StateError::InvalidIdentity);
        }
        Ok(Self {
            request_event_id,
            run_id,
            attempt,
            target_repo_a,
            tip_oid,
            workflow_id,
        })
    }

    pub fn request_event_id(&self) -> &str {
        &self.request_event_id
    }

    pub const fn run_id(&self) -> Uuid {
        self.run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn target_repo_a(&self) -> &str {
        &self.target_repo_a
    }

    pub fn tip_oid(&self) -> &str {
        &self.tip_oid
    }

    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
}

/// Closed kind-46101 run states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Success,
    Failure,
    Cancelled,
    TimedOut,
    InfrastructureFailure,
}

impl RunState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success
                | Self::Failure
                | Self::Cancelled
                | Self::TimedOut
                | Self::InfrastructureFailure
        )
    }

    const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Queued,
                Self::Running | Self::Cancelled | Self::InfrastructureFailure
            ) | (
                Self::Running,
                Self::Success
                    | Self::Failure
                    | Self::Cancelled
                    | Self::TimedOut
                    | Self::InfrastructureFailure
            )
        )
    }
}

/// Stored terminal facts needed before a success transition can be proposed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TerminalFacts {
    evidence_finalized_event_id: Option<String>,
    teardown_attestation_event_id: Option<String>,
}

impl TerminalFacts {
    pub fn evidence_finalized_event_id(&self) -> Option<&str> {
        self.evidence_finalized_event_id.as_deref()
    }

    pub fn teardown_attestation_event_id(&self) -> Option<&str> {
        self.teardown_attestation_event_id.as_deref()
    }

    const fn permits_success(&self) -> bool {
        self.evidence_finalized_event_id.is_some()
            && self.teardown_attestation_event_id.is_some()
    }
}

/// Durable run projection. `sequence` is the current kind-46101 stream sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunRecord {
    identity: RunIdentity,
    state: RunState,
    sequence: u64,
    queued_at: u64,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    reason: Option<String>,
    facts: TerminalFacts,
    terminal_event_id: Option<String>,
}

impl RunRecord {
    pub fn queued(identity: RunIdentity, queued_at: u64) -> Result<Self, StateError> {
        require_timestamp(queued_at)?;
        Ok(Self {
            identity,
            state: RunState::Queued,
            sequence: 1,
            queued_at,
            started_at: None,
            finished_at: None,
            reason: None,
            facts: TerminalFacts::default(),
            terminal_event_id: None,
        })
    }

    pub fn identity(&self) -> &RunIdentity {
        &self.identity
    }

    pub const fn state(&self) -> RunState {
        self.state
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn queued_at(&self) -> u64 {
        self.queued_at
    }

    pub const fn started_at(&self) -> Option<u64> {
        self.started_at
    }

    pub const fn finished_at(&self) -> Option<u64> {
        self.finished_at
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn terminal_facts(&self) -> &TerminalFacts {
        &self.facts
    }

    pub fn terminal_event_id(&self) -> Option<&str> {
        self.terminal_event_id.as_deref()
    }

    /// Return the next immutable projection for one legal protocol transition.
    pub fn transition(
        &self,
        next: RunState,
        at: u64,
        reason: Option<String>,
    ) -> Result<Self, StateError> {
        require_timestamp(at)?;
        if !self.state.permits(next) {
            return Err(if self.state.is_terminal() {
                StateError::TerminalState
            } else {
                StateError::IllegalTransition
            });
        }
        if at < self.queued_at || self.started_at.is_some_and(|started| at < started) {
            return Err(StateError::TimestampRegression);
        }
        if next == RunState::Success && !self.facts.permits_success() {
            return Err(StateError::MissingTerminalFacts);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= MAX_SAFE_INTEGER)
            .ok_or(StateError::SequenceExhausted)?;
        let mut updated = self.clone();
        updated.state = next;
        updated.sequence = sequence;
        updated.reason = reason;
        if next == RunState::Running {
            updated.started_at = Some(at);
        }
        if next.is_terminal() {
            updated.finished_at = Some(at);
        }
        Ok(updated)
    }

    /// Bind an accepted kind-46105 fact before terminal success publication.
    pub fn with_evidence_finalized(
        &self,
        event_id: String,
    ) -> Result<Self, StateError> {
        self.with_terminal_fact(event_id, TerminalFactKind::EvidenceFinalized)
    }

    /// Bind an accepted kind-46106 fact before terminal success publication.
    pub fn with_teardown_attestation(
        &self,
        event_id: String,
    ) -> Result<Self, StateError> {
        self.with_terminal_fact(event_id, TerminalFactKind::TeardownAttestation)
    }

    /// Bind the one stored terminal kind-46101 event to its terminal projection.
    pub fn with_terminal_event(&self, event_id: String) -> Result<Self, StateError> {
        if !self.state.is_terminal() {
            return Err(StateError::NotTerminal);
        }
        if self.terminal_event_id.is_some() {
            return Err(StateError::TerminalEventAlreadyBound);
        }
        require_event_id(&event_id)?;
        let mut updated = self.clone();
        updated.terminal_event_id = Some(event_id);
        Ok(updated)
    }

    fn with_terminal_fact(
        &self,
        event_id: String,
        kind: TerminalFactKind,
    ) -> Result<Self, StateError> {
        if self.state != RunState::Running {
            return Err(StateError::FactsOutsideRunningState);
        }
        require_event_id(&event_id)?;
        let slot = match kind {
            TerminalFactKind::EvidenceFinalized => &self.facts.evidence_finalized_event_id,
            TerminalFactKind::TeardownAttestation => &self.facts.teardown_attestation_event_id,
        };
        if slot.is_some() {
            return Err(StateError::TerminalFactAlreadyBound);
        }
        let mut updated = self.clone();
        match kind {
            TerminalFactKind::EvidenceFinalized => {
                updated.facts.evidence_finalized_event_id = Some(event_id);
            }
            TerminalFactKind::TeardownAttestation => {
                updated.facts.teardown_attestation_event_id = Some(event_id);
            }
        }
        Ok(updated)
    }
}

#[derive(Clone, Copy)]
enum TerminalFactKind {
    EvidenceFinalized,
    TeardownAttestation,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StateError {
    #[error("run identity is invalid")]
    InvalidIdentity,
    #[error("timestamp is zero or exceeds the maximum safe integer")]
    InvalidTimestamp,
    #[error("run transition is not allowed")]
    IllegalTransition,
    #[error("terminal run state cannot transition")]
    TerminalState,
    #[error("transition timestamp moved backwards")]
    TimestampRegression,
    #[error("run sequence is exhausted")]
    SequenceExhausted,
    #[error("success requires accepted evidence-finalized and teardown facts")]
    MissingTerminalFacts,
    #[error("terminal facts can be bound only while the run is running")]
    FactsOutsideRunningState,
    #[error("terminal fact is already bound")]
    TerminalFactAlreadyBound,
    #[error("event ID must be 64 lowercase hexadecimal characters")]
    InvalidEventId,
    #[error("run is not terminal")]
    NotTerminal,
    #[error("terminal event is already bound")]
    TerminalEventAlreadyBound,
}

/// Result of an optimistic persistence write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreWrite {
    Written { revision: u64 },
    Conflict { actual_revision: Option<u64> },
}

/// Persistence boundary for crash-safe, single-writer run ownership.
pub trait RunStateStore {
    type Error;

    fn load(&self, identity: &RunIdentity) -> Result<Option<(u64, RunRecord)>, Self::Error>;

    fn compare_and_swap(
        &mut self,
        identity: &RunIdentity,
        expected_revision: Option<u64>,
        next: &RunRecord,
    ) -> Result<StoreWrite, Self::Error>;
}

fn require_timestamp(value: u64) -> Result<(), StateError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(StateError::InvalidTimestamp);
    }
    Ok(())
}

fn require_event_id(value: &str) -> Result<(), StateError> {
    if !is_lower_hex(value, 64) {
        return Err(StateError::InvalidEventId);
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RunIdentity {
        RunIdentity::new(
            "a".repeat(64),
            Uuid::from_u128(1),
            1,
            format!("30617:{}:buzz", "b".repeat(64)),
            "c".repeat(40),
            "ci".into(),
        )
        .expect("identity")
    }

    fn running() -> RunRecord {
        RunRecord::queued(identity(), 10)
            .expect("queued")
            .transition(RunState::Running, 11, None)
            .expect("running")
    }

    #[test]
    fn protocol_transition_table_is_closed() {
        let states = [
            RunState::Queued,
            RunState::Running,
            RunState::Success,
            RunState::Failure,
            RunState::Cancelled,
            RunState::TimedOut,
            RunState::InfrastructureFailure,
        ];
        for current in states {
            for next in states {
                let expected = matches!(
                    (current, next),
                    (
                        RunState::Queued,
                        RunState::Running
                            | RunState::Cancelled
                            | RunState::InfrastructureFailure
                    ) | (
                        RunState::Running,
                        RunState::Success
                            | RunState::Failure
                            | RunState::Cancelled
                            | RunState::TimedOut
                            | RunState::InfrastructureFailure
                    )
                );
                assert_eq!(current.permits(next), expected, "{current:?} -> {next:?}");
            }
        }

        let queued = RunRecord::queued(identity(), 10).expect("queued");
        assert_eq!(
            queued.transition(RunState::Success, 11, None),
            Err(StateError::IllegalTransition)
        );

        let terminal = running()
            .transition(RunState::Failure, 12, Some("job_failed".into()))
            .expect("failure");
        assert_eq!(terminal.sequence(), 3);
        assert_eq!(terminal.finished_at(), Some(12));
        assert_eq!(
            terminal.transition(RunState::Running, 13, None),
            Err(StateError::TerminalState)
        );
    }

    #[test]
    fn success_requires_both_accepted_terminal_facts() {
        let running = running();
        assert_eq!(
            running.transition(RunState::Success, 12, None),
            Err(StateError::MissingTerminalFacts)
        );
        let with_evidence = running
            .with_evidence_finalized("d".repeat(64))
            .expect("evidence");
        assert_eq!(
            with_evidence.transition(RunState::Success, 12, None),
            Err(StateError::MissingTerminalFacts)
        );
        let success = with_evidence
            .with_teardown_attestation("e".repeat(64))
            .expect("teardown")
            .transition(RunState::Success, 12, None)
            .expect("success");
        assert_eq!(success.state(), RunState::Success);
    }

    #[test]
    fn terminal_event_can_be_bound_only_once() {
        let terminal = running()
            .transition(RunState::InfrastructureFailure, 12, None)
            .expect("terminal");
        let bound = terminal
            .with_terminal_event("f".repeat(64))
            .expect("terminal event");
        assert_eq!(
            bound.with_terminal_event("1".repeat(64)),
            Err(StateError::TerminalEventAlreadyBound)
        );
    }

    #[test]
    fn configuration_rejects_runner_owned_signer_path() {
        assert_eq!(
            ControldConfig::new(
                PathBuf::from("/var/lib/buzzci/runner-output/key"),
                PathBuf::from(RUNNER_CONTROL_SOCKET_PATH),
                PathBuf::from(RUNNER_OUTPUT_ROOT),
                DEFAULT_POLL_INTERVAL,
                DEFAULT_LIVENESS_WINDOW,
            ),
            Err(ConfigError::UnsafeSignerPath)
        );
    }
}
