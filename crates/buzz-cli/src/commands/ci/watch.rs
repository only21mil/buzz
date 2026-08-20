//! Transport-neutral ordering and replay state for `buzz ci watch`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;

/// One typed record from the relay's per-run watch stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchRecord {
    /// Stable run identifier resolved before watching.
    pub run_id: String,
    /// Exact source object ID for the run.
    pub sha: String,
    /// Selected top-level attempt for this event.
    pub attempt: u32,
    /// Durable per-run acceptance cursor.
    pub watch_cursor: u64,
    /// Signed CI event identifier.
    pub event_id: String,
    /// Record category.
    pub scope: WatchScope,
    /// Static job identifier for job-scoped evidence or status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Run or job state for status records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<WatchEventState>,
    /// Event timestamp supplied by the relay.
    pub timestamp: u64,
}

/// Closed watch-record scope from relay/API contract v1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchScope {
    /// Run request or run-status event.
    Run,
    /// Job-status event.
    Job,
    /// Per-job evidence or the run evidence-finalized fact.
    Evidence,
    /// Run teardown-attestation fact.
    Teardown,
}

/// State names shared by typed run and job watch records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchEventState {
    /// Accepted and waiting to start.
    Queued,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Success,
    /// Required code or test work failed.
    Failure,
    /// Cancelled before completion.
    Cancelled,
    /// Exceeded the allowed runtime.
    TimedOut,
    /// Skipped under signed job policy.
    Skipped,
    /// Infrastructure or evidence integrity failed.
    InfrastructureFailure,
}

impl WatchEventState {
    const fn is_terminal_run(self) -> bool {
        !matches!(self, Self::Queued | Self::Running | Self::Skipped)
    }
}

/// An operation for the transport or output layer to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAction {
    /// Emit one cursor-ordered record.
    Emit(WatchRecord),
    /// Fetch a bounded, exclusive replay after the supplied cursor.
    RequestReplay(WatchReplayRequest),
    /// Stop the watch with a terminal result.
    Exit(WatchExit),
}

/// A bounded replay request independent of any HTTP or WebSocket route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchReplayRequest {
    /// Last cursor completely emitted to the caller.
    pub after_cursor: u64,
    /// Maximum records to fetch in this replay request.
    pub limit: NonZeroUsize,
}

/// Terminal result of a watch stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchExit {
    /// A terminal run record and both required terminal facts were emitted.
    Terminal {
        /// Terminal run state observed in cursor order.
        state: WatchEventState,
    },
    /// The relay reported or the ordering state detected infrastructure failure.
    InfrastructureFailure(WatchInfrastructureFailure),
}

/// Typed fail-closed reason from the watch state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchInfrastructureFailure {
    /// The relay emitted a typed `infrastructure_failure` run state.
    Reported {
        /// Event that reported the failure.
        event_id: String,
    },
    /// A record belongs to another run.
    RunMismatch {
        /// Run selected by the caller.
        expected: String,
        /// Run carried by the record.
        received: String,
    },
    /// A record belongs to another source revision.
    ShaMismatch {
        /// Source object ID selected by the caller.
        expected: String,
        /// Source object ID carried by the record.
        received: String,
    },
    /// One cursor was assigned to two event IDs.
    CursorEquivocation {
        /// Equivocated cursor.
        cursor: u64,
        /// First event observed at the cursor.
        first_event_id: String,
        /// Conflicting event observed at the cursor.
        conflicting_event_id: String,
    },
    /// One event ID was assigned more than one durable cursor.
    EventReassigned {
        /// Reassigned event ID.
        event_id: String,
        /// First cursor observed for the event.
        first_cursor: u64,
        /// Conflicting cursor observed for the event.
        conflicting_cursor: u64,
    },
    /// An exclusive stream returned an unknown cursor at or before its checkpoint.
    CursorRegression {
        /// Last cursor completely emitted before the record arrived.
        last_fully_emitted: u64,
        /// Regressing cursor.
        received: u64,
    },
    /// The cursor was zero or the next cursor could not be represented.
    InvalidCursor {
        /// Invalid cursor.
        cursor: u64,
    },
    /// A typed record has a scope-incompatible shape.
    InvalidRecord {
        /// Event whose shape was rejected.
        event_id: String,
        /// Stable machine-readable rejection reason.
        reason: WatchRecordError,
    },
}

/// Scope-local record-shape failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchRecordError {
    /// Attempts are one-based.
    AttemptZero,
    /// A job record requires a job ID.
    MissingJobId,
    /// A job record requires a state.
    MissingJobState,
    /// `infrastructure_failure` is a run-only state.
    InfrastructureFailureOnJob,
    /// `skipped` is a job-only state.
    SkippedRun,
    /// A fact record cannot carry a run or job state.
    StateOnFact,
    /// A teardown fact cannot carry a job ID.
    JobIdOnTeardown,
}

/// Pure state machine for one resolved CI watch stream.
#[derive(Debug)]
pub struct WatchStream {
    run_id: String,
    sha: String,
    replay_limit: NonZeroUsize,
    last_fully_emitted: u64,
    emitted_events: BTreeMap<u64, String>,
    cursor_by_event: HashMap<String, u64>,
    pending: BTreeMap<u64, WatchRecord>,
    replay_requested_after: Option<u64>,
    terminal_run: Option<WatchEventState>,
    evidence_finalized_emitted: bool,
    teardown_emitted: bool,
    exit: Option<WatchExit>,
}

impl WatchStream {
    /// Create state for an exclusive stream after `last_fully_emitted`.
    pub fn new(
        run_id: impl Into<String>,
        sha: impl Into<String>,
        last_fully_emitted: u64,
        replay_limit: NonZeroUsize,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            sha: sha.into(),
            replay_limit,
            last_fully_emitted,
            emitted_events: BTreeMap::new(),
            cursor_by_event: HashMap::new(),
            pending: BTreeMap::new(),
            replay_requested_after: None,
            terminal_run: None,
            evidence_finalized_emitted: false,
            teardown_emitted: false,
            exit: None,
        }
    }

    /// Consume one typed record and return ordered output, replay, or exit actions.
    pub fn consume(&mut self, record: WatchRecord) -> Vec<WatchAction> {
        if self.exit.is_some() {
            return Vec::new();
        }

        if record.run_id != self.run_id {
            return self.fail(WatchInfrastructureFailure::RunMismatch {
                expected: self.run_id.clone(),
                received: record.run_id,
            });
        }
        if record.sha != self.sha {
            return self.fail(WatchInfrastructureFailure::ShaMismatch {
                expected: self.sha.clone(),
                received: record.sha,
            });
        }
        if record.watch_cursor == 0 {
            return self.fail(WatchInfrastructureFailure::InvalidCursor { cursor: 0 });
        }
        if let Err(reason) = validate_record_shape(&record) {
            return self.fail(WatchInfrastructureFailure::InvalidRecord {
                event_id: record.event_id,
                reason,
            });
        }

        if let Some(first_event_id) = self.event_at_cursor(record.watch_cursor) {
            if first_event_id == record.event_id {
                return Vec::new();
            }
            return self.fail(WatchInfrastructureFailure::CursorEquivocation {
                cursor: record.watch_cursor,
                first_event_id: first_event_id.to_owned(),
                conflicting_event_id: record.event_id,
            });
        }

        if let Some(first_cursor) = self.cursor_by_event.get(&record.event_id).copied() {
            return self.fail(WatchInfrastructureFailure::EventReassigned {
                event_id: record.event_id,
                first_cursor,
                conflicting_cursor: record.watch_cursor,
            });
        }

        if record.watch_cursor <= self.last_fully_emitted {
            return self.fail(WatchInfrastructureFailure::CursorRegression {
                last_fully_emitted: self.last_fully_emitted,
                received: record.watch_cursor,
            });
        }

        self.cursor_by_event
            .insert(record.event_id.clone(), record.watch_cursor);
        self.pending.insert(record.watch_cursor, record);

        let mut actions = self.emit_ready();
        if self.exit.is_none() {
            self.request_replay_for_gap(&mut actions);
        }
        actions
    }

    /// Finish the current bounded replay page.
    ///
    /// A page that advanced the fully emitted cursor may request the next page.
    /// An empty or otherwise unreconciled page leaves the gap pending without
    /// spinning on the same request.
    pub fn replay_finished(&mut self) -> Vec<WatchAction> {
        let Some(replay_start) = self.replay_requested_after.take() else {
            return Vec::new();
        };
        if self.exit.is_some()
            || self.pending_gap().is_none()
            || self.last_fully_emitted == replay_start
        {
            return Vec::new();
        }

        let mut actions = Vec::new();
        self.request_replay_for_gap(&mut actions);
        actions
    }

    /// Return the last cursor completely emitted to the caller.
    pub const fn last_fully_emitted_cursor(&self) -> u64 {
        self.last_fully_emitted
    }

    /// Return the current terminal result, if the stream has exited.
    pub fn exit(&self) -> Option<&WatchExit> {
        self.exit.as_ref()
    }

    /// Return the first missing and first buffered cursors while replay is pending.
    pub fn pending_gap(&self) -> Option<(u64, u64)> {
        let first_buffered = self.pending.first_key_value()?.0;
        let first_missing = self.last_fully_emitted.checked_add(1)?;
        (*first_buffered > first_missing).then_some((first_missing, *first_buffered))
    }

    fn event_at_cursor(&self, cursor: u64) -> Option<&str> {
        self.emitted_events
            .get(&cursor)
            .or_else(|| self.pending.get(&cursor).map(|record| &record.event_id))
            .map(String::as_str)
    }

    fn emit_ready(&mut self) -> Vec<WatchAction> {
        let mut actions = Vec::new();
        loop {
            let Some(next_cursor) = self.last_fully_emitted.checked_add(1) else {
                actions.extend(self.fail(WatchInfrastructureFailure::InvalidCursor {
                    cursor: self.last_fully_emitted,
                }));
                break;
            };
            let Some(record) = self.pending.remove(&next_cursor) else {
                break;
            };

            self.last_fully_emitted = next_cursor;
            self.emitted_events
                .insert(next_cursor, record.event_id.clone());
            self.observe_emitted(&record);
            actions.push(WatchAction::Emit(record.clone()));

            if let Some(exit) = self.exit_after(&record) {
                self.exit = Some(exit.clone());
                self.pending.clear();
                actions.push(WatchAction::Exit(exit));
                break;
            }
        }
        actions
    }

    fn observe_emitted(&mut self, record: &WatchRecord) {
        match record.scope {
            WatchScope::Run => {
                if let Some(state) = record.state.filter(|state| state.is_terminal_run()) {
                    self.terminal_run = Some(state);
                }
            }
            WatchScope::Evidence if record.job_id.is_none() => {
                self.evidence_finalized_emitted = true;
            }
            WatchScope::Teardown => self.teardown_emitted = true,
            WatchScope::Job | WatchScope::Evidence => {}
        }
    }

    fn exit_after(&self, record: &WatchRecord) -> Option<WatchExit> {
        if record.scope == WatchScope::Run
            && record.state == Some(WatchEventState::InfrastructureFailure)
        {
            return Some(WatchExit::InfrastructureFailure(
                WatchInfrastructureFailure::Reported {
                    event_id: record.event_id.clone(),
                },
            ));
        }
        if self.evidence_finalized_emitted && self.teardown_emitted {
            return self.terminal_run.map(|state| WatchExit::Terminal { state });
        }
        None
    }

    fn request_replay_for_gap(&mut self, actions: &mut Vec<WatchAction>) {
        if self.pending_gap().is_none() {
            self.replay_requested_after = None;
            return;
        }
        if self.replay_requested_after.is_some() {
            return;
        }
        self.replay_requested_after = Some(self.last_fully_emitted);
        actions.push(WatchAction::RequestReplay(WatchReplayRequest {
            after_cursor: self.last_fully_emitted,
            limit: self.replay_limit,
        }));
    }

    fn fail(&mut self, failure: WatchInfrastructureFailure) -> Vec<WatchAction> {
        let exit = WatchExit::InfrastructureFailure(failure);
        self.exit = Some(exit.clone());
        self.pending.clear();
        vec![WatchAction::Exit(exit)]
    }
}

fn validate_record_shape(record: &WatchRecord) -> Result<(), WatchRecordError> {
    if record.attempt == 0 {
        return Err(WatchRecordError::AttemptZero);
    }
    match record.scope {
        WatchScope::Run => {
            if record.state == Some(WatchEventState::Skipped) {
                return Err(WatchRecordError::SkippedRun);
            }
        }
        WatchScope::Job => {
            if record.job_id.is_none() {
                return Err(WatchRecordError::MissingJobId);
            }
            match record.state {
                None => return Err(WatchRecordError::MissingJobState),
                Some(WatchEventState::InfrastructureFailure) => {
                    return Err(WatchRecordError::InfrastructureFailureOnJob);
                }
                Some(_) => {}
            }
        }
        WatchScope::Evidence => {
            if record.state.is_some() {
                return Err(WatchRecordError::StateOnFact);
            }
        }
        WatchScope::Teardown => {
            if record.state.is_some() {
                return Err(WatchRecordError::StateOnFact);
            }
            if record.job_id.is_some() {
                return Err(WatchRecordError::JobIdOnTeardown);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "run-1";
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn stream() -> WatchStream {
        WatchStream::new(RUN, SHA, 0, NonZeroUsize::new(16).expect("nonzero"))
    }

    fn record(cursor: u64, event_id: &str, scope: WatchScope) -> WatchRecord {
        WatchRecord {
            run_id: RUN.to_owned(),
            sha: SHA.to_owned(),
            attempt: 1,
            watch_cursor: cursor,
            event_id: event_id.to_owned(),
            scope,
            job_id: None,
            state: None,
            timestamp: cursor,
        }
    }

    fn run_record(cursor: u64, event_id: &str, state: WatchEventState) -> WatchRecord {
        WatchRecord {
            state: Some(state),
            ..record(cursor, event_id, WatchScope::Run)
        }
    }

    fn emitted_cursors(actions: &[WatchAction]) -> Vec<u64> {
        actions
            .iter()
            .filter_map(|action| match action {
                WatchAction::Emit(record) => Some(record.watch_cursor),
                WatchAction::RequestReplay(_) | WatchAction::Exit(_) => None,
            })
            .collect()
    }

    #[test]
    fn clean_stream_exits_after_terminal_run_and_facts() {
        let mut state = stream();
        assert_eq!(
            emitted_cursors(&state.consume(run_record(1, "run-running", WatchEventState::Running))),
            [1]
        );
        assert_eq!(
            emitted_cursors(&state.consume(record(2, "evidence", WatchScope::Evidence))),
            [2]
        );
        assert_eq!(
            emitted_cursors(&state.consume(record(3, "teardown", WatchScope::Teardown))),
            [3]
        );

        let actions = state.consume(run_record(4, "run-success", WatchEventState::Success));
        assert_eq!(emitted_cursors(&actions), [4]);
        assert_eq!(
            actions.last(),
            Some(&WatchAction::Exit(WatchExit::Terminal {
                state: WatchEventState::Success
            }))
        );
    }

    #[test]
    fn identical_cursor_event_duplicate_is_suppressed() {
        let mut state = stream();
        let first = run_record(1, "same", WatchEventState::Running);
        assert_eq!(emitted_cursors(&state.consume(first.clone())), [1]);
        assert!(state.consume(first).is_empty());
        assert_eq!(state.last_fully_emitted_cursor(), 1);
    }

    #[test]
    fn cursor_equivocation_fails_closed() {
        let mut state = stream();
        state.consume(run_record(1, "first", WatchEventState::Running));
        let actions = state.consume(run_record(1, "other", WatchEventState::Running));
        assert_eq!(
            actions,
            [WatchAction::Exit(WatchExit::InfrastructureFailure(
                WatchInfrastructureFailure::CursorEquivocation {
                    cursor: 1,
                    first_event_id: "first".to_owned(),
                    conflicting_event_id: "other".to_owned(),
                }
            ))]
        );
    }

    #[test]
    fn gap_requests_bounded_replay_and_recovers_in_order() {
        let mut state = stream();
        state.consume(run_record(1, "one", WatchEventState::Running));

        let gap = state.consume(record(3, "three", WatchScope::Evidence));
        assert_eq!(
            gap,
            [WatchAction::RequestReplay(WatchReplayRequest {
                after_cursor: 1,
                limit: NonZeroUsize::new(16).expect("nonzero"),
            })]
        );
        assert_eq!(state.pending_gap(), Some((2, 3)));

        let recovered = state.consume(record(2, "two", WatchScope::Evidence));
        assert_eq!(emitted_cursors(&recovered), [2, 3]);
        assert_eq!(state.last_fully_emitted_cursor(), 3);
        assert_eq!(state.pending_gap(), None);
    }

    #[test]
    fn replay_pages_do_not_spin_while_a_gap_remains() {
        let mut state = stream();
        state.consume(run_record(1, "one", WatchEventState::Running));
        state.consume(record(5, "five", WatchScope::Evidence));

        let partial = state.consume(record(2, "two", WatchScope::Evidence));
        assert_eq!(emitted_cursors(&partial), [2]);
        assert!(
            !partial
                .iter()
                .any(|action| matches!(action, WatchAction::RequestReplay(_)))
        );

        assert_eq!(
            state.replay_finished(),
            [WatchAction::RequestReplay(WatchReplayRequest {
                after_cursor: 2,
                limit: NonZeroUsize::new(16).expect("nonzero"),
            })]
        );
        assert_eq!(state.pending_gap(), Some((3, 5)));
        assert!(state.replay_finished().is_empty());
        assert_eq!(state.pending_gap(), Some((3, 5)));
    }

    #[test]
    fn stale_run_or_sha_fails_closed() {
        let mut stale_run = record(1, "stale-run", WatchScope::Evidence);
        stale_run.run_id = "run-2".to_owned();
        let mut state = stream();
        assert!(matches!(
            state.consume(stale_run).as_slice(),
            [WatchAction::Exit(WatchExit::InfrastructureFailure(
                WatchInfrastructureFailure::RunMismatch { .. }
            ))]
        ));

        let mut stale_sha = record(1, "stale-sha", WatchScope::Evidence);
        stale_sha.sha = "fedcba9876543210fedcba9876543210fedcba98".to_owned();
        let mut state = stream();
        assert!(matches!(
            state.consume(stale_sha).as_slice(),
            [WatchAction::Exit(WatchExit::InfrastructureFailure(
                WatchInfrastructureFailure::ShaMismatch { .. }
            ))]
        ));
    }

    #[test]
    fn terminal_run_waits_for_both_facts() {
        let mut state = stream();
        let terminal = state.consume(run_record(1, "terminal", WatchEventState::Failure));
        assert_eq!(emitted_cursors(&terminal), [1]);
        assert_eq!(state.exit(), None);

        state.consume(record(2, "evidence", WatchScope::Evidence));
        assert_eq!(state.exit(), None);

        let teardown = state.consume(record(3, "teardown", WatchScope::Teardown));
        assert_eq!(emitted_cursors(&teardown), [3]);
        assert_eq!(
            teardown.last(),
            Some(&WatchAction::Exit(WatchExit::Terminal {
                state: WatchEventState::Failure
            }))
        );
    }

    #[test]
    fn typed_infrastructure_failure_exits_without_terminal_facts() {
        let mut state = stream();
        let actions = state.consume(run_record(
            1,
            "infra-failure",
            WatchEventState::InfrastructureFailure,
        ));
        assert_eq!(emitted_cursors(&actions), [1]);
        assert_eq!(
            actions.last(),
            Some(&WatchAction::Exit(WatchExit::InfrastructureFailure(
                WatchInfrastructureFailure::Reported {
                    event_id: "infra-failure".to_owned()
                }
            )))
        );
    }
}
