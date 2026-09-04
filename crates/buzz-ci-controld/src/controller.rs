//! Capacity-one production composition over explicit host providers.
//!
//! This layer does not discover capabilities or substitute defaults. A host
//! must supply every provider and a validated activation configuration before
//! the controller reports capacity. Any production error consumes that
//! capacity until the process is restarted and durable state is reconciled.

use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use crate::production::{
    AttemptExecutor, CiSigner, ControlStore, EvidenceReader, PollStep, ProductionError,
    ProductionHandler, RelayControl, RunnerAttemptExecutor, RunnerAttemptPreparer,
};
use crate::runner_client::{RunnerClient, RunnerConnector};

const STATUS_SCHEMA_VERSION: u32 = 2;
const CAPACITY: u32 = 1;
const MAX_CHANNEL_BYTES: usize = 512;
const MAX_POLL_INTERVAL_MILLIS: u64 = 60_000;
const MAX_RUNNER_TRANSPORT_ATTEMPTS: u32 = 8;

/// Strict activation configuration for one synchronous controller slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityOneConfig {
    channel_id: String,
    poll_interval: Duration,
    runner_transport_attempts: u32,
}

impl CapacityOneConfig {
    /// Build validated configuration supplied by the sole daemon-config
    /// deserializer after every production provider has been validated.
    pub fn new(
        channel_id: String,
        poll_interval: Duration,
        runner_transport_attempts: u32,
    ) -> Result<Self, ActivationError> {
        if channel_id.is_empty()
            || channel_id.len() > MAX_CHANNEL_BYTES
            || channel_id.chars().any(char::is_control)
            || poll_interval.is_zero()
            || poll_interval > Duration::from_millis(MAX_POLL_INTERVAL_MILLIS)
            || runner_transport_attempts == 0
            || runner_transport_attempts > MAX_RUNNER_TRANSPORT_ATTEMPTS
        {
            return Err(ActivationError::InvalidConfig);
        }
        Ok(Self {
            channel_id,
            poll_interval,
            runner_transport_attempts,
        })
    }

    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub const fn runner_transport_attempts(&self) -> u32 {
        self.runner_transport_attempts
    }
}

/// Explicit provider slots used at the activation boundary.
///
/// `activate` rejects the entire set if any slot is absent. Provider-specific
/// constructors remain responsible for validating endpoints, identities, and
/// local storage before placing a value in a slot.
pub struct CapacityOneProviderSlots<R, S, X, P, O> {
    relay: Option<R>,
    signer: Option<S>,
    executor: Option<X>,
    store: Option<P>,
    output: Option<O>,
}

impl<R, S, X, P, O> CapacityOneProviderSlots<R, S, X, P, O> {
    pub const fn new(
        relay: Option<R>,
        signer: Option<S>,
        executor: Option<X>,
        store: Option<P>,
        output: Option<O>,
    ) -> Self {
        Self {
            relay,
            signer,
            executor,
            store,
            output,
        }
    }

    fn complete(self) -> Result<(R, S, X, P, O), ActivationError> {
        match (
            self.relay,
            self.signer,
            self.executor,
            self.store,
            self.output,
        ) {
            (Some(relay), Some(signer), Some(executor), Some(store), Some(output)) => {
                Ok((relay, signer, executor, store, output))
            }
            _ => Err(ActivationError::MissingProvider),
        }
    }
}

/// Fail-closed activation failures which contain no provider details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ActivationError {
    #[error("capacity-one controller configuration is invalid")]
    InvalidConfig,
    #[error("capacity-one controller requires every production provider")]
    MissingProvider,
    #[error("capacity-one controller provider configuration is invalid")]
    InvalidProvider,
}

/// Capacity-one controller using the frozen runner client and preparation
/// bridge.
pub type RunnerBackedCapacityOneController<R, S, C, A, P, O> =
    CapacityOneController<R, S, RunnerAttemptExecutor<C, A>, P, O>;

/// Compose the stable runner connector/client/attempt bridge and activate the
/// controller in one fail-closed operation.
pub fn activate_runner_backed<R, S, C, A, P, O>(
    config: CapacityOneConfig,
    relay: R,
    signer: S,
    connector: C,
    preparer: A,
    store: P,
    output: O,
) -> Result<RunnerBackedCapacityOneController<R, S, C, A, P, O>, ActivationError>
where
    R: RelayControl,
    S: CiSigner,
    C: RunnerConnector,
    A: RunnerAttemptPreparer,
    P: ControlStore,
    O: EvidenceReader,
{
    let client = RunnerClient::new(connector, config.runner_transport_attempts())
        .map_err(|_| ActivationError::InvalidProvider)?;
    CapacityOneController::activate(
        config,
        CapacityOneProviderSlots::new(
            Some(relay),
            Some(signer),
            Some(RunnerAttemptExecutor::new(client, preparer)),
            Some(store),
            Some(output),
        ),
    )
}

/// Machine-readable controller state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CapacityOneStatus {
    schema_version: u32,
    state: ControllerState,
    configured_capacity: u32,
    available_capacity: u32,
    in_flight: u32,
    terminal_reason: Option<TerminalInfrastructureReason>,
}

impl CapacityOneStatus {
    /// Deliberately dormant default with no admission or provider activity.
    pub const fn parked() -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION,
            state: ControllerState::Parked,
            configured_capacity: 0,
            available_capacity: 0,
            in_flight: 0,
            terminal_reason: None,
        }
    }

    const fn ready() -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION,
            state: ControllerState::Ready,
            configured_capacity: CAPACITY,
            available_capacity: CAPACITY,
            in_flight: 0,
            terminal_reason: None,
        }
    }

    const fn polling() -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION,
            state: ControllerState::Polling,
            configured_capacity: CAPACITY,
            available_capacity: 0,
            in_flight: CAPACITY,
            terminal_reason: None,
        }
    }

    /// Readback while the sole attempt is owned by the durable async worker.
    pub const fn active_attempt() -> Self {
        Self::polling()
    }

    const fn terminal(reason: TerminalInfrastructureReason) -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION,
            state: ControllerState::TerminalInfrastructureFailure,
            configured_capacity: CAPACITY,
            available_capacity: 0,
            in_flight: 0,
            terminal_reason: Some(reason),
        }
    }

    /// Closed startup readback when provider construction fails before a
    /// controller value can exist.
    pub const fn startup_failure(reason: TerminalInfrastructureReason) -> Self {
        Self::terminal(reason)
    }

    pub const fn state(self) -> ControllerState {
        self.state
    }

    pub const fn available_capacity(self) -> u32 {
        self.available_capacity
    }

    pub const fn configured_capacity(self) -> u32 {
        self.configured_capacity
    }

    pub const fn in_flight(self) -> u32 {
        self.in_flight
    }

    pub const fn terminal_reason(self) -> Option<TerminalInfrastructureReason> {
        self.terminal_reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerState {
    Parked,
    Ready,
    Polling,
    TerminalInfrastructureFailure,
}

/// Closed reason set for a terminal host failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalInfrastructureReason {
    Relay,
    Store,
    Signer,
    Runner,
    Evidence,
    InvalidInput,
    State,
    PublicationConflict,
}

impl From<&ProductionError> for TerminalInfrastructureReason {
    fn from(error: &ProductionError) -> Self {
        match error {
            ProductionError::Relay => Self::Relay,
            ProductionError::Store => Self::Store,
            ProductionError::Signer => Self::Signer,
            ProductionError::Runner => Self::Runner,
            ProductionError::Evidence => Self::Evidence,
            ProductionError::Invalid => Self::InvalidInput,
            ProductionError::State(_) => Self::State,
            ProductionError::PublicationConflict => Self::PublicationConflict,
            // A deferral is absorbed by the handler's poll boundary; one that
            // escapes it is the relay refusal it stands for.
            ProductionError::DeferredPublication => Self::Relay,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    Idle,
    CompletedOne,
    /// The head request's publication replay was deferred until the
    /// activation grant is approved; the controller stays ready.
    Deferred,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ControllerError {
    #[error("controller entered terminal infrastructure failure")]
    Infrastructure(TerminalInfrastructureReason),
    #[error("controller capacity is closed after a terminal infrastructure failure")]
    Terminal(TerminalInfrastructureReason),
}

/// One synchronous production controller. Its mutable poll API and internal
/// status ledger make a second simultaneous admission impossible.
pub struct CapacityOneController<R, S, X, P, O> {
    config: CapacityOneConfig,
    handler: ProductionHandler<R, S, X, P, O>,
    status: CapacityOneStatus,
}

impl<R, S, X, P, O> CapacityOneController<R, S, X, P, O>
where
    R: RelayControl,
    S: CiSigner,
    X: AttemptExecutor,
    P: ControlStore,
    O: EvidenceReader,
{
    /// Activate only after strict config validation and complete provider
    /// construction have both succeeded.
    pub fn activate(
        config: CapacityOneConfig,
        providers: CapacityOneProviderSlots<R, S, X, P, O>,
    ) -> Result<Self, ActivationError> {
        let (relay, signer, executor, store, output) = providers.complete()?;
        Ok(Self {
            config,
            handler: ProductionHandler::new(relay, signer, executor, store, output),
            status: CapacityOneStatus::ready(),
        })
    }

    pub const fn status(&self) -> CapacityOneStatus {
        self.status
    }

    pub const fn poll_interval(&self) -> Duration {
        self.config.poll_interval()
    }

    /// Poll and fully settle at most one accepted request. Any error is
    /// terminal for this process, so a host cannot spin or admit later work on
    /// uncertain infrastructure state.
    pub fn poll_once(&mut self) -> Result<PollOutcome, ControllerError> {
        if let Some(reason) = self.status.terminal_reason() {
            return Err(ControllerError::Terminal(reason));
        }
        self.status = CapacityOneStatus::polling();
        match self.handler.poll_once(self.config.channel_id()) {
            Ok(step) => {
                self.status = CapacityOneStatus::ready();
                Ok(match step {
                    PollStep::Completed => PollOutcome::CompletedOne,
                    PollStep::Idle => PollOutcome::Idle,
                    PollStep::Deferred => PollOutcome::Deferred,
                })
            }
            Err(error) => {
                let reason = TerminalInfrastructureReason::from(&error);
                self.status = CapacityOneStatus::terminal(reason);
                Err(ControllerError::Infrastructure(reason))
            }
        }
    }

    /// Enable or clear replay deferral on the handler (see
    /// `ProductionHandler::set_replay_deferral`).
    pub fn set_replay_deferral(&mut self, enabled: bool) {
        self.handler.set_replay_deferral(enabled);
    }

    pub const fn replay_deferral(&self) -> bool {
        self.handler.replay_deferral()
    }

    /// Replay every deferred publication after the activation grant was
    /// accepted by the relay. Any error is terminal exactly like a poll error.
    pub fn replay_deferred_publications(&mut self) -> Result<usize, ControllerError> {
        if let Some(reason) = self.status.terminal_reason() {
            return Err(ControllerError::Terminal(reason));
        }
        self.status = CapacityOneStatus::polling();
        match self
            .handler
            .replay_deferred_publications(self.config.channel_id())
        {
            Ok(replayed) => {
                self.status = CapacityOneStatus::ready();
                Ok(replayed)
            }
            Err(error) => {
                let reason = TerminalInfrastructureReason::from(&error);
                self.status = CapacityOneStatus::terminal(reason);
                Err(ControllerError::Infrastructure(reason))
            }
        }
    }

    pub fn into_handler(self) -> ProductionHandler<R, S, X, P, O> {
        self.handler
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::production::{
        AcceptedRequest, AttemptCompletion, OutputDescriptor, SignedCiEvent, StoredObject,
        StoredPublication,
    };
    use crate::{RunIdentity, RunRecord, StoreWrite};

    struct Relay {
        calls: Rc<Cell<u32>>,
        fail: bool,
    }

    impl RelayControl for Relay {
        type Error = ();

        fn next_accepted(
            &mut self,
            _channel_id: &str,
            _after_cursor: u64,
        ) -> Result<Option<AcceptedRequest>, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err(())
            } else {
                Ok(None)
            }
        }

        fn publish(&mut self, _event: &SignedCiEvent) -> Result<String, Self::Error> {
            Err(())
        }

        fn publication_exists(&mut self, _event: &SignedCiEvent) -> Result<bool, Self::Error> {
            Err(())
        }

        fn put_log(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &crate::production::JobCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(())
        }

        fn put_artifact(
            &mut self,
            _accepted: &AcceptedRequest,
            _job: &crate::production::JobCompletion,
            _artifact: &crate::production::ArtifactCompletion,
            _bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            Err(())
        }
    }

    struct Signer;

    impl CiSigner for Signer {
        type Error = ();

        fn pubkey(&self) -> &str {
            "11"
        }

        fn sign(
            &mut self,
            _kind: u32,
            _content: &str,
            _tags: serde_json::Value,
        ) -> Result<SignedCiEvent, Self::Error> {
            Err(())
        }
    }

    struct Executor;

    impl AttemptExecutor for Executor {
        type Error = ();

        fn execute(
            &mut self,
            _request: &AcceptedRequest,
        ) -> Result<AttemptCompletion, Self::Error> {
            Err(())
        }
    }

    #[derive(Default)]
    struct Store;

    impl ControlStore for Store {
        type Error = ();

        fn cursor(&self, _channel_id: &str) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn advance_cursor(
            &mut self,
            _channel_id: &str,
            _expected: u64,
            _next: u64,
        ) -> Result<bool, Self::Error> {
            Err(())
        }

        fn load_run(
            &self,
            _identity: &RunIdentity,
        ) -> Result<Option<(u64, RunRecord)>, Self::Error> {
            Err(())
        }

        fn compare_and_swap_run(
            &mut self,
            _identity: &RunIdentity,
            _expected_revision: Option<u64>,
            _next: &RunRecord,
        ) -> Result<StoreWrite, Self::Error> {
            Err(())
        }

        fn load_publication(&self, _key: &str) -> Result<Option<StoredPublication>, Self::Error> {
            Err(())
        }

        fn record_publication_intent(
            &mut self,
            _key: &str,
            _event: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            Err(())
        }

        fn refresh_pending_publication(
            &mut self,
            _key: &str,
            _expected_event_id: &str,
            _replacement: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            Err(())
        }

        fn defer_publication(&mut self, _key: &str) -> Result<(), Self::Error> {
            Err(())
        }

        fn deferred_publications(&self) -> Result<Vec<String>, Self::Error> {
            Ok(Vec::new())
        }

        fn accept_publication(&mut self, _key: &str, _event_id: &str) -> Result<(), Self::Error> {
            Err(())
        }
    }

    struct Output;

    impl EvidenceReader for Output {
        type Error = ();

        fn read(&self, _descriptor: &OutputDescriptor) -> Result<Vec<u8>, Self::Error> {
            Err(())
        }
    }

    fn config() -> CapacityOneConfig {
        CapacityOneConfig::new("ci".to_owned(), Duration::from_secs(2), 2).expect("config")
    }

    fn providers(
        calls: Rc<Cell<u32>>,
        fail: bool,
    ) -> CapacityOneProviderSlots<Relay, Signer, Executor, Store, Output> {
        CapacityOneProviderSlots::new(
            Some(Relay { calls, fail }),
            Some(Signer),
            Some(Executor),
            Some(Store),
            Some(Output),
        )
    }

    #[test]
    fn typed_config_preserves_strict_bounds_without_a_second_json_schema() {
        assert_eq!(config().channel_id(), "ci");
        for invalid in [
            CapacityOneConfig::new(String::new(), Duration::from_secs(2), 2),
            CapacityOneConfig::new("ci".to_owned(), Duration::ZERO, 2),
            CapacityOneConfig::new("ci".to_owned(), Duration::from_secs(2), 0),
            CapacityOneConfig::new("ci".to_owned(), Duration::from_secs(61), 2),
            CapacityOneConfig::new("ci".to_owned(), Duration::from_secs(2), 9),
        ] {
            assert_eq!(invalid, Err(ActivationError::InvalidConfig));
        }
    }

    #[test]
    fn activation_rejects_any_absent_provider() {
        let calls = Rc::new(Cell::new(0));
        let slots = CapacityOneProviderSlots::new(
            Some(Relay { calls, fail: false }),
            Some(Signer),
            None::<Executor>,
            Some(Store),
            Some(Output),
        );

        assert!(matches!(
            CapacityOneController::activate(config(), slots),
            Err(ActivationError::MissingProvider)
        ));
    }

    #[test]
    fn idle_poll_releases_the_only_capacity_slot() {
        let calls = Rc::new(Cell::new(0));
        let mut controller =
            CapacityOneController::activate(config(), providers(Rc::clone(&calls), false))
                .expect("activate");

        assert_eq!(
            serde_json::to_value(controller.status()).expect("status"),
            serde_json::json!({
                "schema_version": 2,
                "state": "ready",
                "configured_capacity": 1,
                "available_capacity": 1,
                "in_flight": 0,
                "terminal_reason": null,
            })
        );
        assert_eq!(controller.status().available_capacity(), 1);
        assert_eq!(controller.poll_once(), Ok(PollOutcome::Idle));
        assert_eq!(controller.status().available_capacity(), 1);
        assert_eq!(controller.status().in_flight(), 0);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn replay_deferral_is_a_handler_switch_and_replay_follows_the_poll_contract() {
        let calls = Rc::new(Cell::new(0));
        let mut controller =
            CapacityOneController::activate(config(), providers(Rc::clone(&calls), false))
                .expect("activate");
        assert!(
            !controller.replay_deferral(),
            "deferral is off until the service enables it"
        );
        controller.set_replay_deferral(true);
        assert!(controller.replay_deferral());
        controller.set_replay_deferral(false);
        assert!(!controller.replay_deferral());
        // Nothing deferred: the replay is a no-op that leaves capacity open.
        assert_eq!(controller.replay_deferred_publications(), Ok(0));
        assert_eq!(controller.status(), CapacityOneStatus::ready());
        assert_eq!(calls.get(), 0, "no deferred key, no relay read");
        assert_eq!(
            TerminalInfrastructureReason::from(&ProductionError::DeferredPublication),
            TerminalInfrastructureReason::Relay,
            "a deferral that escapes the poll boundary is the relay refusal it stands for"
        );

        let mut failed =
            CapacityOneController::activate(config(), providers(Rc::clone(&calls), true))
                .expect("activate");
        assert_eq!(
            failed.poll_once(),
            Err(ControllerError::Infrastructure(
                TerminalInfrastructureReason::Relay
            ))
        );
        assert_eq!(
            failed.replay_deferred_publications(),
            Err(ControllerError::Terminal(
                TerminalInfrastructureReason::Relay
            )),
            "a closed controller never replays"
        );
    }

    #[test]
    fn production_error_closes_capacity_and_blocks_later_polling() {
        let calls = Rc::new(Cell::new(0));
        let mut controller =
            CapacityOneController::activate(config(), providers(Rc::clone(&calls), true))
                .expect("activate");

        assert_eq!(
            controller.poll_once(),
            Err(ControllerError::Infrastructure(
                TerminalInfrastructureReason::Relay
            ))
        );
        assert_eq!(controller.status().available_capacity(), 0);
        assert_eq!(controller.status().in_flight(), 0);
        assert_eq!(
            controller.status().state(),
            ControllerState::TerminalInfrastructureFailure
        );
        assert_eq!(
            serde_json::to_value(controller.status()).expect("status"),
            serde_json::json!({
                "schema_version": 2,
                "state": "terminal_infrastructure_failure",
                "configured_capacity": 1,
                "available_capacity": 0,
                "in_flight": 0,
                "terminal_reason": "relay",
            })
        );
        assert_eq!(
            controller.poll_once(),
            Err(ControllerError::Terminal(
                TerminalInfrastructureReason::Relay
            ))
        );
        assert_eq!(calls.get(), 1);
    }
}
