//! Inherited Unix-socket transport for the policy decision core.
//!
//! This module intentionally accepts already-open sockets rather than paths or
//! addresses. The trusted broker chooses both endpoints; executor-controlled
//! input can never select the rootless runtime endpoint. Each accepted executor
//! connection carries exactly one bounded HTTP/1.1 request and is closed after
//! its response. Every upstream exchange consumes a fresh broker-provided
//! connection capability which stays private to this process.

use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use buzz_ci_isolation_contract::{RuntimeEndpointIdentity, ValidatedAttemptLeaseBinding};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde_json::Value;

use crate::{
    archive::mediate_archive, Admission, CanonicalCreate, CanonicalExec, DockerMethod, DockerRoute,
    EffectiveContainerSpec, ProxyError, ProxyPolicy, VerifiedStart,
};

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_STATUS_LINE_BYTES: usize = 4 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADER_COUNT: usize = 64;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_CHUNK_COUNT: usize = 4096;
const MAX_CHUNK_FRAMING_BYTES: usize = 64 * 1024;
const CHUNK_INPUT_BUFFER_BYTES: usize = 8 * 1024;
const MAX_PATH_STAT_HEADER_BYTES: usize = 8 * 1024;

/// Broker capability authorizing one connection to a lease's raw runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamCapability {
    lease_id: String,
    token: String,
    runtime_uid: u32,
}

impl UpstreamCapability {
    /// Derive the capability from an already-validated attempt lease.
    pub fn from_validated_lease(lease: &ValidatedAttemptLeaseBinding) -> Self {
        let binding = lease.as_binding();
        let (token, runtime_uid) = match &binding.runtime_endpoint {
            RuntimeEndpointIdentity::UnixSocket {
                token, owner_uid, ..
            }
            | RuntimeEndpointIdentity::InheritedFd { token, owner_uid } => {
                (token.clone(), *owner_uid)
            }
        };
        Self {
            lease_id: binding.lease_id.clone(),
            token,
            runtime_uid,
        }
    }

    /// Return the lease identifier bound to this capability.
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Return the opaque broker token bound to this capability.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Return the runtime peer UID the connection must reach.
    pub fn runtime_uid(&self) -> u32 {
        self.runtime_uid
    }
}

/// Supplies a fresh already-connected raw-runtime descriptor for one exchange.
///
/// Implementations must obtain descriptors from the trusted broker. They must
/// never resolve an executor-provided path, URL, host, or TCP endpoint.
pub trait OneShotUpstreamConnector {
    /// Consume one capability-authorized runtime connection.
    fn connect(&mut self, capability: &UpstreamCapability) -> Result<UnixStream, ProxyError>;
}

/// A single broker-inherited connection useful for one exchange.
///
/// Production brokers normally implement [`OneShotUpstreamConnector`] over an
/// authenticated descriptor-passing channel. This adapter deliberately cannot
/// reconnect or reuse its descriptor.
pub struct InheritedOneShotConnector {
    stream: Option<UnixStream>,
    capability: UpstreamCapability,
}

impl InheritedOneShotConnector {
    /// Bind one inherited connection to the exact broker capability.
    pub fn new(stream: UnixStream, capability: UpstreamCapability) -> Result<Self, ProxyError> {
        if peer_uid(&stream)? != capability.runtime_uid {
            return Err(ProxyError::Transport(
                "inherited upstream peer UID does not match its capability".into(),
            ));
        }
        Ok(Self {
            stream: Some(stream),
            capability,
        })
    }
}

impl OneShotUpstreamConnector for InheritedOneShotConnector {
    fn connect(&mut self, capability: &UpstreamCapability) -> Result<UnixStream, ProxyError> {
        if capability != &self.capability {
            return Err(ProxyError::Transport(
                "upstream capability does not match the inherited descriptor".into(),
            ));
        }
        self.stream.take().ok_or_else(|| {
            ProxyError::Transport("one-shot upstream descriptor was already consumed".into())
        })
    }
}

/// Direction of a manifest-bound archive mediation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveDirection {
    /// Bounded tar bytes from the executor to an owned container.
    Upload,
    /// Bounded sanitized tar bytes from an owned container to the broker.
    Download,
}

/// Typed grant for one bounded owned-container archive transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveGrant {
    /// Attempt lease identifier.
    pub lease_id: String,
    /// Attempt-owned container identifier.
    pub container_id: String,
    /// Exact normalized absolute container path.
    pub container_path: String,
    /// Permitted transfer direction.
    pub direction: ArchiveDirection,
    /// Hard tar-stream byte ceiling.
    pub max_bytes: usize,
    /// Hard count of regular-file and directory entries.
    pub max_entries: usize,
    /// Hard sum of declared regular-file payload bytes.
    pub max_total_bytes: usize,
    /// Maximum decoded tar bytes per encoded gzip byte.
    pub max_decompression_ratio: usize,
}

/// Typed grant required before Docker hijack mediation can be enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HijackGrant {
    /// Attempt lease identifier.
    pub lease_id: String,
    /// Attempt-owned exec identifier.
    pub exec_id: String,
    /// Hard runtime-to-executor byte ceiling.
    pub max_output_bytes: usize,
    /// Hard executor-to-runtime byte ceiling for bounded cancellation input.
    pub max_input_bytes: usize,
    /// Whether any executor-to-runtime bytes are permitted.
    pub allow_input: bool,
}

/// Byte and time ceilings for one executor/upstream exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    /// Maximum executor request body bytes.
    pub request_body_bytes: usize,
    /// Maximum upstream response body bytes.
    pub response_body_bytes: usize,
    /// Read/write deadline applied to inherited sockets.
    pub io_timeout: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            request_body_bytes: 1024 * 1024,
            response_body_bytes: 4 * 1024 * 1024,
            io_timeout: Duration::from_secs(30),
        }
    }
}

impl TransportLimits {
    fn validate(self) -> Result<Self, ProxyError> {
        if self.request_body_bytes == 0
            || self.response_body_bytes == 0
            || self.io_timeout.is_zero()
        {
            return Err(ProxyError::Transport(
                "transport limits must be non-zero".into(),
            ));
        }
        Ok(self)
    }
}

/// Explicit container lifecycle phase retained by the policy proxy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhase {
    /// No create has reached the runtime.
    AwaitCreate,
    /// Create intent exists and its upstream result is unresolved.
    Creating,
    /// One exact runtime container ID is owned and has not started.
    Created,
    /// Start intent exists and its upstream result is unresolved.
    Starting,
    /// The one owned container received a successful start acknowledgement.
    Started,
    /// Delete intent exists and its upstream result is unresolved.
    Deleting,
    /// The one owned container was deleted and may not be recreated.
    Removed,
}

/// Typed lifecycle fact emitted at each create, start, exec, and delete boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEvent<'a> {
    /// Emitted before the first upstream create byte.
    CreateIntent {
        /// Exact canonical create capability that the runtime will receive.
        create: &'a CanonicalCreate,
    },
    /// A complete upstream response definitely rejected create.
    CreateRejected {
        /// Exact canonical create capability rejected by the runtime.
        create: &'a CanonicalCreate,
    },
    /// A successful create returned this full runtime ID.
    Created {
        /// Exact canonical create capability bound to the returned ID.
        create: &'a CanonicalCreate,
        /// Full runtime container ID.
        container_id: &'a str,
    },
    /// Emitted after pre-start proof persistence and before the first start byte.
    StartIntent {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// A complete upstream response definitely rejected start.
    StartRejected {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// A successful empty acknowledgement committed start.
    Started {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// Emitted before the first upstream exec-create byte.
    ExecCreateIntent {
        /// Exact canonical exec-create capability that the runtime will receive.
        exec: &'a CanonicalExec,
    },
    /// A complete upstream response definitely rejected exec-create.
    ExecCreateRejected {
        /// Exact canonical exec-create capability rejected by the runtime.
        exec: &'a CanonicalExec,
    },
    /// A successful exec-create returned this full runtime ID.
    ExecCreated {
        /// Exact canonical exec-create capability bound to the returned ID.
        exec: &'a CanonicalExec,
        /// Full runtime exec ID.
        exec_id: &'a str,
    },
    /// Emitted before the first upstream container-delete byte.
    DeleteIntent {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// A complete upstream response definitely rejected delete.
    DeleteRejected {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// A successful delete removed the full owned container ID.
    Removed {
        /// Full owned container ID.
        container_id: &'a str,
    },
    /// Runtime mutation state became ambiguous and requires reconciliation.
    Poisoned {
        /// Last explicit lifecycle phase.
        phase: LifecyclePhase,
        /// Full known container ID, if create had resolved it.
        container_id: Option<&'a str>,
    },
}

/// Fail-closed observer for lifecycle facts and the existing pre-start proof.
pub trait LifecycleObserver {
    /// Receive one ordered lifecycle fact.
    fn observe_lifecycle(&mut self, event: LifecycleEvent<'_>) -> Result<(), ProxyError>;

    /// Persist the verified effective specification before the start request.
    fn observe_pre_start(
        &mut self,
        create: &CanonicalCreate,
        container_id: &str,
        effective: &EffectiveContainerSpec,
        proof: &VerifiedStart,
    ) -> Result<(), ProxyError>;
}

/// A fail-closed proxy whose listener and raw upstream are broker-inherited.
///
/// The upstream descriptor is never returned or duplicated into an executor
/// process. `serve_once` verifies `SO_PEERCRED`, processes one non-pipelined
/// request, writes one filtered response, and closes that executor connection.
pub struct InheritedProxy<C: OneShotUpstreamConnector, O: LifecycleObserver> {
    listener: UnixListener,
    upstream_connector: C,
    upstream_capability: UpstreamCapability,
    expected_executor_uid: u32,
    limits: TransportLimits,
    policy: ProxyPolicy,
    observer: O,
    poisoned: bool,
}

impl<C: OneShotUpstreamConnector, O: LifecycleObserver> InheritedProxy<C, O> {
    /// Install a proxy with a fail-closed pre-start persistence observer.
    pub fn new_with_observer(
        listener: UnixListener,
        upstream_connector: C,
        upstream_capability: UpstreamCapability,
        limits: TransportLimits,
        policy: ProxyPolicy,
        observer: O,
    ) -> Result<Self, ProxyError> {
        let expected_executor_uid = policy.executor_uid();
        if expected_executor_uid == 0 {
            return Err(ProxyError::Transport(
                "executor peer UID must be non-root".into(),
            ));
        }
        let limits = limits.validate()?;
        if upstream_capability.runtime_uid != policy.runtime_uid() {
            return Err(ProxyError::Transport(
                "upstream capability does not match the lease runtime principal".into(),
            ));
        }
        Ok(Self {
            listener,
            upstream_connector,
            upstream_capability,
            expected_executor_uid,
            limits,
            policy,
            observer,
            poisoned: false,
        })
    }

    /// Accept and serve one executor request.
    ///
    /// Any ambiguous upstream framing or I/O failure poisons this instance.
    /// The broker must then terminate it and reconcile runtime objects before
    /// another request or any successful verdict is possible.
    pub fn serve_once(&mut self) -> Result<(), ProxyError> {
        if self.poisoned {
            return Err(ProxyError::Transport(
                "proxy is poisoned and requires broker reconciliation".into(),
            ));
        }
        let (mut executor, _) = self
            .listener
            .accept()
            .map_err(|error| ProxyError::Transport(format!("accept failed: {error}")))?;
        self.serve_executor(&mut executor)
    }

    /// Poll a nonblocking listener once, returning `false` when no executor is
    /// waiting. The caller owns the bounded poll loop and child deadline.
    pub fn try_serve_once(&mut self) -> Result<bool, ProxyError> {
        if self.poisoned {
            return Err(ProxyError::Transport(
                "proxy is poisoned and requires broker reconciliation".into(),
            ));
        }
        let (mut executor, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(ProxyError::Transport(format!("accept failed: {error}"))),
        };
        self.serve_executor(&mut executor)?;
        Ok(true)
    }

    /// Select blocking or nonblocking acceptance without changing either
    /// connected stream's read/write deadlines.
    pub fn set_listener_nonblocking(&self, nonblocking: bool) -> Result<(), ProxyError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|error| ProxyError::Transport(format!("listener mode failed: {error}")))
    }

    fn serve_executor(&mut self, executor: &mut UnixStream) -> Result<(), ProxyError> {
        configure_stream(executor, self.limits.io_timeout)?;
        let executor_peer_uid = peer_uid(executor)?;
        if executor_peer_uid != self.expected_executor_uid {
            let _ = write_error_response(executor, 403, "executor peer refused");
            return Err(ProxyError::Transport(
                "executor peer UID does not match the broker manifest".into(),
            ));
        }
        let prepared =
            match prepare_request(executor, &mut self.policy, self.limits.request_body_bytes) {
                Ok(prepared) => prepared,
                Err(failure) => {
                    let _ = write_error_response(executor, failure.status, failure.public_message);
                    return Err(failure.error);
                }
            };
        let mut upstream = if prepared.requires_upstream() {
            let acquired = self
                .upstream_connector
                .connect(&self.upstream_capability)
                .and_then(|stream| {
                    configure_stream(&stream, self.limits.io_timeout)?;
                    if peer_uid(&stream)? != self.upstream_capability.runtime_uid {
                        return Err(ProxyError::Transport(
                            "upstream peer UID does not match the broker capability".into(),
                        ));
                    }
                    Ok(stream)
                });
            match acquired {
                Ok(stream) => Some(stream),
                Err(error) => {
                    let rollback = prepared.abort_before_upstream(&mut self.policy);
                    let _ = write_error_response(executor, 502, "runtime capability refused");
                    rollback?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        match serve_prepared(
            executor,
            upstream.as_mut(),
            &mut self.policy,
            &mut self.observer,
            prepared,
            self.limits,
        ) {
            Ok(outcome) => {
                if outcome.upstream_closed && outcome.mutated {
                    self.poison()?;
                }
                Ok(())
            }
            Err(failure) => {
                let poison = failure.poison.then(|| self.poison()).transpose();
                let _ = write_error_response(executor, failure.status, failure.public_message);
                poison?;
                Err(failure.error)
            }
        }
    }

    /// Report whether the broker must terminate and reconcile this proxy.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn poison(&mut self) -> Result<(), ProxyError> {
        if self.poisoned {
            return Ok(());
        }
        self.poisoned = true;
        let (phase, container_id) = self.policy.lifecycle_snapshot();
        let container_id = container_id.map(str::to_owned);
        self.observer.observe_lifecycle(LifecycleEvent::Poisoned {
            phase,
            container_id: container_id.as_deref(),
        })
    }
}

impl<O: LifecycleObserver> InheritedProxy<InheritedOneShotConnector, O> {
    /// Authenticate and install the next one-shot runtime descriptor while
    /// retaining this lease's policy ledger and observer state.
    pub fn replace_inherited_upstream(&mut self, stream: UnixStream) -> Result<(), ProxyError> {
        if self.poisoned {
            return Err(ProxyError::Transport(
                "poisoned proxy cannot accept another runtime descriptor".into(),
            ));
        }
        self.upstream_connector =
            InheritedOneShotConnector::new(stream, self.upstream_capability.clone())?;
        Ok(())
    }

    /// Report whether the next admitted upstream exchange already has its
    /// one-shot descriptor installed.
    pub fn has_inherited_upstream(&self) -> bool {
        self.upstream_connector.stream.is_some()
    }
}

fn configure_stream(stream: &UnixStream, timeout: Duration) -> Result<(), ProxyError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| ProxyError::Transport(format!("socket timeout setup failed: {error}")))
}

fn peer_uid(stream: &UnixStream) -> Result<u32, ProxyError> {
    getsockopt(stream, PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(|error| ProxyError::Transport(format!("SO_PEERCRED failed: {error}")))
}

#[derive(Debug)]
struct ConnectionFailure {
    error: ProxyError,
    poison: bool,
    status: u16,
    public_message: &'static str,
}

impl ConnectionFailure {
    fn before_upstream(error: ProxyError) -> Self {
        Self {
            error,
            poison: false,
            status: 403,
            public_message: "request refused",
        }
    }

    fn after_upstream(error: ProxyError) -> Self {
        Self {
            error,
            poison: true,
            status: 502,
            public_message: "upstream exchange failed closed",
        }
    }

    fn resolved_upstream(error: ProxyError) -> Self {
        Self {
            error,
            poison: false,
            status: 502,
            public_message: "upstream response refused",
        }
    }
}

struct PreparedRequest {
    request: HttpRequest,
    route: DockerRoute,
    admission: Admission,
}

impl PreparedRequest {
    fn requires_upstream(&self) -> bool {
        !matches!(self.admission, Admission::LocalResponse(_))
    }

    fn abort_before_upstream(&self, policy: &mut ProxyPolicy) -> Result<(), ProxyError> {
        match &self.admission {
            Admission::Create(approved) => policy.abort_create(approved),
            Admission::ExecCreate(approved) => policy.abort_exec(approved),
            Admission::ExecStart { exec_id, .. } => policy.abort_exec_start(exec_id),
            Admission::Delete { container_id, .. } => policy.abort_delete(container_id),
            _ => Ok(()),
        }
    }
}

struct ServeOutcome {
    upstream_closed: bool,
    mutated: bool,
}

fn prepare_request(
    executor: &mut UnixStream,
    policy: &mut ProxyPolicy,
    max_request_body: usize,
) -> Result<PreparedRequest, ConnectionFailure> {
    let request =
        read_request(executor, max_request_body).map_err(ConnectionFailure::before_upstream)?;
    let route = DockerRoute::parse(request.method, &request.target)
        .map_err(ConnectionFailure::before_upstream)?;
    if matches!(
        &route,
        DockerRoute::ContainerAttach { .. } | DockerRoute::ContainerLogs { .. }
    ) {
        return Err(ConnectionFailure::before_upstream(ProxyError::Transport(
            "Docker stream/archive routes are disabled until bounded mediation is proven".into(),
        )));
    }
    let admission = policy
        .admit(request.method, &request.target, &request.body)
        .map_err(ConnectionFailure::before_upstream)?;
    Ok(PreparedRequest {
        request,
        route,
        admission,
    })
}

#[cfg(test)]
fn serve_connection(
    executor: &mut UnixStream,
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    limits: TransportLimits,
) -> Result<bool, ConnectionFailure> {
    let prepared = prepare_request(executor, policy, limits.request_body_bytes)?;
    serve_prepared(executor, Some(upstream), policy, observer, prepared, limits)
        .map(|outcome| outcome.upstream_closed)
}

fn serve_prepared(
    executor: &mut UnixStream,
    mut upstream: Option<&mut UnixStream>,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    prepared: PreparedRequest,
    limits: TransportLimits,
) -> Result<ServeOutcome, ConnectionFailure> {
    let PreparedRequest {
        request,
        route,
        admission,
    } = prepared;
    let max_request = limits.request_body_bytes;
    let max_response = limits.response_body_bytes;
    if let Admission::ExecStart {
        target,
        exec_id,
        body,
        allow_input,
    } = &admission
    {
        if !request.upgrade {
            return Err(ConnectionFailure::before_upstream(ProxyError::Transport(
                "exec-start did not carry the required upgrade".into(),
            )));
        }
        let grant = HijackGrant {
            lease_id: policy.lease_id().to_owned(),
            exec_id: exec_id.clone(),
            max_output_bytes: limits.response_body_bytes,
            max_input_bytes: if *allow_input {
                limits.request_body_bytes
            } else {
                0
            },
            allow_input: *allow_input,
        };
        let started = handle_exec_start(
            executor,
            upstream.as_deref_mut().ok_or_else(|| {
                ConnectionFailure::before_upstream(ProxyError::Transport(
                    "exec-start lacks a runtime descriptor".into(),
                ))
            })?,
            policy,
            target,
            body,
            &grant,
            limits.io_timeout,
        )?;
        return Ok(ServeOutcome {
            upstream_closed: false,
            mutated: started,
        });
    }
    let mut mutated = false;
    let mut upstream_used = false;
    let response = match admission {
        Admission::LocalResponse(body) => HttpResponse::local(&route, request.method, body),
        Admission::Forward { target } => {
            upstream_used = true;
            exchange(
                upstream.as_deref_mut().ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "admitted upstream route lacks a runtime descriptor".into(),
                    ))
                })?,
                request.method,
                &target,
                &[],
                max_response,
            )
            .map_err(ConnectionFailure::after_upstream)?
        }
        Admission::Create(approved) => {
            upstream_used = true;
            let response = handle_create(
                upstream.as_deref_mut().ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "create lacks a runtime descriptor".into(),
                    ))
                })?,
                policy,
                observer,
                &approved,
                max_response,
            )?;
            mutated = response.is_success();
            response
        }
        Admission::ExecCreate(approved) => {
            upstream_used = true;
            let response = handle_exec_create(
                upstream.as_deref_mut().ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "exec create lacks a runtime descriptor".into(),
                    ))
                })?,
                policy,
                observer,
                &approved,
                max_response,
            )?;
            mutated = response.is_success();
            response
        }
        Admission::ExecStart { .. } => {
            return Err(ConnectionFailure::before_upstream(ProxyError::Transport(
                "exec-start bypassed its bounded mediator".into(),
            )));
        }
        Admission::NeedsPreStartProof {
            container_id,
            target,
        } => {
            upstream_used = true;
            let response = handle_start(
                upstream.as_deref_mut().ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "start lacks a runtime descriptor".into(),
                    ))
                })?,
                policy,
                observer,
                &container_id,
                &target,
                max_response,
            )?;
            mutated = response.is_success();
            response
        }
        Admission::Delete {
            container_id,
            target,
        } => {
            upstream_used = true;
            let response = handle_delete(
                upstream.as_deref_mut().ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "delete lacks a runtime descriptor".into(),
                    ))
                })?,
                policy,
                observer,
                &container_id,
                &target,
                max_response,
            )?;
            mutated = response.is_success();
            response
        }
        Admission::Wait {
            container_id,
            target,
        } => {
            upstream_used = true;
            let response = exchange(
                upstream.ok_or_else(|| {
                    ConnectionFailure::before_upstream(ProxyError::Transport(
                        "wait lacks a runtime descriptor".into(),
                    ))
                })?,
                DockerMethod::Post,
                &target,
                &[],
                max_response,
            )
            .map_err(ConnectionFailure::after_upstream)?;
            if response.is_success() {
                validate_wait_response(&response.body)
                    .map_err(ConnectionFailure::after_upstream)?;
                policy
                    .commit_stopped(&container_id)
                    .map_err(ConnectionFailure::after_upstream)?;
            }
            response
        }
        Admission::Archive(grant) => {
            let upstream = upstream.ok_or_else(|| {
                ConnectionFailure::before_upstream(ProxyError::Transport(
                    "archive transfer lacks a runtime descriptor".into(),
                ))
            })?;
            let no_overwrite_dir_non_dir = match &route {
                DockerRoute::Archive {
                    no_overwrite_dir_non_dir,
                    ..
                } => *no_overwrite_dir_non_dir,
                _ => {
                    return Err(ConnectionFailure::before_upstream(ProxyError::Transport(
                        "archive grant is not paired with an archive route".into(),
                    )));
                }
            };
            let target = archive_target(&grant, no_overwrite_dir_non_dir);
            match grant.direction {
                ArchiveDirection::Upload => {
                    let body = mediate_archive(&grant, &request.body, max_request)
                        .map_err(ConnectionFailure::before_upstream)?;
                    let response = exchange_with_content_type(
                        upstream,
                        DockerMethod::Put,
                        &target,
                        &body,
                        "application/x-tar",
                        max_response,
                    )
                    .map_err(ConnectionFailure::after_upstream)?;
                    if !response.is_success() {
                        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
                            "archive upload response does not prove atomic extraction".into(),
                        )));
                    }
                    validate_empty_ack(&response.body)
                        .map_err(ConnectionFailure::after_upstream)?;
                    mutated = true;
                    projected_empty(response)
                }
                ArchiveDirection::Download => {
                    let mut response = exchange_archive_download(
                        upstream,
                        DockerMethod::Get,
                        &target,
                        &[],
                        max_response,
                    )
                    .map_err(ConnectionFailure::after_upstream)?;
                    if response.is_success() {
                        response.body = mediate_archive(&grant, &response.body, max_response)
                            .map_err(ConnectionFailure::resolved_upstream)?;
                        response.content_type = Some("application/x-tar".into());
                        let path_stat = response
                            .safe_headers
                            .remove("X-Docker-Container-Path-Stat")
                            .ok_or_else(|| {
                                ConnectionFailure::resolved_upstream(ProxyError::Transport(
                                    "archive download response lacks required path stat".into(),
                                ))
                            })?;
                        validate_path_stat_header(&path_stat)
                            .map_err(ConnectionFailure::resolved_upstream)?;
                        response.safe_headers.clear();
                        response
                            .safe_headers
                            .insert("X-Docker-Container-Path-Stat".into(), path_stat);
                        response
                    } else {
                        project_error_response(response)
                            .map_err(ConnectionFailure::resolved_upstream)?
                    }
                }
            }
        }
    };
    let response = if upstream_used {
        project_upstream_response(&route, response, policy).map_err(|error| {
            if mutated {
                ConnectionFailure::after_upstream(error)
            } else {
                ConnectionFailure::resolved_upstream(error)
            }
        })?
    } else {
        response
    };
    let upstream_closed = response.connection_close;
    write_filtered_response(executor, &response).map_err(|error| {
        if mutated {
            ConnectionFailure::after_upstream(error)
        } else {
            ConnectionFailure::resolved_upstream(error)
        }
    })?;
    Ok(ServeOutcome {
        upstream_closed,
        mutated,
    })
}

fn archive_target(grant: &ArchiveGrant, no_overwrite_dir_non_dir: bool) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if grant.direction == ArchiveDirection::Upload && no_overwrite_dir_non_dir {
        serializer.append_pair("noOverwriteDirNonDir", "true");
    }
    serializer.append_pair("path", &grant.container_path);
    let query = serializer.finish();
    format!("/containers/{}/archive?{query}", grant.container_id)
}

fn validate_wait_response(body: &[u8]) -> Result<(), ProxyError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| ProxyError::Transport(format!("invalid wait response: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProxyError::Transport("wait response is not an object".into()))?;
    let status = object
        .get("StatusCode")
        .and_then(Value::as_i64)
        .ok_or_else(|| ProxyError::Transport("wait response lacks StatusCode".into()))?;
    if !(-1..=255).contains(&status) {
        return Err(ProxyError::Transport(
            "wait response StatusCode is out of range".into(),
        ));
    }
    if object
        .get("Error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("Message"))
        .and_then(Value::as_str)
        .is_some_and(|message| !message.is_empty())
    {
        return Err(ProxyError::Transport(
            "wait response reports a runtime error".into(),
        ));
    }
    Ok(())
}

fn handle_create(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    approved: &CanonicalCreate,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    observer
        .observe_lifecycle(LifecycleEvent::CreateIntent { create: approved })
        .map_err(|error| {
            let _ = policy.abort_create(approved);
            ConnectionFailure::before_upstream(error)
        })?;
    let response = exchange(
        upstream,
        DockerMethod::Post,
        &approved.target,
        &approved.body,
        max_response,
    )
    .map_err(ConnectionFailure::after_upstream)?;
    if response.is_success() {
        let id = response_object_id(&response.body).map_err(ConnectionFailure::after_upstream)?;
        policy
            .record_created(id.clone(), approved)
            .map_err(ConnectionFailure::after_upstream)?;
        observer
            .observe_lifecycle(LifecycleEvent::Created {
                create: approved,
                container_id: &id,
            })
            .map_err(ConnectionFailure::after_upstream)?;
    } else if is_definite_mutation_rejection(response.status) {
        observer
            .observe_lifecycle(LifecycleEvent::CreateRejected { create: approved })
            .map_err(ConnectionFailure::after_upstream)?;
        policy
            .abort_create(approved)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
            "create response does not prove that no runtime mutation occurred".into(),
        )));
    }
    Ok(response)
}

fn handle_exec_create(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    approved: &CanonicalExec,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    observer
        .observe_lifecycle(LifecycleEvent::ExecCreateIntent { exec: approved })
        .map_err(|error| {
            let _ = policy.abort_exec(approved);
            ConnectionFailure::before_upstream(error)
        })?;
    let response = exchange(
        upstream,
        DockerMethod::Post,
        &approved.target,
        &approved.body,
        max_response,
    )
    .map_err(ConnectionFailure::after_upstream)?;
    if response.is_success() {
        let id = response_object_id(&response.body).map_err(ConnectionFailure::after_upstream)?;
        policy
            .record_exec(id.clone(), approved)
            .map_err(ConnectionFailure::after_upstream)?;
        observer
            .observe_lifecycle(LifecycleEvent::ExecCreated {
                exec: approved,
                exec_id: &id,
            })
            .map_err(ConnectionFailure::after_upstream)?;
    } else if is_definite_mutation_rejection(response.status) {
        observer
            .observe_lifecycle(LifecycleEvent::ExecCreateRejected { exec: approved })
            .map_err(ConnectionFailure::after_upstream)?;
        policy
            .abort_exec(approved)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
            "exec-create response does not prove that no runtime mutation occurred".into(),
        )));
    }
    Ok(response)
}

fn handle_exec_start(
    executor: &mut UnixStream,
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    target: &str,
    body: &[u8],
    grant: &HijackGrant,
    timeout: Duration,
) -> Result<bool, ConnectionFailure> {
    write_upgrade_request(upstream, target, body).map_err(ConnectionFailure::after_upstream)?;
    match read_upgrade_response(upstream, grant.max_output_bytes)
        .map_err(ConnectionFailure::after_upstream)?
    {
        UpgradeResponse::Rejected(response) => {
            if !is_definite_mutation_rejection(response.status) {
                return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
                    "exec-start response does not prove that no runtime mutation occurred".into(),
                )));
            }
            policy
                .abort_exec_start(&grant.exec_id)
                .map_err(ConnectionFailure::after_upstream)?;
            let response =
                project_error_response(response).map_err(ConnectionFailure::resolved_upstream)?;
            write_filtered_response(executor, &response)
                .map_err(ConnectionFailure::resolved_upstream)?;
            Ok(false)
        }
        UpgradeResponse::Accepted(initial) => {
            policy
                .commit_exec_started(&grant.exec_id)
                .map_err(ConnectionFailure::after_upstream)?;
            executor
                .write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
                .and_then(|()| executor.flush())
                .map_err(|error| {
                    ConnectionFailure::after_upstream(ProxyError::Transport(format!(
                        "executor upgrade response failed: {error}"
                    )))
                })?;
            relay_hijack(executor, upstream, &initial, grant, timeout)
                .map_err(ConnectionFailure::after_upstream)?;
            Ok(true)
        }
    }
}

enum UpgradeResponse {
    Accepted(Vec<u8>),
    Rejected(HttpResponse),
}

fn write_upgrade_request(
    stream: &mut UnixStream,
    target: &str,
    body: &[u8],
) -> Result<(), ProxyError> {
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|error| ProxyError::Transport(format!("upstream upgrade write failed: {error}")))
}

fn read_upgrade_response(
    stream: &mut UnixStream,
    max_body: usize,
) -> Result<UpgradeResponse, ProxyError> {
    let head = read_head(stream, MAX_STATUS_LINE_BYTES)?;
    let parsed = parse_head(&head, false)?;
    let mut status_line = parsed.start_line.splitn(3, ' ');
    if status_line.next() != Some("HTTP/1.1") {
        return Err(ProxyError::Transport(
            "upstream upgrade status line is not HTTP/1.1".into(),
        ));
    }
    let status = status_line
        .next()
        .ok_or_else(|| ProxyError::Transport("upstream upgrade status is missing".into()))?
        .parse::<u16>()
        .map_err(|_| ProxyError::Transport("upstream upgrade status is invalid".into()))?;
    let reason = status_line.next().unwrap_or("");
    if status == 101 {
        let content_type_ok = parsed
            .headers
            .get("content-type")
            .is_none_or(|value| value.eq_ignore_ascii_case("application/vnd.docker.raw-stream"));
        if parsed
            .headers
            .keys()
            .any(|name| !matches!(name.as_str(), "connection" | "upgrade" | "content-type"))
            || !parsed
                .headers
                .get("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
            || !parsed
                .headers
                .get("upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("tcp"))
            || !content_type_ok
            || parsed.trailing.len() > max_body
        {
            return Err(ProxyError::Transport(
                "upstream exec-start upgrade headers or initial bytes are invalid".into(),
            ));
        }
        return Ok(UpgradeResponse::Accepted(parsed.trailing));
    }
    if !(400..600).contains(&status) {
        return Err(ProxyError::Transport(
            "upstream exec-start returned an ambiguous status".into(),
        ));
    }
    let content_length = validate_framing(&parsed.headers, max_body, false, false)?;
    let content_type = parsed.headers.get("content-type").cloned();
    let body = read_exact_body(stream, parsed.trailing, content_length, max_body)?;
    Ok(UpgradeResponse::Rejected(HttpResponse {
        status,
        reason: reason.into(),
        content_type,
        safe_headers: BTreeMap::new(),
        body,
        connection_close: true,
    }))
}

fn relay_hijack(
    executor: &mut UnixStream,
    upstream: &mut UnixStream,
    initial_output: &[u8],
    grant: &HijackGrant,
    timeout: Duration,
) -> Result<(), ProxyError> {
    if initial_output.len() > grant.max_output_bytes
        || (grant.allow_input && grant.max_input_bytes == 0)
        || (!grant.allow_input && grant.max_input_bytes != 0)
    {
        return Err(ProxyError::Transport(
            "hijack grant has inconsistent byte limits".into(),
        ));
    }
    executor
        .write_all(initial_output)
        .and_then(|()| executor.flush())
        .map_err(|error| ProxyError::Transport(format!("initial hijack write failed: {error}")))?;

    let deadline = Instant::now() + timeout;
    let stopped = AtomicBool::new(false);
    let mut executor_read = executor
        .try_clone()
        .map_err(|error| ProxyError::Transport(format!("executor clone failed: {error}")))?;
    let mut upstream_write = upstream
        .try_clone()
        .map_err(|error| ProxyError::Transport(format!("upstream clone failed: {error}")))?;
    let input_limit = grant.max_input_bytes;
    let allow_input = grant.allow_input;
    let output_limit = grant.max_output_bytes - initial_output.len();

    let result = std::thread::scope(|scope| {
        let input = allow_input.then(|| {
            scope.spawn(|| {
                copy_hijack_direction(
                    &mut executor_read,
                    &mut upstream_write,
                    input_limit,
                    deadline,
                    &stopped,
                    "executor-to-runtime",
                )
            })
        });
        let output = copy_hijack_direction(
            upstream,
            executor,
            output_limit,
            deadline,
            &stopped,
            "runtime-to-executor",
        );
        stopped.store(true, Ordering::Release);
        let _ = executor.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        let input = input.map(|handle| {
            handle.join().unwrap_or_else(|_| {
                Err(ProxyError::Transport("hijack input relay panicked".into()))
            })
        });
        output.and(input.unwrap_or(Ok(())))
    });
    result
}

fn copy_hijack_direction(
    reader: &mut UnixStream,
    writer: &mut UnixStream,
    limit: usize,
    deadline: Instant,
    stopped: &AtomicBool,
    direction: &str,
) -> Result<(), ProxyError> {
    let mut copied = 0_usize;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if stopped.load(Ordering::Acquire) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(ProxyError::Transport(format!(
                "{direction} hijack deadline exceeded"
            )));
        }
        let slice = (deadline - now).min(Duration::from_millis(100));
        reader
            .set_read_timeout(Some(slice))
            .map_err(|error| ProxyError::Transport(format!("hijack timeout failed: {error}")))?;
        match reader.read(&mut buffer) {
            Ok(0) => {
                stopped.store(true, Ordering::Release);
                let _ = writer.shutdown(Shutdown::Both);
                return Ok(());
            }
            Ok(count) => {
                if count > limit.saturating_sub(copied) {
                    return Err(ProxyError::Transport(format!(
                        "{direction} hijack byte cap exceeded"
                    )));
                }
                writer.write_all(&buffer[..count]).map_err(|error| {
                    ProxyError::Transport(format!("{direction} hijack write failed: {error}"))
                })?;
                copied += count;
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => {
                return Err(ProxyError::Transport(format!(
                    "{direction} hijack read failed: {error}"
                )));
            }
        }
    }
}

fn handle_delete(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    container_id: &str,
    target: &str,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    observer
        .observe_lifecycle(LifecycleEvent::DeleteIntent { container_id })
        .map_err(|error| {
            let _ = policy.abort_delete(container_id);
            ConnectionFailure::before_upstream(error)
        })?;
    let response = exchange(upstream, DockerMethod::Delete, target, &[], max_response)
        .map_err(ConnectionFailure::after_upstream)?;
    if response.is_success() {
        validate_empty_ack(&response.body).map_err(ConnectionFailure::after_upstream)?;
        policy
            .commit_deleted(container_id)
            .map_err(ConnectionFailure::after_upstream)?;
        observer
            .observe_lifecycle(LifecycleEvent::Removed { container_id })
            .map_err(ConnectionFailure::after_upstream)?;
    } else if is_definite_mutation_rejection(response.status) {
        observer
            .observe_lifecycle(LifecycleEvent::DeleteRejected { container_id })
            .map_err(ConnectionFailure::after_upstream)?;
        policy
            .abort_delete(container_id)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
            "delete response does not prove that no runtime mutation occurred".into(),
        )));
    }
    Ok(response)
}

fn handle_start(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    observer: &mut impl LifecycleObserver,
    container_id: &str,
    start_target: &str,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    let inspect_target = format!("/containers/{container_id}/json");
    let inspect = exchange(
        upstream,
        DockerMethod::Get,
        &inspect_target,
        &[],
        max_response,
    )
    .map_err(ConnectionFailure::resolved_upstream)?;
    if !inspect.is_success() {
        return Err(ConnectionFailure::resolved_upstream(ProxyError::Transport(
            "pre-start inspect did not succeed".into(),
        )));
    }
    let inspected_id =
        response_object_id(&inspect.body).map_err(ConnectionFailure::resolved_upstream)?;
    if inspected_id != container_id {
        return Err(ConnectionFailure::resolved_upstream(
            ProxyError::PolicyRefused(
                "pre-start inspect Id does not match the owned container".into(),
            ),
        ));
    }
    let effective =
        decode_effective_spec(&inspect.body).map_err(ConnectionFailure::resolved_upstream)?;
    let proof = policy
        .verify_pre_start(container_id, &effective)
        .map_err(ConnectionFailure::resolved_upstream)?;
    let create = policy
        .created_request(container_id)
        .cloned()
        .map_err(ConnectionFailure::resolved_upstream)?;
    observer
        .observe_pre_start(&create, container_id, &effective, &proof)
        .map_err(ConnectionFailure::resolved_upstream)?;
    policy
        .begin_start(&proof)
        .map_err(ConnectionFailure::resolved_upstream)?;
    observer
        .observe_lifecycle(LifecycleEvent::StartIntent { container_id })
        .map_err(|error| {
            let _ = policy.abort_start(&proof);
            ConnectionFailure::resolved_upstream(error)
        })?;
    let response = exchange(
        upstream,
        DockerMethod::Post,
        start_target,
        &[],
        max_response,
    )
    .map_err(ConnectionFailure::after_upstream)?;
    if response.is_success() {
        validate_empty_ack(&response.body).map_err(ConnectionFailure::after_upstream)?;
        policy
            .commit_started(&proof)
            .map_err(ConnectionFailure::after_upstream)?;
        observer
            .observe_lifecycle(LifecycleEvent::Started { container_id })
            .map_err(ConnectionFailure::after_upstream)?;
    } else if is_definite_mutation_rejection(response.status) {
        observer
            .observe_lifecycle(LifecycleEvent::StartRejected { container_id })
            .map_err(ConnectionFailure::after_upstream)?;
        policy
            .abort_start(&proof)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
            "start response does not prove that no runtime mutation occurred".into(),
        )));
    }
    Ok(response)
}

fn is_definite_mutation_rejection(status: u16) -> bool {
    matches!(status, 400 | 401 | 403)
}

fn exchange(
    upstream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    max_response: usize,
) -> Result<HttpResponse, ProxyError> {
    write_upstream_request(upstream, method, target, body)?;
    read_response(upstream, method, max_response, false)
}

fn exchange_archive_download(
    upstream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    max_response: usize,
) -> Result<HttpResponse, ProxyError> {
    write_upstream_request(upstream, method, target, body)?;
    read_response(upstream, method, max_response, true)
}

fn exchange_with_content_type(
    upstream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    content_type: &str,
    max_response: usize,
) -> Result<HttpResponse, ProxyError> {
    write_upstream_request_with_content_type(upstream, method, target, body, content_type)?;
    read_response(upstream, method, max_response, false)
}

#[derive(Debug)]
struct HttpRequest {
    method: DockerMethod,
    target: String,
    body: Vec<u8>,
    upgrade: bool,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    reason: String,
    content_type: Option<String>,
    safe_headers: BTreeMap<String, String>,
    body: Vec<u8>,
    connection_close: bool,
}

impl HttpResponse {
    fn local(route: &DockerRoute, method: DockerMethod, body: Vec<u8>) -> Self {
        if matches!(route, DockerRoute::Ping) {
            let mut safe_headers = BTreeMap::new();
            safe_headers.insert("API-Version".into(), "1.47".into());
            return Self {
                status: 200,
                reason: "OK".into(),
                content_type: Some("text/plain".into()),
                safe_headers,
                body: if method == DockerMethod::Head {
                    Vec::new()
                } else {
                    body
                },
                connection_close: false,
            };
        }
        Self {
            status: 200,
            reason: "OK".into(),
            content_type: Some("application/json".into()),
            safe_headers: BTreeMap::new(),
            body,
            connection_close: false,
        }
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

fn project_upstream_response(
    route: &DockerRoute,
    response: HttpResponse,
    policy: &ProxyPolicy,
) -> Result<HttpResponse, ProxyError> {
    if !response.is_success() {
        return project_error_response(response);
    }

    let body = match route {
        DockerRoute::ImageInspect { image } => {
            if image != policy.image_digest() {
                return Err(ProxyError::Transport(
                    "image response is not bound to the manifest digest".into(),
                ));
            }
            let value = response_object(&response.body, "image inspect")?;
            let id = bounded_string(&value, "Id", 128)?;
            let architecture = bounded_string(&value, "Architecture", 64)?;
            let os = bounded_string(&value, "Os", 32)?;
            if id != image || architecture != policy.engine_arch() || os != "linux" {
                return Err(ProxyError::Transport(
                    "image inspect identity does not match the policy manifest".into(),
                ));
            }
            let config = value
                .get("Config")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ProxyError::Transport("image inspect Config is not an object".into())
                })?;
            let environment = bounded_optional_strings(config, "Env", 256, 8192)?;
            serde_json::json!({
                "Id": id,
                "RepoDigests": [image],
                "Architecture": architecture,
                "Os": os,
                "Config": {"Env": environment},
            })
        }
        DockerRoute::ContainerInspect { id } => {
            let value = response_object(&response.body, "container inspect")?;
            let returned_id = bounded_string(&value, "Id", 128)?;
            if returned_id != id {
                return Err(ProxyError::Transport(
                    "container inspect returned a different object".into(),
                ));
            }
            let name = bounded_string(&value, "Name", 256)?;
            let config = value
                .get("Config")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ProxyError::Transport("container inspect Config is not an object".into())
                })?;
            let image = bounded_string(config, "Image", 128)?;
            if image != policy.image_digest() {
                return Err(ProxyError::Transport(
                    "container inspect image is not manifest-pinned".into(),
                ));
            }
            let state = value
                .get("State")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ProxyError::Transport("container inspect State is not an object".into())
                })?;
            let running = state
                .get("Running")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    ProxyError::Transport("container inspect Running is not a bool".into())
                })?;
            let status = bounded_string(state, "Status", 32)?;
            let exit_code = bounded_exit_code(state, "ExitCode")?;
            serde_json::json!({
                "Id": returned_id,
                "Name": name,
                "Config": {"Image": image},
                "State": {
                    "Running": running,
                    "Status": status,
                    "ExitCode": exit_code,
                },
            })
        }
        DockerRoute::ExecInspect { exec_id } => {
            let value = response_object(&response.body, "exec inspect")?;
            let returned_id = bounded_string(&value, "ID", 128)?;
            if returned_id != exec_id {
                return Err(ProxyError::Transport(
                    "exec inspect returned a different object".into(),
                ));
            }
            let running = value
                .get("Running")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    ProxyError::Transport("exec inspect Running is not a bool".into())
                })?;
            let exit_code = bounded_exit_code(&value, "ExitCode")?;
            serde_json::json!({
                "ID": returned_id,
                "Running": running,
                "ExitCode": exit_code,
            })
        }
        DockerRoute::ContainerCreate => {
            serde_json::json!({"Id": response_object_id(&response.body)?, "Warnings": []})
        }
        DockerRoute::ExecCreate { .. } => {
            serde_json::json!({"Id": response_object_id(&response.body)?})
        }
        DockerRoute::ContainerWait { .. } => {
            validate_wait_response(&response.body)?;
            let value = response_object(&response.body, "container wait")?;
            let status = bounded_exit_code(&value, "StatusCode")?;
            serde_json::json!({"StatusCode": status, "Error": null})
        }
        DockerRoute::ContainerStart { .. } | DockerRoute::ContainerDelete { .. } => {
            validate_empty_ack(&response.body)?;
            return Ok(projected_empty(response));
        }
        DockerRoute::Ping
        | DockerRoute::Version
        | DockerRoute::Info
        | DockerRoute::ContainerList
        | DockerRoute::VolumeList => {
            return Err(ProxyError::Transport(
                "local-only route unexpectedly reached the runtime".into(),
            ));
        }
        DockerRoute::ContainerAttach { .. }
        | DockerRoute::ContainerLogs { .. }
        | DockerRoute::ExecStart { .. }
        | DockerRoute::Archive { .. }
        | DockerRoute::ImagePull
        | DockerRoute::Build
        | DockerRoute::ForbiddenFamily => {
            return Err(ProxyError::Transport(
                "unmediated runtime route has no response projector".into(),
            ));
        }
    };

    projected_json(response, body)
}

fn project_error_response(response: HttpResponse) -> Result<HttpResponse, ProxyError> {
    let value = response_object(&response.body, "runtime error")?;
    let message = bounded_string(&value, "message", 4096)?;
    projected_json(response, serde_json::json!({"message": message}))
}

fn projected_json(mut response: HttpResponse, value: Value) -> Result<HttpResponse, ProxyError> {
    response.body = serde_json::to_vec(&value)
        .map_err(|error| ProxyError::Transport(format!("response projection failed: {error}")))?;
    response.content_type = Some("application/json".into());
    response.safe_headers.clear();
    Ok(response)
}

fn projected_empty(mut response: HttpResponse) -> HttpResponse {
    response.body.clear();
    response.content_type = Some("application/octet-stream".into());
    response.safe_headers.clear();
    response
}

fn validate_empty_ack(body: &[u8]) -> Result<(), ProxyError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(ProxyError::Transport(
            "empty runtime acknowledgement carried a body".into(),
        ))
    }
}

fn response_object(
    body: &[u8],
    context: &str,
) -> Result<serde_json::Map<String, Value>, ProxyError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| {
        ProxyError::Transport(format!("{context} response JSON failed: {error}"))
    })?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| ProxyError::Transport(format!("{context} response is not an object")))
}

fn bounded_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<&'a str, ProxyError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProxyError::Transport(format!("response {field} is not a string")))?;
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .bytes()
            .any(|byte| byte == 0 || (byte < 0x20 && byte != b'\t'))
    {
        return Err(ProxyError::Transport(format!(
            "response {field} is empty, oversized, or contains controls"
        )));
    }
    Ok(value)
}

fn bounded_optional_strings(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_items: usize,
    max_item_bytes: usize,
) -> Result<Vec<String>, ProxyError> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| ProxyError::Transport(format!("response {field} is not an array")))?;
    if values.len() > max_items {
        return Err(ProxyError::Transport(format!(
            "response {field} has too many items"
        )));
    }
    values
        .iter()
        .map(|item| {
            let value = item.as_str().ok_or_else(|| {
                ProxyError::Transport(format!("response {field} contains a non-string"))
            })?;
            if value.len() > max_item_bytes || value.bytes().any(|byte| byte == 0) {
                return Err(ProxyError::Transport(format!(
                    "response {field} contains an oversized or NUL-bearing string"
                )));
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn bounded_exit_code(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<i64, ProxyError> {
    let value = object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| ProxyError::Transport(format!("response {field} is not an integer")))?;
    if !(-1..=255).contains(&value) {
        return Err(ProxyError::Transport(format!(
            "response {field} is out of range"
        )));
    }
    Ok(value)
}

fn read_request(stream: &mut UnixStream, max_body: usize) -> Result<HttpRequest, ProxyError> {
    let head = read_head(stream, MAX_REQUEST_LINE_BYTES)?;
    let parsed = parse_head(&head, true)?;
    let request_line = parsed.start_line.split(' ').collect::<Vec<_>>();
    if request_line.len() != 3 || request_line[2] != "HTTP/1.1" {
        return Err(ProxyError::Transport(
            "request line must be METHOD SP target SP HTTP/1.1".into(),
        ));
    }
    let method = DockerMethod::parse(request_line[0])?;
    let target = request_line[1];
    let allow_upgrade = matches!(
        DockerRoute::parse(method, target)?,
        DockerRoute::ExecStart { .. }
    );
    let content_length = validate_framing(&parsed.headers, max_body, true, allow_upgrade)?;
    let body = read_exact_body(stream, parsed.trailing, content_length, max_body)?;
    Ok(HttpRequest {
        method,
        target: target.into(),
        body,
        upgrade: allow_upgrade,
    })
}

fn read_response(
    stream: &mut UnixStream,
    request_method: DockerMethod,
    max_body: usize,
    allow_chunked: bool,
) -> Result<HttpResponse, ProxyError> {
    let head = read_head(stream, MAX_STATUS_LINE_BYTES)?;
    let parsed = parse_head(&head, false)?;
    let mut status_line = parsed.start_line.splitn(3, ' ');
    if status_line.next() != Some("HTTP/1.1") {
        return Err(ProxyError::Transport(
            "upstream status line is not HTTP/1.1".into(),
        ));
    }
    let status = status_line
        .next()
        .ok_or_else(|| ProxyError::Transport("upstream status is missing".into()))?
        .parse::<u16>()
        .map_err(|_| ProxyError::Transport("upstream status is invalid".into()))?;
    if !(200..600).contains(&status) || status == 101 {
        return Err(ProxyError::Transport(
            "informational and upgrade responses are refused".into(),
        ));
    }
    let reason = status_line.next().unwrap_or("");
    if !reason
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(ProxyError::Transport(
            "upstream reason contains invalid bytes".into(),
        ));
    }
    let mut headers = parsed.headers;
    let body_forbidden = request_method == DockerMethod::Head || matches!(status, 204 | 304);
    if body_forbidden {
        match headers.get("content-length") {
            Some(value) if parse_content_length(value)? != 0 => {
                return Err(ProxyError::Transport(
                    "body-forbidden response declares a non-zero body".into(),
                ));
            }
            Some(_) => {}
            None => {
                headers.insert("content-length".into(), "0".into());
            }
        }
    }
    let framing = validate_response_framing(&headers, max_body, body_forbidden, allow_chunked)?;
    let body = match framing {
        ResponseFraming::ContentLength(content_length) => {
            read_exact_body(stream, parsed.trailing, content_length, max_body)?
        }
        ResponseFraming::Chunked => read_chunked_body(stream, parsed.trailing, max_body)?,
    };
    let content_type = headers.get("content-type").cloned().filter(|value| {
        value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    });
    let connection_close = headers
        .get("connection")
        .map(|value| connection_has_token(value, "close"))
        .transpose()?
        .unwrap_or(false);
    let mut safe_headers = BTreeMap::new();
    if let Some(value) = headers.get("x-docker-container-path-stat") {
        safe_headers.insert("X-Docker-Container-Path-Stat".into(), value.clone());
    }
    Ok(HttpResponse {
        status,
        reason: reason.into(),
        content_type,
        safe_headers,
        body,
        connection_close,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseFraming {
    ContentLength(usize),
    Chunked,
}

fn validate_response_framing(
    headers: &BTreeMap<String, String>,
    max_body: usize,
    body_forbidden: bool,
    allow_chunked: bool,
) -> Result<ResponseFraming, ProxyError> {
    if let Some(transfer_encoding) = headers.get("transfer-encoding") {
        if body_forbidden
            || !allow_chunked
            || headers.contains_key("content-length")
            || !transfer_encoding.eq_ignore_ascii_case("chunked")
        {
            return Err(ProxyError::Transport(
                "unsupported or conflicting upstream Transfer-Encoding".into(),
            ));
        }
        for forbidden in ["upgrade", "proxy-connection", "trailer", "expect"] {
            if headers.contains_key(forbidden) {
                return Err(ProxyError::Transport(format!(
                    "unsupported HTTP framing header: {forbidden}"
                )));
            }
        }
        if headers
            .get("connection")
            .map(|value| connection_has_token(value, "upgrade"))
            .transpose()?
            .unwrap_or(false)
        {
            return Err(ProxyError::Transport("HTTP upgrade is refused".into()));
        }
        return Ok(ResponseFraming::Chunked);
    }
    validate_framing(headers, max_body, false).map(ResponseFraming::ContentLength)
}

fn read_chunked_body(
    stream: &mut UnixStream,
    initial: Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut input = ChunkInput::new(stream, initial);
    let mut body = Vec::new();
    let mut chunks = 0_usize;
    let mut framing_bytes = 0_usize;
    loop {
        let line = input.read_line(MAX_CHUNK_LINE_BYTES)?;
        framing_bytes = framing_bytes
            .checked_add(line.len() + 2)
            .ok_or_else(|| ProxyError::Transport("chunk framing size overflowed".into()))?;
        if framing_bytes > MAX_CHUNK_FRAMING_BYTES {
            return Err(ProxyError::Transport(
                "chunk framing exceeds its byte cap".into(),
            ));
        }
        if line.is_empty()
            || line.len() > 16
            || !line.iter().all(u8::is_ascii_hexdigit)
            || (line.len() > 1 && line[0] == b'0')
        {
            return Err(ProxyError::Transport(
                "chunk size line is not canonical hexadecimal".into(),
            ));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| ProxyError::Transport("chunk size line is not ASCII".into()))?;
        let chunk_size = usize::from_str_radix(line, 16)
            .map_err(|_| ProxyError::Transport("chunk size overflows".into()))?;
        if chunk_size == 0 {
            let final_line = input.read_line(MAX_CHUNK_LINE_BYTES)?;
            framing_bytes = framing_bytes
                .checked_add(final_line.len() + 2)
                .ok_or_else(|| ProxyError::Transport("chunk framing size overflowed".into()))?;
            if framing_bytes > MAX_CHUNK_FRAMING_BYTES
                || !final_line.is_empty()
                || input.has_buffered_bytes()
            {
                return Err(ProxyError::Transport(
                    "chunk trailers or pipelined bytes are refused".into(),
                ));
            }
            return Ok(body);
        }
        chunks = chunks
            .checked_add(1)
            .ok_or_else(|| ProxyError::Transport("chunk count overflowed".into()))?;
        if chunks > MAX_CHUNK_COUNT {
            return Err(ProxyError::Transport("chunk count exceeds its cap".into()));
        }
        let new_len = body
            .len()
            .checked_add(chunk_size)
            .ok_or_else(|| ProxyError::Transport("chunked body size overflowed".into()))?;
        if new_len > max_body {
            return Err(ProxyError::Transport("HTTP body exceeds limit".into()));
        }
        input.read_exact_into(&mut body, chunk_size)?;
        if input.read_byte()? != b'\r' || input.read_byte()? != b'\n' {
            return Err(ProxyError::Transport(
                "chunk payload lacks its CRLF terminator".into(),
            ));
        }
        framing_bytes = framing_bytes
            .checked_add(2)
            .ok_or_else(|| ProxyError::Transport("chunk framing size overflowed".into()))?;
    }
}

struct ChunkInput<'a> {
    stream: &'a mut UnixStream,
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a> ChunkInput<'a> {
    fn new(stream: &'a mut UnixStream, initial: Vec<u8>) -> Self {
        Self {
            stream,
            buffer: initial,
            offset: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8, ProxyError> {
        self.fill()?;
        let byte = self.buffer[self.offset];
        self.offset += 1;
        Ok(byte)
    }

    fn read_line(&mut self, max_bytes: usize) -> Result<Vec<u8>, ProxyError> {
        let mut line = Vec::new();
        loop {
            let byte = self.read_byte()?;
            if byte == b'\r' {
                if self.read_byte()? != b'\n' {
                    return Err(ProxyError::Transport(
                        "chunk framing contains a bare carriage return".into(),
                    ));
                }
                return Ok(line);
            }
            if byte == b'\n' || line.len() == max_bytes {
                return Err(ProxyError::Transport(
                    "chunk line is malformed or exceeds its cap".into(),
                ));
            }
            line.push(byte);
        }
    }

    fn read_exact_into(&mut self, output: &mut Vec<u8>, length: usize) -> Result<(), ProxyError> {
        output
            .try_reserve_exact(length)
            .map_err(|_| ProxyError::Transport("chunk allocation was refused".into()))?;
        let mut remaining = length;
        while remaining != 0 {
            self.fill()?;
            let available = self.buffer.len() - self.offset;
            let take = available.min(remaining);
            output.extend_from_slice(&self.buffer[self.offset..self.offset + take]);
            self.offset += take;
            remaining -= take;
        }
        Ok(())
    }

    fn has_buffered_bytes(&self) -> bool {
        self.offset < self.buffer.len()
    }

    fn fill(&mut self) -> Result<(), ProxyError> {
        if self.has_buffered_bytes() {
            return Ok(());
        }
        self.buffer.resize(CHUNK_INPUT_BUFFER_BYTES, 0);
        let count = self
            .stream
            .read(&mut self.buffer)
            .map_err(|error| ProxyError::Transport(format!("chunked body read failed: {error}")))?;
        if count == 0 {
            return Err(ProxyError::Transport(
                "connection closed before complete chunked body".into(),
            ));
        }
        self.buffer.truncate(count);
        self.offset = 0;
        Ok(())
    }
}

fn validate_path_stat_header(value: &str) -> Result<(), ProxyError> {
    if value.is_empty()
        || value.len() > MAX_PATH_STAT_HEADER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(ProxyError::Transport(
            "archive path stat header is malformed or oversized".into(),
        ));
    }
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| ProxyError::Transport("archive path stat header is not base64".into()))?;
    if decoded.len() > MAX_PATH_STAT_HEADER_BYTES
        || !serde_json::from_slice::<Value>(&decoded).is_ok_and(|value| value.is_object())
    {
        return Err(ProxyError::Transport(
            "archive path stat header is not a bounded JSON object".into(),
        ));
    }
    Ok(())
}

struct ParsedHead {
    start_line: String,
    headers: BTreeMap<String, String>,
    trailing: Vec<u8>,
}

fn read_head(stream: &mut UnixStream, max_start_line: usize) -> Result<Vec<u8>, ProxyError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| ProxyError::Transport(format!("HTTP read failed: {error}")))?;
        if count == 0 {
            return Err(ProxyError::Transport(
                "connection closed before complete HTTP head".into(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(ProxyError::Transport("HTTP head exceeds limit".into()));
        }
        if let Some(end) = find_subsequence(&bytes, b"\r\n\r\n") {
            if bytes[..end]
                .iter()
                .position(|byte| *byte == b'\n')
                .is_some_and(|line_end| line_end > max_start_line)
            {
                return Err(ProxyError::Transport(
                    "HTTP start line exceeds limit".into(),
                ));
            }
            return Ok(bytes);
        }
    }
}

fn parse_head(bytes: &[u8], request: bool) -> Result<ParsedHead, ProxyError> {
    let end = find_subsequence(bytes, b"\r\n\r\n")
        .ok_or_else(|| ProxyError::Transport("incomplete HTTP head".into()))?;
    let text = std::str::from_utf8(&bytes[..end])
        .map_err(|_| ProxyError::Transport("HTTP head is not UTF-8/ASCII".into()))?;
    if text
        .bytes()
        .any(|byte| byte == 0 || (byte < 0x20 && !matches!(byte, b'\r' | b'\n' | b'\t')))
    {
        return Err(ProxyError::Transport(
            "HTTP head contains control bytes".into(),
        ));
    }
    let mut lines = text.split("\r\n");
    let start_line = lines
        .next()
        .ok_or_else(|| ProxyError::Transport("HTTP start line is missing".into()))?
        .to_string();
    let mut headers = BTreeMap::new();
    for (index, line) in lines.enumerate() {
        if index >= MAX_HEADER_COUNT {
            return Err(ProxyError::Transport("too many HTTP headers".into()));
        }
        if line.starts_with([' ', '\t']) {
            return Err(ProxyError::Transport(
                "obsolete header folding refused".into(),
            ));
        }
        let (name, raw_value) = line
            .split_once(':')
            .ok_or_else(|| ProxyError::Transport("malformed HTTP header".into()))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(ProxyError::Transport("invalid HTTP header name".into()));
        }
        let name = name.to_ascii_lowercase();
        let value = raw_value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte < 0x20 && byte != b'\t' || byte == 0x7f)
        {
            return Err(ProxyError::Transport("invalid HTTP header value".into()));
        }
        if headers.insert(name, value.into()).is_some() {
            return Err(ProxyError::Transport(
                "duplicate HTTP header refused".into(),
            ));
        }
    }
    if request && !headers.contains_key("host") {
        return Err(ProxyError::Transport(
            "HTTP/1.1 Host header is required".into(),
        ));
    }
    Ok(ParsedHead {
        start_line,
        headers,
        trailing: bytes[end + 4..].to_vec(),
    })
}

fn validate_framing(
    headers: &BTreeMap<String, String>,
    max_body: usize,
    request: bool,
    allow_upgrade: bool,
) -> Result<usize, ProxyError> {
    for forbidden in ["transfer-encoding", "proxy-connection", "trailer", "expect"] {
        if headers.contains_key(forbidden) {
            return Err(ProxyError::Transport(format!(
                "unsupported HTTP framing header: {forbidden}"
            )));
        }
    }
    let requests_upgrade = headers
        .get("connection")
        .map(|value| connection_has_token(value, "upgrade"))
        .transpose()?
        .unwrap_or(false)
        || headers.contains_key("upgrade");
    if allow_upgrade {
        if !headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
        {
            return Err(ProxyError::Transport(
                "exec-start requires an exact Connection: Upgrade header".into(),
            ));
        }
        if !headers
            .get("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("tcp"))
        {
            return Err(ProxyError::Transport(
                "exec-start requires Upgrade: tcp".into(),
            ));
        }
    } else if requests_upgrade {
        return Err(ProxyError::Transport("HTTP upgrade is refused".into()));
    }
    let content_length = match headers.get("content-length") {
        Some(value) => parse_content_length(value)?,
        None if request => 0,
        None => {
            return Err(ProxyError::Transport(
                "upstream response requires Content-Length".into(),
            ))
        }
    };
    if content_length > max_body {
        return Err(ProxyError::Transport("HTTP body exceeds limit".into()));
    }
    Ok(content_length)
}

fn parse_content_length(value: &str) -> Result<usize, ProxyError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProxyError::Transport(
            "Content-Length is not canonical decimal".into(),
        ));
    }
    value
        .parse::<usize>()
        .map_err(|_| ProxyError::Transport("Content-Length overflows".into()))
}

fn read_exact_body(
    stream: &mut UnixStream,
    mut initial: Vec<u8>,
    length: usize,
    max_body: usize,
) -> Result<Vec<u8>, ProxyError> {
    if length > max_body || initial.len() > length {
        return Err(ProxyError::Transport(
            "HTTP pipeline or body length mismatch refused".into(),
        ));
    }
    let already = initial.len();
    initial.resize(length, 0);
    if already < length {
        stream
            .read_exact(&mut initial[already..])
            .map_err(|error| ProxyError::Transport(format!("HTTP body read failed: {error}")))?;
    }
    Ok(initial)
}

fn write_upstream_request(
    stream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
) -> Result<(), ProxyError> {
    write_upstream_request_with_content_type(stream, method, target, body, "application/json")
}

fn write_upstream_request_with_content_type(
    stream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    content_type: &str,
) -> Result<(), ProxyError> {
    let method = method_name(method);
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|error| ProxyError::Transport(format!("upstream write failed: {error}")))
}

fn write_filtered_response(
    stream: &mut UnixStream,
    response: &HttpResponse,
) -> Result<(), ProxyError> {
    let reason = canonical_reason(response.status, &response.reason);
    let content_type = response
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in &response.safe_headers {
        let valid = match name.as_str() {
            "API-Version" => {
                value.len() <= 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            }
            "X-Docker-Container-Path-Stat" => validate_path_stat_header(value).is_ok(),
            _ => false,
        };
        if !valid {
            return Err(ProxyError::Transport(
                "response projector produced an unsafe header".into(),
            ));
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&response.body))
        .and_then(|()| stream.flush())
        .map_err(|error| ProxyError::Transport(format!("executor response failed: {error}")))
}

fn write_error_response(
    stream: &mut UnixStream,
    status: u16,
    message: &str,
) -> Result<(), ProxyError> {
    let body = serde_json::to_vec(&serde_json::json!({"message": message}))
        .map_err(|error| ProxyError::Transport(error.to_string()))?;
    write_filtered_response(
        stream,
        &HttpResponse {
            status,
            reason: canonical_reason(status, "").into(),
            content_type: Some("application/json".into()),
            safe_headers: BTreeMap::new(),
            body,
            connection_close: true,
        },
    )
}

fn method_name(method: DockerMethod) -> &'static str {
    match method {
        DockerMethod::Get => "GET",
        DockerMethod::Head => "HEAD",
        DockerMethod::Post => "POST",
        DockerMethod::Put => "PUT",
        DockerMethod::Delete => "DELETE",
    }
}

fn canonical_reason(status: u16, _upstream: &str) -> &str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Response",
    }
}

fn response_object_id(body: &[u8]) -> Result<String, ProxyError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| ProxyError::Transport(format!("object response JSON failed: {error}")))?;
    let id = value
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| ProxyError::Transport("object response has no Id".into()))?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ProxyError::Transport(
            "object response Id is invalid".into(),
        ));
    }
    Ok(id.into())
}

fn decode_effective_spec(body: &[u8]) -> Result<EffectiveContainerSpec, ProxyError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| ProxyError::Transport(format!("inspect JSON failed: {error}")))?;
    let config = object_field(&value, "Config")?;
    let host = object_field(&value, "HostConfig")?;
    let networking = object_field(&value, "NetworkSettings")?;
    let binds = strings_field(host, "Binds")?;
    let cap_drop = strings_field(host, "CapDrop")?;
    let cap_add = strings_field(host, "CapAdd")?;
    let security_opt = strings_field(host, "SecurityOpt")?;
    let devices = array_field(host, "Devices")?;
    if !devices.is_empty() {
        return Err(ProxyError::Transport(
            "inspect reports effective devices".into(),
        ));
    }
    let port_bindings = nested_object_field(host, "PortBindings")?;
    if !port_bindings.is_empty() {
        return Err(ProxyError::Transport(
            "inspect reports effective port bindings".into(),
        ));
    }
    let networks = nested_object_field(networking, "Networks")?;
    let labels = string_map_field(config, "Labels")?;
    let restart = nested_object_field(host, "RestartPolicy")?;
    let log = nested_object_field(host, "LogConfig")?;
    Ok(EffectiveContainerSpec {
        image: string_field(config, "Image")?,
        user: string_field(config, "User")?,
        binds,
        network_mode: string_field(host, "NetworkMode")?,
        readonly_rootfs: bool_field(host, "ReadonlyRootfs")?,
        cap_drop,
        cap_add,
        privileged: bool_field(host, "Privileged")?,
        security_opt,
        pids_limit: u64_field(host, "PidsLimit")?,
        memory: u64_field(host, "Memory")?,
        memory_swap: u64_field(host, "MemorySwap")?,
        shm_size: u64_field(host, "ShmSize")?,
        nano_cpus: u64_field(host, "NanoCpus")?,
        devices: Vec::new(),
        port_bindings: BTreeMap::new(),
        publish_all_ports: bool_field(host, "PublishAllPorts")?,
        pid_mode: string_field(host, "PidMode")?,
        ipc_mode: string_field(host, "IpcMode")?,
        uts_mode: string_field(host, "UTSMode")?,
        cgroupns_mode: string_field(host, "CgroupnsMode")?,
        userns_mode: string_field(host, "UsernsMode")?,
        restart_policy: string_field(restart, "Name")?,
        log_driver: string_field(log, "Type")?,
        network_endpoints: networks.keys().cloned().collect(),
        labels,
    })
}

fn object_field<'a>(
    value: &'a Value,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not an object")))
}

fn nested_object_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not an object")))
}

fn array_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a Vec<Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not an array")))
}

fn strings_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, ProxyError> {
    array_field(value, name)?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                ProxyError::Transport(format!("inspect field {name} has non-string"))
            })
        })
        .collect()
}

fn string_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<String, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not a string")))
}

fn bool_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<bool, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not a bool")))
}

fn u64_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<u64, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not a u64")))
}

fn string_map_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<BTreeMap<String, String>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ProxyError::Transport(format!("inspect field {name} is not an object")))?
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.into()))
                .ok_or_else(|| {
                    ProxyError::Transport(format!("inspect field {name} has non-string"))
                })
        })
        .collect()
}

fn connection_has_token(value: &str, expected: &str) -> Result<bool, ProxyError> {
    let mut matched = false;
    for token in value.split(',').map(str::trim) {
        if token.is_empty()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(ProxyError::Transport(
                "Connection contains an invalid token".into(),
            ));
        }
        matched |= token.eq_ignore_ascii_case(expected);
    }
    Ok(matched)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::{
        os::linux::net::SocketAddrExt,
        os::unix::net::SocketAddr,
        os::unix::net::UnixStream,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        sync::{Arc, Mutex},
        thread,
    };

    use super::*;
    use crate::{
        AllowedMount, EngineKind, ExecExpectation, IsolationLimits, IsolationProfile,
        NetworkPolicy, PolicyManifest,
    };
    use tar::EntryType;

    fn manifest() -> PolicyManifest {
        PolicyManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "run-transport".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            sha: "a".repeat(40),
            base_oid: "d".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
            job_id: "job".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
            isolation_profile: IsolationProfile {
                image_digest: format!("sha256:{}", "c".repeat(64)),
                engine_kind: EngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                seccomp_profile_path: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH
                    .into(),
                seccomp_profile_digest: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_DIGEST
                    .into(),
                limits: IsolationLimits {
                    cpu_quota_micros: 50_000,
                    memory_max_bytes: 1024 * 1024 * 1024,
                    memory_swap_max_bytes: 0,
                    pids_max: 128,
                    shm_size_bytes: 64 * 1024 * 1024,
                    disk_max_bytes: 1024 * 1024 * 1024,
                    timeout_seconds: 60,
                },
                network_policy: NetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-test".into(),
            },
            container_user: "10001:10001".into(),
            mounts: vec![AllowedMount {
                source: "/var/lib/buzz-ci/attempt/source".into(),
                destination: "/workspace".into(),
                read_only: true,
            }],
            allowed_environment: Vec::new(),
            expected_execs: vec![ExecExpectation {
                argv: vec!["true".into()],
                environment: Vec::new(),
                user: "10001:10001".into(),
                working_dir: "/workspace".into(),
                attach_stdin: false,
                attach_stdout: false,
                attach_stderr: false,
                tty: false,
            }],
        }
    }

    fn test_tar(path: &str, entry_type: EntryType, data: &[u8], mode: u32) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_entry_type(entry_type);
        header.set_mode(mode);
        header.set_uid(1234);
        header.set_gid(5678);
        header.set_mtime(1_700_000_000);
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, data).unwrap();
        builder.into_inner().unwrap()
    }

    fn path_stat_header() -> String {
        base64::Engine::encode(
            &BASE64_STANDARD,
            br#"{"name":"output.txt","size":4,"mode":420,"mtime":"2026-08-26T00:00:00Z","linkTarget":""}"#,
        )
    }

    fn chunked_body(body: &[u8], chunk_bytes: usize) -> Vec<u8> {
        let mut encoded = Vec::new();
        for chunk in body.chunks(chunk_bytes) {
            encoded.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            encoded.extend_from_slice(chunk);
            encoded.extend_from_slice(b"\r\n");
        }
        encoded.extend_from_slice(b"0\r\n\r\n");
        encoded
    }

    fn policy() -> ProxyPolicy {
        ProxyPolicy::install_for_test(manifest()).unwrap()
    }

    fn inspect_body() -> Vec<u8> {
        let manifest = manifest();
        serde_json::to_vec(&serde_json::json!({
            "Id": "owned",
            "Config": {
                "Image": manifest.isolation_profile.image_digest,
                "User": manifest.container_user,
                "Labels": {
                    "buzz.ci.run": manifest.run_id,
                    "buzz.ci.sha": manifest.sha,
                    "buzz.ci.job": manifest.job_id,
                    "buzz.ci.attempt": manifest.attempt.to_string(),
                    "buzz.ci.manifest": manifest.manifest_digest,
                }
            },
            "HostConfig": {
                "Binds": ["/var/lib/buzz-ci/attempt/source:/workspace:ro,Z"],
                "NetworkMode": "none",
                "ReadonlyRootfs": true,
                "CapDrop": ["ALL"],
                "CapAdd": [],
                "Privileged": false,
                "SecurityOpt": [
                    "no-new-privileges",
                    "label=type:container_t",
                    format!("seccomp={}", buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH)
                ],
                "PidsLimit": 128,
                "Memory": 1024 * 1024 * 1024_u64,
                "MemorySwap": 0,
                "ShmSize": 64 * 1024 * 1024_u64,
                "NanoCpus": 500_000_000_u64,
                "Devices": [],
                "PortBindings": {},
                "PublishAllPorts": false,
                "PidMode": "private",
                "IpcMode": "private",
                "UTSMode": "private",
                "CgroupnsMode": "private",
                "UsernsMode": "private",
                "RestartPolicy": {"Name": "no"},
                "LogConfig": {"Type": "none"}
            },
            "NetworkSettings": {"Networks": {}}
        }))
        .unwrap()
    }

    struct RecordingObserver {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
        fail_on_event: Option<&'static str>,
    }

    impl LifecycleObserver for RecordingObserver {
        fn observe_lifecycle(&mut self, event: LifecycleEvent<'_>) -> Result<(), ProxyError> {
            let label = match event {
                LifecycleEvent::CreateIntent { .. } => "create-intent",
                LifecycleEvent::CreateRejected { .. } => "create-rejected",
                LifecycleEvent::Created { .. } => "created",
                LifecycleEvent::StartIntent { .. } => "start-intent",
                LifecycleEvent::StartRejected { .. } => "start-rejected",
                LifecycleEvent::Started { .. } => "started",
                LifecycleEvent::ExecCreateIntent { .. } => "exec-create-intent",
                LifecycleEvent::ExecCreateRejected { .. } => "exec-create-rejected",
                LifecycleEvent::ExecCreated { .. } => "exec-created",
                LifecycleEvent::DeleteIntent { .. } => "delete-intent",
                LifecycleEvent::DeleteRejected { .. } => "delete-rejected",
                LifecycleEvent::Removed { .. } => "removed",
                LifecycleEvent::Poisoned { .. } => "poisoned",
            };
            self.events.lock().unwrap().push(label);
            if self.fail_on_event == Some(label) {
                return Err(ProxyError::Transport(format!(
                    "injected {label} persistence failure"
                )));
            }
            Ok(())
        }

        fn observe_pre_start(
            &mut self,
            _create: &CanonicalCreate,
            _container_id: &str,
            _effective: &EffectiveContainerSpec,
            _proof: &VerifiedStart,
        ) -> Result<(), ProxyError> {
            self.events.lock().unwrap().push("persist");
            if self.fail {
                Err(ProxyError::Transport("injected persistence failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct NoopLifecycleObserver;

    impl LifecycleObserver for NoopLifecycleObserver {
        fn observe_lifecycle(&mut self, _event: LifecycleEvent<'_>) -> Result<(), ProxyError> {
            Ok(())
        }

        fn observe_pre_start(
            &mut self,
            _create: &CanonicalCreate,
            _container_id: &str,
            _effective: &EffectiveContainerSpec,
            _proof: &VerifiedStart,
        ) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    struct CountingConnector {
        calls: Arc<Mutex<usize>>,
    }

    impl OneShotUpstreamConnector for CountingConnector {
        fn connect(&mut self, _capability: &UpstreamCapability) -> Result<UnixStream, ProxyError> {
            *self.calls.lock().unwrap() += 1;
            Err(ProxyError::Transport(
                "counting connector must not be reached".into(),
            ))
        }
    }

    struct LifecycleLogObserver {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl LifecycleObserver for LifecycleLogObserver {
        fn observe_lifecycle(&mut self, event: LifecycleEvent<'_>) -> Result<(), ProxyError> {
            let event = match event {
                LifecycleEvent::CreateIntent { .. } => "create-intent".into(),
                LifecycleEvent::CreateRejected { .. } => "create-rejected".into(),
                LifecycleEvent::Created { container_id, .. } => {
                    format!("created:{container_id}")
                }
                LifecycleEvent::StartIntent { container_id } => {
                    format!("start-intent:{container_id}")
                }
                LifecycleEvent::StartRejected { container_id } => {
                    format!("start-rejected:{container_id}")
                }
                LifecycleEvent::Started { container_id } => format!("started:{container_id}"),
                LifecycleEvent::ExecCreateIntent { exec } => {
                    format!("exec-create-intent:{}", exec.container_id())
                }
                LifecycleEvent::ExecCreateRejected { exec } => {
                    format!("exec-create-rejected:{}", exec.container_id())
                }
                LifecycleEvent::ExecCreated { exec, exec_id } => {
                    format!("exec-created:{}:{exec_id}", exec.container_id())
                }
                LifecycleEvent::DeleteIntent { container_id } => {
                    format!("delete-intent:{container_id}")
                }
                LifecycleEvent::DeleteRejected { container_id } => {
                    format!("delete-rejected:{container_id}")
                }
                LifecycleEvent::Removed { container_id } => {
                    format!("removed:{container_id}")
                }
                LifecycleEvent::Poisoned {
                    phase,
                    container_id,
                } => format!("poisoned:{phase:?}:{}", container_id.unwrap_or("none")),
            };
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        fn observe_pre_start(
            &mut self,
            _create: &CanonicalCreate,
            _container_id: &str,
            _effective: &EffectiveContainerSpec,
            _proof: &VerifiedStart,
        ) -> Result<(), ProxyError> {
            self.events.lock().unwrap().push("persist".into());
            Ok(())
        }
    }

    fn transport_policy() -> ProxyPolicy {
        let uid = nix::unistd::geteuid().as_raw();
        assert_ne!(uid, 0, "tests require an unprivileged process");
        ProxyPolicy::install_for_transport_test(manifest(), uid, uid).unwrap()
    }

    fn transport_capability() -> UpstreamCapability {
        UpstreamCapability {
            lease_id: "transport-test".into(),
            token: "a".repeat(64),
            runtime_uid: nix::unistd::geteuid().as_raw(),
        }
    }

    fn test_listener() -> (UnixListener, SocketAddr) {
        static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);
        let name = format!(
            "buzz-ci-policy-proxy-{}-{}",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        );
        let address = SocketAddr::from_abstract_name(name).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        (listener, address)
    }

    fn executor_exchange(address: &SocketAddr, request: Vec<u8>) -> thread::JoinHandle<Vec<u8>> {
        let address = address.clone();
        thread::spawn(move || {
            let mut client = UnixStream::connect_addr(&address).unwrap();
            client.write_all(&request).unwrap();
            read_to_end(&mut client)
        })
    }

    fn policy_with_created_container() -> ProxyPolicy {
        record_created_container(policy())
    }

    fn transport_policy_with_created_container() -> ProxyPolicy {
        record_created_container(transport_policy())
    }

    fn transport_policy_with_started_container() -> ProxyPolicy {
        let mut policy = transport_policy_with_created_container();
        let expected = decode_effective_spec(&inspect_body()).unwrap();
        let proof = policy.verify_pre_start("owned", &expected).unwrap();
        policy.begin_start(&proof).unwrap();
        policy.commit_started(&proof).unwrap();
        policy
    }

    fn record_created_container(mut policy: ProxyPolicy) -> ProxyPolicy {
        let Admission::Create(create) = policy
            .admit(
                DockerMethod::Post,
                "/containers/create",
                &serde_json::to_vec(&serde_json::json!({
                    "Image": format!("sha256:{}", "c".repeat(64))
                }))
                .unwrap(),
            )
            .unwrap()
        else {
            panic!("create admission");
        };
        policy.record_created("owned".into(), &create).unwrap();
        policy
    }

    fn assert_exec_create_response_is_ambiguous(response: Vec<u8>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024 * 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/exec");
            runtime_events.lock().unwrap().push("exec-create-byte");
            runtime.write_all(&response).unwrap();
        });
        let mut policy = transport_policy_with_started_container();
        let Admission::ExecCreate(exec) = policy
            .admit(
                DockerMethod::Post,
                "/containers/owned/exec",
                br#"{"Cmd":["true"],"WorkingDir":"/workspace"}"#,
            )
            .unwrap()
        else {
            panic!("exec admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let failure =
            handle_exec_create(&mut proxy, &mut policy, &mut observer, &exec, 1024 * 1024)
                .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            *events.lock().unwrap(),
            ["exec-create-intent", "exec-create-byte"]
        );
        assert!(policy.begin_seal().is_err());
    }

    #[test]
    fn exec_created_observer_failure_retains_owned_exec_and_poisons() {
        let (listener, listener_address) = test_listener();
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        let connector = InheritedOneShotConnector::new(upstream, transport_capability()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy_with_started_container(),
            RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: Some("exec-created"),
            },
        )
        .unwrap();
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024 * 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/exec");
            let body = br#"{"Id":"exec-one"}"#;
            write!(
                runtime,
                "HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(body).unwrap();
        });
        let body = br#"{"Cmd":["true"],"WorkingDir":"/workspace"}"#;
        let executor = executor_exchange(
            &listener_address,
            format!(
                "POST /containers/owned/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            )
            .into_bytes(),
        );
        let error = proxy.serve_once().unwrap_err();
        runtime_handle.join().unwrap();
        let _ = executor.join().unwrap();
        assert!(proxy.is_poisoned());
        assert!(matches!(
            error,
            ProxyError::Transport(message) if message.contains("exec-created persistence failure")
        ));
        assert!(proxy
            .policy
            .admit(DockerMethod::Get, "/exec/exec-one/json", &[])
            .is_ok());
        assert_eq!(
            *events.lock().unwrap(),
            ["exec-create-intent", "exec-created", "poisoned"]
        );
    }

    #[test]
    fn prestart_observer_runs_before_start_and_commit() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/json");
            runtime_events.lock().unwrap().push("inspect");
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let request = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/start");
            runtime_events.lock().unwrap().push("start");
            runtime
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        assert!(handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .is_ok());
        runtime_handle.join().unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["inspect", "persist", "start-intent", "start", "started"]
        );
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Started, Some("owned"))
        );
    }

    #[test]
    fn lifecycle_rejections_emit_ordered_resolution_facts() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024 * 1024).unwrap();
            assert!(request.target.starts_with("/containers/create?name="));
            runtime_events.lock().unwrap().push("create-byte");
            let body = br#"{"message":"create rejected"}"#;
            write!(
                runtime,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(body).unwrap();
        });
        let mut policy = policy();
        let request_body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
        let Admission::Create(create) = policy
            .admit(
                DockerMethod::Post,
                "/containers/create",
                request_body.as_bytes(),
            )
            .unwrap()
        else {
            panic!("create admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let response =
            handle_create(&mut proxy, &mut policy, &mut observer, &create, 1024 * 1024).unwrap();
        runtime_handle.join().unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            *events.lock().unwrap(),
            ["create-intent", "create-byte", "create-rejected"]
        );
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::AwaitCreate, None)
        );

        events.lock().unwrap().clear();
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let inspect = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(inspect.target, "/containers/owned/json");
            runtime_events.lock().unwrap().push("inspect");
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let start = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(start.target, "/containers/owned/start");
            runtime_events.lock().unwrap().push("start-byte");
            let body = br#"{"message":"start rejected"}"#;
            write!(
                runtime,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(body).unwrap();
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let response = handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .unwrap();
        runtime_handle.join().unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "inspect",
                "persist",
                "start-intent",
                "start-byte",
                "start-rejected",
            ]
        );
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Created, Some("owned"))
        );
    }

    #[test]
    fn ambiguous_mutation_responses_retain_inflight_state() {
        for (status, reason) in [
            (409, "Conflict"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
            let runtime_events = Arc::clone(&events);
            let runtime_handle = thread::spawn(move || {
                let request = read_request(&mut runtime, 1024 * 1024).unwrap();
                assert!(request.target.starts_with("/containers/create?name="));
                runtime_events.lock().unwrap().push("create-byte");
                write!(
                    runtime,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            });
            let mut policy = policy();
            let request_body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
            let Admission::Create(create) = policy
                .admit(
                    DockerMethod::Post,
                    "/containers/create",
                    request_body.as_bytes(),
                )
                .unwrap()
            else {
                panic!("create admission");
            };
            let mut observer = RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: None,
            };
            let failure =
                handle_create(&mut proxy, &mut policy, &mut observer, &create, 1024 * 1024)
                    .unwrap_err();
            runtime_handle.join().unwrap();
            assert!(failure.poison, "status {status}");
            assert_eq!(
                *events.lock().unwrap(),
                ["create-intent", "create-byte"],
                "status {status}"
            );
            assert_eq!(
                policy.lifecycle_snapshot(),
                (LifecyclePhase::Creating, None),
                "status {status}"
            );
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let inspect = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(inspect.target, "/containers/owned/json");
            runtime_events.lock().unwrap().push("inspect");
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let start = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(start.target, "/containers/owned/start");
            runtime_events.lock().unwrap().push("start-byte");
            runtime
                .write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let failure = handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            *events.lock().unwrap(),
            ["inspect", "persist", "start-intent", "start-byte"]
        );
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Starting, Some("owned"))
        );
    }

    #[test]
    fn exec_create_ambiguity_retains_pending_state() {
        for (status, reason) in [
            (409, "Conflict"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
            let runtime_events = Arc::clone(&events);
            let runtime_handle = thread::spawn(move || {
                let request = read_request(&mut runtime, 1024 * 1024).unwrap();
                assert_eq!(request.target, "/containers/owned/exec");
                runtime_events.lock().unwrap().push("exec-create-byte");
                write!(
                    runtime,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            });
            let mut policy = transport_policy_with_started_container();
            let Admission::ExecCreate(exec) = policy
                .admit(
                    DockerMethod::Post,
                    "/containers/owned/exec",
                    br#"{"Cmd":["true"],"WorkingDir":"/workspace"}"#,
                )
                .unwrap()
            else {
                panic!("exec admission");
            };
            let mut observer = RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: None,
            };
            let failure =
                handle_exec_create(&mut proxy, &mut policy, &mut observer, &exec, 1024 * 1024)
                    .unwrap_err();
            runtime_handle.join().unwrap();
            assert!(failure.poison, "status {status}");
            assert_eq!(
                *events.lock().unwrap(),
                ["exec-create-intent", "exec-create-byte"],
                "status {status}"
            );
            assert!(policy.begin_seal().is_err(), "status {status}");
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024 * 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/exec");
            runtime_events.lock().unwrap().push("exec-create-byte");
        });
        let mut policy = transport_policy_with_started_container();
        let Admission::ExecCreate(exec) = policy
            .admit(
                DockerMethod::Post,
                "/containers/owned/exec",
                br#"{"Cmd":["true"],"WorkingDir":"/workspace"}"#,
            )
            .unwrap()
        else {
            panic!("exec admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let failure =
            handle_exec_create(&mut proxy, &mut policy, &mut observer, &exec, 1024 * 1024)
                .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            *events.lock().unwrap(),
            ["exec-create-intent", "exec-create-byte"]
        );
        assert!(policy.begin_seal().is_err());

        assert_exec_create_response_is_ambiguous(
            b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        );
        assert_exec_create_response_is_ambiguous(
            b"HTTP/1.1 201 Created\r\nContent-Length: 32\r\n\r\n{\"Id\":\"partial".to_vec(),
        );
    }

    fn assert_delete_response_is_ambiguous(response: Vec<u8>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(request.target, "/containers/owned?force=1&v=1");
            runtime_events.lock().unwrap().push("delete-byte");
            runtime.write_all(&response).unwrap();
        });
        let mut policy = transport_policy_with_started_container();
        let Admission::Delete {
            container_id,
            target,
        } = policy
            .admit(DockerMethod::Delete, "/containers/owned?force=1&v=1", &[])
            .unwrap()
        else {
            panic!("delete admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        let failure = handle_delete(
            &mut proxy,
            &mut policy,
            &mut observer,
            &container_id,
            &target,
            1024,
        )
        .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(*events.lock().unwrap(), ["delete-intent", "delete-byte"]);
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Deleting, Some("owned"))
        );
    }

    #[test]
    fn exec_create_rejections_emit_ordered_resolution_facts() {
        for (status, reason) in [
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
            let runtime_events = Arc::clone(&events);
            let runtime_handle = thread::spawn(move || {
                let request = read_request(&mut runtime, 1024 * 1024).unwrap();
                assert_eq!(request.target, "/containers/owned/exec");
                runtime_events.lock().unwrap().push("exec-create-byte");
                write!(
                    runtime,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            });
            let mut policy = transport_policy_with_started_container();
            let Admission::ExecCreate(exec) = policy
                .admit(
                    DockerMethod::Post,
                    "/containers/owned/exec",
                    br#"{"Cmd":["true"],"WorkingDir":"/workspace"}"#,
                )
                .unwrap()
            else {
                panic!("exec admission");
            };
            let mut observer = RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: None,
            };
            let response =
                handle_exec_create(&mut proxy, &mut policy, &mut observer, &exec, 1024 * 1024)
                    .unwrap();
            runtime_handle.join().unwrap();
            assert_eq!(response.status, status);
            assert_eq!(
                *events.lock().unwrap(),
                [
                    "exec-create-intent",
                    "exec-create-byte",
                    "exec-create-rejected",
                ]
            );
            assert!(policy.begin_seal().is_ok());
        }
    }

    #[test]
    fn delete_lifecycle_is_write_ahead_and_ambiguous_until_resolved() {
        for (status, reason) in [
            (409, "Conflict"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
            let runtime_events = Arc::clone(&events);
            let runtime_handle = thread::spawn(move || {
                let request = read_request(&mut runtime, 1024).unwrap();
                assert_eq!(request.target, "/containers/owned?force=1&v=1");
                runtime_events.lock().unwrap().push("delete-byte");
                write!(
                    runtime,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            });
            let mut policy = transport_policy_with_started_container();
            let Admission::Delete {
                container_id,
                target,
            } = policy
                .admit(DockerMethod::Delete, "/containers/owned?force=1&v=1", &[])
                .unwrap()
            else {
                panic!("delete admission");
            };
            let mut observer = RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: None,
            };
            let failure = handle_delete(
                &mut proxy,
                &mut policy,
                &mut observer,
                &container_id,
                &target,
                1024,
            )
            .unwrap_err();
            runtime_handle.join().unwrap();
            assert!(failure.poison, "status {status}");
            assert_eq!(
                *events.lock().unwrap(),
                ["delete-intent", "delete-byte"],
                "status {status}"
            );
            assert_eq!(
                policy.lifecycle_snapshot(),
                (LifecyclePhase::Deleting, Some("owned")),
                "status {status}"
            );
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(request.target, "/containers/owned?force=1&v=1");
            runtime_events.lock().unwrap().push("delete-byte");
            runtime
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = transport_policy_with_started_container();
        let Admission::Delete {
            container_id,
            target,
        } = policy
            .admit(DockerMethod::Delete, "/containers/owned?force=1&v=1", &[])
            .unwrap()
        else {
            panic!("delete admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: None,
        };
        handle_delete(
            &mut proxy,
            &mut policy,
            &mut observer,
            &container_id,
            &target,
            1024,
        )
        .unwrap();
        runtime_handle.join().unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["delete-intent", "delete-byte", "removed"]
        );
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Removed, Some("owned"))
        );

        assert_delete_response_is_ambiguous(Vec::new());
        assert_delete_response_is_ambiguous(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        );
        assert_delete_response_is_ambiguous(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 8\r\n\r\npar".to_vec(),
        );
    }

    #[test]
    fn delete_rejections_restore_created_or_started_phase() {
        for started in [false, true] {
            for (status, reason) in [
                (400, "Bad Request"),
                (401, "Unauthorized"),
                (403, "Forbidden"),
            ] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
                let runtime_events = Arc::clone(&events);
                let runtime_handle = thread::spawn(move || {
                    let request = read_request(&mut runtime, 1024).unwrap();
                    assert_eq!(request.target, "/containers/owned?force=1&v=1");
                    runtime_events.lock().unwrap().push("delete-byte");
                    write!(
                        runtime,
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                    )
                    .unwrap();
                });
                let mut policy = if started {
                    transport_policy_with_started_container()
                } else {
                    transport_policy_with_created_container()
                };
                let Admission::Delete {
                    container_id,
                    target,
                } = policy
                    .admit(DockerMethod::Delete, "/containers/owned?force=1&v=1", &[])
                    .unwrap()
                else {
                    panic!("delete admission");
                };
                let mut observer = RecordingObserver {
                    events: Arc::clone(&events),
                    fail: false,
                    fail_on_event: None,
                };
                let response = handle_delete(
                    &mut proxy,
                    &mut policy,
                    &mut observer,
                    &container_id,
                    &target,
                    1024,
                )
                .unwrap();
                runtime_handle.join().unwrap();
                assert_eq!(response.status, status);
                assert_eq!(
                    *events.lock().unwrap(),
                    ["delete-intent", "delete-byte", "delete-rejected"]
                );
                assert_eq!(
                    policy.lifecycle_snapshot(),
                    (
                        if started {
                            LifecyclePhase::Started
                        } else {
                            LifecyclePhase::Created
                        },
                        Some("owned"),
                    ),
                );
            }
        }

        let (listener, listener_address) = test_listener();
        let calls = Arc::new(Mutex::new(0));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            CountingConnector {
                calls: Arc::clone(&calls),
            },
            transport_capability(),
            TransportLimits::default(),
            transport_policy_with_started_container(),
            NoopLifecycleObserver,
        )
        .unwrap();
        let executor = executor_exchange(
            &listener_address,
            b"DELETE /containers/owned?force=1&v=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        );
        assert!(proxy.serve_once().is_err());
        let _ = executor.join().unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(
            proxy.policy.lifecycle_snapshot(),
            (LifecyclePhase::Started, Some("owned"))
        );
    }

    #[test]
    fn poison_observer_failure_is_returned_while_memory_stays_poisoned() {
        let (listener, listener_address) = test_listener();
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        let connector = InheritedOneShotConnector::new(upstream, transport_capability()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy(),
            RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: Some("poisoned"),
            },
        )
        .unwrap();
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024 * 1024).unwrap();
            assert!(request.target.starts_with("/containers/create?name="));
            runtime
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
        let executor = executor_exchange(
            &listener_address,
            format!(
                "POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes(),
        );
        let error = proxy.serve_once().unwrap_err();
        runtime_handle.join().unwrap();
        let _ = executor.join().unwrap();
        assert!(proxy.is_poisoned());
        assert!(matches!(
            error,
            ProxyError::Transport(message) if message.contains("poisoned persistence failure")
        ));
        assert_eq!(*events.lock().unwrap(), ["create-intent", "poisoned"]);
    }

    #[test]
    fn truncated_mutation_responses_poison_the_exact_inflight_state() {
        let (listener, listener_address) = test_listener();
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        let connector = InheritedOneShotConnector::new(upstream, transport_capability()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy(),
            LifecycleLogObserver {
                events: Arc::clone(&events),
            },
        )
        .unwrap();
        let runtime_handle = thread::spawn(move || {
            let request = read_test_http(&mut runtime);
            assert!(request.starts_with(b"POST /containers/create?name=buzz-ci-"));
            runtime
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 64\r\n\r\n{\"Id\":\"partial")
                .unwrap();
        });
        let body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
        let request = format!(
            "POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let executor = executor_exchange(&listener_address, request.into_bytes());
        assert!(proxy.serve_once().is_err());
        runtime_handle.join().unwrap();
        assert!(executor
            .join()
            .unwrap()
            .starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(proxy.is_poisoned());
        assert_eq!(
            proxy.policy.lifecycle_snapshot(),
            (LifecyclePhase::Creating, None)
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["create-intent", "poisoned:Creating:none"]
        );

        let (listener, listener_address) = test_listener();
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        let connector = InheritedOneShotConnector::new(upstream, transport_capability()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy_with_created_container(),
            LifecycleLogObserver {
                events: Arc::clone(&events),
            },
        )
        .unwrap();
        let runtime_handle = thread::spawn(move || {
            let inspect = read_test_http(&mut runtime);
            assert!(inspect.starts_with(b"GET /containers/owned/json"));
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let start = read_test_http(&mut runtime);
            assert!(start.starts_with(b"POST /containers/owned/start"));
            runtime
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\n")
                .unwrap();
        });
        let executor = executor_exchange(
            &listener_address,
            b"POST /containers/owned/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        );
        assert!(proxy.serve_once().is_err());
        runtime_handle.join().unwrap();
        assert!(executor
            .join()
            .unwrap()
            .starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(proxy.is_poisoned());
        assert_eq!(
            proxy.policy.lifecycle_snapshot(),
            (LifecyclePhase::Starting, Some("owned"))
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["persist", "start-intent:owned", "poisoned:Starting:owned",]
        );
    }

    #[test]
    fn lifecycle_persistence_failures_preserve_the_recovery_state() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_handle = thread::spawn(move || {
            let _ = read_request(&mut runtime, 1024 * 1024).unwrap();
            runtime
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = policy();
        let request_body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
        let Admission::Create(create) = policy
            .admit(
                DockerMethod::Post,
                "/containers/create",
                request_body.as_bytes(),
            )
            .unwrap()
        else {
            panic!("create admission");
        };
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: Some("create-rejected"),
        };
        let failure = handle_create(&mut proxy, &mut policy, &mut observer, &create, 1024 * 1024)
            .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Creating, None)
        );

        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_handle = thread::spawn(move || {
            let _ = read_request(&mut runtime, 1024).unwrap();
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let _ = read_request(&mut runtime, 1024).unwrap();
            runtime
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: false,
            fail_on_event: Some("start-rejected"),
        };
        let failure = handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Starting, Some("owned"))
        );

        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_handle = thread::spawn(move || {
            let _ = read_request(&mut runtime, 1024).unwrap();
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            let _ = read_request(&mut runtime, 1024).unwrap();
            runtime
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events,
            fail: false,
            fail_on_event: Some("started"),
        };
        let failure = handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .unwrap_err();
        runtime_handle.join().unwrap();
        assert!(failure.poison);
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Started, Some("owned"))
        );
    }

    #[test]
    fn prestart_observer_failure_never_forwards_start() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        let runtime_events = Arc::clone(&events);
        let runtime_handle = thread::spawn(move || {
            let request = read_request(&mut runtime, 1024).unwrap();
            assert_eq!(request.target, "/containers/owned/json");
            runtime_events.lock().unwrap().push("inspect");
            let body = inspect_body();
            write!(
                runtime,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
            runtime
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(read_request(&mut runtime, 1024).is_err());
        });
        let mut policy = policy_with_created_container();
        let mut observer = RecordingObserver {
            events: Arc::clone(&events),
            fail: true,
            fail_on_event: None,
        };
        assert!(handle_start(
            &mut proxy,
            &mut policy,
            &mut observer,
            "owned",
            "/containers/owned/start",
            1024 * 1024,
        )
        .is_err());
        drop(proxy);
        runtime_handle.join().unwrap();
        assert_eq!(*events.lock().unwrap(), ["inspect", "persist"]);
        assert_eq!(
            policy.lifecycle_snapshot(),
            (LifecyclePhase::Created, Some("owned"))
        );
    }

    #[test]
    fn prestart_inspect_requires_exact_id_and_effective_spec() {
        let mut wrong_id: Value = serde_json::from_slice(&inspect_body()).unwrap();
        wrong_id["Id"] = Value::String("different".into());
        let mut drifted: Value = serde_json::from_slice(&inspect_body()).unwrap();
        drifted["HostConfig"]["Privileged"] = Value::Bool(true);

        for body in [
            serde_json::to_vec(&wrong_id).unwrap(),
            serde_json::to_vec(&drifted).unwrap(),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
            let runtime_events = Arc::clone(&events);
            let runtime_handle = thread::spawn(move || {
                let request = read_request(&mut runtime, 1024).unwrap();
                assert_eq!(request.target, "/containers/owned/json");
                runtime_events.lock().unwrap().push("inspect");
                write!(
                    runtime,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .unwrap();
                runtime.write_all(&body).unwrap();
                runtime
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                assert!(read_request(&mut runtime, 1024).is_err());
            });
            let mut policy = policy_with_created_container();
            let mut observer = RecordingObserver {
                events: Arc::clone(&events),
                fail: false,
                fail_on_event: None,
            };
            assert!(handle_start(
                &mut proxy,
                &mut policy,
                &mut observer,
                "owned",
                "/containers/owned/start",
                1024 * 1024,
            )
            .is_err());
            drop(proxy);
            runtime_handle.join().unwrap();
            assert_eq!(*events.lock().unwrap(), ["inspect"]);
            assert_eq!(
                policy.lifecycle_snapshot(),
                (LifecyclePhase::Created, Some("owned"))
            );
        }
    }

    fn serve_pair(
        executor_server: UnixStream,
        upstream_client: UnixStream,
        limits: TransportLimits,
    ) -> thread::JoinHandle<Result<(), ProxyError>> {
        thread::spawn(move || {
            let mut executor_server = executor_server;
            let mut upstream_client = upstream_client;
            let mut observer = NoopLifecycleObserver;
            serve_connection(
                &mut executor_server,
                &mut upstream_client,
                &mut policy(),
                &mut observer,
                limits,
            )
            .map(|_| ())
            .map_err(|failure| failure.error)
        })
    }

    #[test]
    fn local_routes_do_not_acquire_runtime_descriptor() {
        let (listener, listener_address) = test_listener();
        let calls = Arc::new(Mutex::new(0));
        let connector = CountingConnector {
            calls: Arc::clone(&calls),
        };
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy(),
            NoopLifecycleObserver,
        )
        .unwrap();

        for target in [
            "/_ping",
            "/version",
            "/info",
            "/containers/json?all=1",
            "/volumes",
        ] {
            let request =
                format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                    .into_bytes();
            let executor = executor_exchange(&listener_address, request);
            proxy.serve_once().unwrap();
            assert!(executor.join().unwrap().starts_with(b"HTTP/1.1 200 OK\r\n"));
        }
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[test]
    fn create_ack_failure_retains_exact_id_and_poisons() {
        let (listener, listener_address) = test_listener();
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        let connector = InheritedOneShotConnector::new(upstream, transport_capability()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut proxy = InheritedProxy::new_with_observer(
            listener,
            connector,
            transport_capability(),
            TransportLimits::default(),
            transport_policy(),
            LifecycleLogObserver {
                events: Arc::clone(&events),
            },
        )
        .unwrap();
        let exact_id = "abcdef0123456789".repeat(4);
        let runtime_id = exact_id.clone();
        let runtime_handle = thread::spawn(move || {
            let request = read_test_http(&mut runtime);
            assert!(request.starts_with(b"POST /containers/create?name=buzz-ci-"));
            let body = serde_json::to_vec(&serde_json::json!({"Id": runtime_id})).unwrap();
            write!(
                runtime,
                "HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            runtime.write_all(&body).unwrap();
        });
        let client_address = listener_address.clone();
        let executor = thread::spawn(move || {
            let mut client = UnixStream::connect_addr(&client_address).unwrap();
            let body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));
            write!(
                client,
                "POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        executor.join().unwrap();
        assert!(proxy.serve_once().is_err());
        runtime_handle.join().unwrap();
        assert!(proxy.is_poisoned());
        assert_eq!(
            proxy.policy.lifecycle_snapshot(),
            (LifecyclePhase::Created, Some(exact_id.as_str()))
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "create-intent".to_owned(),
                format!("created:{exact_id}"),
                format!("poisoned:Created:{exact_id}"),
            ]
        );
    }

    #[test]
    fn duplicate_create_and_start_refuse_before_connect() {
        let create_body = format!(r#"{{"Image":"sha256:{}"}}"#, "c".repeat(64));

        let duplicate_create_policy = transport_policy_with_created_container();
        let mut started_policy = transport_policy_with_created_container();
        let expected = decode_effective_spec(&inspect_body()).unwrap();
        let proof = started_policy.verify_pre_start("owned", &expected).unwrap();
        started_policy.begin_start(&proof).unwrap();
        started_policy.commit_started(&proof).unwrap();

        for (policy, request) in [
            (
                duplicate_create_policy,
                format!(
                    "POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
                    create_body.len(),
                    create_body
                ),
            ),
            (
                started_policy,
                "POST /containers/owned/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".into(),
            ),
            (
                transport_policy_with_created_container(),
                "POST /containers/other/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".into(),
            ),
        ] {
            let (listener, listener_address) = test_listener();
            let calls = Arc::new(Mutex::new(0));
            let connector = CountingConnector {
                calls: Arc::clone(&calls),
            };
            let mut proxy = InheritedProxy::new_with_observer(
                listener,
                connector,
                transport_capability(),
                TransportLimits::default(),
                policy,
                NoopLifecycleObserver,
            )
            .unwrap();
            let executor = executor_exchange(&listener_address, request.into_bytes());
            assert!(proxy.serve_once().is_err());
            assert!(executor
                .join()
                .unwrap()
                .starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
            assert_eq!(*calls.lock().unwrap(), 0);
        }
    }

    #[test]
    fn local_ping_never_touches_upstream() {
        let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
        upstream_server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let handle = serve_pair(executor_server, upstream_client, TransportLimits::default());
        executor_client
            .write_all(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let response = read_to_end(&mut executor_client);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response
            .windows(b"API-Version: 1.47\r\n".len())
            .any(|part| part == b"API-Version: 1.47\r\n"));
        assert!(response.ends_with(b"OK"));
        assert!(handle.join().unwrap().is_ok());
        assert_no_upstream_bytes(&mut upstream_server);
    }

    #[test]
    fn local_discovery_responses_have_fixed_schemas() {
        for (target, expected) in [
            (
                "/version",
                serde_json::json!({
                    "ApiVersion": "1.47",
                    "Arch": "x86_64",
                    "MinAPIVersion": "1.41",
                    "Os": "linux",
                    "Version": "5.8.4"
                }),
            ),
            (
                "/info",
                serde_json::json!({
                    "Architecture": "x86_64",
                    "Containers": 0,
                    "Images": 1,
                    "Name": "buzz-ci-policy-proxy",
                    "OSType": "linux"
                }),
            ),
            ("/containers/json?all=1", serde_json::json!([])),
            (
                "/volumes",
                serde_json::json!({"Volumes": [], "Warnings": []}),
            ),
        ] {
            let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
            let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
            upstream_server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let handle = serve_pair(executor_server, upstream_client, TransportLimits::default());
            write!(
                executor_client,
                "GET {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
            let response = read_to_end(&mut executor_client);
            let body = response.split(|byte| *byte == b'\n').collect::<Vec<_>>();
            let json: Value = serde_json::from_slice(body.last().copied().unwrap()).unwrap();
            assert_eq!(json, expected, "wrong response projection for {target}");
            assert!(handle.join().unwrap().is_ok());
            assert_no_upstream_bytes(&mut upstream_server);
        }
    }

    #[test]
    fn projected_inspects_strip_unapproved_runtime_fields() {
        let policy = policy();
        let image = policy.image_digest().to_owned();
        let response = project_upstream_response(
            &DockerRoute::ImageInspect {
                image: image.clone(),
            },
            test_response(serde_json::json!({
                "Id": image,
                "Architecture": "x86_64",
                "Os": "linux",
                "Config": {"Env": ["PATH=/usr/bin"]},
                "GraphDriver": {"Data": {"MergedDir": "/host/secret"}},
                "RepoTags": ["untrusted:latest"]
            })),
            &policy,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(
            value["Config"],
            serde_json::json!({"Env": ["PATH=/usr/bin"]})
        );
        assert!(!String::from_utf8(response.body)
            .unwrap()
            .contains("/host/secret"));

        let response = project_upstream_response(
            &DockerRoute::ContainerInspect {
                id: "container-one".into(),
            },
            test_response(serde_json::json!({
                "Id": "container-one",
                "Name": "/owned",
                "Config": {"Image": policy.image_digest(), "Labels": {"secret": "value"}},
                "State": {"Running": true, "Status": "running", "ExitCode": 0, "Pid": 4242},
                "Mounts": [{"Source": "/host/private"}]
            })),
            &policy,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["State"].as_object().unwrap().len(), 3);
        assert!(value.get("Mounts").is_none());
        assert!(value["Config"].get("Labels").is_none());

        let response = project_upstream_response(
            &DockerRoute::ExecInspect {
                exec_id: "exec-one".into(),
            },
            test_response(serde_json::json!({
                "ID": "exec-one",
                "Running": false,
                "ExitCode": 0,
                "ProcessConfig": {"entrypoint": "secret"}
            })),
            &policy,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert!(value.get("ProcessConfig").is_none());
    }

    #[test]
    fn projected_inspects_reject_identity_and_shape_mismatches() {
        let policy = policy();
        let cases = [
            (
                DockerRoute::ImageInspect {
                    image: policy.image_digest().into(),
                },
                serde_json::json!({
                    "Id": "sha256:wrong",
                    "Architecture": "x86_64",
                    "Os": "linux",
                    "Config": {"Env": []}
                }),
            ),
            (
                DockerRoute::ContainerInspect { id: "owned".into() },
                serde_json::json!({
                    "Id": "other",
                    "Name": "/other",
                    "Config": {"Image": policy.image_digest()},
                    "State": {"Running": false, "Status": "exited", "ExitCode": 0}
                }),
            ),
            (
                DockerRoute::ExecInspect {
                    exec_id: "exec-one".into(),
                },
                serde_json::json!({"ID": "other", "Running": false, "ExitCode": 0}),
            ),
        ];
        for (route, body) in cases {
            assert!(project_upstream_response(&route, test_response(body), &policy).is_err());
        }
    }

    #[test]
    fn projected_runtime_errors_expose_only_a_bounded_message() {
        let response = HttpResponse {
            status: 404,
            reason: "runtime-private-reason".into(),
            content_type: Some("application/json".into()),
            safe_headers: BTreeMap::from([("x-runtime-path".into(), "/host/private".into())]),
            body: serde_json::to_vec(&serde_json::json!({
                "message": "not found",
                "details": {"socket": "/run/user/1000/podman.sock"}
            }))
            .unwrap(),
            connection_close: false,
        };
        let projected = project_upstream_response(
            &DockerRoute::ContainerInspect { id: "owned".into() },
            response,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&projected.body).unwrap(),
            serde_json::json!({"message": "not found"})
        );
        assert!(projected.safe_headers.is_empty());
        assert_eq!(projected.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn hijack_grants_do_not_enable_forwarding() {
        let hijack = HijackGrant {
            lease_id: "lease".into(),
            exec_id: "owned-exec".into(),
            max_output_bytes: 1024,
            max_input_bytes: 0,
            allow_input: false,
        };
        assert!(!hijack.allow_input);

        let request = b"POST /exec/owned-exec/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
        upstream_server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let handle = serve_pair(executor_server, upstream_client, TransportLimits::default());
        executor_client.write_all(request).unwrap();
        drop(executor_client);
        assert!(handle.join().unwrap().is_err());
        assert_no_upstream_bytes(&mut upstream_server);
    }

    #[test]
    fn owned_archive_upload_is_validated_and_rebuilt_before_forwarding() {
        let input = test_tar("script.sh", EntryType::Regular, b"echo ok", 0o6777);
        let request = format!(
            "PUT /v1.47/containers/owned/archive?noOverwriteDirNonDir=true&path=%2Fworkspace HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            input.len()
        );
        let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, mut upstream_client) = UnixStream::pair().unwrap();
        let runtime = thread::spawn(move || {
            let request = read_test_http(&mut upstream_server);
            upstream_server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });
        executor_client.write_all(request.as_bytes()).unwrap();
        executor_client.write_all(&input).unwrap();

        let mut policy = transport_policy_with_started_container();
        let mut observer = NoopLifecycleObserver;
        assert!(serve_connection(
            &mut executor_server,
            &mut upstream_client,
            &mut policy,
            &mut observer,
            TransportLimits::default(),
        )
        .is_ok());
        drop(executor_server);
        let response = read_to_end(&mut executor_client);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

        let forwarded = runtime.join().unwrap();
        let split = find_subsequence(&forwarded, b"\r\n\r\n").unwrap() + 4;
        assert!(forwarded[..split].starts_with(
            b"PUT /containers/owned/archive?noOverwriteDirNonDir=true&path=%2Fworkspace HTTP/1.1\r\n"
        ));
        assert!(forwarded[..split]
            .windows(b"Content-Type: application/x-tar".len())
            .any(|window| window == b"Content-Type: application/x-tar"));
        let mut archive = tar::Archive::new(&forwarded[split..]);
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap(), Path::new("script.sh"));
        assert_eq!(entry.header().mode().unwrap(), 0o755);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
    }

    #[test]
    fn owned_archive_download_is_rebuilt_before_executor_visibility() {
        let input = test_tar("output.txt", EntryType::Regular, b"done", 0o6666);
        let path_stat = path_stat_header();
        let expected_path_stat = path_stat.clone();
        let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, mut upstream_client) = UnixStream::pair().unwrap();
        let runtime = thread::spawn(move || {
            let request = read_test_http(&mut upstream_server);
            assert!(request.starts_with(
                b"GET /containers/owned/archive?path=%2Fworkspace%2Foutput.txt HTTP/1.1\r\n"
            ));
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nContent-Length: {}\r\nX-Docker-Container-Path-Stat: {path_stat}\r\nX-Runtime-Path: /host/private\r\n\r\n",
                input.len(),
            );
            upstream_server.write_all(head.as_bytes()).unwrap();
            upstream_server.write_all(&input).unwrap();
        });
        executor_client
            .write_all(b"GET /containers/owned/archive?path=%2Fworkspace%2Foutput.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .unwrap();

        let mut policy = transport_policy_with_started_container();
        let mut observer = NoopLifecycleObserver;
        assert!(serve_connection(
            &mut executor_server,
            &mut upstream_client,
            &mut policy,
            &mut observer,
            TransportLimits::default(),
        )
        .is_ok());
        drop(executor_server);
        runtime.join().unwrap();

        let response = read_to_end(&mut executor_client);
        let split = find_subsequence(&response, b"\r\n\r\n").unwrap() + 4;
        assert!(response[..split]
            .windows(b"Content-Type: application/x-tar".len())
            .any(|window| window == b"Content-Type: application/x-tar"));
        assert!(response[..split]
            .windows(expected_path_stat.len())
            .any(|window| { window == expected_path_stat.as_bytes() }));
        assert!(!response[..split]
            .windows(b"X-Runtime-Path".len())
            .any(|window| window == b"X-Runtime-Path"));
        let mut archive = tar::Archive::new(&response[split..]);
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap(), Path::new("output.txt"));
        assert_eq!(entry.header().mode().unwrap(), 0o644);
        assert_eq!(entry.header().uid().unwrap(), 0);
    }

    #[test]
    fn chunked_archive_download_is_bounded_decoded_and_rebuilt() {
        let input = test_tar("output.txt", EntryType::Regular, b"done", 0o6666);
        let chunked = chunked_body(&input, 37);
        let path_stat = path_stat_header();
        let expected_path_stat = path_stat.clone();
        let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, mut upstream_client) = UnixStream::pair().unwrap();
        let runtime = thread::spawn(move || {
            let request = read_test_http(&mut upstream_server);
            assert!(request.starts_with(
                b"GET /containers/owned/archive?path=%2Fworkspace%2Foutput.txt HTTP/1.1\r\n"
            ));
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\nX-Unsafe-Runtime-Header: private\r\n\r\n"
            );
            upstream_server.write_all(head.as_bytes()).unwrap();
            upstream_server.write_all(&chunked).unwrap();
        });
        executor_client
            .write_all(b"GET /containers/owned/archive?path=%2Fworkspace%2Foutput.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .unwrap();

        let mut policy = transport_policy_with_started_container();
        let mut observer = NoopLifecycleObserver;
        assert!(serve_connection(
            &mut executor_server,
            &mut upstream_client,
            &mut policy,
            &mut observer,
            TransportLimits::default(),
        )
        .is_ok());
        drop(executor_server);
        runtime.join().unwrap();

        let response = read_to_end(&mut executor_client);
        let split = find_subsequence(&response, b"\r\n\r\n").unwrap() + 4;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response[..split]
            .windows(b"Content-Length:".len())
            .any(|window| window == b"Content-Length:"));
        assert!(!response[..split]
            .windows(b"Transfer-Encoding".len())
            .any(|window| window == b"Transfer-Encoding"));
        assert!(!response[..split]
            .windows(b"X-Unsafe-Runtime-Header".len())
            .any(|window| window == b"X-Unsafe-Runtime-Header"));
        assert!(response[..split]
            .windows(expected_path_stat.len())
            .any(|window| { window == expected_path_stat.as_bytes() }));
        let mut archive = tar::Archive::new(&response[split..]);
        let mut entries = archive.entries().unwrap();
        let entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap(), Path::new("output.txt"));
        assert_eq!(entry.header().mode().unwrap(), 0o644);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert!(entries.next().is_none());
    }

    #[test]
    fn hostile_archive_download_framing_and_headers_refuse_before_visibility() {
        let valid_tar = test_tar("secret.txt", EntryType::Regular, b"unsafe", 0o644);
        let valid_chunks = chunked_body(&valid_tar, 64);
        let path_stat = path_stat_header();
        let mut responses = vec![
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n0\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n0\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n400001\r\n"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n1;extension=x\r\na\r\n0\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n0\r\nX-Trailer: refused\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n0\r\n\r\nunsafe-pipeline"
            )
            .into_bytes(),
            {
                let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .to_vec();
                response.extend_from_slice(&valid_chunks);
                response
            },
            {
                let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: !!!\r\n\r\n"
                    .to_vec();
                response.extend_from_slice(&valid_chunks);
                response
            },
        ];
        let mut too_many_chunks = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Docker-Container-Path-Stat: {path_stat}\r\n\r\n"
        )
        .into_bytes();
        for _ in 0..=MAX_CHUNK_COUNT {
            too_many_chunks.extend_from_slice(b"1\r\na\r\n");
        }
        too_many_chunks.extend_from_slice(b"0\r\n\r\n");
        responses.push(too_many_chunks);

        for response in responses {
            let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
            let (mut upstream_server, mut upstream_client) = UnixStream::pair().unwrap();
            let runtime = thread::spawn(move || {
                let _request = read_test_http(&mut upstream_server);
                upstream_server.write_all(&response).unwrap();
            });
            executor_client
                .write_all(b"GET /containers/owned/archive?path=%2Fworkspace%2Fsecret.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            let mut policy = transport_policy_with_started_container();
            let mut observer = NoopLifecycleObserver;
            assert!(serve_connection(
                &mut executor_server,
                &mut upstream_client,
                &mut policy,
                &mut observer,
                TransportLimits::default(),
            )
            .is_err());
            drop(executor_server);
            runtime.join().unwrap();
            assert!(read_to_end(&mut executor_client).is_empty());
        }
    }

    #[test]
    fn chunked_upstream_responses_remain_closed_outside_archive_downloads() {
        let (mut runtime, mut proxy) = UnixStream::pair().unwrap();
        runtime
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
            .unwrap();
        assert!(read_response(
            &mut proxy,
            DockerMethod::Get,
            TransportLimits::default().response_body_bytes,
            false,
        )
        .is_err());
    }

    #[test]
    fn hostile_archive_upload_refuses_before_any_upstream_byte() {
        let input = test_tar("escape", EntryType::Symlink, b"", 0o777);
        let request = format!(
            "PUT /containers/owned/archive?path=%2Fworkspace HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            input.len()
        );
        let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, mut upstream_client) = UnixStream::pair().unwrap();
        upstream_server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        executor_client.write_all(request.as_bytes()).unwrap();
        executor_client.write_all(&input).unwrap();

        let mut policy = transport_policy_with_started_container();
        let mut observer = NoopLifecycleObserver;
        assert!(serve_connection(
            &mut executor_server,
            &mut upstream_client,
            &mut policy,
            &mut observer,
            TransportLimits::default(),
        )
        .is_err());
        assert_no_upstream_bytes(&mut upstream_server);
    }

    #[test]
    fn inherited_connector_consumes_one_exact_capability() {
        let (stream, peer) = UnixStream::pair().unwrap();
        let capability = UpstreamCapability {
            lease_id: "lease-one".into(),
            token: "a".repeat(64),
            runtime_uid: peer_uid(&peer).unwrap(),
        };
        let mut connector = InheritedOneShotConnector::new(stream, capability.clone()).unwrap();
        assert!(connector.connect(&capability).is_ok());
        assert!(connector.connect(&capability).is_err());

        let (stream, peer) = UnixStream::pair().unwrap();
        let wrong = UpstreamCapability {
            lease_id: "lease-two".into(),
            token: "b".repeat(64),
            runtime_uid: peer_uid(&peer).unwrap(),
        };
        let mut connector = InheritedOneShotConnector::new(stream, wrong).unwrap();
        assert!(connector.connect(&capability).is_err());
    }

    #[test]
    fn create_is_rebuilt_and_committed_only_after_success() {
        let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
        let fake = thread::spawn(move || {
            let request = read_test_http(&mut upstream_server);
            assert!(request.starts_with(b"POST /containers/create?name=buzz-ci-"));
            assert!(request
                .windows(b"\"Privileged\":false".len())
                .any(|part| part == b"\"Privileged\":false"));
            let body = br#"{"Id":"container-one"}"#;
            write!(
                upstream_server,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            upstream_server.write_all(body).unwrap();
        });
        let handle = serve_pair(executor_server, upstream_client, TransportLimits::default());
        let body = format!(r#"{{"Image":"sha256:{}","Cmd":["true"]}}"#, "c".repeat(64));
        write!(
            executor_client,
            "POST /v1.47/containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        let response = read_to_end(&mut executor_client);
        assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));
        assert!(handle.join().unwrap().is_ok());
        fake.join().unwrap();
    }

    #[test]
    fn chunked_and_upgrade_requests_fail_before_upstream() {
        for request in [
            b"POST /containers/create HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
            b"POST /containers/id/attach HTTP/1.1\r\nHost: localhost\r\nConnection: UpGrAdE\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close,,keep-alive\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ] {
            let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
            let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
            upstream_server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let handle = serve_pair(executor_server, upstream_client, TransportLimits::default());
            executor_client.write_all(request).unwrap();
            drop(executor_client);
            assert!(handle.join().unwrap().is_err());
            assert_no_upstream_bytes(&mut upstream_server);
        }
    }

    #[test]
    fn foreign_exec_hijack_is_refused_before_upstream() {
        let (mut executor_client, mut executor_server) = UnixStream::pair().unwrap();
        let body = br#"{"Detach":false,"Tty":false}"#;
        write!(
            executor_client,
            "POST /exec/foreign/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
            body.len()
        )
        .unwrap();
        executor_client.write_all(body).unwrap();
        let failure = match prepare_request(&mut executor_server, &mut policy(), 1024 * 1024) {
            Ok(_) => panic!("foreign exec must fail closed"),
            Err(failure) => failure,
        };
        assert!(!failure.poison);
        assert!(matches!(failure.error, ProxyError::StateRefused(_)));
    }

    #[test]
    fn hijack_relay_copies_both_directions_and_closes_the_pair() {
        let (mut executor_client, mut executor_proxy) = UnixStream::pair().unwrap();
        let (mut runtime_client, mut runtime_proxy) = UnixStream::pair().unwrap();
        let grant = HijackGrant {
            lease_id: "lease".into(),
            exec_id: "exec".into(),
            max_output_bytes: 64,
            max_input_bytes: 64,
            allow_input: true,
        };
        let relay = thread::spawn(move || {
            relay_hijack(
                &mut executor_proxy,
                &mut runtime_proxy,
                b"prefix",
                &grant,
                Duration::from_secs(1),
            )
        });

        let mut prefix = [0_u8; 6];
        executor_client.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"prefix");
        executor_client.write_all(b"stdin").unwrap();
        let mut stdin = [0_u8; 5];
        runtime_client.read_exact(&mut stdin).unwrap();
        assert_eq!(&stdin, b"stdin");
        runtime_client.write_all(b"stdout").unwrap();
        let mut stdout = [0_u8; 6];
        executor_client.read_exact(&mut stdout).unwrap();
        assert_eq!(&stdout, b"stdout");
        runtime_client.shutdown(Shutdown::Both).unwrap();
        assert!(relay.join().unwrap().is_ok());
    }

    #[test]
    fn hijack_relay_enforces_output_cap_and_deadline() {
        let (mut executor_client, mut executor_proxy) = UnixStream::pair().unwrap();
        let (mut runtime_client, mut runtime_proxy) = UnixStream::pair().unwrap();
        let cap = HijackGrant {
            lease_id: "lease".into(),
            exec_id: "exec".into(),
            max_output_bytes: 3,
            max_input_bytes: 0,
            allow_input: false,
        };
        let capped = thread::spawn(move || {
            relay_hijack(
                &mut executor_proxy,
                &mut runtime_proxy,
                b"",
                &cap,
                Duration::from_secs(1),
            )
        });
        runtime_client.write_all(b"four").unwrap();
        assert!(capped.join().unwrap().is_err());
        let _ = executor_client.read(&mut [0_u8; 1]);

        let (_executor_client, mut executor_proxy) = UnixStream::pair().unwrap();
        let (_runtime_client, mut runtime_proxy) = UnixStream::pair().unwrap();
        let deadline = HijackGrant {
            lease_id: "lease".into(),
            exec_id: "exec".into(),
            max_output_bytes: 8,
            max_input_bytes: 0,
            allow_input: false,
        };
        let result = relay_hijack(
            &mut executor_proxy,
            &mut runtime_proxy,
            b"",
            &deadline,
            Duration::from_millis(25),
        );
        assert!(
            matches!(result, Err(ProxyError::Transport(message)) if message.contains("deadline"))
        );
    }

    #[test]
    fn mixed_case_upstream_close_marks_the_connection_closed() {
        let (mut executor_client, executor_server) = UnixStream::pair().unwrap();
        let (mut upstream_server, upstream_client) = UnixStream::pair().unwrap();
        let fake = thread::spawn(move || {
            let _request = read_test_http(&mut upstream_server);
            let body = serde_json::to_vec(&serde_json::json!({
                "Id": format!("sha256:{}", "c".repeat(64)),
                "Architecture": "x86_64",
                "Os": "linux",
                "Config": {"Env": []}
            }))
            .unwrap();
            write!(
                upstream_server,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: ClOsE\r\n\r\n",
                body.len()
            )
            .unwrap();
            upstream_server.write_all(&body).unwrap();
        });
        let mut executor_server = executor_server;
        let mut upstream_client = upstream_client;
        let handle = thread::spawn(move || {
            let mut observer = NoopLifecycleObserver;
            serve_connection(
                &mut executor_server,
                &mut upstream_client,
                &mut policy(),
                &mut observer,
                TransportLimits::default(),
            )
        });
        executor_client
            .write_all(
                format!(
                    "GET /images/sha256%3A{}/json HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                    "c".repeat(64)
                )
                .as_bytes(),
            )
            .unwrap();
        let response = read_to_end(&mut executor_client);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(matches!(handle.join().unwrap(), Ok(true)));
        fake.join().unwrap();
    }

    fn test_response(value: Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            reason: "OK".into(),
            content_type: Some("application/json".into()),
            safe_headers: BTreeMap::from([("unsafe-runtime-header".into(), "secret".into())]),
            body: serde_json::to_vec(&value).unwrap(),
            connection_close: false,
        }
    }

    fn assert_no_upstream_bytes(stream: &mut UnixStream) {
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Ok(count) => panic!("proxy forwarded {count} unexpected upstream byte(s)"),
            Err(error) => panic!("unexpected upstream read error: {error}"),
        }
    }

    fn read_to_end(stream: &mut UnixStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn read_test_http(stream: &mut UnixStream) -> Vec<u8> {
        let head = read_head(stream, MAX_REQUEST_LINE_BYTES).unwrap();
        let parsed = parse_head(&head, true).unwrap();
        let length = validate_framing(&parsed.headers, 1024 * 1024, true, false).unwrap();
        let body = read_exact_body(stream, parsed.trailing, length, 1024 * 1024).unwrap();
        let mut all = head;
        all.extend_from_slice(&body);
        all
    }
}
