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
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    time::Duration,
};

use buzz_ci_isolation_contract::{RuntimeEndpointIdentity, ValidatedAttemptLeaseBinding};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde_json::Value;

use crate::{
    Admission, CanonicalCreate, CanonicalExec, DockerMethod, DockerRoute, EffectiveContainerSpec,
    ProxyError, ProxyPolicy,
};

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_STATUS_LINE_BYTES: usize = 4 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADER_COUNT: usize = 64;

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

/// Direction of a future manifest-bound archive mediation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveDirection {
    /// Bounded tar bytes from the executor to an owned container.
    Upload,
    /// Bounded sanitized tar bytes from an owned container to the broker.
    Download,
}

/// Typed grant required before archive mediation can be enabled.
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

/// A fail-closed proxy whose listener and raw upstream are broker-inherited.
///
/// The upstream descriptor is never returned or duplicated into an executor
/// process. `serve_once` verifies `SO_PEERCRED`, processes one non-pipelined
/// request, writes one filtered response, and closes that executor connection.
pub struct InheritedProxy<C: OneShotUpstreamConnector> {
    listener: UnixListener,
    upstream_connector: C,
    upstream_capability: UpstreamCapability,
    expected_executor_uid: u32,
    limits: TransportLimits,
    policy: ProxyPolicy,
    poisoned: bool,
}

impl<C: OneShotUpstreamConnector> InheritedProxy<C> {
    /// Install a proxy over broker-opened Unix descriptors.
    pub fn new(
        listener: UnixListener,
        upstream_connector: C,
        upstream_capability: UpstreamCapability,
        limits: TransportLimits,
        policy: ProxyPolicy,
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
        configure_stream(&executor, self.limits.io_timeout)?;
        let executor_peer_uid = peer_uid(&executor)?;
        if executor_peer_uid != self.expected_executor_uid {
            let _ = write_error_response(&mut executor, 403, "executor peer refused");
            return Err(ProxyError::Transport(
                "executor peer UID does not match the broker manifest".into(),
            ));
        }
        let mut upstream = match self.upstream_connector.connect(&self.upstream_capability) {
            Ok(stream) => stream,
            Err(error) => {
                self.poisoned = true;
                let _ = write_error_response(&mut executor, 502, "runtime capability refused");
                return Err(error);
            }
        };
        configure_stream(&upstream, self.limits.io_timeout)?;
        if peer_uid(&upstream)? != self.upstream_capability.runtime_uid {
            self.poisoned = true;
            let _ = write_error_response(&mut executor, 502, "runtime peer refused");
            return Err(ProxyError::Transport(
                "upstream peer UID does not match the broker capability".into(),
            ));
        }
        match serve_connection(&mut executor, &mut upstream, &mut self.policy, self.limits) {
            Ok(upstream_closed) => {
                self.poisoned |= upstream_closed;
                Ok(())
            }
            Err(failure) => {
                if failure.upstream_touched {
                    self.poisoned = true;
                }
                let _ = write_error_response(&mut executor, failure.status, failure.public_message);
                Err(failure.error)
            }
        }
    }

    /// Report whether the broker must terminate and reconcile this proxy.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
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

struct ConnectionFailure {
    error: ProxyError,
    upstream_touched: bool,
    status: u16,
    public_message: &'static str,
}

impl ConnectionFailure {
    fn before_upstream(error: ProxyError) -> Self {
        Self {
            error,
            upstream_touched: false,
            status: 403,
            public_message: "request refused",
        }
    }

    fn after_upstream(error: ProxyError) -> Self {
        Self {
            error,
            upstream_touched: true,
            status: 502,
            public_message: "upstream exchange failed closed",
        }
    }
}

fn serve_connection(
    executor: &mut UnixStream,
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    limits: TransportLimits,
) -> Result<bool, ConnectionFailure> {
    let request = read_request(executor, limits.request_body_bytes)
        .map_err(ConnectionFailure::before_upstream)?;
    let route = DockerRoute::parse(request.method, &request.target)
        .map_err(ConnectionFailure::before_upstream)?;
    if matches!(
        &route,
        DockerRoute::ContainerAttach { .. }
            | DockerRoute::ContainerLogs { .. }
            | DockerRoute::ExecStart { .. }
            | DockerRoute::Archive { .. }
    ) {
        return Err(ConnectionFailure::before_upstream(ProxyError::Transport(
            "Docker stream/archive routes are disabled until bounded mediation is proven".into(),
        )));
    }
    let admission = policy
        .admit(request.method, &request.target, &request.body)
        .map_err(ConnectionFailure::before_upstream)?;

    let (response, upstream_touched) = match admission {
        Admission::LocalResponse(body) => {
            (HttpResponse::local(&route, request.method, body), false)
        }
        Admission::Forward { target } => (
            exchange(
                upstream,
                request.method,
                &target,
                &[],
                limits.response_body_bytes,
            )
            .map_err(ConnectionFailure::after_upstream)?,
            true,
        ),
        Admission::Create(approved) => (
            handle_create(upstream, policy, &approved, limits.response_body_bytes)?,
            true,
        ),
        Admission::ExecCreate(approved) => (
            handle_exec_create(upstream, policy, &approved, limits.response_body_bytes)?,
            true,
        ),
        Admission::NeedsPreStartProof {
            container_id,
            target,
        } => (
            handle_start(
                upstream,
                policy,
                &container_id,
                &target,
                limits.response_body_bytes,
            )?,
            true,
        ),
        Admission::Delete {
            container_id,
            target,
        } => {
            let response = exchange(
                upstream,
                DockerMethod::Delete,
                &target,
                &[],
                limits.response_body_bytes,
            )
            .map_err(ConnectionFailure::after_upstream)?;
            if response.is_success() {
                validate_empty_ack(&response.body).map_err(ConnectionFailure::after_upstream)?;
                policy
                    .commit_deleted(&container_id)
                    .map_err(ConnectionFailure::after_upstream)?;
            }
            (response, true)
        }
        Admission::Wait {
            container_id,
            target,
        } => {
            let response = exchange(
                upstream,
                DockerMethod::Post,
                &target,
                &[],
                limits.response_body_bytes,
            )
            .map_err(ConnectionFailure::after_upstream)?;
            if response.is_success() {
                validate_wait_response(&response.body)
                    .map_err(ConnectionFailure::after_upstream)?;
                policy
                    .commit_stopped(&container_id)
                    .map_err(ConnectionFailure::after_upstream)?;
            }
            (response, true)
        }
    };
    let response = if upstream_touched {
        project_upstream_response(&route, response, policy)
            .map_err(ConnectionFailure::after_upstream)?
    } else {
        response
    };
    let upstream_closed = response.connection_close;
    write_filtered_response(executor, &response).map_err(ConnectionFailure::after_upstream)?;
    Ok(upstream_closed)
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
    approved: &CanonicalCreate,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    let response = exchange(
        upstream,
        DockerMethod::Post,
        &approved.target,
        &approved.body,
        max_response,
    )
    .map_err(|error| {
        let _ = policy.abort_create(approved);
        ConnectionFailure::after_upstream(error)
    })?;
    if response.is_success() {
        let id = response_object_id(&response.body).map_err(|error| {
            let _ = policy.abort_create(approved);
            ConnectionFailure::after_upstream(error)
        })?;
        policy
            .record_created(id, approved)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        policy
            .abort_create(approved)
            .map_err(ConnectionFailure::after_upstream)?;
    }
    Ok(response)
}

fn handle_exec_create(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
    approved: &CanonicalExec,
    max_response: usize,
) -> Result<HttpResponse, ConnectionFailure> {
    let response = exchange(
        upstream,
        DockerMethod::Post,
        &approved.target,
        &approved.body,
        max_response,
    )
    .map_err(|error| {
        let _ = policy.abort_exec(approved);
        ConnectionFailure::after_upstream(error)
    })?;
    if response.is_success() {
        let id = response_object_id(&response.body).map_err(|error| {
            let _ = policy.abort_exec(approved);
            ConnectionFailure::after_upstream(error)
        })?;
        policy
            .record_exec(id, approved)
            .map_err(ConnectionFailure::after_upstream)?;
    } else {
        policy
            .abort_exec(approved)
            .map_err(ConnectionFailure::after_upstream)?;
    }
    Ok(response)
}

fn handle_start(
    upstream: &mut UnixStream,
    policy: &mut ProxyPolicy,
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
    .map_err(ConnectionFailure::after_upstream)?;
    if !inspect.is_success() {
        return Err(ConnectionFailure::after_upstream(ProxyError::Transport(
            "pre-start inspect did not succeed".into(),
        )));
    }
    let effective =
        decode_effective_spec(&inspect.body).map_err(ConnectionFailure::after_upstream)?;
    let proof = policy
        .verify_pre_start(container_id, &effective)
        .map_err(ConnectionFailure::after_upstream)?;
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
    }
    Ok(response)
}

fn exchange(
    upstream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    max_response: usize,
) -> Result<HttpResponse, ProxyError> {
    write_upstream_request(upstream, method, target, body)?;
    read_response(upstream, method, max_response)
}

#[derive(Debug)]
struct HttpRequest {
    method: DockerMethod,
    target: String,
    body: Vec<u8>,
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
    let content_length = validate_framing(&parsed.headers, max_body, true)?;
    let body = read_exact_body(stream, parsed.trailing, content_length, max_body)?;
    Ok(HttpRequest {
        method,
        target: request_line[1].into(),
        body,
    })
}

fn read_response(
    stream: &mut UnixStream,
    request_method: DockerMethod,
    max_body: usize,
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
    let content_length = validate_framing(&headers, max_body, false)?;
    let body = read_exact_body(stream, parsed.trailing, content_length, max_body)?;
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
    Ok(HttpResponse {
        status,
        reason: reason.into(),
        content_type,
        safe_headers: BTreeMap::new(),
        body,
        connection_close,
    })
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
) -> Result<usize, ProxyError> {
    for forbidden in [
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "trailer",
        "expect",
    ] {
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
    let method = method_name(method);
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
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
        if name != "API-Version"
            || value.len() > 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
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
    use std::{os::unix::net::UnixStream, thread};

    use super::*;
    use crate::{
        AllowedMount, EngineKind, IsolationLimits, IsolationProfile, NetworkPolicy, PolicyManifest,
    };

    fn policy() -> ProxyPolicy {
        ProxyPolicy::install_for_test(PolicyManifest {
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
        })
        .unwrap()
    }

    fn serve_pair(
        executor_server: UnixStream,
        upstream_client: UnixStream,
        limits: TransportLimits,
    ) -> thread::JoinHandle<Result<(), ProxyError>> {
        thread::spawn(move || {
            let mut executor_server = executor_server;
            let mut upstream_client = upstream_client;
            serve_connection(
                &mut executor_server,
                &mut upstream_client,
                &mut policy(),
                limits,
            )
            .map(|_| ())
            .map_err(|failure| failure.error)
        })
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
    fn archive_and_hijack_grants_do_not_enable_forwarding() {
        let archive = ArchiveGrant {
            lease_id: "lease".into(),
            container_id: "owned".into(),
            container_path: "/workspace/file".into(),
            direction: ArchiveDirection::Upload,
            max_bytes: 1024,
        };
        let hijack = HijackGrant {
            lease_id: "lease".into(),
            exec_id: "owned-exec".into(),
            max_output_bytes: 1024,
            max_input_bytes: 0,
            allow_input: false,
        };
        assert_eq!(archive.direction, ArchiveDirection::Upload);
        assert!(!hijack.allow_input);

        for request in [
            b"PUT /containers/owned/archive?path=%2Fworkspace HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"POST /exec/owned-exec/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
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
            serve_connection(
                &mut executor_server,
                &mut upstream_client,
                &mut policy(),
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
        let length = validate_framing(&parsed.headers, 1024 * 1024, true).unwrap();
        let body = read_exact_body(stream, parsed.trailing, length, 1024 * 1024).unwrap();
        let mut all = head;
        all.extend_from_slice(&body);
        all
    }
}
