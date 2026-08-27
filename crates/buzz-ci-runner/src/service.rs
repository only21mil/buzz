//! Sequential local service loop and frozen systemd listener validation.

use std::convert::Infallible;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::{env, os::fd::AsRawFd, path::Path, process};

#[cfg(target_os = "linux")]
use nix::sys::socket::{
    getsockname, getsockopt, sockopt::AcceptConn, sockopt::PeerCredentials, sockopt::SockType,
    SockType as NixSockType, UnixAddr,
};

use thiserror::Error;

use crate::transport::{
    read_request_frame, ReceiptWriteError, ReceiptWriter, RefusalReason, RunnerReceipt,
    RunnerRequest, RUNNER_TRANSPORT_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
use crate::transport::{RUNNER_CONTROL_SOCKET_PATH, SYSTEMD_FD_NAME};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Service-loop failures without protocol-specific details.
#[derive(Debug, Error)]
pub enum ServiceLoopError {
    #[error("local connection acceptance failed")]
    Accept(#[source] io::Error),
    #[error("local connection handling failed")]
    Handle(#[source] io::Error),
}

/// One reviewed-protocol connection failure. No variant grants execution.
#[derive(Debug, Error)]
pub enum RunnerConnectionError {
    #[error("runner control peer is not the configured controld UID")]
    UnauthorizedPeer,
    #[error("runner control socket setup failed")]
    Socket(#[source] io::Error),
    #[error("runner request frame was rejected")]
    Frame(#[from] crate::transport::FrameError),
    #[error("runner refusal receipt could not be written")]
    Receipt(#[from] ReceiptWriteError),
    #[error("configured runner handler failed")]
    Handler,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum ActivationError {
    #[error("invalid systemd socket activation: {0}")]
    Invalid(&'static str),
    #[error("systemd listener inspection failed")]
    Inspect(#[source] io::Error),
}

#[cfg(target_os = "linux")]
pub fn validate_systemd_environment() -> Result<(), ActivationError> {
    let listen_pid = parse_env_u32("LISTEN_PID")?;
    let listen_fds = parse_env_u32("LISTEN_FDS")?;
    let listen_fdnames = env::var("LISTEN_FDNAMES").ok();
    validate_systemd_environment_values(
        process::id(),
        listen_pid,
        listen_fds,
        listen_fdnames.as_deref(),
    )
}

#[cfg(target_os = "linux")]
fn validate_systemd_environment_values(
    process_id: u32,
    listen_pid: u32,
    listen_fds: u32,
    listen_fdnames: Option<&str>,
) -> Result<(), ActivationError> {
    if listen_pid != process_id {
        return Err(ActivationError::Invalid(
            "LISTEN_PID does not match this process",
        ));
    }
    if listen_fds != 1 {
        return Err(ActivationError::Invalid("LISTEN_FDS must equal one"));
    }
    if listen_fdnames != Some(SYSTEMD_FD_NAME) {
        return Err(ActivationError::Invalid(
            "LISTEN_FDNAMES does not identify the runner control socket",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_systemd_listener(listener: UnixListener) -> Result<UnixListener, ActivationError> {
    if getsockopt(&listener, SockType).map_err(nix_io)? != NixSockType::Stream {
        return Err(ActivationError::Invalid("fd 3 is not a stream socket"));
    }
    if !getsockopt(&listener, AcceptConn).map_err(nix_io)? {
        return Err(ActivationError::Invalid("fd 3 is not listening"));
    }
    let address = getsockname::<UnixAddr>(listener.as_raw_fd()).map_err(nix_io)?;
    if address.path() != Some(Path::new(RUNNER_CONTROL_SOCKET_PATH)) {
        return Err(ActivationError::Invalid(
            "fd 3 is not the fixed runner control socket",
        ));
    }
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn parse_env_u32(key: &'static str) -> Result<u32, ActivationError> {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(ActivationError::Invalid(
            "socket activation environment is missing or invalid",
        ))
}

#[cfg(target_os = "linux")]
fn nix_io(error: nix::errno::Errno) -> ActivationError {
    ActivationError::Inspect(io::Error::from_raw_os_error(error as i32))
}

/// Authenticate controld before reading bytes, then return the closed
/// `backend_unavailable` receipt until the reviewed policy and materializer
/// providers are composed. This starts the real socket service without
/// treating peer identity as request authority.
#[cfg(target_os = "linux")]
pub fn serve_runner_connection(
    stream: UnixStream,
    expected_controld_uid: u32,
) -> Result<(), RunnerConnectionError> {
    serve_runner_connection_with_handler(stream, expected_controld_uid, &mut |request, writer| {
        let (dispatch_id, request_event_id, run_id, attempt) = request.refusal_identity();
        let refusal = RunnerReceipt::Refused {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: dispatch_id.to_owned(),
            request_event_id: request_event_id.to_owned(),
            run_id: run_id.to_owned(),
            attempt,
            receipt_sequence: 1,
            reason: RefusalReason::BackendUnavailable,
        };
        ReceiptWriter::new(writer).send(&refusal).map_err(|_| ())
    })
}

/// Authenticate controld, parse one frame, and invoke an injected production handler.
///
/// The default binary deliberately does not call this path until its verifier,
/// receipt journal, broker transport, and unprivileged executor are configured.
#[cfg(target_os = "linux")]
pub fn serve_runner_connection_with_handler(
    mut stream: UnixStream,
    expected_controld_uid: u32,
    handler: &mut impl FnMut(RunnerRequest, &mut UnixStream) -> Result<(), ()>,
) -> Result<(), RunnerConnectionError> {
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|error| {
        RunnerConnectionError::Socket(io::Error::from_raw_os_error(error as i32))
    })?;
    if credentials.uid() != expected_controld_uid {
        return Err(RunnerConnectionError::UnauthorizedPeer);
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(RunnerConnectionError::Socket)?;

    let request = read_request_frame(&mut stream)?;
    handler(request, &mut stream).map_err(|()| RunnerConnectionError::Handler)
}

/// Hand one local connection to a caller-supplied protocol implementation.
pub fn serve_connection(
    stream: UnixStream,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<(), ServiceLoopError> {
    handler(stream).map_err(ServiceLoopError::Handle)
}

/// Accept and handle one local connection.
pub fn accept_one(
    listener: &UnixListener,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<(), ServiceLoopError> {
    let (stream, _) = listener.accept().map_err(ServiceLoopError::Accept)?;
    serve_connection(stream, handler)
}

/// Run the sequential local connection loop.
///
/// Sequential handling preserves the Phase-1 concurrency ceiling. The caller
/// remains responsible for supplying a listener and the frozen C3 handler.
pub fn run_service_loop(
    listener: &UnixListener,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<Infallible, ServiceLoopError> {
    loop {
        accept_one(listener, handler)?;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::thread;

    #[cfg(target_os = "linux")]
    use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::transport::{read_frame, write_frame, ExecuteJob, RunnerRequest};

    #[test]
    fn protocol_neutral_handler_receives_one_end_of_socket_pair() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        client.write_all(b"opaque").expect("write fixture bytes");
        client.shutdown(Shutdown::Write).expect("finish fixture");

        let mut observed = Vec::new();
        serve_connection(server, &mut |mut stream| {
            stream.read_to_end(&mut observed).map(|_| ())
        })
        .expect("serve connection");

        assert_eq!(observed, b"opaque");
    }

    #[cfg(target_os = "linux")]
    fn request() -> RunnerRequest {
        RunnerRequest::ExecuteAttempt {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: "123e4567-e89b-12d3-a456-426614174010".into(),
            request_event_id: "11".repeat(32),
            request_event: CiRequestEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_type: CiRequestType::Run,
                target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
                pr_root_event_id: "33".repeat(32),
                pr_update_event_id: None,
                source_clone_url: "https://relay.example/git/repo".into(),
                immutable_source_ref: "refs/nostr/source".into(),
                tip_oid: "44".repeat(20),
                source_branch: "feature".into(),
                base_ref: "refs/heads/main".into(),
                base_oid: "55".repeat(20),
                workflow_id: "ci".into(),
                workflow_digest: "66".repeat(32),
                job_ids: vec!["test".into()],
                run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
                attempt: 1,
                parent_attempt: None,
                parent_run_id: None,
                trigger_event_id: "33".repeat(32),
                actor: "77".repeat(32),
                timeout_seconds: 10,
                idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
                issued_at: 1,
                expires_at: 20,
            },
            signed_request_digest: "88".repeat(32),
            assigned_at: 10,
            deadline_at: 20,
            jobs: vec![ExecuteJob {
                job_id: "test".into(),
                attempt: 1,
                parent_attempt: 0,
                workflow_path: ".github/workflows/ci.yml".into(),
                job_manifest: "{}".into(),
                job_manifest_digest: "99".repeat(32),
                audience_digest: "aa".repeat(32),
                isolation_profile_digest: "bb".repeat(32),
            }],
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_framed_dispatch_gets_closed_backend_refusal() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let uid = getsockopt(&server, PeerCredentials)
            .expect("peer credentials")
            .uid();
        let worker = thread::spawn(move || serve_runner_connection(server, uid));

        write_frame(&mut client, &request()).expect("request frame");
        let receipt: RunnerReceipt = read_frame(&mut client).expect("refusal frame");
        assert!(matches!(
            receipt,
            RunnerReceipt::Refused {
                reason: RefusalReason::BackendUnavailable,
                receipt_sequence: 1,
                ..
            }
        ));
        worker.join().expect("join").expect("serve connection");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_dispatch_reaches_injected_handler() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let uid = getsockopt(&server, PeerCredentials)
            .expect("peer credentials")
            .uid();
        let worker = thread::spawn(move || {
            serve_runner_connection_with_handler(server, uid, &mut |request, stream| {
                let (dispatch_id, request_event_id, run_id, attempt) = request.refusal_identity();
                ReceiptWriter::new(stream)
                    .send(&RunnerReceipt::Accepted {
                        schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
                        dispatch_id: dispatch_id.to_owned(),
                        request_event_id: request_event_id.to_owned(),
                        run_id: run_id.to_owned(),
                        attempt,
                        receipt_sequence: 1,
                        accepted_at: 10,
                    })
                    .map_err(|_| ())
            })
        });

        write_frame(&mut client, &request()).expect("request frame");
        let receipt: RunnerReceipt = read_frame(&mut client).expect("accepted frame");
        assert!(matches!(receipt, RunnerReceipt::Accepted { .. }));
        worker.join().expect("join").expect("serve connection");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_uid_is_checked_before_request_bytes_are_read() {
        let (_client, server) = UnixStream::pair().expect("socket pair");
        let uid = getsockopt(&server, PeerCredentials)
            .expect("peer credentials")
            .uid();
        assert!(matches!(
            serve_runner_connection(server, uid.saturating_add(1)),
            Err(RunnerConnectionError::UnauthorizedPeer)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_environment_requires_exact_fd_three_assignment() {
        assert!(
            validate_systemd_environment_values(100, 100, 1, Some("buzz-ci-runner-control"))
                .is_ok()
        );
        assert!(
            validate_systemd_environment_values(100, 100, 2, Some("buzz-ci-runner-control"))
                .is_err()
        );
        assert!(validate_systemd_environment_values(100, 101, 1, Some("wrong")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_listener_rejects_a_different_unix_socket_path() {
        let directory = tempdir().expect("tempdir");
        let listener = UnixListener::bind(directory.path().join("runner.sock"))
            .expect("bind in-process listener");
        assert!(matches!(
            validate_systemd_listener(listener),
            Err(ActivationError::Invalid(
                "fd 3 is not the fixed runner control socket"
            ))
        ));
    }
}
