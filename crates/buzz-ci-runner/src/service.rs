//! Sequential local service loop and frozen systemd listener validation.
//!
//! This module does not authenticate peers or dispatch execution.

use std::convert::Infallible;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(target_os = "linux")]
use std::{env, os::fd::AsRawFd, path::Path, process};

#[cfg(target_os = "linux")]
use nix::sys::socket::{
    getsockname, getsockopt, sockopt::AcceptConn, sockopt::SockType, SockType as NixSockType,
    UnixAddr,
};

use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::transport::{RUNNER_CONTROL_SOCKET_PATH, SYSTEMD_FD_NAME};

/// Service-loop failures without protocol-specific details.
#[derive(Debug, Error)]
pub enum ServiceLoopError {
    #[error("local connection acceptance failed")]
    Accept(#[source] io::Error),
    #[error("local connection handling failed")]
    Handle(#[source] io::Error),
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

    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    use super::*;

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
