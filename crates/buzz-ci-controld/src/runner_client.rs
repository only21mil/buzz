//! Authenticated Unix transport for the version-2 runner proxy.

use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Factory for fresh byte streams. Each retry receives the identical request.
pub trait RunnerConnector {
    /// Fresh readable and writable connection type.
    type Connection: Read + Write;
    /// Connector-specific transport error.
    type Error;
    /// Open one fresh connection to the configured runner endpoint.
    fn connect(&mut self) -> Result<Self::Connection, Self::Error>;
}

/// Exact local runner-control endpoint binding used by the production daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixRunnerConnectorConfig {
    pub socket_path: PathBuf,
    pub runner_uid: u32,
    pub runner_gid: u32,
    pub connect_timeout_millis: u64,
    pub io_timeout_millis: u64,
}

impl UnixRunnerConnectorConfig {
    /// Reject incomplete identities, unbounded waits, and non-canonical paths.
    pub fn validate(&self) -> Result<(), UnixRunnerConnectorError> {
        if self.runner_uid == 0
            || self.runner_gid == 0
            || self.connect_timeout_millis == 0
            || self.connect_timeout_millis > 5_000
            || self.io_timeout_millis == 0
            || self.io_timeout_millis > 30_000
            || !self.socket_path.is_absolute()
            || self.socket_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir
                        | std::path::Component::ParentDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(UnixRunnerConnectorError::InvalidConfig);
        }
        Ok(())
    }
}

/// Sanitized production runner transport failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UnixRunnerConnectorError {
    #[error("runner connector configuration is invalid")]
    InvalidConfig,
    #[error("runner control socket is unavailable")]
    Unavailable,
    #[error("runner control socket metadata is invalid")]
    WrongSocket,
    #[error("runner service identity is invalid")]
    WrongPeer,
    #[error("runner connection timed out")]
    Timeout,
    #[error("runner returned an invalid response frame")]
    InvalidResponse,
}

/// Per-attempt connection factory for the dedicated runner-control socket.
#[derive(Clone, Debug)]
pub struct UnixRunnerConnector {
    config: UnixRunnerConnectorConfig,
}

impl UnixRunnerConnector {
    pub fn new(config: UnixRunnerConnectorConfig) -> Result<Self, UnixRunnerConnectorError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Send one immutable v2 frame, close the write half, and read one exact
    /// operation-specific response. Every retry reuses the same bytes.
    #[cfg(target_os = "linux")]
    pub fn exchange_v2_frame(
        &mut self,
        frame: &[u8],
        response_length: usize,
        transport_attempts: u32,
    ) -> Result<Vec<u8>, UnixRunnerConnectorError> {
        use std::net::Shutdown;

        if frame.is_empty()
            || frame.len() > buzz_ci_broker_protocol::v2::MAX_FRAME_SIZE
            || response_length == 0
            || response_length > buzz_ci_broker_protocol::v2::MAX_FRAME_SIZE
            || !(1..=8).contains(&transport_attempts)
        {
            return Err(UnixRunnerConnectorError::InvalidConfig);
        }
        for attempt in 1..=transport_attempts {
            let result = (|| {
                let mut stream = self.connect()?;
                stream
                    .write_all(frame)
                    .and_then(|()| stream.flush())
                    .and_then(|()| stream.shutdown(Shutdown::Write))
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::TimedOut {
                            UnixRunnerConnectorError::Timeout
                        } else {
                            UnixRunnerConnectorError::Unavailable
                        }
                    })?;
                let mut response = Vec::with_capacity(response_length);
                stream
                    .take(response_length as u64 + 1)
                    .read_to_end(&mut response)
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::TimedOut {
                            UnixRunnerConnectorError::Timeout
                        } else {
                            UnixRunnerConnectorError::Unavailable
                        }
                    })?;
                if response.len() != response_length {
                    return Err(UnixRunnerConnectorError::InvalidResponse);
                }
                Ok(response)
            })();
            match result {
                Err(UnixRunnerConnectorError::Unavailable | UnixRunnerConnectorError::Timeout)
                    if attempt < transport_attempts => {}
                other => return other,
            }
        }
        Err(UnixRunnerConnectorError::Unavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn exchange_v2_frame(
        &mut self,
        _frame: &[u8],
        _response_length: usize,
        _transport_attempts: u32,
    ) -> Result<Vec<u8>, UnixRunnerConnectorError> {
        Err(UnixRunnerConnectorError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
impl RunnerConnector for UnixRunnerConnector {
    type Connection = UnixStream;
    type Error = UnixRunnerConnectorError;

    fn connect(&mut self) -> Result<Self::Connection, Self::Error> {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        use nix::unistd::getegid;

        let metadata = std::fs::symlink_metadata(&self.config.socket_path)
            .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o7777 != 0o620
            || metadata.uid() != self.config.runner_uid
            || metadata.gid() != getegid().as_raw()
        {
            return Err(UnixRunnerConnectorError::WrongSocket);
        }
        let stream = connect_unix_with_timeout(
            &self.config.socket_path,
            Duration::from_millis(self.config.connect_timeout_millis),
        )?;
        let peer = getsockopt(&stream, PeerCredentials)
            .map_err(|_| UnixRunnerConnectorError::WrongPeer)?;
        if !runner_listener_accepted(peer.pid(), peer.uid(), peer.gid(), &self.config) {
            return Err(UnixRunnerConnectorError::WrongPeer);
        }
        let timeout = Duration::from_millis(self.config.io_timeout_millis);
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
        Ok(stream)
    }
}

#[cfg(not(target_os = "linux"))]
impl RunnerConnector for UnixRunnerConnector {
    type Connection = std::io::Cursor<Vec<u8>>;
    type Error = UnixRunnerConnectorError;

    fn connect(&mut self) -> Result<Self::Connection, Self::Error> {
        Err(UnixRunnerConnectorError::Unavailable)
    }
}

/// `SO_PEERCRED` names the process that called `listen()`. Production binds
/// `/run/buzzci/runner-control.sock` through `buzz-ci-runner.socket`, so the
/// kernel reports pid 1 root while `buzz-ci-runner.service` accepts as its own
/// account. The shared acceptance-driver rule accepts exactly that listener or
/// the runner account; the inode check in `connect` has already proven the
/// socket is the runner's (owner uid, controld's group, mode `0620`).
#[cfg(target_os = "linux")]
fn runner_listener_accepted(
    pid: i32,
    uid: u32,
    gid: u32,
    config: &UnixRunnerConnectorConfig,
) -> bool {
    use buzz_ci_acceptance_ctl::production::{listener_peer_accepted, ListenerPeer};

    listener_peer_accepted(
        ListenerPeer { pid, uid, gid },
        config.runner_uid,
        config.runner_gid,
    )
}

#[cfg(target_os = "linux")]
fn connect_unix_with_timeout(
    path: &std::path::Path,
    timeout: Duration,
) -> Result<UnixStream, UnixRunnerConnectorError> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag, SockType,
        UnixAddr,
    };
    use std::os::fd::{AsFd, AsRawFd};

    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    let address = UnixAddr::new(path).map_err(|_| UnixRunnerConnectorError::InvalidConfig)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {
            let mut poll_descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            let timeout = PollTimeout::try_from(timeout)
                .map_err(|_| UnixRunnerConnectorError::InvalidConfig)?;
            if poll(&mut poll_descriptors, timeout)
                .map_err(|_| UnixRunnerConnectorError::Unavailable)?
                == 0
            {
                return Err(UnixRunnerConnectorError::Timeout);
            }
            let socket_error = getsockopt(&descriptor, SocketError)
                .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
            if socket_error != 0 {
                return Err(UnixRunnerConnectorError::Unavailable);
            }
        }
        Err(_) => return Err(UnixRunnerConnectorError::Unavailable),
    }
    let current =
        fcntl(&descriptor, FcntlArg::F_GETFL).map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    let mut flags = OFlag::from_bits_truncate(current);
    flags.remove(OFlag::O_NONBLOCK);
    fcntl(&descriptor, FcntlArg::F_SETFL(flags))
        .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    Ok(UnixStream::from(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn listener_rule_accepts_the_socket_unit_or_the_runner_and_rejects_the_rest() {
        let config = UnixRunnerConnectorConfig {
            socket_path: PathBuf::from("/run/buzzci/runner-control.sock"),
            runner_uid: 1200,
            runner_gid: 1200,
            connect_timeout_millis: 100,
            io_timeout_millis: 100,
        };
        assert!(runner_listener_accepted(1, 0, 0, &config));
        assert!(runner_listener_accepted(4242, 1200, 1200, &config));
        for (pid, uid, gid) in [
            (4242, 0, 0),
            (0, 0, 0),
            (-1, 0, 0),
            (1, 1200, 0),
            (1, 0, 1200),
            (4242, 1200, 1201),
            (4242, 1201, 1200),
            (4242, 1204, 1204),
        ] {
            assert!(
                !runner_listener_accepted(pid, uid, gid, &config),
                "{pid} {uid}:{gid}"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn connect_authenticates_a_listener_the_runner_account_bound_and_rejects_a_foreign_inode() {
        use std::os::unix::net::UnixListener;

        use nix::unistd::{getegid, geteuid};

        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("runner-control.sock");
        let listener = UnixListener::bind(&path).expect("bind runner test socket");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620))
            .expect("socket mode");
        let config = UnixRunnerConnectorConfig {
            socket_path: path.clone(),
            runner_uid: geteuid().as_raw(),
            runner_gid: getegid().as_raw(),
            connect_timeout_millis: 500,
            io_timeout_millis: 500,
        };
        let mut connector = UnixRunnerConnector::new(config.clone()).expect("connector");
        let stream = connector.connect().expect("own listener is accepted");
        drop(stream);
        let (accepted, _) = listener.accept().expect("connection reached the listener");
        drop(accepted);

        // An inode owned by another account is rejected before connecting.
        let foreign = UnixRunnerConnector::new(UnixRunnerConnectorConfig {
            runner_uid: geteuid().as_raw().wrapping_add(1),
            ..config
        })
        .expect("connector")
        .connect()
        .err();
        assert_eq!(foreign, Some(UnixRunnerConnectorError::WrongSocket));
    }
}
