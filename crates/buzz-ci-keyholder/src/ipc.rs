use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::{env, os::fd::AsRawFd, path::Path, process};

#[cfg(target_os = "linux")]
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
#[cfg(target_os = "linux")]
use nix::sys::socket::{
    getsockname, getsockopt, sockopt::AcceptConn, sockopt::PeerCredentials, sockopt::SockType,
    SockType as NixSockType, UnixAddr,
};
use thiserror::Error;

use crate::{
    decode_request, encode_response, FrameHeader, PeerIdentity, ProductionKeyholder, Request,
    SigningBackend, HEADER_SIZE, MAX_BODY_SIZE,
};

/// Sole inherited systemd descriptor.
pub const SYSTEMD_LISTEN_FD: i32 = 3;
/// Exact systemd descriptor name.
pub const SYSTEMD_FD_NAME: &str = "buzz-ci-keyholder-control";
/// Fixed keyholder control socket.
pub const KEYHOLDER_SOCKET_PATH: &str = "/run/buzzci/keyholder.sock";
/// Per-connection read and write deadline.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Socket-activation validation failure.
#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum ActivationError {
    /// The inherited descriptor environment is not exact.
    #[error("invalid systemd socket activation: {0}")]
    Invalid(&'static str),
    /// Descriptor inspection failed.
    #[error("systemd listener inspection failed")]
    Inspect(#[source] io::Error),
}

/// One connection failure. No variant contains request or secret bytes.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// The operating-system peer does not match the configured identity.
    #[error("keyholder peer is unauthorized")]
    UnauthorizedPeer,
    /// Socket setup or transfer failed.
    #[error("keyholder socket operation failed")]
    Socket(#[source] io::Error),
    /// The bounded request frame was malformed.
    #[error("keyholder request frame was rejected")]
    Frame,
    /// The bounded response could not be encoded.
    #[error("keyholder response encoding failed")]
    Response,
}

/// Validate the exact systemd descriptor handoff before fd 3 is adopted.
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
            "LISTEN_FDNAMES does not identify the keyholder socket",
        ));
    }
    Ok(())
}

/// Verify fd type, listening state, fixed pathname, and close-on-exec state.
#[cfg(target_os = "linux")]
pub fn validate_systemd_listener(listener: UnixListener) -> Result<UnixListener, ActivationError> {
    validate_listener_path(listener, Path::new(KEYHOLDER_SOCKET_PATH))
}

#[cfg(target_os = "linux")]
fn validate_listener_path(
    listener: UnixListener,
    expected_path: &Path,
) -> Result<UnixListener, ActivationError> {
    if getsockopt(&listener, SockType).map_err(nix_io)? != NixSockType::Stream {
        return Err(ActivationError::Invalid("fd 3 is not a stream socket"));
    }
    if !getsockopt(&listener, AcceptConn).map_err(nix_io)? {
        return Err(ActivationError::Invalid("fd 3 is not listening"));
    }
    let address = getsockname::<UnixAddr>(listener.as_raw_fd()).map_err(nix_io)?;
    if address.path() != Some(expected_path) {
        return Err(ActivationError::Invalid(
            "fd 3 is not the fixed keyholder socket",
        ));
    }
    fcntl(&listener, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(nix_io)?;
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

/// Authenticate the peer before reading bytes, then process one bounded frame.
#[cfg(target_os = "linux")]
pub fn serve_connection<B: SigningBackend>(
    mut stream: UnixStream,
    service: &ProductionKeyholder<B>,
) -> Result<(), ConnectionError> {
    let credentials = getsockopt(&stream, PeerCredentials)
        .map_err(|error| ConnectionError::Socket(io::Error::from_raw_os_error(error as i32)))?;
    let expected_peer = service.peer_policy();
    if credentials.uid() != expected_peer.uid || credentials.gid() != expected_peer.gid {
        return Err(ConnectionError::UnauthorizedPeer);
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(ConnectionError::Socket)?;
    let (header, request) = read_request_frame(&mut stream)?;
    let response = service.handle(
        PeerIdentity {
            uid: credentials.uid(),
            gid: credentials.gid(),
        },
        request,
    );
    let encoded = encode_response(header, &response).map_err(|_| ConnectionError::Response)?;
    stream
        .write_all(encoded.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(ConnectionError::Socket)
}

/// Read exactly one frame while bounding allocation from the untrusted length field.
pub fn read_request_frame(
    reader: &mut impl Read,
) -> Result<(FrameHeader, Request), ConnectionError> {
    let mut header = [0_u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .map_err(|_| ConnectionError::Frame)?;
    let declared = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| ConnectionError::Frame)?,
    ) as usize;
    if declared > MAX_BODY_SIZE {
        return Err(ConnectionError::Frame);
    }
    let mut frame = Vec::with_capacity(HEADER_SIZE + declared);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_SIZE + declared, 0);
    reader
        .read_exact(&mut frame[HEADER_SIZE..])
        .map_err(|_| ConnectionError::Frame)?;
    decode_request(&frame).map_err(|_| ConnectionError::Frame)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        decode_response, encode_request, BackendError, DescribeRequest, OperationSet, PeerPolicy,
        PublicIdentity, SelectorSet, SigningPolicy,
    };

    struct FakeBackend([[u8; 32]; 3]);

    impl SigningBackend for FakeBackend {
        fn public_key(&self, selector: crate::KeySelector) -> Result<[u8; 32], BackendError> {
            Ok(self.0[match selector {
                crate::KeySelector::CiEvent => 0,
                crate::KeySelector::Nip98 => 1,
                crate::KeySelector::Manifest => 2,
            }])
        }

        fn sign_digest(
            &self,
            _: crate::KeySelector,
            _: [u8; 32],
        ) -> Result<[u8; 64], BackendError> {
            Ok([1_u8; 64])
        }
    }

    #[cfg(target_os = "linux")]
    fn current_peer_service() -> ProductionKeyholder<FakeBackend> {
        use nix::unistd::{getegid, geteuid};

        let keys = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];
        let selectors = SelectorSet::new(
            PublicIdentity {
                public_key: keys[0],
                generation: 1,
            },
            PublicIdentity {
                public_key: keys[1],
                generation: 1,
            },
            PublicIdentity {
                public_key: keys[2],
                generation: 1,
            },
        )
        .expect("selectors");
        let policy = SigningPolicy::new(
            PeerPolicy {
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
                allowed_operations: OperationSet::only(crate::Operation::Describe),
            },
            selectors,
            "https://relay.example.test".to_owned(),
        )
        .expect("policy");
        ProductionKeyholder::new(policy, FakeBackend(keys)).expect("service")
    }

    #[test]
    fn frame_reader_accepts_one_exact_frame_and_rejects_oversized_lengths() {
        let encoded =
            encode_request([1_u8; 16], &Request::Describe(DescribeRequest)).expect("request frame");
        let (header, request) =
            read_request_frame(&mut Cursor::new(encoded.as_bytes())).expect("read request");
        assert_eq!(header.request_id, [1_u8; 16]);
        assert_eq!(request, Request::Describe(DescribeRequest));

        let mut oversized = encoded.into_bytes();
        oversized[12..16].copy_from_slice(&((MAX_BODY_SIZE + 1) as u32).to_be_bytes());
        assert!(matches!(
            read_request_frame(&mut Cursor::new(oversized)),
            Err(ConnectionError::Frame)
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn listener_validation_requires_the_exact_path_and_sets_cloexec() {
        let directory = tempdir().expect("socket directory");
        let socket_path = directory.path().join("keyholder.sock");
        let listener = UnixListener::bind(&socket_path).expect("listener");
        let listener = validate_listener_path(listener, &socket_path).expect("valid listener");
        let flags = fcntl(&listener, FcntlArg::F_GETFD).expect("descriptor flags");
        assert_ne!(flags & FdFlag::FD_CLOEXEC.bits(), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn authenticated_socket_pair_serves_one_bound_frame() {
        let service = current_peer_service();
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let request =
            encode_request([9_u8; 16], &Request::Describe(DescribeRequest)).expect("request frame");
        client
            .write_all(request.as_bytes())
            .expect("write request frame");

        serve_connection(server, &service).expect("serve request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        assert!(matches!(
            decode_response(
                FrameHeader {
                    operation: crate::Operation::Describe,
                    request_id: [9_u8; 16],
                },
                &response
            ),
            Ok(crate::Response::Describe(_))
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn activation_environment_is_exact() {
        assert!(validate_systemd_environment_values(7, 7, 1, Some(SYSTEMD_FD_NAME)).is_ok());
        assert!(validate_systemd_environment_values(7, 8, 1, Some(SYSTEMD_FD_NAME)).is_err());
        assert!(validate_systemd_environment_values(7, 7, 2, Some(SYSTEMD_FD_NAME)).is_err());
        assert!(validate_systemd_environment_values(7, 7, 1, Some("wrong")).is_err());
    }
}
