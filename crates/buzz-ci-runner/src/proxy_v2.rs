//! Capacity-one, transport-only broker-v2 proxy.
//!
//! The proxy accepts canonical broker-v2 frames from the configured controld
//! peer, pins admissions to root-authored static lane coordinates, forwards the
//! exact frame to root execd, and returns the exact execd response. It has no
//! job execution or evidence API.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::v2::{self, BrokerResponse, FrameHeader, Request};
use buzz_ci_broker_protocol::{ResponseCode, HEADER_SIZE};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{validate_private_directory, RunnerConfig, RunnerMode};

const REPLAY_SCHEMA_VERSION: u16 = 1;
const MAX_REPLAY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPLAY_ENTRIES: usize = 4096;
const RESPONSE_FRAME_SIZE: usize = HEADER_SIZE + v2::RESPONSE_BODY_SIZE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySettings {
    pub controld_uid: u32,
    pub controld_gid: u32,
    pub execd_socket: PathBuf,
    pub execd_uid: u32,
    pub execd_gid: u32,
    pub replay_journal: PathBuf,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub transport_attempts: u8,
    pub retry_delay: Duration,
    lane_manifest_digest: [u8; 32],
    lane_epoch: u64,
    admission_key_generation: u64,
    isolation_profile_digest: [u8; 32],
    audience_digest: [u8; 32],
}

impl ProxySettings {
    pub fn from_config(config: &RunnerConfig) -> Option<Self> {
        let RunnerMode::V2Proxy {
            execd_socket,
            execd_uid,
            execd_gid,
            replay_journal,
            connect_timeout_millis,
            io_timeout_millis,
            transport_attempts,
            retry_delay_millis,
            lane_manifest_digest,
            lane_epoch,
            admission_key_generation,
            isolation_profile_digest,
            audience_digest,
        } = &config.mode
        else {
            return None;
        };
        Some(Self {
            controld_uid: config.controld_uid,
            controld_gid: config.controld_gid,
            execd_socket: execd_socket.clone(),
            execd_uid: *execd_uid,
            execd_gid: *execd_gid,
            replay_journal: replay_journal.clone(),
            connect_timeout: Duration::from_millis(*connect_timeout_millis),
            io_timeout: Duration::from_millis(*io_timeout_millis),
            transport_attempts: *transport_attempts,
            retry_delay: Duration::from_millis(*retry_delay_millis),
            lane_manifest_digest: decode_digest(lane_manifest_digest)?,
            lane_epoch: *lane_epoch,
            admission_key_generation: *admission_key_generation,
            isolation_profile_digest: decode_digest(isolation_profile_digest)?,
            audience_digest: decode_digest(audience_digest)?,
        })
    }
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("runner control peer identity was refused")]
    UnauthorizedControlPeer,
    #[error("runner control frame was refused")]
    InvalidControlFrame,
    #[error("runner v2 request does not match static activation coordinates")]
    InvalidActivationCoordinates,
    #[error("runner replay identifier was reused for different bytes")]
    ReplayConflict,
    #[error("runner durable replay map is unavailable")]
    ReplayUnavailable,
    #[error("execd transport failed or timed out")]
    ExecdUnavailable,
    #[error("execd peer identity was refused")]
    UnauthorizedExecdPeer,
    #[error("execd response was not bound to the exact request")]
    InvalidExecdResponse,
    #[error("runner control response write failed")]
    ResponseWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayDocument {
    schema_version: u16,
    entries: BTreeMap<String, ReplayEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayEntry {
    request_digest: String,
    response_frame: Option<String>,
}

pub struct DurableReplayMap {
    path: PathBuf,
    document: ReplayDocument,
}

enum ReplayDecision {
    Forward,
    Cached(Vec<u8>),
}

impl DurableReplayMap {
    pub fn open(path: PathBuf) -> Result<Self, ProxyError> {
        let parent = path.parent().ok_or(ProxyError::ReplayUnavailable)?;
        validate_private_directory(parent).map_err(|()| ProxyError::ReplayUnavailable)?;
        let document = if path.exists() {
            read_replay_document(&path)?
        } else {
            ReplayDocument {
                schema_version: REPLAY_SCHEMA_VERSION,
                entries: BTreeMap::new(),
            }
        };
        let replay = Self { path, document };
        if !replay.path.exists() {
            replay.persist()?;
        }
        Ok(replay)
    }

    fn reserve(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<ReplayDecision, ProxyError> {
        let key = hex::encode(request_id);
        let digest = hex::encode(request_digest);
        if let Some(entry) = self.document.entries.get(&key) {
            if entry.request_digest != digest {
                return Err(ProxyError::ReplayConflict);
            }
            return match &entry.response_frame {
                Some(response) => hex::decode(response)
                    .map(ReplayDecision::Cached)
                    .map_err(|_| ProxyError::ReplayUnavailable),
                None => Ok(ReplayDecision::Forward),
            };
        }
        if self.document.entries.len() >= MAX_REPLAY_ENTRIES {
            return Err(ProxyError::ReplayUnavailable);
        }
        self.document.entries.insert(
            key,
            ReplayEntry {
                request_digest: digest,
                response_frame: None,
            },
        );
        self.persist()?;
        Ok(ReplayDecision::Forward)
    }

    fn complete(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        response: &[u8],
    ) -> Result<(), ProxyError> {
        let entry = self
            .document
            .entries
            .get_mut(&hex::encode(request_id))
            .ok_or(ProxyError::ReplayUnavailable)?;
        if entry.request_digest != hex::encode(request_digest) {
            return Err(ProxyError::ReplayConflict);
        }
        let encoded = hex::encode(response);
        if entry
            .response_frame
            .as_ref()
            .is_some_and(|old| old != &encoded)
        {
            return Err(ProxyError::ReplayConflict);
        }
        entry.response_frame = Some(encoded);
        self.persist()
    }

    fn persist(&self) -> Result<(), ProxyError> {
        let bytes =
            serde_json::to_vec(&self.document).map_err(|_| ProxyError::ReplayUnavailable)?;
        if bytes.len() as u64 > MAX_REPLAY_BYTES {
            return Err(ProxyError::ReplayUnavailable);
        }
        let parent = self.path.parent().ok_or(ProxyError::ReplayUnavailable)?;
        let name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ProxyError::ReplayUnavailable)?;
        let temporary = parent.join(format!(".{name}.{}.new", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| ProxyError::ReplayUnavailable)?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProxyError::ReplayUnavailable)?;
            std::fs::rename(&temporary, &self.path).map_err(|_| ProxyError::ReplayUnavailable)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ProxyError::ReplayUnavailable)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn read_replay_document(path: &Path) -> Result<ReplayDocument, ProxyError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ProxyError::ReplayUnavailable)?;
    let metadata = file.metadata().map_err(|_| ProxyError::ReplayUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_REPLAY_BYTES
    {
        return Err(ProxyError::ReplayUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPLAY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProxyError::ReplayUnavailable)?;
    let document: ReplayDocument =
        serde_json::from_slice(&bytes).map_err(|_| ProxyError::ReplayUnavailable)?;
    if document.schema_version != REPLAY_SCHEMA_VERSION
        || document.entries.len() > MAX_REPLAY_ENTRIES
        || serde_json::to_vec(&document).map_err(|_| ProxyError::ReplayUnavailable)? != bytes
        || document.entries.iter().any(|(request_id, entry)| {
            decode_exact::<16>(request_id).is_none()
                || decode_exact::<32>(&entry.request_digest).is_none()
                || entry.response_frame.as_ref().is_some_and(|response| {
                    hex::decode(response)
                        .map(|value| value.len() != RESPONSE_FRAME_SIZE)
                        .unwrap_or(true)
                })
        })
    {
        return Err(ProxyError::ReplayUnavailable);
    }
    Ok(document)
}

pub struct ConnectedExecd {
    stream: UnixStream,
    peer_uid: u32,
    peer_gid: u32,
}

pub trait ExecdConnector {
    fn connect(&mut self, path: &Path, timeout: Duration) -> io::Result<ConnectedExecd>;
}

pub struct UnixExecdConnector;

impl ExecdConnector for UnixExecdConnector {
    fn connect(&mut self, path: &Path, timeout: Duration) -> io::Result<ConnectedExecd> {
        let stream = connect_with_timeout(path, timeout)?;
        let credentials = getsockopt(&stream, PeerCredentials).map_err(io::Error::from)?;
        Ok(ConnectedExecd {
            stream,
            peer_uid: credentials.uid(),
            peer_gid: credentials.gid(),
        })
    }
}

pub struct RunnerV2Proxy<C = UnixExecdConnector> {
    settings: ProxySettings,
    replay: DurableReplayMap,
    connector: C,
}

impl RunnerV2Proxy<UnixExecdConnector> {
    pub fn open(config: &RunnerConfig) -> Result<Self, ProxyError> {
        let settings = ProxySettings::from_config(config).ok_or(ProxyError::ReplayUnavailable)?;
        let replay = DurableReplayMap::open(settings.replay_journal.clone())?;
        Ok(Self {
            settings,
            replay,
            connector: UnixExecdConnector,
        })
    }
}

impl<C: ExecdConnector> RunnerV2Proxy<C> {
    #[cfg(test)]
    fn with_connector(settings: ProxySettings, connector: C) -> Result<Self, ProxyError> {
        let replay = DurableReplayMap::open(settings.replay_journal.clone())?;
        Ok(Self {
            settings,
            replay,
            connector,
        })
    }

    pub fn serve(&mut self, mut control: UnixStream) -> Result<(), ProxyError> {
        let credentials = getsockopt(&control, PeerCredentials)
            .map_err(|_| ProxyError::UnauthorizedControlPeer)?;
        self.serve_authenticated(&mut control, credentials.uid(), credentials.gid())
    }

    fn serve_authenticated(
        &mut self,
        control: &mut UnixStream,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Result<(), ProxyError> {
        if peer_uid != self.settings.controld_uid || peer_gid != self.settings.controld_gid {
            return Err(ProxyError::UnauthorizedControlPeer);
        }
        control
            .set_read_timeout(Some(self.settings.io_timeout))
            .and_then(|()| control.set_write_timeout(Some(self.settings.io_timeout)))
            .map_err(|_| ProxyError::InvalidControlFrame)?;
        let frame = read_v2_request(control)?;
        let (header, request) =
            v2::decode_request(&frame).map_err(|_| ProxyError::InvalidControlFrame)?;
        if header.request_id == [0; 16] {
            return Err(ProxyError::InvalidControlFrame);
        }
        validate_request(&self.settings, request, unix_now()?)?;
        let request_digest: [u8; 32] = Sha256::digest(&frame).into();
        let response = match self.replay.reserve(header.request_id, request_digest)? {
            ReplayDecision::Cached(response) => response,
            ReplayDecision::Forward => {
                let response = self.forward(header, request, &frame)?;
                self.replay
                    .complete(header.request_id, request_digest, &response)?;
                response
            }
        };
        control
            .write_all(&response)
            .and_then(|()| control.flush())
            .map_err(|_| ProxyError::ResponseWrite)
    }

    fn forward(
        &mut self,
        header: FrameHeader,
        request: Request,
        frame: &[u8],
    ) -> Result<Vec<u8>, ProxyError> {
        for attempt in 0..self.settings.transport_attempts {
            let result = self.forward_once(header, request, frame);
            match result {
                Ok(response) => return Ok(response),
                Err(ProxyError::UnauthorizedExecdPeer | ProxyError::InvalidExecdResponse) => {
                    return result
                }
                Err(_) if attempt + 1 < self.settings.transport_attempts => {
                    if !self.settings.retry_delay.is_zero() {
                        thread::sleep(self.settings.retry_delay);
                    }
                }
                Err(_) => return Err(ProxyError::ExecdUnavailable),
            }
        }
        Err(ProxyError::ExecdUnavailable)
    }

    fn forward_once(
        &mut self,
        header: FrameHeader,
        request: Request,
        frame: &[u8],
    ) -> Result<Vec<u8>, ProxyError> {
        let mut connected = self
            .connector
            .connect(&self.settings.execd_socket, self.settings.connect_timeout)
            .map_err(|_| ProxyError::ExecdUnavailable)?;
        if connected.peer_uid != self.settings.execd_uid
            || connected.peer_gid != self.settings.execd_gid
        {
            return Err(ProxyError::UnauthorizedExecdPeer);
        }
        connected
            .stream
            .set_read_timeout(Some(self.settings.io_timeout))
            .and_then(|()| {
                connected
                    .stream
                    .set_write_timeout(Some(self.settings.io_timeout))
            })
            .map_err(|_| ProxyError::ExecdUnavailable)?;
        connected
            .stream
            .write_all(frame)
            .and_then(|()| connected.stream.flush())
            .and_then(|()| connected.stream.shutdown(Shutdown::Write))
            .map_err(|_| ProxyError::ExecdUnavailable)?;
        let mut response = vec![0; RESPONSE_FRAME_SIZE];
        connected
            .stream
            .read_exact(&mut response)
            .map_err(|_| ProxyError::ExecdUnavailable)?;
        let mut trailing = [0_u8; 1];
        if connected
            .stream
            .read(&mut trailing)
            .map_err(|_| ProxyError::ExecdUnavailable)?
            != 0
        {
            return Err(ProxyError::InvalidExecdResponse);
        }
        let decoded =
            v2::decode_response(header, &response).map_err(|_| ProxyError::InvalidExecdResponse)?;
        validate_response(request, decoded)?;
        Ok(response)
    }
}

fn read_v2_request(stream: &mut UnixStream) -> Result<Vec<u8>, ProxyError> {
    let mut header = [0_u8; HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .map_err(|_| ProxyError::InvalidControlFrame)?;
    let (_, body_length) =
        v2::decode_request_header(&header).map_err(|_| ProxyError::InvalidControlFrame)?;
    let mut frame = Vec::with_capacity(HEADER_SIZE + body_length);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_SIZE + body_length, 0);
    stream
        .read_exact(&mut frame[HEADER_SIZE..])
        .map_err(|_| ProxyError::InvalidControlFrame)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .map_err(|_| ProxyError::InvalidControlFrame)?
        != 0
    {
        return Err(ProxyError::InvalidControlFrame);
    }
    Ok(frame)
}

fn validate_request(
    settings: &ProxySettings,
    request: Request,
    now: u64,
) -> Result<(), ProxyError> {
    match request {
        Request::AdmitAttempt(request) => {
            if request.audience_digest != settings.audience_digest
                || request.isolation_profile_digest != settings.isolation_profile_digest
                || request.lane_manifest_digest != settings.lane_manifest_digest
                || request.lane_epoch != settings.lane_epoch
                || request.admission_key_generation != settings.admission_key_generation
                || request.signed_request_digest == [0; 32]
                || request.job_intent_digest == [0; 32]
                || request.admission_signature == [0; 64]
                || request.run_id == [0; 16]
                || request.issued_at == 0
                || request.issued_at > now
                || now >= request.expires_at
                || request.wall_timeout_seconds == 0
                || request.attempt == 0
                || (request.attempt == 1 && request.parent_attempt != 0)
                || (request.attempt > 1
                    && request.parent_attempt.checked_add(1) != Some(request.attempt))
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::GetAttempt(request) => {
            if request.attempt_id == [0; 16] || request.execution_binding_digest == [0; 32] {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::Hello(_)
        | Request::CancelAttempt(_)
        | Request::AdmitQualification(_)
        | Request::CompleteAttempt(_) => return Err(ProxyError::InvalidActivationCoordinates),
    }
    Ok(())
}

fn validate_response(request: Request, response: BrokerResponse) -> Result<(), ProxyError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing) {
        return Ok(());
    }
    if response.execution_binding_digest == [0; 32]
        || response.generation == 0
        || response.accepted_at == 0
        || response.updated_at < response.accepted_at
        || response.lease_generation == 0
    {
        return Err(ProxyError::InvalidExecdResponse);
    }
    let bound = match request {
        Request::AdmitAttempt(request) => {
            response.run_id == request.run_id
                && response.accepted_request_digest == request.signed_request_digest
                && response.job_intent_digest == request.job_intent_digest
                && response.tip_oid == Some(request.tip_oid)
                && response.attempt == request.attempt
        }
        Request::GetAttempt(request) => {
            response.attempt_id == request.attempt_id
                && response.execution_binding_digest == request.execution_binding_digest
        }
        Request::Hello(_)
        | Request::CancelAttempt(_)
        | Request::AdmitQualification(_)
        | Request::CompleteAttempt(_) => false,
    };
    bound.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

#[cfg(target_os = "linux")]
fn connect_with_timeout(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::os::fd::{AsFd, AsRawFd};

    use nix::errno::Errno;
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag, SockType,
        UnixAddr,
    };

    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(io::Error::from)?;
    let address = UnixAddr::new(path).map_err(io::Error::from)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS) => {
            let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            let timeout = PollTimeout::try_from(timeout)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid timeout"))?;
            if poll(&mut descriptors, timeout).map_err(io::Error::from)? == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
            let socket_error = getsockopt(&descriptor, SocketError).map_err(io::Error::from)?;
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
        }
        Err(error) => return Err(io::Error::from(error)),
    }
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_with_timeout(_path: &Path, _timeout: Duration) -> io::Result<UnixStream> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux only"))
}

fn unix_now() -> Result<u64, ProxyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProxyError::InvalidActivationCoordinates)
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    decode_exact(value)
}

fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    hex::decode(value).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use buzz_ci_broker_protocol::v2::AdmissionSignatureAlgorithm;
    use buzz_ci_broker_protocol::{BrokerState, Conclusion, GitOid, Operation, TrustClass};
    use tempfile::{tempdir, TempDir};

    use super::*;

    struct FakeConnector {
        connections: VecDeque<io::Result<ConnectedExecd>>,
        calls: Arc<AtomicUsize>,
    }

    impl ExecdConnector for FakeConnector {
        fn connect(&mut self, _path: &Path, _timeout: Duration) -> io::Result<ConnectedExecd> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.connections.pop_front().unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no fake connection",
                ))
            })
        }
    }

    fn private_directory() -> TempDir {
        let directory = tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        directory
    }

    fn settings(directory: &Path) -> ProxySettings {
        let uid = nix::unistd::Uid::effective().as_raw();
        let gid = nix::unistd::Gid::effective().as_raw();
        ProxySettings {
            controld_uid: uid,
            controld_gid: gid,
            execd_socket: "/fake/execd.sock".into(),
            execd_uid: uid,
            execd_gid: gid,
            replay_journal: directory.join("replay.json"),
            connect_timeout: Duration::from_millis(10),
            io_timeout: Duration::from_millis(100),
            transport_attempts: 2,
            retry_delay: Duration::ZERO,
            lane_manifest_digest: [9; 32],
            lane_epoch: 4,
            admission_key_generation: 9,
            isolation_profile_digest: [8; 32],
            audience_digest: [3; 32],
        }
    }

    fn admission(now: u64) -> v2::AdmitAttemptRequest {
        v2::AdmitAttemptRequest {
            signed_request_digest: [1; 32],
            actor_pubkey: [2; 32],
            audience_digest: [3; 32],
            idempotency_digest: [4; 32],
            source_pin_event_id: [5; 32],
            workflow_digest: [6; 32],
            job_intent_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            lane_manifest_digest: [9; 32],
            admission_signature: [10; 64],
            run_id: [11; 16],
            tip_oid: GitOid::Sha256([12; 32]),
            base_oid: GitOid::Sha256([13; 32]),
            issued_at: now.saturating_sub(1),
            expires_at: now + 60,
            lane_epoch: 4,
            admission_key_generation: 9,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
        }
    }

    fn response(request: v2::AdmitAttemptRequest) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: [14; 16],
            run_id: request.run_id,
            accepted_request_digest: request.signed_request_digest,
            job_intent_digest: request.job_intent_digest,
            execution_binding_digest: [15; 32],
            tip_oid: Some(request.tip_oid),
            broker_state: BrokerState::Leased,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: 2,
            accepted_at: request.issued_at + 1,
            updated_at: request.issued_at + 1,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: request.attempt,
        }
    }

    fn request_frame(request_id: [u8; 16], request: v2::AdmitAttemptRequest) -> Vec<u8> {
        v2::encode_request(request_id, Request::AdmitAttempt(request))
            .as_bytes()
            .to_vec()
    }

    fn fake_execd(
        expected_request: Vec<u8>,
        response: Vec<u8>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> ConnectedExecd {
        let (client, mut server) = UnixStream::pair().expect("socket pair");
        std::thread::spawn(move || {
            let mut observed = Vec::new();
            server.read_to_end(&mut observed).expect("read request");
            assert_eq!(observed, expected_request);
            server.write_all(&response).expect("write response");
            server.shutdown(Shutdown::Write).expect("close response");
        });
        client.set_nonblocking(false).expect("blocking fake client");
        ConnectedExecd {
            stream: client,
            peer_uid,
            peer_gid,
        }
    }

    fn exchange<C: ExecdConnector>(
        proxy: &mut RunnerV2Proxy<C>,
        frame: &[u8],
    ) -> Result<Vec<u8>, ProxyError> {
        let (mut client, mut server) = UnixStream::pair().expect("control pair");
        client.write_all(frame).expect("write control request");
        client.shutdown(Shutdown::Write).expect("finish request");
        proxy.serve_authenticated(
            &mut server,
            proxy.settings.controld_uid,
            proxy.settings.controld_gid,
        )?;
        server.shutdown(Shutdown::Write).expect("finish response");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        Ok(response)
    }

    #[test]
    fn restart_replays_cached_exact_response_without_second_execd_call() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let now = unix_now().expect("clock");
        let request = admission(now);
        let header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [21; 16],
        };
        let frame = request_frame(header.request_id, request);
        let response = v2::encode_response(header, response(request))
            .as_bytes()
            .to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let connected = fake_execd(
            frame.clone(),
            response.clone(),
            settings.execd_uid,
            settings.execd_gid,
        );
        let mut first = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::from([Ok(connected)]),
                calls: Arc::clone(&calls),
            },
        )
        .expect("first proxy");
        assert_eq!(
            exchange(&mut first, &frame).expect("first exchange"),
            response
        );
        drop(first);

        let mut restarted = RunnerV2Proxy::with_connector(
            settings,
            FakeConnector {
                connections: VecDeque::new(),
                calls: Arc::clone(&calls),
            },
        )
        .expect("restart proxy");
        assert_eq!(
            exchange(&mut restarted, &frame).expect("cached exchange"),
            response
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replay_id_with_wrong_request_digest_is_rejected_durably() {
        let directory = private_directory();
        let path = directory.path().join("replay.json");
        let mut replay = DurableReplayMap::open(path.clone()).expect("open replay");
        assert!(matches!(
            replay.reserve([1; 16], [2; 32]),
            Ok(ReplayDecision::Forward)
        ));
        drop(replay);
        let mut restarted = DurableReplayMap::open(path).expect("restart replay");
        assert!(matches!(
            restarted.reserve([1; 16], [3; 32]),
            Err(ProxyError::ReplayConflict)
        ));
    }

    #[test]
    fn wrong_control_and_execd_peer_pairs_fail_closed() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut proxy = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::new(),
                calls,
            },
        )
        .expect("proxy");
        let (_client, mut server) = UnixStream::pair().expect("pair");
        assert!(matches!(
            proxy.serve_authenticated(
                &mut server,
                settings.controld_uid,
                settings.controld_gid.saturating_add(1)
            ),
            Err(ProxyError::UnauthorizedControlPeer)
        ));

        let now = unix_now().expect("clock");
        let request = admission(now);
        let header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [22; 16],
        };
        let frame = request_frame(header.request_id, request);
        let response = v2::encode_response(header, response(request))
            .as_bytes()
            .to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let wrong = fake_execd(
            frame.clone(),
            response,
            settings.execd_uid.saturating_add(1),
            settings.execd_gid,
        );
        let mut proxy = RunnerV2Proxy::with_connector(
            ProxySettings {
                replay_journal: directory.path().join("wrong-execd.json"),
                ..settings
            },
            FakeConnector {
                connections: VecDeque::from([Ok(wrong)]),
                calls,
            },
        )
        .expect("proxy");
        assert!(matches!(
            exchange(&mut proxy, &frame),
            Err(ProxyError::UnauthorizedExecdPeer)
        ));
    }

    #[test]
    fn connect_timeouts_stop_at_configured_attempt_bound() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let failures = (0..settings.transport_attempts)
            .map(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")))
            .collect();
        let mut proxy = RunnerV2Proxy::with_connector(
            settings,
            FakeConnector {
                connections: failures,
                calls: Arc::clone(&calls),
            },
        )
        .expect("proxy");
        let now = unix_now().expect("clock");
        let frame = request_frame([23; 16], admission(now));
        assert!(matches!(
            exchange(&mut proxy, &frame),
            Err(ProxyError::ExecdUnavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
