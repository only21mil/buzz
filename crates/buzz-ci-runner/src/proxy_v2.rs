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
use std::time::Duration;

use buzz_ci_broker_protocol::v2::{self, BrokerResponse, FrameHeader, Request};
use buzz_ci_broker_protocol::{BrokerState, Conclusion, GitOid, ResponseCode, HEADER_SIZE};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{validate_private_directory, RunnerConfig, RunnerMode};

const REPLAY_SCHEMA_VERSION: u16 = 1;
const MAX_REPLAY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPLAY_ENTRIES: usize = 4096;
const INTENT_REGISTRATION_REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:broker-request-id:v2\0";

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
    /// The package's bound time reference. The lane's Run/Grant/Rerun/
    /// Tombstone fixture is frozen with this value, so request windows are
    /// judged against it rather than the wall clock.
    time_reference: u64,
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
            acceptance_time_reference,
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
            time_reference: *acceptance_time_reference,
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
    #[error(
        "runner v2 request was issued after the package time reference: issued_at {issued_at} > time_reference {reference}"
    )]
    IssuedAfterTimeReference { issued_at: u64, reference: u64 },
    #[error(
        "runner v2 request expired at the package time reference: expires_at {expires_at} <= time_reference {reference}"
    )]
    ExpiredAtTimeReference { expires_at: u64, reference: u64 },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admitted_binding: Option<AdmittedBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmittedBinding {
    attempt_id: String,
    execution_binding_digest: String,
    actor_pubkey: String,
    signed_request_digest: String,
    run_id: String,
    workflow_digest: String,
    job_intent_digest: String,
    tip_oid: String,
    attempt: u32,
    generation: u64,
    accepted_at: u64,
    lease_generation: u64,
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
                admitted_binding: None,
            },
        );
        self.persist()?;
        Ok(ReplayDecision::Forward)
    }

    fn cached_exact(
        &self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, ProxyError> {
        let Some(entry) = self.document.entries.get(&hex::encode(request_id)) else {
            return Ok(None);
        };
        if entry.request_digest != hex::encode(request_digest) {
            return Err(ProxyError::ReplayConflict);
        }
        entry
            .response_frame
            .as_ref()
            .map(|response| hex::decode(response).map_err(|_| ProxyError::ReplayUnavailable))
            .transpose()
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

    fn admitted_binding_for_cancel(
        &self,
        request: v2::CancelAttemptRequest,
    ) -> Result<AdmittedBinding, ProxyError> {
        let attempt_id = hex::encode(request.attempt_id);
        let mut found: Option<AdmittedBinding> = None;
        for candidate in self
            .document
            .entries
            .values()
            .filter_map(|entry| entry.admitted_binding.as_ref())
            .filter(|binding| binding.attempt_id == attempt_id)
        {
            if let Some(current) = found.as_mut() {
                if !current.same_identity(candidate) {
                    return Err(ProxyError::ReplayUnavailable);
                }
                current.generation = current.generation.max(candidate.generation);
            } else {
                found = Some(candidate.clone());
            }
        }
        let binding = found.ok_or(ProxyError::InvalidActivationCoordinates)?;
        if binding.execution_binding_digest != hex::encode(request.execution_binding_digest)
            || binding.actor_pubkey != hex::encode(request.actor_pubkey)
        {
            return Err(ProxyError::InvalidActivationCoordinates);
        }
        Ok(binding)
    }

    fn remember_admission(
        &mut self,
        request_id: [u8; 16],
        request: v2::AdmitAttemptRequest,
        response: BrokerResponse,
    ) -> Result<(), ProxyError> {
        let binding = AdmittedBinding::from_admission(request, response)?;
        let entry = self
            .document
            .entries
            .get_mut(&hex::encode(request_id))
            .ok_or(ProxyError::ReplayUnavailable)?;
        if entry.response_frame.is_none() {
            return Err(ProxyError::ReplayUnavailable);
        }
        if let Some(current) = entry.admitted_binding.as_ref() {
            return current
                .same_identity(&binding)
                .then_some(())
                .ok_or(ProxyError::ReplayConflict);
        }
        entry.admitted_binding = Some(binding);
        self.persist()
    }

    fn remember_cancelled(
        &mut self,
        admitted: &AdmittedBinding,
        response: BrokerResponse,
    ) -> Result<(), ProxyError> {
        let mut found = false;
        for binding in self
            .document
            .entries
            .values_mut()
            .filter_map(|entry| entry.admitted_binding.as_mut())
            .filter(|binding| binding.attempt_id == admitted.attempt_id)
        {
            if !binding.same_identity(admitted) {
                return Err(ProxyError::ReplayUnavailable);
            }
            binding.generation = response.generation;
            found = true;
        }
        if !found {
            return Err(ProxyError::ReplayUnavailable);
        }
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

impl AdmittedBinding {
    fn from_admission(
        request: v2::AdmitAttemptRequest,
        response: BrokerResponse,
    ) -> Result<Self, ProxyError> {
        let tip_oid = response.tip_oid.ok_or(ProxyError::InvalidExecdResponse)?;
        Ok(Self {
            attempt_id: hex::encode(response.attempt_id),
            execution_binding_digest: hex::encode(response.execution_binding_digest),
            actor_pubkey: hex::encode(request.actor_pubkey),
            signed_request_digest: hex::encode(request.signed_request_digest),
            run_id: hex::encode(request.run_id),
            workflow_digest: hex::encode(request.workflow_digest),
            job_intent_digest: hex::encode(request.job_intent_digest),
            tip_oid: encode_git_oid(tip_oid),
            attempt: request.attempt,
            generation: response.generation,
            accepted_at: response.accepted_at,
            lease_generation: response.lease_generation,
        })
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.execution_binding_digest == other.execution_binding_digest
            && self.actor_pubkey == other.actor_pubkey
            && self.signed_request_digest == other.signed_request_digest
            && self.run_id == other.run_id
            && self.workflow_digest == other.workflow_digest
            && self.job_intent_digest == other.job_intent_digest
            && self.tip_oid == other.tip_oid
            && self.attempt == other.attempt
            && self.accepted_at == other.accepted_at
            && self.lease_generation == other.lease_generation
    }

    fn is_valid(&self) -> bool {
        decode_nonzero::<16>(&self.attempt_id).is_some()
            && decode_nonzero::<32>(&self.execution_binding_digest).is_some()
            && decode_nonzero::<32>(&self.actor_pubkey).is_some()
            && decode_nonzero::<32>(&self.signed_request_digest).is_some()
            && decode_nonzero::<16>(&self.run_id).is_some()
            && decode_nonzero::<32>(&self.workflow_digest).is_some()
            && decode_nonzero::<32>(&self.job_intent_digest).is_some()
            && valid_git_oid(&self.tip_oid)
            && self.attempt != 0
            && self.generation != 0
            && self.accepted_at != 0
            && self.lease_generation != 0
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
                        .map(|value| value.len() < HEADER_SIZE || value.len() > v2::MAX_FRAME_SIZE)
                        .unwrap_or(true)
                })
                || entry
                    .admitted_binding
                    .as_ref()
                    .is_some_and(|binding| !binding.is_valid())
        })
        || !admitted_bindings_are_consistent(&document)
    {
        return Err(ProxyError::ReplayUnavailable);
    }
    Ok(document)
}

fn admitted_bindings_are_consistent(document: &ReplayDocument) -> bool {
    let mut observed: BTreeMap<&str, &AdmittedBinding> = BTreeMap::new();
    for binding in document
        .entries
        .values()
        .filter_map(|entry| entry.admitted_binding.as_ref())
    {
        if observed
            .get(binding.attempt_id.as_str())
            .is_some_and(|current| !current.same_identity(binding))
        {
            return false;
        }
        observed.insert(binding.attempt_id.as_str(), binding);
    }
    true
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
        validate_request(&self.settings, header, request)?;
        let admitted_binding = match request {
            Request::CancelAttempt(request) => {
                Some(self.replay.admitted_binding_for_cancel(request)?)
            }
            _ => None,
        };
        let request_digest: [u8; 32] = Sha256::digest(&frame).into();
        let stale_cancel = matches!(
            (request, admitted_binding.as_ref()),
            (Request::CancelAttempt(request), Some(binding))
                if request.expected_generation != binding.generation
        );
        // A bound state read is not a mutation: it is forwarded every time so
        // a poll observes the broker's current state. Journaling it would
        // replay the first observation (leased) for the attempt's whole life
        // and let the poll run out its deadline (H10 clean host, stage 6).
        let state_read = matches!(request, Request::GetAttempt(_));
        let decision = if state_read {
            ReplayDecision::Forward
        } else if stale_cancel {
            ReplayDecision::Cached(
                self.replay
                    .cached_exact(header.request_id, request_digest)?
                    .ok_or(ProxyError::InvalidActivationCoordinates)?,
            )
        } else {
            self.replay.reserve(header.request_id, request_digest)?
        };
        let response = match decision {
            ReplayDecision::Cached(response) => response,
            ReplayDecision::Forward => {
                let response = self.forward(header, request, &frame)?;
                if !state_read {
                    self.replay
                        .complete(header.request_id, request_digest, &response)?;
                }
                response
            }
        };
        validate_encoded_response(header, request, &response)?;
        match request {
            Request::AdmitAttempt(request) => {
                let decoded = v2::decode_response(header, &response)
                    .map_err(|_| ProxyError::InvalidExecdResponse)?;
                if matches!(decoded.code, ResponseCode::Ok | ResponseCode::Existing) {
                    self.replay
                        .remember_admission(header.request_id, request, decoded)?;
                }
            }
            Request::CancelAttempt(request) => {
                let decoded = v2::decode_response(header, &response)
                    .map_err(|_| ProxyError::InvalidExecdResponse)?;
                let admitted = admitted_binding
                    .as_ref()
                    .ok_or(ProxyError::InvalidActivationCoordinates)?;
                validate_cancelled_binding(request, decoded, admitted)?;
                self.replay.remember_cancelled(admitted, decoded)?;
            }
            _ => {}
        }
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
        let expected_body_length = response_body_length(request);
        let mut response_header = [0_u8; HEADER_SIZE];
        connected
            .stream
            .read_exact(&mut response_header)
            .map_err(|_| ProxyError::ExecdUnavailable)?;
        let declared_body_length = u32::from_be_bytes(
            response_header[12..16]
                .try_into()
                .map_err(|_| ProxyError::InvalidExecdResponse)?,
        ) as usize;
        if declared_body_length != expected_body_length {
            return Err(ProxyError::InvalidExecdResponse);
        }
        let mut response = Vec::with_capacity(HEADER_SIZE + expected_body_length);
        response.extend_from_slice(&response_header);
        response.resize(HEADER_SIZE + expected_body_length, 0);
        connected
            .stream
            .read_exact(&mut response[HEADER_SIZE..])
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
        validate_encoded_response(header, request, &response)?;
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
    header: FrameHeader,
    request: Request,
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
                || request.wall_timeout_seconds == 0
                || request.attempt == 0
                || (request.attempt == 1 && request.parent_attempt != 0)
                || (request.attempt > 1
                    && request.parent_attempt.checked_add(1) != Some(request.attempt))
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
            validate_window(
                request.issued_at,
                request.expires_at,
                settings.time_reference,
            )?;
        }
        Request::RegisterJobIntent(request) => {
            validate_admission(settings, request.admission)?;
            if header.request_id != intent_registration_request_id(request)
                || v2::intent_registration_request_frame_digest(header, &request)
                    != Some(request.request_frame_digest)
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::GetAttempt(request) => {
            if request.attempt_id == [0; 16] || request.execution_binding_digest == [0; 32] {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::CancelAttempt(request) => {
            if request.attempt_id == [0; 16]
                || request.execution_binding_digest == [0; 32]
                || request.actor_pubkey == [0; 32]
                || request.cancel_digest == [0; 32]
                || request.issued_at == 0
                || request.expected_generation == 0
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
            validate_window(
                request.issued_at,
                request.expires_at,
                settings.time_reference,
            )?;
        }
        Request::DescribeAttemptEvidence(request) => {
            if v2::evidence_request_frame_digest(header, &Request::DescribeAttemptEvidence(request))
                != Some(request.request_frame_digest)
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::ReadAttemptEvidence(request) => {
            if v2::evidence_request_frame_digest(header, &Request::ReadAttemptEvidence(request))
                != Some(request.request_frame_digest)
            {
                return Err(ProxyError::InvalidActivationCoordinates);
            }
        }
        Request::Hello(_) | Request::AdmitQualification(_) | Request::CompleteAttempt(_) => {
            return Err(ProxyError::InvalidActivationCoordinates)
        }
    }
    Ok(())
}

fn intent_registration_request_id(request: v2::RegisterJobIntentRequest) -> [u8; 16] {
    let mut canonical = request;
    canonical.request_frame_digest = [0; 32];
    let frame = v2::encode_request([0; 16], Request::RegisterJobIntent(canonical));
    let mut hasher = Sha256::new();
    hasher.update(INTENT_REGISTRATION_REQUEST_ID_DOMAIN);
    hasher.update(frame.as_bytes());
    let digest = hasher.finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id
}

/// The v2 proxy serves one static activation lane whose Run/Grant/Rerun/
/// Tombstone fixture is frozen into the package. Request windows are judged
/// against the package's bound time reference, recorded at freeze and carried
/// in the manifest and in these static coordinates, never against the wall
/// clock: the fixture stays reproducible and replayable on any host date. The
/// two window failures are named separately from a coordinate mismatch.
fn validate_window(issued_at: u64, expires_at: u64, reference: u64) -> Result<(), ProxyError> {
    if issued_at > reference {
        return Err(ProxyError::IssuedAfterTimeReference {
            issued_at,
            reference,
        });
    }
    if reference >= expires_at {
        return Err(ProxyError::ExpiredAtTimeReference {
            expires_at,
            reference,
        });
    }
    Ok(())
}

fn validate_admission(
    settings: &ProxySettings,
    request: v2::AdmitAttemptRequest,
) -> Result<(), ProxyError> {
    let valid = request.audience_digest == settings.audience_digest
        && request.isolation_profile_digest == settings.isolation_profile_digest
        && request.lane_manifest_digest == settings.lane_manifest_digest
        && request.lane_epoch == settings.lane_epoch
        && request.admission_key_generation == settings.admission_key_generation
        && request.signed_request_digest != [0; 32]
        && request.job_intent_digest != [0; 32]
        && request.admission_signature != [0; 64]
        && request.run_id != [0; 16]
        && request.issued_at != 0
        && request.wall_timeout_seconds != 0
        && request.attempt != 0
        && ((request.attempt == 1 && request.parent_attempt == 0)
            || (request.attempt > 1
                && request.parent_attempt.checked_add(1) == Some(request.attempt)));
    valid
        .then_some(())
        .ok_or(ProxyError::InvalidActivationCoordinates)?;
    validate_window(
        request.issued_at,
        request.expires_at,
        settings.time_reference,
    )
}

fn validate_response(request: Request, response: BrokerResponse) -> Result<(), ProxyError> {
    if let Request::CancelAttempt(request) = request {
        return validate_cancel_response(request, response);
    }
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
        | Request::CompleteAttempt(_)
        | Request::DescribeAttemptEvidence(_)
        | Request::ReadAttemptEvidence(_)
        | Request::RegisterJobIntent(_) => false,
    };
    bound.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

fn validate_cancel_response(
    request: v2::CancelAttemptRequest,
    response: BrokerResponse,
) -> Result<(), ProxyError> {
    let valid = matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        && response.attempt_id == request.attempt_id
        && response.execution_binding_digest == request.execution_binding_digest
        && response.generation > request.expected_generation
        && response.broker_state == BrokerState::Terminal
        && response.conclusion == Conclusion::Cancelled
        && response.accepted_at != 0
        && response.updated_at >= response.accepted_at
        && response.lease_generation != 0
        && response.evidence_set_digest != [0; 32]
        && response.teardown_digest != [0; 32];
    valid.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

fn validate_cancelled_binding(
    request: v2::CancelAttemptRequest,
    response: BrokerResponse,
    admitted: &AdmittedBinding,
) -> Result<(), ProxyError> {
    let valid = admitted.attempt_id == hex::encode(request.attempt_id)
        && admitted.execution_binding_digest == hex::encode(request.execution_binding_digest)
        && admitted.actor_pubkey == hex::encode(request.actor_pubkey)
        && admitted.signed_request_digest == hex::encode(response.accepted_request_digest)
        && admitted.run_id == hex::encode(response.run_id)
        && admitted.job_intent_digest == hex::encode(response.job_intent_digest)
        && git_oid_matches(&admitted.tip_oid, response.tip_oid)
        && admitted.attempt == response.attempt
        && admitted.accepted_at == response.accepted_at
        && admitted.lease_generation == response.lease_generation;
    valid.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

fn response_body_length(request: Request) -> usize {
    match request {
        Request::DescribeAttemptEvidence(_) => v2::EVIDENCE_DESCRIPTION_BODY_SIZE,
        Request::ReadAttemptEvidence(_) => v2::EVIDENCE_CHUNK_BODY_SIZE,
        Request::RegisterJobIntent(_) => v2::INTENT_REGISTRATION_RESPONSE_BODY_SIZE,
        _ => v2::RESPONSE_BODY_SIZE,
    }
}

fn validate_encoded_response(
    header: FrameHeader,
    request: Request,
    response: &[u8],
) -> Result<(), ProxyError> {
    match request {
        Request::RegisterJobIntent(request) => {
            let response = v2::decode_intent_registration_response(header, response)
                .map_err(|_| ProxyError::InvalidExecdResponse)?;
            validate_intent_registration_response(request, response)
        }
        Request::DescribeAttemptEvidence(request) => {
            let response = v2::decode_evidence_description_response(header, response)
                .map_err(|_| ProxyError::InvalidExecdResponse)?;
            validate_description_response(request, response)
        }
        Request::ReadAttemptEvidence(request) => {
            let response = v2::decode_evidence_chunk_response(header, response)
                .map_err(|_| ProxyError::InvalidExecdResponse)?;
            validate_chunk_response(request, &response)
        }
        _ => {
            let decoded = v2::decode_response(header, response)
                .map_err(|_| ProxyError::InvalidExecdResponse)?;
            validate_response(request, decoded)
        }
    }
}

fn validate_intent_registration_response(
    request: v2::RegisterJobIntentRequest,
    response: v2::IntentRegistrationResponse,
) -> Result<(), ProxyError> {
    let admission = request.admission;
    let admission_message_digest: [u8; 32] =
        Sha256::digest(v2::admission_signature_message(&admission)).into();
    let valid = matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        && response.retry_after_millis == 0
        && response.signed_request_digest == admission.signed_request_digest
        && response.job_intent_digest == admission.job_intent_digest
        && response.request_frame_digest == request.request_frame_digest
        && response.admission_message_digest == admission_message_digest
        && response.registration_key_digest == v2::intent_registration_key_digest(&request)
        && response.lane_manifest_digest == admission.lane_manifest_digest
        && response.run_id == admission.run_id
        && response.lane_epoch == admission.lane_epoch
        && response.admission_key_generation == admission.admission_key_generation
        && response.issued_at == admission.issued_at
        && response.expires_at == admission.expires_at
        && response.attempt == admission.attempt;
    valid.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

fn validate_description_response(
    request: v2::DescribeAttemptEvidenceRequest,
    response: v2::EvidenceDescriptionResponse,
) -> Result<(), ProxyError> {
    if response.execution_binding_digest != request.coordinates.execution_binding_digest
        || response.generation != request.coordinates.expected_generation
        || response.request_frame_digest != request.request_frame_digest
    {
        return Err(ProxyError::InvalidExecdResponse);
    }
    if response.code != ResponseCode::Ok {
        return (response.item_count == 0
            && response.descriptor_set_digest == [0; 32]
            && response.items.iter().all(Option::is_none))
        .then_some(())
        .ok_or(ProxyError::InvalidExecdResponse);
    }
    if response.item_count == 0
        || response.descriptor_set_digest == [0; 32]
        || usize::from(response.item_count) > v2::MAX_EVIDENCE_ITEMS
    {
        return Err(ProxyError::InvalidExecdResponse);
    }
    for item in response.items.iter().flatten() {
        validate_descriptor(*item)?;
    }
    Ok(())
}

fn validate_descriptor(item: v2::EvidenceDescriptor) -> Result<(), ProxyError> {
    let zero_artifact =
        item.artifact_name_digest == [0; 32] && item.artifact_media_type_digest == [0; 32];
    let zero_teardown = item.teardown_lease_id == [0; 16]
        && item.teardown_lease_generation == 0
        && item.teardown_attestation_digest == [0; 32];
    let valid = match item.kind {
        v2::EvidenceKind::Stdout | v2::EvidenceKind::Stderr => zero_artifact && zero_teardown,
        v2::EvidenceKind::Artifact => {
            item.artifact_name_digest != [0; 32]
                && item.artifact_media_type_digest != [0; 32]
                && zero_teardown
        }
        v2::EvidenceKind::Teardown => {
            zero_artifact
                && item.teardown_lease_id != [0; 16]
                && item.teardown_lease_generation != 0
                && item.teardown_attestation_digest != [0; 32]
        }
    };
    valid.then_some(()).ok_or(ProxyError::InvalidExecdResponse)
}

fn validate_chunk_response(
    request: v2::ReadAttemptEvidenceRequest,
    response: &v2::EvidenceChunkResponse,
) -> Result<(), ProxyError> {
    if response.execution_binding_digest != request.coordinates.execution_binding_digest
        || response.generation != request.coordinates.expected_generation
        || response.request_frame_digest != request.request_frame_digest
        || response.kind != request.kind
        || response.item_index != request.item_index
        || response.descriptor_digest != request.descriptor_digest
        || response.offset != request.offset
    {
        return Err(ProxyError::InvalidExecdResponse);
    }
    if response.code != ResponseCode::Ok {
        return (response.bytes.is_empty() && response.total_length == 0)
            .then_some(())
            .ok_or(ProxyError::InvalidExecdResponse);
    }
    let end = response
        .offset
        .checked_add(response.bytes.len() as u32)
        .ok_or(ProxyError::InvalidExecdResponse)?;
    if response.bytes.len() > request.max_length as usize
        || end > response.total_length
        || (response.bytes.len() < request.max_length as usize && end != response.total_length)
    {
        return Err(ProxyError::InvalidExecdResponse);
    }
    Ok(())
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

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    decode_exact(value)
}

fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    hex::decode(value).ok()?.try_into().ok()
}

fn decode_nonzero<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = decode_exact(value)?;
    (decoded != [0; N]).then_some(decoded)
}

fn encode_git_oid(value: GitOid) -> String {
    match value {
        GitOid::Sha1(bytes) => format!("sha1:{}", hex::encode(bytes)),
        GitOid::Sha256(bytes) => format!("sha256:{}", hex::encode(bytes)),
    }
}

fn valid_git_oid(value: &str) -> bool {
    value
        .strip_prefix("sha1:")
        .and_then(decode_nonzero::<20>)
        .is_some()
        || value
            .strip_prefix("sha256:")
            .and_then(decode_nonzero::<32>)
            .is_some()
}

fn git_oid_matches(encoded: &str, value: Option<GitOid>) -> bool {
    value.is_some_and(|value| encode_git_oid(value) == encoded)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use buzz_ci_broker_protocol::v2::AdmissionSignatureAlgorithm;
    use buzz_ci_broker_protocol::{
        BrokerState, CancelReason, Conclusion, GitOid, Operation, TrustClass,
    };
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
            time_reference: 1_800_000_000,
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

    fn cancel_request(
        admitted: v2::AdmitAttemptRequest,
        response: BrokerResponse,
        now: u64,
    ) -> v2::CancelAttemptRequest {
        v2::CancelAttemptRequest {
            attempt_id: response.attempt_id,
            execution_binding_digest: response.execution_binding_digest,
            actor_pubkey: admitted.actor_pubkey,
            cancel_digest: [19; 32],
            issued_at: now,
            expires_at: now + 60,
            expected_generation: response.generation,
            reason: CancelReason::UserRequest,
        }
    }

    fn cancelled_response(admitted: BrokerResponse) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            broker_state: BrokerState::Terminal,
            conclusion: Conclusion::Cancelled,
            generation: admitted.generation + 3,
            updated_at: admitted.updated_at + 3,
            evidence_set_digest: [20; 32],
            teardown_digest: [21; 32],
            ..admitted
        }
    }

    fn evidence_coordinates() -> v2::AttemptEvidenceCoordinates {
        v2::AttemptEvidenceCoordinates {
            signed_request_digest: [31; 32],
            run_id: [32; 16],
            workflow_digest: [33; 32],
            job_intent_digest: [34; 32],
            attempt: 1,
            attempt_id: [35; 16],
            execution_binding_digest: [36; 32],
            expected_generation: 7,
            request_event_id: [40; 32],
            workflow_id: v2::WireText64::from_ascii("workflow").expect("workflow id"),
            job_id: v2::WireText64::from_ascii("job").expect("job id"),
        }
    }

    fn describe_request(header: FrameHeader) -> v2::DescribeAttemptEvidenceRequest {
        let mut request = v2::DescribeAttemptEvidenceRequest {
            coordinates: evidence_coordinates(),
            idempotency_digest: [37; 32],
            request_frame_digest: [1; 32],
        };
        request.request_frame_digest =
            v2::evidence_request_frame_digest(header, &Request::DescribeAttemptEvidence(request))
                .expect("describe digest");
        request
    }

    fn read_request(header: FrameHeader) -> v2::ReadAttemptEvidenceRequest {
        let mut request = v2::ReadAttemptEvidenceRequest {
            coordinates: evidence_coordinates(),
            idempotency_digest: [37; 32],
            request_frame_digest: [1; 32],
            kind: v2::EvidenceKind::Stdout,
            item_index: 0,
            descriptor_digest: [38; 32],
            offset: 0,
            max_length: 16,
        };
        request.request_frame_digest =
            v2::evidence_request_frame_digest(header, &Request::ReadAttemptEvidence(request))
                .expect("read digest");
        request
    }

    fn registration_request(now: u64) -> (FrameHeader, v2::RegisterJobIntentRequest) {
        let mut request = v2::RegisterJobIntentRequest {
            admission: admission(now),
            request_event_id: [24; 32],
            workflow_id: v2::WireText64::from_ascii("workflow").expect("workflow id"),
            job_id: v2::WireText64::from_ascii("job").expect("job id"),
            artifact_count: 1,
            artifacts: [Some(v2::JobArtifactDeclaration {
                artifact_id: v2::WireText64::from_ascii("report").expect("artifact id"),
                name: v2::WireText64::from_ascii("report.txt").expect("artifact name"),
                media_type: v2::WireText64::from_ascii("text/plain").expect("media type"),
                relative_name: v2::WireText64::from_ascii("report.txt").expect("relative name"),
                max_bytes: 4096,
            })],
            request_frame_digest: [25; 32],
        };
        let header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: intent_registration_request_id(request),
        };
        request.request_frame_digest =
            v2::intent_registration_request_frame_digest(header, &request)
                .expect("registration frame digest");
        (header, request)
    }

    fn registration_response(
        request: v2::RegisterJobIntentRequest,
        code: ResponseCode,
    ) -> v2::IntentRegistrationResponse {
        let admission = request.admission;
        v2::IntentRegistrationResponse {
            code,
            retry_after_millis: 0,
            signed_request_digest: admission.signed_request_digest,
            job_intent_digest: admission.job_intent_digest,
            request_frame_digest: request.request_frame_digest,
            admission_message_digest: Sha256::digest(v2::admission_signature_message(&admission))
                .into(),
            registration_key_digest: v2::intent_registration_key_digest(&request),
            lane_manifest_digest: admission.lane_manifest_digest,
            run_id: admission.run_id,
            lane_epoch: admission.lane_epoch,
            admission_key_generation: admission.admission_key_generation,
            issued_at: admission.issued_at,
            expires_at: admission.expires_at,
            attempt: admission.attempt,
        }
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
        let now = settings.time_reference;
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

    /// H10 clean host, boot 5: controld polls GetAttempt under one
    /// deterministic request id, the journal cached the first (leased)
    /// observation of a ten-second job and replayed it for the attempt's
    /// whole deadline. A bound state read is forwarded every time and never
    /// journaled; mutations keep their exactly-once cache.
    #[test]
    fn state_reads_are_forwarded_every_time_and_never_journaled() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let now = settings.time_reference;
        let leased = response(admission(now));
        let mut terminal = leased;
        terminal.code = ResponseCode::Existing;
        terminal.broker_state = BrokerState::Terminal;
        terminal.conclusion = Conclusion::Success;
        terminal.generation = 5;
        terminal.updated_at = leased.accepted_at + 10;
        terminal.evidence_set_digest = [16; 32];
        terminal.teardown_digest = [17; 32];
        let header = FrameHeader {
            operation: Operation::GetAttempt,
            request_id: [61; 16],
        };
        let frame = v2::encode_request(
            header.request_id,
            Request::GetAttempt(v2::GetAttemptRequest {
                attempt_id: leased.attempt_id,
                execution_binding_digest: leased.execution_binding_digest,
            }),
        )
        .as_bytes()
        .to_vec();
        let leased_frame = v2::encode_response(header, leased).as_bytes().to_vec();
        let terminal_frame = v2::encode_response(header, terminal).as_bytes().to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut proxy = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::from([
                    Ok(fake_execd(
                        frame.clone(),
                        leased_frame.clone(),
                        settings.execd_uid,
                        settings.execd_gid,
                    )),
                    Ok(fake_execd(
                        frame.clone(),
                        terminal_frame.clone(),
                        settings.execd_uid,
                        settings.execd_gid,
                    )),
                ]),
                calls: Arc::clone(&calls),
            },
        )
        .expect("proxy");
        assert_eq!(
            exchange(&mut proxy, &frame).expect("first poll"),
            leased_frame
        );
        assert_eq!(
            exchange(&mut proxy, &frame).expect("second poll"),
            terminal_frame
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(proxy.replay.document.entries.is_empty());
        // The third poll has no execd and fails transport-closed instead of
        // answering from a cache.
        assert!(matches!(
            exchange(&mut proxy, &frame),
            Err(ProxyError::ExecdUnavailable)
        ));
    }

    #[test]
    fn cancel_is_bound_to_cached_admission_and_replays_only_exact_terminal_response() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let now = settings.time_reference;
        let admitted_request = admission(now);
        let admitted_header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [50; 16],
        };
        let admitted_frame = request_frame(admitted_header.request_id, admitted_request);
        let admitted_response_value = response(admitted_request);
        let admitted_response = v2::encode_response(admitted_header, admitted_response_value)
            .as_bytes()
            .to_vec();

        let cancel_header = FrameHeader {
            operation: Operation::CancelAttempt,
            request_id: [51; 16],
        };
        let cancel_request = cancel_request(admitted_request, admitted_response_value, now);
        let cancel_frame = v2::encode_request(
            cancel_header.request_id,
            Request::CancelAttempt(cancel_request),
        )
        .as_bytes()
        .to_vec();
        let cancelled_response_value = cancelled_response(admitted_response_value);
        let cancelled_response = v2::encode_response(cancel_header, cancelled_response_value)
            .as_bytes()
            .to_vec();

        let calls = Arc::new(AtomicUsize::new(0));
        let mut proxy = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::from([Ok(fake_execd(
                    admitted_frame.clone(),
                    admitted_response.clone(),
                    settings.execd_uid,
                    settings.execd_gid,
                ))]),
                calls: Arc::clone(&calls),
            },
        )
        .expect("proxy");
        assert_eq!(
            exchange(&mut proxy, &admitted_frame).expect("admit"),
            admitted_response
        );

        let mut wrong_actor = cancel_request;
        wrong_actor.actor_pubkey[0] ^= 1;
        let wrong_actor_frame = v2::encode_request([52; 16], Request::CancelAttempt(wrong_actor))
            .as_bytes()
            .to_vec();
        assert!(matches!(
            exchange(&mut proxy, &wrong_actor_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let mut wrong_binding = cancel_request;
        wrong_binding.execution_binding_digest[0] ^= 1;
        let wrong_binding_frame =
            v2::encode_request([54; 16], Request::CancelAttempt(wrong_binding))
                .as_bytes()
                .to_vec();
        assert!(matches!(
            exchange(&mut proxy, &wrong_binding_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let mut stale = cancel_request;
        stale.expected_generation = stale.expected_generation.saturating_add(1);
        let stale_frame = v2::encode_request([53; 16], Request::CancelAttempt(stale))
            .as_bytes()
            .to_vec();
        assert!(matches!(
            exchange(&mut proxy, &stale_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let mut expired = cancel_request;
        expired.issued_at = now.saturating_sub(2);
        expired.expires_at = now.saturating_sub(1);
        let expired_frame = v2::encode_request([55; 16], Request::CancelAttempt(expired))
            .as_bytes()
            .to_vec();
        assert!(matches!(
            exchange(&mut proxy, &expired_frame),
            Err(ProxyError::ExpiredAtTimeReference { .. })
        ));

        let admitted_binding = proxy
            .replay
            .admitted_binding_for_cancel(cancel_request)
            .expect("cached binding");
        let mut wrong_job = cancelled_response_value;
        wrong_job.job_intent_digest[0] ^= 1;
        assert!(matches!(
            validate_cancelled_binding(cancel_request, wrong_job, &admitted_binding),
            Err(ProxyError::InvalidExecdResponse)
        ));
        let nonterminal = BrokerResponse {
            code: ResponseCode::Existing,
            ..admitted_response_value
        };
        assert!(matches!(
            validate_cancel_response(cancel_request, nonterminal),
            Err(ProxyError::InvalidExecdResponse)
        ));
        let stale_response = BrokerResponse {
            code: ResponseCode::StateConflict,
            generation: admitted_response_value.generation + 1,
            ..cancelled_response_value
        };
        assert!(matches!(
            validate_cancel_response(cancel_request, stale_response),
            Err(ProxyError::InvalidExecdResponse)
        ));
        drop(proxy);

        let mut cancel_proxy = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::from([Ok(fake_execd(
                    cancel_frame.clone(),
                    cancelled_response.clone(),
                    settings.execd_uid,
                    settings.execd_gid,
                ))]),
                calls: Arc::clone(&calls),
            },
        )
        .expect("cancel restart");
        assert_eq!(
            exchange(&mut cancel_proxy, &cancel_frame).expect("cancel"),
            cancelled_response
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(cancel_proxy);

        let mut restarted = RunnerV2Proxy::with_connector(
            settings,
            FakeConnector {
                connections: VecDeque::new(),
                calls: Arc::clone(&calls),
            },
        )
        .expect("restart");
        assert_eq!(
            exchange(&mut restarted, &admitted_frame).expect("cached admission"),
            admitted_response
        );
        assert_eq!(
            exchange(&mut restarted, &cancel_frame).expect("cached cancel"),
            cancelled_response
        );
        let mut drift = cancel_request;
        drift.cancel_digest[0] ^= 1;
        let drift_frame =
            v2::encode_request(cancel_header.request_id, Request::CancelAttempt(drift))
                .as_bytes()
                .to_vec();
        assert!(matches!(
            exchange(&mut restarted, &drift_frame),
            Err(ProxyError::ReplayConflict)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
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

        let now = settings.time_reference;
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
        let now = proxy.settings.time_reference;
        let frame = request_frame([23; 16], admission(now));
        assert!(matches!(
            exchange(&mut proxy, &frame),
            Err(ProxyError::ExecdUnavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// H7 clean host: the frozen fixture's run request carried
    /// `issued_at 1800000000, expires_at 1800000300` while the guest clock read
    /// 2026, and the runner refused controld's dispatch with the coordinate
    /// mismatch text. Windows are judged against the package time reference
    /// (the same frozen value), the two window failures are named, and a
    /// coordinate mismatch still reports as such.
    #[test]
    fn admission_window_is_judged_against_the_package_time_reference_not_the_wall_clock() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let header = FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [60; 16],
        };
        let mut frozen = admission(settings.time_reference);
        frozen.issued_at = 1_800_000_000;
        frozen.expires_at = 1_800_000_300;
        assert_eq!(settings.time_reference, 1_800_000_000);
        validate_request(&settings, header, Request::AdmitAttempt(frozen))
            .expect("frozen fixture window contains the package time reference");

        let mut future = frozen;
        future.issued_at = settings.time_reference + 1;
        let error = validate_request(&settings, header, Request::AdmitAttempt(future))
            .expect_err("issued after the reference");
        assert!(matches!(
            error,
            ProxyError::IssuedAfterTimeReference {
                issued_at: 1_800_000_001,
                reference: 1_800_000_000
            }
        ));
        let message = error.to_string();
        assert!(
            message.contains("issued after the package time reference"),
            "{message}"
        );
        assert!(
            !message.contains("static activation coordinates"),
            "{message}"
        );

        let mut expired = frozen;
        expired.expires_at = settings.time_reference;
        let error = validate_request(&settings, header, Request::AdmitAttempt(expired))
            .expect_err("expired at the reference");
        assert!(matches!(
            error,
            ProxyError::ExpiredAtTimeReference {
                expires_at: 1_800_000_000,
                reference: 1_800_000_000
            }
        ));
        assert!(error
            .to_string()
            .contains("expired at the package time reference"));

        let mut mismatch = future;
        mismatch.lane_epoch += 1;
        assert!(matches!(
            validate_request(&settings, header, Request::AdmitAttempt(mismatch)),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let (intent_header, mut intent) = registration_request(settings.time_reference);
        intent.admission.issued_at = settings.time_reference + 1;
        assert!(matches!(
            validate_request(&settings, intent_header, Request::RegisterJobIntent(intent)),
            Err(ProxyError::IssuedAfterTimeReference { .. })
        ));
    }

    #[test]
    fn evidence_requests_reject_divergent_coordinates_and_idempotency() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let describe_header = FrameHeader {
            operation: Operation::DescribeAttemptEvidence,
            request_id: [40; 16],
        };
        let mut describe = describe_request(describe_header);
        describe.idempotency_digest[0] ^= 1;
        assert!(matches!(
            validate_request(
                &settings,
                describe_header,
                Request::DescribeAttemptEvidence(describe),
            ),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let read_header = FrameHeader {
            operation: Operation::ReadAttemptEvidence,
            request_id: [43; 16],
        };
        let mut read = read_request(read_header);
        read.coordinates.attempt = read.coordinates.attempt.saturating_add(1);
        assert!(matches!(
            validate_request(&settings, read_header, Request::ReadAttemptEvidence(read),),
            Err(ProxyError::InvalidActivationCoordinates)
        ));
    }

    #[test]
    fn describe_evidence_forwards_exact_frame_and_binds_path_free_descriptors() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let header = FrameHeader {
            operation: Operation::DescribeAttemptEvidence,
            request_id: [41; 16],
        };
        let request = describe_request(header);
        let frame =
            v2::encode_request(header.request_id, Request::DescribeAttemptEvidence(request))
                .as_bytes()
                .to_vec();
        let descriptor = v2::EvidenceDescriptor {
            kind: v2::EvidenceKind::Stdout,
            digest: [38; 32],
            length: 3,
            artifact_name_digest: [0; 32],
            artifact_media_type_digest: [0; 32],
            artifact_id: v2::WireText64::EMPTY,
            artifact_name: v2::WireText64::EMPTY,
            artifact_media_type: v2::WireText64::EMPTY,
            teardown_lease_id: [0; 16],
            teardown_lease_generation: 0,
            teardown_attestation_digest: [0; 32],
        };
        let mut items = [None; v2::MAX_EVIDENCE_ITEMS];
        items[0] = Some(descriptor);
        let response = v2::encode_evidence_description_response(
            header,
            v2::EvidenceDescriptionResponse {
                code: ResponseCode::Ok,
                execution_binding_digest: request.coordinates.execution_binding_digest,
                generation: request.coordinates.expected_generation,
                request_frame_digest: request.request_frame_digest,
                descriptor_set_digest: [39; 32],
                item_count: 1,
                items,
                request_event_id: request.coordinates.request_event_id,
                run_id: request.coordinates.run_id,
                workflow_id: request.coordinates.workflow_id,
                workflow_digest: request.coordinates.workflow_digest,
                job_id: request.coordinates.job_id,
                attempt: request.coordinates.attempt,
            },
        )
        .as_bytes()
        .to_vec();
        let connected = fake_execd(
            frame.clone(),
            response.clone(),
            settings.execd_uid,
            settings.execd_gid,
        );
        let mut proxy = RunnerV2Proxy::with_connector(
            settings,
            FakeConnector {
                connections: VecDeque::from([Ok(connected)]),
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("proxy");
        assert_eq!(exchange(&mut proxy, &frame).expect("describe"), response);

        let mut wrong_binding =
            v2::decode_evidence_description_response(header, &response).expect("decode response");
        wrong_binding.execution_binding_digest[0] ^= 1;
        assert!(matches!(
            validate_description_response(request, wrong_binding),
            Err(ProxyError::InvalidExecdResponse)
        ));
    }

    #[test]
    fn read_evidence_binds_chunk_coordinates_and_bounds() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let header = FrameHeader {
            operation: Operation::ReadAttemptEvidence,
            request_id: [42; 16],
        };
        let request = read_request(header);
        let frame = v2::encode_request(header.request_id, Request::ReadAttemptEvidence(request))
            .as_bytes()
            .to_vec();
        let response_value = v2::EvidenceChunkResponse {
            code: ResponseCode::Ok,
            execution_binding_digest: request.coordinates.execution_binding_digest,
            generation: request.coordinates.expected_generation,
            request_frame_digest: request.request_frame_digest,
            kind: request.kind,
            item_index: request.item_index,
            descriptor_digest: request.descriptor_digest,
            offset: request.offset,
            total_length: 3,
            bytes: b"log".to_vec(),
            request_event_id: request.coordinates.request_event_id,
            run_id: request.coordinates.run_id,
            workflow_id: request.coordinates.workflow_id,
            workflow_digest: request.coordinates.workflow_digest,
            job_id: request.coordinates.job_id,
            attempt: request.coordinates.attempt,
        };
        let response = v2::encode_evidence_chunk_response(header, &response_value)
            .as_bytes()
            .to_vec();
        let connected = fake_execd(
            frame.clone(),
            response.clone(),
            settings.execd_uid,
            settings.execd_gid,
        );
        let mut proxy = RunnerV2Proxy::with_connector(
            settings,
            FakeConnector {
                connections: VecDeque::from([Ok(connected)]),
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("proxy");
        assert_eq!(exchange(&mut proxy, &frame).expect("read"), response);

        let mut hostile = response_value.clone();
        hostile.total_length = 2;
        assert!(matches!(
            validate_chunk_response(request, &hostile),
            Err(ProxyError::InvalidExecdResponse)
        ));
        hostile = response_value;
        hostile.generation = hostile.generation.saturating_add(1);
        assert!(matches!(
            validate_chunk_response(request, &hostile),
            Err(ProxyError::InvalidExecdResponse)
        ));
    }

    #[test]
    fn intent_registration_forwards_exact_frame_and_rejects_drift_or_unbound_response() {
        let directory = private_directory();
        let settings = settings(directory.path());
        let now = settings.time_reference;
        let (header, request) = registration_request(now);
        let frame = v2::encode_request(header.request_id, Request::RegisterJobIntent(request))
            .as_bytes()
            .to_vec();
        let response_value = registration_response(request, ResponseCode::Ok);
        let response = v2::encode_intent_registration_response(header, response_value)
            .as_bytes()
            .to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut proxy = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::from([Ok(fake_execd(
                    frame.clone(),
                    response.clone(),
                    settings.execd_uid,
                    settings.execd_gid,
                ))]),
                calls: Arc::clone(&calls),
            },
        )
        .expect("proxy");
        assert_eq!(
            exchange(&mut proxy, &frame).expect("register intent"),
            response
        );
        drop(proxy);

        let mut restarted = RunnerV2Proxy::with_connector(
            settings.clone(),
            FakeConnector {
                connections: VecDeque::new(),
                calls: Arc::clone(&calls),
            },
        )
        .expect("restart");
        assert_eq!(
            exchange(&mut restarted, &frame).expect("cached registration"),
            response
        );

        let mut drift = request;
        drift.job_id = v2::WireText64::from_ascii("other-job").expect("drift job id");
        drift.request_frame_digest = v2::intent_registration_request_frame_digest(header, &drift)
            .expect("drift frame digest");
        let drift_frame = v2::encode_request(header.request_id, Request::RegisterJobIntent(drift))
            .as_bytes()
            .to_vec();
        assert!(matches!(
            exchange(&mut restarted, &drift_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let wrong_header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: [61; 16],
        };
        let wrong_digest_frame =
            v2::encode_request(wrong_header.request_id, Request::RegisterJobIntent(request))
                .as_bytes()
                .to_vec();
        assert!(matches!(
            exchange(&mut restarted, &wrong_digest_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let (_, mut wrong_static) = registration_request(now);
        wrong_static.admission.lane_epoch = wrong_static.admission.lane_epoch.saturating_add(1);
        let static_header = FrameHeader {
            operation: Operation::RegisterJobIntent,
            request_id: intent_registration_request_id(wrong_static),
        };
        wrong_static.request_frame_digest =
            v2::intent_registration_request_frame_digest(static_header, &wrong_static)
                .expect("static frame digest");
        let wrong_static_frame = v2::encode_request(
            static_header.request_id,
            Request::RegisterJobIntent(wrong_static),
        )
        .as_bytes()
        .to_vec();
        assert!(matches!(
            exchange(&mut restarted, &wrong_static_frame),
            Err(ProxyError::InvalidActivationCoordinates)
        ));

        let mut wrong_response = response_value;
        wrong_response.run_id[0] ^= 1;
        assert!(matches!(
            validate_intent_registration_response(request, wrong_response),
            Err(ProxyError::InvalidExecdResponse)
        ));
        let conflict = registration_response(request, ResponseCode::ReplayConflict);
        assert!(matches!(
            validate_intent_registration_response(request, conflict),
            Err(ProxyError::InvalidExecdResponse)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
