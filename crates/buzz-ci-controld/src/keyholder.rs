//! Authenticated, bounded client for the isolated CI signing keyholder.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use buzz_ci_keyholder::{
    decode_response, encode_request, AcceptanceMutation, CanonicalPayload,
    DescribeAcceptanceRequest, DescribeAcceptanceResponse, DescribeRequest, DescribeResponse,
    ErrorCode, FrameHeader, HttpMethod as KeyholderHttpMethod, KeySelector, KeyholderClient,
    ManifestKind, Nip98AuthorizeRequest, OperationSet, PeerPolicy, PublicIdentity, Request,
    Response, SelectorSet, SignAcceptanceMutationRequest, SignCiEventRequest, SignManifestRequest,
    SignatureResponse, Url as KeyholderUrl, HEADER_SIZE, KEYHOLDER_SOCKET_PATH, MAX_BODY_SIZE,
};
use nostr::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use nostr::{Event, Tag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::production::{CiSigner, SignedCiEvent};
use crate::source::{HttpMethod, Nip98Authorizer, Nip98Binding};

const MAX_TIMEOUT_MILLIS: u64 = 5_000;
const MAX_TRANSPORT_ATTEMPTS: u32 = 8;
const NIP98_EVENT_KIND: u32 = 27_235;
const MANIFEST_DOMAIN: &[u8] = b"buzz-ci-keyholder:manifest:v1\0";

/// One exact public key and active generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyholderSelectorBinding {
    pub public_key: String,
    pub generation: u64,
}

impl KeyholderSelectorBinding {
    fn identity(&self) -> Result<PublicIdentity, KeyholderError> {
        if !is_lower_hex(&self.public_key, 64) || self.generation == 0 {
            return Err(KeyholderError::InvalidConfig);
        }
        let bytes = hex::decode(&self.public_key).map_err(|_| KeyholderError::InvalidConfig)?;
        let public_key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyholderError::InvalidConfig)?;
        XOnlyPublicKey::from_slice(&public_key).map_err(|_| KeyholderError::InvalidConfig)?;
        Ok(PublicIdentity {
            public_key,
            generation: self.generation,
        })
    }
}

/// Closed public selector state expected from the keyholder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyholderSelectorBindings {
    pub ci_event: KeyholderSelectorBinding,
    pub nip98: KeyholderSelectorBinding,
    pub manifest: KeyholderSelectorBinding,
}

impl KeyholderSelectorBindings {
    fn selector_set(&self) -> Result<SelectorSet, KeyholderError> {
        SelectorSet::new(
            self.ci_event.identity()?,
            self.nip98.identity()?,
            self.manifest.identity()?,
        )
        .ok_or(KeyholderError::InvalidConfig)
    }
}

/// Complete secret-free client binding for the fixed local keyholder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyholderClientConfig {
    pub keyholder_socket: PathBuf,
    pub keyholder_uid: u32,
    pub keyholder_gid: u32,
    pub keyholder_selectors: KeyholderSelectorBindings,
    pub keyholder_timeout_millis: u64,
    pub keyholder_transport_attempts: u32,
}

impl KeyholderClientConfig {
    /// Validate the fixed path, exact public identities, and bounded transport.
    pub fn validate(&self) -> Result<(), KeyholderError> {
        if self.keyholder_socket != Path::new(KEYHOLDER_SOCKET_PATH) {
            return Err(KeyholderError::InvalidConfig);
        }
        self.validate_common()
    }

    fn validate_common(&self) -> Result<(), KeyholderError> {
        if self.keyholder_uid == 0
            || self.keyholder_gid == 0
            || self.keyholder_timeout_millis == 0
            || self.keyholder_timeout_millis > MAX_TIMEOUT_MILLIS
            || self.keyholder_transport_attempts == 0
            || self.keyholder_transport_attempts > MAX_TRANSPORT_ATTEMPTS
        {
            return Err(KeyholderError::InvalidConfig);
        }
        self.keyholder_selectors.selector_set()?;
        Ok(())
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.keyholder_timeout_millis)
    }

    fn expected_identity(&self, selector: KeySelector) -> Result<PublicIdentity, KeyholderError> {
        Ok(self.keyholder_selectors.selector_set()?.identity(selector))
    }
}

/// Sanitized client failure. No variant contains paths, bytes, or OS details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeyholderError {
    #[error("keyholder client configuration is invalid")]
    InvalidConfig,
    #[error("keyholder service is unavailable")]
    Unavailable,
    #[error("keyholder service identity is invalid")]
    WrongServer,
    #[error("keyholder request timed out")]
    Timeout,
    #[error("keyholder protocol response is invalid")]
    Protocol,
    #[error("keyholder public identity does not match configuration")]
    WrongIdentity,
    #[error("keyholder signed an unexpected digest")]
    WrongDigest,
    #[error("keyholder signature is invalid")]
    InvalidSignature,
    #[error("keyholder generation is stale")]
    StaleGeneration { current: u64 },
    #[error("keyholder rejected the requested operation")]
    Rejected(ErrorCode),
    #[error("keyholder signing input is invalid")]
    InvalidInput,
}

/// Per-request Unix client. Every connection authenticates the server with
/// `SO_PEERCRED`; every response is bound to its operation and request ID.
pub struct UnixKeyholderClient {
    config: KeyholderClientConfig,
    ci_pubkey: String,
}

impl std::fmt::Debug for UnixKeyholderClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixKeyholderClient")
            .field("config", &self.config)
            .finish()
    }
}

impl UnixKeyholderClient {
    /// Validate the binding and perform an authenticated describe handshake.
    pub fn connect(config: KeyholderClientConfig) -> Result<Self, KeyholderError> {
        config.validate()?;
        Self::connect_validated(config)
    }

    fn connect_validated(config: KeyholderClientConfig) -> Result<Self, KeyholderError> {
        let ci_pubkey = config.keyholder_selectors.ci_event.public_key.clone();
        let mut client = Self { config, ci_pubkey };
        let description = KeyholderClient::describe(&mut client, DescribeRequest)?;
        client.validate_description(description)?;
        Ok(client)
    }

    #[cfg(test)]
    fn connect_for_test(config: KeyholderClientConfig) -> Result<Self, KeyholderError> {
        config.validate_common()?;
        Self::connect_validated(config)
    }

    fn validate_description(&self, value: DescribeResponse) -> Result<(), KeyholderError> {
        let expected = self.config.keyholder_selectors.selector_set()?;
        if value.ci_event != expected.identity(KeySelector::CiEvent)
            || value.nip98 != expected.identity(KeySelector::Nip98)
            || value.manifest != expected.identity(KeySelector::Manifest)
            || value.peer_policy != expected_client_policy()
        {
            return Err(KeyholderError::WrongIdentity);
        }
        Ok(())
    }

    fn exchange(&self, request: &Request) -> Result<Response, KeyholderError> {
        for attempt in 1..=self.config.keyholder_transport_attempts {
            match self.exchange_once(request) {
                Err(KeyholderError::Unavailable | KeyholderError::Timeout)
                    if attempt < self.config.keyholder_transport_attempts => {}
                result => return result,
            }
        }
        Err(KeyholderError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn exchange_once(&self, request: &Request) -> Result<Response, KeyholderError> {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

        validate_socket_file(&self.config.keyholder_socket, self.config.keyholder_uid)?;
        let mut stream =
            connect_with_timeout(&self.config.keyholder_socket, self.config.timeout())?;
        let peer = getsockopt(&stream, PeerCredentials).map_err(|_| KeyholderError::WrongServer)?;
        if peer.uid() != self.config.keyholder_uid || peer.gid() != self.config.keyholder_gid {
            return Err(KeyholderError::WrongServer);
        }
        stream
            .set_read_timeout(Some(self.config.timeout()))
            .and_then(|()| stream.set_write_timeout(Some(self.config.timeout())))
            .map_err(classify_transport_error)?;

        let request_id = request_id();
        let encoded =
            encode_request(request_id, request).map_err(|_| KeyholderError::InvalidInput)?;
        stream
            .write_all(encoded.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(classify_transport_error)?;
        let frame = read_response_frame(&mut stream)?;
        decode_response(
            FrameHeader {
                operation: request.operation(),
                request_id,
            },
            &frame,
        )
        .map_err(|_| KeyholderError::Protocol)
    }

    #[cfg(not(target_os = "linux"))]
    fn exchange_once(&self, _request: &Request) -> Result<Response, KeyholderError> {
        Err(KeyholderError::Unavailable)
    }

    fn signature_response(
        &self,
        request: Request,
        selector: KeySelector,
        expected_digest: [u8; 32],
    ) -> Result<SignatureResponse, KeyholderError> {
        let response = self.exchange(&request)?;
        let signature = match response {
            Response::SignCiEvent(value)
            | Response::Nip98Authorize(value)
            | Response::SignManifest(value) => value,
            Response::Error { error, .. } => return Err(map_server_error(error)),
            Response::Describe(_)
            | Response::DescribeAcceptance(_)
            | Response::SignAcceptanceMutation(_) => return Err(KeyholderError::Protocol),
        };
        let expected_identity = self.config.expected_identity(selector)?;
        if signature.identity != expected_identity {
            return Err(KeyholderError::WrongIdentity);
        }
        if signature.signed_digest != expected_digest {
            return Err(KeyholderError::WrongDigest);
        }
        verify_signature(signature)?;
        Ok(signature)
    }

    /// Sign the exact version-2 admission message with the configured manifest
    /// generation. The keyholder re-parses and policy-checks every field.
    pub fn sign_admission_v2(
        &mut self,
        request: &mut buzz_ci_broker_protocol::v2::AdmitAttemptRequest,
    ) -> Result<(), KeyholderError> {
        use buzz_ci_broker_protocol::v2::{
            admission_signature_message, AdmissionSignatureAlgorithm,
        };

        let identity = self.config.expected_identity(KeySelector::Manifest)?;
        if request.admission_signature_algorithm
            != AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256
            || request.admission_key_generation != identity.generation
        {
            return Err(KeyholderError::InvalidInput);
        }
        request.admission_signature = [0; 64];
        let message = admission_signature_message(request);
        let digest: [u8; 32] = Sha256::digest(&message).into();
        let response = self.signature_response(
            Request::SignManifest(SignManifestRequest {
                expected_generation: identity.generation,
                manifest_kind: ManifestKind::JobIntentV2,
                canonical_manifest: CanonicalPayload::new(message)
                    .map_err(|_| KeyholderError::InvalidInput)?,
            }),
            KeySelector::Manifest,
            digest,
        )?;
        request.admission_signature = response.signature;
        Ok(())
    }

    /// Read the activation-bound acceptance authority over the same exact
    /// authenticated keyholder socket used for production signing.
    pub fn describe_acceptance(&self) -> Result<DescribeAcceptanceResponse, KeyholderError> {
        match self.exchange(&Request::DescribeAcceptance(DescribeAcceptanceRequest))? {
            Response::DescribeAcceptance(value) => Ok(value),
            Response::Error { error, .. } => Err(map_server_error(error)),
            _ => Err(KeyholderError::Protocol),
        }
    }

    /// Sign one preconfigured activation mutation and verify the returned
    /// actor, digest, generation, and BIP-340 signature locally.
    pub fn sign_acceptance_mutation(
        &self,
        actor: PublicIdentity,
        scenario_sha256: [u8; 32],
        mutation: AcceptanceMutation,
        event_id: [u8; 32],
    ) -> Result<SignatureResponse, KeyholderError> {
        let response = self.exchange(&Request::SignAcceptanceMutation(
            SignAcceptanceMutationRequest {
                expected_generation: actor.generation,
                scenario_sha256,
                mutation,
            },
        ))?;
        let signature = match response {
            Response::SignAcceptanceMutation(value) => value,
            Response::Error { error, .. } => return Err(map_server_error(error)),
            _ => return Err(KeyholderError::Protocol),
        };
        if signature.identity != actor {
            return Err(KeyholderError::WrongIdentity);
        }
        if signature.signed_digest != event_id {
            return Err(KeyholderError::WrongDigest);
        }
        verify_signature(signature)?;
        Ok(signature)
    }
}

#[cfg(target_os = "linux")]
fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream, KeyholderError> {
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
    .map_err(|_| KeyholderError::Unavailable)?;
    let address = UnixAddr::new(path).map_err(|_| KeyholderError::InvalidConfig)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS) => {
            let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            let timeout =
                PollTimeout::try_from(timeout).map_err(|_| KeyholderError::InvalidConfig)?;
            if poll(&mut descriptors, timeout).map_err(|_| KeyholderError::Unavailable)? == 0 {
                return Err(KeyholderError::Timeout);
            }
            let socket_error =
                getsockopt(&descriptor, SocketError).map_err(|_| KeyholderError::Unavailable)?;
            if socket_error != 0 {
                return Err(KeyholderError::Unavailable);
            }
        }
        Err(_) => return Err(KeyholderError::Unavailable),
    }
    let stream = UnixStream::from(descriptor);
    stream
        .set_nonblocking(false)
        .map_err(classify_transport_error)?;
    Ok(stream)
}

impl KeyholderClient for UnixKeyholderClient {
    type Error = KeyholderError;

    fn describe(&mut self, _request: DescribeRequest) -> Result<DescribeResponse, Self::Error> {
        match self.exchange(&Request::Describe(DescribeRequest))? {
            Response::Describe(value) => Ok(value),
            Response::Error { error, .. } => Err(map_server_error(error)),
            _ => Err(KeyholderError::Protocol),
        }
    }

    fn sign_ci_event(
        &mut self,
        request: SignCiEventRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        let digest = Sha256::digest(request.canonical_event.as_bytes()).into();
        self.signature_response(Request::SignCiEvent(request), KeySelector::CiEvent, digest)
    }

    fn nip98_authorize(
        &mut self,
        request: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        let digest = nip98_digest(
            self.config
                .expected_identity(KeySelector::Nip98)?
                .public_key,
            &request,
        )?;
        self.signature_response(Request::Nip98Authorize(request), KeySelector::Nip98, digest)
    }

    fn sign_manifest(
        &mut self,
        request: SignManifestRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_DOMAIN);
        digest.update([request.manifest_kind as u8]);
        digest.update(
            u32::try_from(request.canonical_manifest.as_bytes().len())
                .map_err(|_| KeyholderError::InvalidInput)?
                .to_be_bytes(),
        );
        digest.update(request.canonical_manifest.as_bytes());
        self.signature_response(
            Request::SignManifest(request),
            KeySelector::Manifest,
            digest.finalize().into(),
        )
    }
}

impl CiSigner for UnixKeyholderClient {
    type Error = KeyholderError;

    fn pubkey(&self) -> &str {
        &self.ci_pubkey
    }

    fn sign(
        &mut self,
        kind: u32,
        content: &str,
        tags: serde_json::Value,
    ) -> Result<SignedCiEvent, Self::Error> {
        let event_kind = u16::try_from(kind).map_err(|_| KeyholderError::InvalidInput)?;
        let tags: Vec<Tag> =
            serde_json::from_value(tags).map_err(|_| KeyholderError::InvalidInput)?;
        let created_at = unix_time()?;
        let unsigned =
            serde_json::json!([0, self.ci_pubkey, created_at, event_kind, tags, content]);
        let canonical = serde_json::to_vec(&unsigned).map_err(|_| KeyholderError::InvalidInput)?;
        let response = KeyholderClient::sign_ci_event(
            self,
            SignCiEventRequest {
                expected_generation: self
                    .config
                    .expected_identity(KeySelector::CiEvent)?
                    .generation,
                event_kind: kind,
                canonical_event: CanonicalPayload::new(canonical)
                    .map_err(|_| KeyholderError::InvalidInput)?,
            },
        )?;
        let event = signed_event(response, created_at, event_kind.into(), tags, content)?;
        Ok(SignedCiEvent {
            event_id: event.id.to_hex(),
            kind,
            content: content.to_owned(),
            tags: serde_json::to_value(&event.tags).map_err(|_| KeyholderError::Protocol)?,
            signed_event: serde_json::to_value(event).map_err(|_| KeyholderError::Protocol)?,
        })
    }
}

impl Nip98Authorizer for UnixKeyholderClient {
    type Error = KeyholderError;

    fn authorization(&mut self, binding: &Nip98Binding) -> Result<String, Self::Error> {
        binding
            .validate()
            .map_err(|_| KeyholderError::InvalidInput)?;
        let method = protocol_method(binding.method);
        let payload_digest = binding
            .payload_sha256
            .as_deref()
            .map(decode_digest)
            .transpose()?;
        let created_at = unix_time()?;
        let nonce = *Uuid::new_v4().as_bytes();
        let request = Nip98AuthorizeRequest {
            expected_generation: self
                .config
                .expected_identity(KeySelector::Nip98)?
                .generation,
            method,
            url: KeyholderUrl::new(binding.url.as_str().to_owned())
                .map_err(|_| KeyholderError::InvalidInput)?,
            payload_digest,
            created_at,
            nonce,
        };
        let response = KeyholderClient::nip98_authorize(self, request)?;
        let mut tags = vec![
            serde_json::json!(["u", binding.url.as_str()]),
            serde_json::json!(["method", binding.method.as_str()]),
        ];
        if let Some(digest) = payload_digest {
            tags.push(serde_json::json!(["payload", hex::encode(digest)]));
        }
        tags.push(serde_json::json!(["nonce", hex::encode(nonce)]));
        let event = signed_event(response, created_at, NIP98_EVENT_KIND, tags, "")?;
        let json = serde_json::to_vec(&event).map_err(|_| KeyholderError::Protocol)?;
        Ok(format!("Nostr {}", BASE64.encode(json)))
    }
}

fn signed_event<T: Serialize>(
    response: SignatureResponse,
    created_at: u64,
    kind: u32,
    tags: T,
    content: &str,
) -> Result<Event, KeyholderError> {
    serde_json::from_value(serde_json::json!({
        "id": hex::encode(response.signed_digest),
        "pubkey": hex::encode(response.identity.public_key),
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex::encode(response.signature),
    }))
    .map_err(|_| KeyholderError::Protocol)
}

fn verify_signature(response: SignatureResponse) -> Result<(), KeyholderError> {
    let public_key = XOnlyPublicKey::from_slice(&response.identity.public_key)
        .map_err(|_| KeyholderError::WrongIdentity)?;
    let signature =
        Signature::from_slice(&response.signature).map_err(|_| KeyholderError::InvalidSignature)?;
    SECP256K1
        .verify_schnorr(
            &signature,
            &Message::from_digest(response.signed_digest),
            &public_key,
        )
        .map_err(|_| KeyholderError::InvalidSignature)
}

fn nip98_digest(
    public_key: [u8; 32],
    request: &Nip98AuthorizeRequest,
) -> Result<[u8; 32], KeyholderError> {
    let mut tags = vec![
        serde_json::json!(["u", request.url.as_str()]),
        serde_json::json!(["method", keyholder_method(request.method)]),
    ];
    if let Some(payload) = request.payload_digest {
        tags.push(serde_json::json!(["payload", hex::encode(payload)]));
    }
    tags.push(serde_json::json!(["nonce", hex::encode(request.nonce)]));
    let canonical = serde_json::to_vec(&serde_json::json!([
        0,
        hex::encode(public_key),
        request.created_at,
        NIP98_EVENT_KIND,
        tags,
        ""
    ]))
    .map_err(|_| KeyholderError::InvalidInput)?;
    Ok(Sha256::digest(canonical).into())
}

fn map_server_error(error: buzz_ci_keyholder::ErrorResponse) -> KeyholderError {
    if error.code == ErrorCode::StaleGeneration && error.current_generation != 0 {
        KeyholderError::StaleGeneration {
            current: error.current_generation,
        }
    } else if error.code != ErrorCode::StaleGeneration && error.current_generation == 0 {
        KeyholderError::Rejected(error.code)
    } else {
        KeyholderError::Protocol
    }
}

fn request_id() -> [u8; 16] {
    loop {
        let value = *Uuid::new_v4().as_bytes();
        if value != [0; 16] {
            return value;
        }
    }
}

fn read_response_frame(stream: &mut UnixStream) -> Result<Vec<u8>, KeyholderError> {
    let mut header = [0_u8; HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .map_err(classify_transport_error)?;
    let declared = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| KeyholderError::Protocol)?,
    ) as usize;
    if declared > MAX_BODY_SIZE {
        return Err(KeyholderError::Protocol);
    }
    let mut frame = Vec::with_capacity(HEADER_SIZE + declared);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_SIZE + declared, 0);
    stream
        .read_exact(&mut frame[HEADER_SIZE..])
        .map_err(classify_transport_error)?;
    Ok(frame)
}

fn classify_transport_error(error: io::Error) -> KeyholderError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => KeyholderError::Timeout,
        _ => KeyholderError::Unavailable,
    }
}

#[cfg(target_os = "linux")]
fn validate_socket_file(path: &Path, expected_owner_uid: u32) -> Result<(), KeyholderError> {
    use nix::unistd::getegid;

    let metadata = fs::symlink_metadata(path).map_err(|_| KeyholderError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner_uid
        || metadata.gid() != getegid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o620
    {
        return Err(KeyholderError::WrongServer);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn expected_client_policy() -> PeerPolicy {
    use nix::unistd::{getegid, geteuid};

    PeerPolicy {
        uid: geteuid().as_raw(),
        gid: getegid().as_raw(),
        allowed_operations: OperationSet::ALL,
    }
}

#[cfg(not(target_os = "linux"))]
fn expected_client_policy() -> PeerPolicy {
    PeerPolicy {
        uid: 0,
        gid: 0,
        allowed_operations: OperationSet::ALL,
    }
}

fn unix_time() -> Result<u64, KeyholderError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KeyholderError::Unavailable)?
        .as_secs();
    (value != 0)
        .then_some(value)
        .ok_or(KeyholderError::Unavailable)
}

fn decode_digest(value: &str) -> Result<[u8; 32], KeyholderError> {
    if !is_lower_hex(value, 64) {
        return Err(KeyholderError::InvalidInput);
    }
    hex::decode(value)
        .map_err(|_| KeyholderError::InvalidInput)?
        .try_into()
        .map_err(|_| KeyholderError::InvalidInput)
}

const fn protocol_method(method: HttpMethod) -> KeyholderHttpMethod {
    match method {
        HttpMethod::Get => KeyholderHttpMethod::Get,
        HttpMethod::Post => KeyholderHttpMethod::Post,
        HttpMethod::Put => KeyholderHttpMethod::Put,
    }
}

const fn keyholder_method(method: KeyholderHttpMethod) -> &'static str {
    match method {
        KeyholderHttpMethod::Get => "GET",
        KeyholderHttpMethod::Head => "HEAD",
        KeyholderHttpMethod::Post => "POST",
        KeyholderHttpMethod::Put => "PUT",
        KeyholderHttpMethod::Patch => "PATCH",
        KeyholderHttpMethod::Delete => "DELETE",
        KeyholderHttpMethod::Options => "OPTIONS",
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;

    use buzz_ci_keyholder::{
        decode_request, encode_response, DescribeAcceptanceResponse, ErrorResponse, Operation,
        SignCiEventRequest,
    };
    use nix::unistd::{getegid, geteuid};
    use tempfile::TempDir;

    use super::*;

    const CI_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const NIP98_KEY: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const MANIFEST_KEY: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[derive(Clone, Copy)]
    enum Reply {
        Describe,
        SignCiEvent,
        DescribeAcceptance,
        SignAcceptance,
        Stale,
        WrongOperation,
        WrongRequestId,
        Stall,
    }

    fn bindings() -> KeyholderSelectorBindings {
        KeyholderSelectorBindings {
            ci_event: KeyholderSelectorBinding {
                public_key: CI_KEY.to_owned(),
                generation: 7,
            },
            nip98: KeyholderSelectorBinding {
                public_key: NIP98_KEY.to_owned(),
                generation: 8,
            },
            manifest: KeyholderSelectorBinding {
                public_key: MANIFEST_KEY.to_owned(),
                generation: 9,
            },
        }
    }

    fn config(path: PathBuf, timeout_millis: u64, attempts: u32) -> KeyholderClientConfig {
        KeyholderClientConfig {
            keyholder_socket: path,
            keyholder_uid: geteuid().as_raw(),
            keyholder_gid: getegid().as_raw(),
            keyholder_selectors: bindings(),
            keyholder_timeout_millis: timeout_millis,
            keyholder_transport_attempts: attempts,
        }
    }

    fn spawn_server(replies: Vec<Reply>) -> (TempDir, PathBuf, thread::JoinHandle<()>) {
        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("keyholder.sock");
        let listener = UnixListener::bind(&path).expect("bind keyholder test socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).expect("socket mode");
        let (ready_tx, ready_rx) = mpsc::channel();
        let selector_state = bindings().selector_set().expect("selectors");
        let handle = thread::spawn(move || {
            ready_tx.send(()).expect("ready");
            for reply in replies {
                let (mut stream, _) = listener.accept().expect("accept");
                if matches!(reply, Reply::Stall) {
                    thread::sleep(Duration::from_millis(150));
                    continue;
                }
                let mut frame = Vec::new();
                let mut header = [0_u8; HEADER_SIZE];
                stream.read_exact(&mut header).expect("request header");
                let body_len =
                    u32::from_be_bytes(header[12..16].try_into().expect("length")) as usize;
                frame.extend_from_slice(&header);
                frame.resize(HEADER_SIZE + body_len, 0);
                stream
                    .read_exact(&mut frame[HEADER_SIZE..])
                    .expect("request body");
                let (request_header, request) = decode_request(&frame).expect("request");
                let (response_header, response) = match reply {
                    Reply::Describe => (
                        request_header,
                        Response::Describe(DescribeResponse {
                            ci_event: selector_state.identity(KeySelector::CiEvent),
                            nip98: selector_state.identity(KeySelector::Nip98),
                            manifest: selector_state.identity(KeySelector::Manifest),
                            peer_policy: expected_client_policy(),
                        }),
                    ),
                    Reply::Stale => (
                        request_header,
                        Response::Error {
                            operation: request.operation(),
                            error: ErrorResponse {
                                code: ErrorCode::StaleGeneration,
                                current_generation: 11,
                            },
                        },
                    ),
                    Reply::SignCiEvent => {
                        use nostr::secp256k1::{Keypair, SecretKey};

                        let Request::SignCiEvent(request) = request else {
                            panic!("sign request")
                        };
                        let digest: [u8; 32] =
                            Sha256::digest(request.canonical_event.as_bytes()).into();
                        let mut scalar = [0_u8; 32];
                        scalar[31] = 1;
                        let secret = SecretKey::from_slice(&scalar).expect("secret");
                        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
                        (
                            request_header,
                            Response::SignCiEvent(SignatureResponse {
                                identity: selector_state.identity(KeySelector::CiEvent),
                                signed_digest: digest,
                                signature: SECP256K1
                                    .sign_schnorr_no_aux_rand(
                                        &Message::from_digest(digest),
                                        &keypair,
                                    )
                                    .serialize(),
                            }),
                        )
                    }
                    Reply::DescribeAcceptance => (
                        request_header,
                        Response::DescribeAcceptance(DescribeAcceptanceResponse {
                            actor: PublicIdentity {
                                public_key: selector_state
                                    .identity(KeySelector::CiEvent)
                                    .public_key,
                                generation: 10,
                            },
                            scenario_sha256: [9; 32],
                            event_ids: [[1; 32], [2; 32], [3; 32], [4; 32]],
                        }),
                    ),
                    Reply::SignAcceptance => {
                        use nostr::secp256k1::{Keypair, SecretKey};

                        let Request::SignAcceptanceMutation(request) = request else {
                            panic!("acceptance sign request")
                        };
                        assert_eq!(request.scenario_sha256, [9; 32]);
                        assert_eq!(request.mutation, AcceptanceMutation::Run);
                        let mut scalar = [0_u8; 32];
                        scalar[31] = 1;
                        let secret = SecretKey::from_slice(&scalar).expect("secret");
                        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
                        let digest = [1; 32];
                        (
                            request_header,
                            Response::SignAcceptanceMutation(SignatureResponse {
                                identity: PublicIdentity {
                                    public_key: selector_state
                                        .identity(KeySelector::CiEvent)
                                        .public_key,
                                    generation: 10,
                                },
                                signed_digest: digest,
                                signature: SECP256K1
                                    .sign_schnorr_no_aux_rand(
                                        &Message::from_digest(digest),
                                        &keypair,
                                    )
                                    .serialize(),
                            }),
                        )
                    }
                    Reply::WrongOperation => {
                        let header = FrameHeader {
                            operation: Operation::SignManifest,
                            request_id: request_header.request_id,
                        };
                        (
                            header,
                            Response::Error {
                                operation: Operation::SignManifest,
                                error: ErrorResponse {
                                    code: ErrorCode::Unavailable,
                                    current_generation: 0,
                                },
                            },
                        )
                    }
                    Reply::WrongRequestId => {
                        let header = FrameHeader {
                            operation: request_header.operation,
                            request_id: [0x55; 16],
                        };
                        (
                            header,
                            Response::Error {
                                operation: request_header.operation,
                                error: ErrorResponse {
                                    code: ErrorCode::Unavailable,
                                    current_generation: 0,
                                },
                            },
                        )
                    }
                    Reply::Stall => unreachable!(),
                };
                let encoded = encode_response(response_header, &response).expect("response");
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write response");
            }
        });
        ready_rx.recv().expect("server ready");
        (directory, path, handle)
    }

    #[test]
    fn config_rejects_noncanonical_path_unknown_fields_and_invalid_bounds() {
        let value = serde_json::json!({
            "keyholder_socket": KEYHOLDER_SOCKET_PATH,
            "keyholder_uid": 1000,
            "keyholder_gid": 1001,
            "keyholder_selectors": bindings(),
            "keyholder_timeout_millis": 500,
            "keyholder_transport_attempts": 2,
            "key_path": "/forbidden"
        });
        assert!(serde_json::from_value::<KeyholderClientConfig>(value).is_err());
        let mut invalid = config(PathBuf::from("/wrong.sock"), 500, 2);
        assert_eq!(invalid.validate(), Err(KeyholderError::InvalidConfig));
        invalid.keyholder_socket = PathBuf::from(KEYHOLDER_SOCKET_PATH);
        invalid.keyholder_timeout_millis = 0;
        assert_eq!(invalid.validate(), Err(KeyholderError::InvalidConfig));
    }

    #[test]
    fn stale_generation_is_terminal_and_public() {
        let (_directory, path, server) = spawn_server(vec![Reply::Describe, Reply::Stale]);
        let mut client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        let request = SignCiEventRequest {
            expected_generation: 7,
            event_kind: 46_101,
            canonical_event: CanonicalPayload::new(
                format!(r#"[0,"{CI_KEY}",1,46101,[],"{{}}"]"#).into_bytes(),
            )
            .expect("payload"),
        };
        assert_eq!(
            KeyholderClient::sign_ci_event(&mut client, request),
            Err(KeyholderError::StaleGeneration { current: 11 })
        );
        server.join().expect("server");
    }

    #[test]
    fn ci_signer_builds_an_event_from_only_the_remote_signature() {
        let (_directory, path, server) = spawn_server(vec![Reply::Describe, Reply::SignCiEvent]);
        let mut client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        let signed = CiSigner::sign(&mut client, 46_101, "{}", serde_json::json!([]))
            .expect("remote signature");
        let event: Event = serde_json::from_value(signed.signed_event).expect("signed event");
        event.verify().expect("valid event");
        assert_eq!(event.pubkey.to_hex(), CI_KEY);
        server.join().expect("server");
    }

    #[test]
    fn acceptance_authority_description_and_signature_are_exactly_bound() {
        let (_directory, path, server) = spawn_server(vec![
            Reply::Describe,
            Reply::DescribeAcceptance,
            Reply::SignAcceptance,
        ]);
        let client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        let description = client
            .describe_acceptance()
            .expect("acceptance description");
        assert_eq!(description.scenario_sha256, [9; 32]);
        assert_eq!(description.event_ids[0], [1; 32]);

        let signature = client
            .sign_acceptance_mutation(
                description.actor,
                description.scenario_sha256,
                AcceptanceMutation::Run,
                description.event_ids[0],
            )
            .expect("acceptance signature");
        assert_eq!(signature.signed_digest, description.event_ids[0]);
        server.join().expect("server");
    }

    #[test]
    fn wrong_operation_and_request_id_are_rejected() {
        for reply in [Reply::WrongOperation, Reply::WrongRequestId] {
            let (_directory, path, server) = spawn_server(vec![reply]);
            assert!(matches!(
                UnixKeyholderClient::connect_for_test(config(path, 500, 1)),
                Err(KeyholderError::Protocol)
            ));
            server.join().expect("server");
        }
    }

    #[test]
    fn timeout_is_bounded_and_retries_stop_at_the_configured_limit() {
        let (_directory, path, server) = spawn_server(vec![Reply::Stall, Reply::Stall]);
        let started = std::time::Instant::now();
        assert!(matches!(
            UnixKeyholderClient::connect_for_test(config(path, 40, 2)),
            Err(KeyholderError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().expect("server");
    }

    #[test]
    fn absent_socket_fails_closed() {
        let directory = tempfile::tempdir().expect("socket directory");
        assert!(matches!(
            UnixKeyholderClient::connect_for_test(config(
                directory.path().join("missing.sock"),
                50,
                1,
            )),
            Err(KeyholderError::Unavailable)
        ));
    }
}
