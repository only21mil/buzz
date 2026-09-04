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
    ManifestKind, Nip98AuthorizeRequest, Nip98Signer, OperationSet, PeerPolicy, PublicIdentity,
    QueryFilter, Request, Response, SelectorSet, SignAcceptanceMutationRequest, SignCiEventRequest,
    SignManifestRequest, SignatureResponse, Url as KeyholderUrl, HEADER_SIZE,
    KEYHOLDER_SOCKET_PATH, MAX_BODY_SIZE,
};
use nostr::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use nostr::{Event, Tag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::production::{CiSigner, SignedCiEvent};
use crate::source::{HttpMethod, Nip98Authorization, Nip98Authorizer, Nip98Binding, Nip98Proof};

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
    /// Activation-bound acceptance actor, bound after the keyholder's
    /// `describe_acceptance` matched the receipt. Only a client that publishes
    /// the five frozen acceptance events binds one.
    acceptance_actor: Option<PublicIdentity>,
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
        let mut client = Self {
            config,
            ci_pubkey,
            acceptance_actor: None,
        };
        let description = KeyholderClient::describe(&mut client, DescribeRequest)?;
        client.validate_description(description)?;
        Ok(client)
    }

    #[cfg(test)]
    fn connect_for_test(config: KeyholderClientConfig) -> Result<Self, KeyholderError> {
        config.validate_common()?;
        Self::connect_validated(config)
    }

    /// Bind the acceptance actor this client may name as a `POST /events`
    /// publisher. The actor must be distinct from every keyholder selector.
    pub fn bind_acceptance_actor(&mut self, actor: PublicIdentity) -> Result<(), KeyholderError> {
        let selectors = self.config.keyholder_selectors.selector_set()?;
        if actor.public_key == [0; 32]
            || actor.generation == 0
            || [
                KeySelector::CiEvent,
                KeySelector::Nip98,
                KeySelector::Manifest,
            ]
            .iter()
            .any(|selector| selectors.identity(*selector).public_key == actor.public_key)
        {
            return Err(KeyholderError::InvalidConfig);
        }
        XOnlyPublicKey::from_slice(&actor.public_key).map_err(|_| KeyholderError::InvalidConfig)?;
        self.acceptance_actor = Some(actor);
        Ok(())
    }

    /// Identity that signs a NIP-98 token for the given signer.
    fn nip98_identity(&self, signer: Nip98Signer) -> Result<PublicIdentity, KeyholderError> {
        match signer {
            Nip98Signer::Nip98 => self.config.expected_identity(KeySelector::Nip98),
            Nip98Signer::CiEvent => self.config.expected_identity(KeySelector::CiEvent),
            Nip98Signer::AcceptanceActor => {
                self.acceptance_actor.ok_or(KeyholderError::WrongIdentity)
            }
        }
    }

    /// Select the token signer for one binding: a publish names its event
    /// author and that author must be an identity this client holds; any
    /// other route is the dedicated NIP-98 identity. Fails closed otherwise.
    fn nip98_signer(&self, binding: &Nip98Binding) -> Result<Nip98Signer, KeyholderError> {
        let Some(publisher) = binding.publisher.as_deref() else {
            return Ok(Nip98Signer::Nip98);
        };
        let publisher = decode_digest(publisher)?;
        if publisher
            == self
                .config
                .expected_identity(KeySelector::CiEvent)?
                .public_key
        {
            return Ok(Nip98Signer::CiEvent);
        }
        if self
            .acceptance_actor
            .is_some_and(|actor| actor.public_key == publisher)
        {
            return Ok(Nip98Signer::AcceptanceActor);
        }
        Err(KeyholderError::WrongIdentity)
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
        if !keyholder_listener_accepted(peer.pid(), peer.uid(), peer.gid(), &self.config) {
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
        expected_identity: PublicIdentity,
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
            identity,
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
        let identity = self.config.expected_identity(KeySelector::CiEvent)?;
        self.signature_response(Request::SignCiEvent(request), identity, digest)
    }

    fn nip98_authorize(
        &mut self,
        request: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        let identity = self.nip98_identity(request.signer)?;
        let digest = nip98_digest(identity.public_key, &request)?;
        self.signature_response(Request::Nip98Authorize(request), identity, digest)
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
        let identity = self.config.expected_identity(KeySelector::Manifest)?;
        self.signature_response(
            Request::SignManifest(request),
            identity,
            digest.finalize().into(),
        )
    }
}

impl CiSigner for UnixKeyholderClient {
    type Error = KeyholderError;

    fn pubkey(&self) -> &str {
        &self.ci_pubkey
    }

    fn generation(&self) -> u64 {
        self.config.keyholder_selectors.ci_event.generation
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

    fn authorization(&mut self, binding: &Nip98Binding) -> Result<Nip98Authorization, Self::Error> {
        binding
            .validate()
            .map_err(|_| KeyholderError::InvalidInput)?;
        let method = protocol_method(binding.method);
        let payload_digest = binding
            .payload_sha256
            .as_deref()
            .map(decode_digest)
            .transpose()?;
        let signer = self.nip98_signer(binding)?;
        let identity = self.nip98_identity(signer)?;
        let created_at = unix_time()?;
        let nonce = *Uuid::new_v4().as_bytes();
        // The exact-event query carries its literal body so the keyholder
        // checks the filter itself before it signs.
        let query_filter = binding
            .query_filter
            .clone()
            .map(QueryFilter::new)
            .transpose()
            .map_err(|_| KeyholderError::InvalidInput)?;
        let request = Nip98AuthorizeRequest {
            expected_generation: identity.generation,
            method,
            url: KeyholderUrl::new(binding.url.as_str().to_owned())
                .map_err(|_| KeyholderError::InvalidInput)?,
            payload_digest,
            created_at,
            nonce,
            signer,
            query_filter,
        };
        let response = KeyholderClient::nip98_authorize(self, request)?;
        // The keyholder answered with the identity chosen above; a publish
        // token must carry the event author or the relay refuses the event.
        if let Some(publisher) = binding.publisher.as_deref() {
            if hex::encode(response.identity.public_key) != publisher {
                return Err(KeyholderError::WrongIdentity);
            }
        }
        let mut tags = vec![
            serde_json::json!(["u", binding.url.as_str()]),
            serde_json::json!(["method", binding.method.as_str()]),
        ];
        if let Some(digest) = payload_digest {
            tags.push(serde_json::json!(["payload", hex::encode(digest)]));
        }
        tags.push(serde_json::json!(["nonce", hex::encode(nonce)]));
        let proof = Nip98Proof {
            subject: hex::encode(response.identity.public_key),
            generation: response.identity.generation,
            event_id: hex::encode(response.signed_digest),
        };
        let event = signed_event(response, created_at, NIP98_EVENT_KIND, tags, "")?;
        let json = serde_json::to_vec(&event).map_err(|_| KeyholderError::Protocol)?;
        Ok(Nip98Authorization::new(
            format!("Nostr {}", BASE64.encode(json)),
            proof,
        ))
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

/// `SO_PEERCRED` names the process that called `listen()`. Production binds
/// `/run/buzzci/keyholder.sock` through `buzz-ci-keyholder.socket`, so the
/// kernel reports pid 1 root even though `buzz-ci-keyholder.service` accepts
/// the connection as its own account. The shared rule from the acceptance
/// driver accepts exactly that listener or the keyholder account itself;
/// [`validate_socket_file`] has already proven the inode is the keyholder's
/// (owner uid, controld's group, mode `0620` under root-owned `0711`
/// `/run/buzzci`).
#[cfg(target_os = "linux")]
fn keyholder_listener_accepted(
    pid: i32,
    uid: u32,
    gid: u32,
    config: &KeyholderClientConfig,
) -> bool {
    use buzz_ci_acceptance_ctl::production::{listener_peer_accepted, ListenerPeer};

    listener_peer_accepted(
        ListenerPeer { pid, uid, gid },
        config.keyholder_uid,
        config.keyholder_gid,
    )
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
        /// Sign a NIP-98 request with the key its `signer` names.
        Nip98,
        /// Answer a NIP-98 request with the nip98 identity whatever it named.
        Nip98WrongKey,
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

    fn scalar_key(scalar: u8) -> (nostr::secp256k1::Keypair, [u8; 32]) {
        use nostr::secp256k1::{Keypair, SecretKey};

        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let secret = SecretKey::from_slice(&bytes).expect("secret");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        (keypair, keypair.x_only_public_key().0.serialize())
    }

    fn actor_identity() -> PublicIdentity {
        PublicIdentity {
            public_key: scalar_key(4).1,
            generation: 10,
        }
    }

    fn publish_binding(publisher: &str) -> Nip98Binding {
        Nip98Binding {
            method: HttpMethod::Post,
            url: url::Url::parse("https://relay.example.test/events").expect("url"),
            payload_sha256: Some("11".repeat(32)),
            publisher: Some(publisher.to_owned()),
            query_filter: None,
        }
    }

    fn token_event(header: &str) -> Event {
        let encoded = header.strip_prefix("Nostr ").expect("nostr scheme");
        let json = BASE64.decode(encoded).expect("base64 token");
        let event: Event = serde_json::from_slice(&json).expect("token event");
        event.verify().expect("token signature");
        event
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
                            event_ids: [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
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
                    Reply::Nip98 | Reply::Nip98WrongKey => {
                        let Request::Nip98Authorize(request) = request else {
                            panic!("nip98 request")
                        };
                        // A query token carries the literal filter whose
                        // SHA-256 is the payload digest; no other route does.
                        let is_query = request.url.as_str().ends_with("/query");
                        match (&request.query_filter, request.payload_digest) {
                            (Some(filter), Some(digest)) if is_query => assert_eq!(
                                <[u8; 32]>::from(Sha256::digest(filter.as_bytes())),
                                digest,
                                "query filter bytes must be the digested body"
                            ),
                            (None, _) if !is_query => {}
                            other => panic!("query filter binding: {other:?}"),
                        }
                        let (scalar, generation) = match (reply, request.signer) {
                            (Reply::Nip98WrongKey, _) | (_, Nip98Signer::Nip98) => (2, 8),
                            (_, Nip98Signer::CiEvent) => (1, 7),
                            (_, Nip98Signer::AcceptanceActor) => (4, 10),
                        };
                        let (keypair, public_key) = scalar_key(scalar);
                        let digest = nip98_digest(public_key, &request).expect("digest");
                        (
                            request_header,
                            Response::Nip98Authorize(SignatureResponse {
                                identity: PublicIdentity {
                                    public_key,
                                    generation,
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
    fn publish_tokens_carry_the_event_author_and_reads_keep_the_nip98_identity() {
        let (_directory, path, server) = spawn_server(vec![
            Reply::Describe,
            Reply::Nip98,
            Reply::Nip98,
            Reply::Nip98,
        ]);
        let mut client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        client
            .bind_acceptance_actor(actor_identity())
            .expect("bind actor");
        let actor_hex = hex::encode(actor_identity().public_key);

        let read = Nip98Binding {
            method: HttpMethod::Get,
            url: url::Url::parse(
                "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=0&limit=1",
            )
            .expect("url"),
            payload_sha256: None,
            publisher: None,
            query_filter: None,
        };
        let authorization = client.authorization(&read).expect("read token");
        let token = token_event(authorization.header());
        assert_eq!(token.pubkey.to_hex(), NIP98_KEY);
        assert_eq!(token.kind.as_u16() as u32, NIP98_EVENT_KIND);

        let authorization = client
            .authorization(&publish_binding(CI_KEY))
            .expect("status publish token");
        let token = token_event(authorization.header());
        assert_eq!(token.pubkey.to_hex(), CI_KEY);

        let authorization = client
            .authorization(&publish_binding(&actor_hex))
            .expect("acceptance publish token");
        let token = token_event(authorization.header());
        assert_eq!(token.pubkey.to_hex(), actor_hex);
        server.join().expect("server");
    }

    #[test]
    fn pending_publication_reconciliation_requests_an_exact_event_query_token_as_the_author() {
        use crate::production::RelayControl as _;
        use crate::source::{AuthenticatedRelay, HttpRequest, HttpResponse, HttpTransport};
        use nostr::{EventBuilder, Keys, Kind};

        struct RecordingTransport {
            requests: Vec<HttpRequest>,
        }

        impl HttpTransport for RecordingTransport {
            type Error = ();

            fn execute(&mut self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
                self.requests.push(request);
                Ok(HttpResponse {
                    status: 200,
                    body: b"[]".to_vec(),
                })
            }
        }

        // The pending event was signed by the ci-event key the keyholder holds.
        let keys = Keys::parse(&format!("{}01", "00".repeat(31))).expect("ci-event key");
        assert_eq!(keys.public_key().to_hex(), CI_KEY);
        let event = EventBuilder::new(Kind::Custom(46101), "{}")
            .sign_with_keys(&keys)
            .expect("signed event");
        let signed = SignedCiEvent {
            event_id: event.id.to_hex(),
            kind: 46101,
            content: "{}".to_owned(),
            tags: serde_json::to_value(&event.tags).expect("tags"),
            signed_event: serde_json::to_value(&event).expect("event"),
        };

        let (_directory, path, server) = spawn_server(vec![Reply::Describe, Reply::Nip98]);
        let client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        let mut relay = AuthenticatedRelay::new(
            url::Url::parse("https://relay.example.test/").expect("url"),
            RecordingTransport {
                requests: Vec::new(),
            },
            client,
        )
        .expect("relay");

        assert!(!relay
            .publication_exists(&signed)
            .expect("exact-event query"));
        let (transport, _client) = relay.into_parts();
        server.join().expect("server");

        let [request] = transport.requests.as_slice() else {
            panic!("exactly one relay request");
        };
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.url.as_str(), "https://relay.example.test/query");
        let token = token_event(&request.headers["authorization"]);
        assert_eq!(token.pubkey.to_hex(), CI_KEY);
        assert_eq!(token.kind.as_u16() as u32, NIP98_EVENT_KIND);
        let tag = |name: &str| {
            token
                .tags
                .iter()
                .map(|tag| tag.as_slice())
                .find(|tag| tag.first().map(String::as_str) == Some(name))
                .map(|tag| tag[1].clone())
                .expect(name)
        };
        assert_eq!(tag("u"), "https://relay.example.test/query");
        assert_eq!(tag("method"), "POST");
        assert_eq!(tag("payload"), hex::encode(Sha256::digest(&request.body)));
        // The body is the canonical one-event filter naming the ci-event key
        // as author; the fake keyholder checked that the token request carried
        // exactly these bytes as its filter before it signed.
        assert_eq!(
            request.body,
            format!(
                r#"[{{"ids":["{}"],"authors":["{CI_KEY}"],"kinds":[46101],"limit":1}}]"#,
                event.id.to_hex()
            )
            .into_bytes()
        );
    }

    #[test]
    fn publish_with_an_unknown_author_is_refused_before_any_keyholder_request() {
        let (_directory, path, server) = spawn_server(vec![Reply::Describe]);
        let mut client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        // nip98.key signs no event, the manifest key signs no event, and the
        // actor is not bound on this client.
        for publisher in [
            NIP98_KEY,
            MANIFEST_KEY,
            &hex::encode(actor_identity().public_key),
        ] {
            assert!(matches!(
                client.authorization(&publish_binding(publisher)),
                Err(KeyholderError::WrongIdentity)
            ));
        }
        // The actor may not collide with a selector.
        assert_eq!(
            client.bind_acceptance_actor(PublicIdentity {
                public_key: scalar_key(2).1,
                generation: 10,
            }),
            Err(KeyholderError::InvalidConfig)
        );
        server.join().expect("server");
    }

    #[test]
    fn a_token_identity_that_differs_from_the_publisher_is_refused() {
        let (_directory, path, server) = spawn_server(vec![Reply::Describe, Reply::Nip98WrongKey]);
        let mut client = UnixKeyholderClient::connect_for_test(config(path, 500, 1))
            .expect("authenticated client");
        assert!(matches!(
            client.authorization(&publish_binding(CI_KEY)),
            Err(KeyholderError::WrongIdentity)
        ));
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
    fn listener_rule_accepts_the_socket_unit_or_the_keyholder_and_rejects_the_rest() {
        let config = KeyholderClientConfig {
            keyholder_uid: 1202,
            keyholder_gid: 1202,
            ..config(PathBuf::from("/run/buzzci/keyholder.sock"), 100, 1)
        };
        // pid 1 root: the shape a systemd socket unit reports (H4 probe, H5 rule).
        assert!(keyholder_listener_accepted(1, 0, 0, &config));
        // The keyholder service bound the socket itself.
        assert!(keyholder_listener_accepted(4242, 1202, 1202, &config));
        for (pid, uid, gid) in [
            (4242, 0, 0),
            (0, 0, 0),
            (-1, 0, 0),
            (1, 1202, 0),
            (1, 0, 1202),
            (4242, 1202, 1203),
            (4242, 1203, 1202),
            (4242, 1201, 1201),
        ] {
            assert!(
                !keyholder_listener_accepted(pid, uid, gid, &config),
                "{pid} {uid}:{gid}"
            );
        }
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
