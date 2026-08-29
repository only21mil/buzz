//! Authenticated relay source and publication adapter.
//!
//! The adapter deliberately owns no socket implementation. A reviewed host
//! supplies an HTTP transport and a NIP-98 authorizer; this module binds both
//! to exact request bytes and validates every relay response fail-closed.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use buzz_core::ci::{validate_signed_ci_event, ValidatedCiEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::keyholder::KeyholderClientConfig;
use crate::production::{
    AcceptedRequest, ArtifactCompletion, JobCompletion, RelayControl, SignedCiEvent, StoredObject,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const CONFIG_MODE: u32 = 0o600;

/// Complete opt-in source configuration. Omitting the keyholder binding or any
/// other field is a parse error, so the default binary remains closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySourceConfig {
    pub schema_version: u32,
    pub relay_base_url: String,
    pub channel_id: String,
    pub store_root: PathBuf,
    pub keyholder: KeyholderClientConfig,
}

impl RelaySourceConfig {
    #[cfg(target_os = "linux")]
    pub fn load(path: &Path, expected_owner_uid: u32) -> Result<Self, SourceError> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;

        validate_config_path(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| SourceError::ConfigUnavailable)?;
        validate_config_metadata(&before, expected_owner_uid)?;
        if fs::canonicalize(path).map_err(|_| SourceError::ConfigUnavailable)? != path {
            return Err(SourceError::InsecureConfig);
        }
        if before.len() > MAX_CONFIG_BYTES {
            return Err(SourceError::InvalidConfig);
        }
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SourceError::ConfigUnavailable)?;
        let file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| SourceError::ConfigUnavailable)?;
        validate_config_metadata(&opened, expected_owner_uid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(SourceError::InsecureConfig);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SourceError::ConfigUnavailable)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(SourceError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| SourceError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_path: &Path, _expected_owner_uid: u32) -> Result<Self, SourceError> {
        Err(SourceError::ConfigUnavailable)
    }

    pub fn validate(&self) -> Result<(), SourceError> {
        if self.schema_version != 1 || self.channel_id.is_empty() || self.channel_id.len() > 512 {
            return Err(SourceError::InvalidConfig);
        }
        validate_config_path(&self.store_root)?;
        self.keyholder
            .validate()
            .map_err(|_| SourceError::InvalidConfig)?;
        AuthenticatedRelay::<(), ()>::validate_base_url(&self.relay_base_url)?;
        Ok(())
    }

    pub fn relay_url(&self) -> Result<Url, SourceError> {
        Url::parse(&self.relay_base_url).map_err(|_| SourceError::InvalidConfig)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// The exact values covered by one fresh NIP-98 authorization event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nip98Binding {
    pub method: HttpMethod,
    pub url: Url,
    pub payload_sha256: Option<String>,
}

impl Nip98Binding {
    pub fn validate(&self) -> Result<(), SourceError> {
        if !matches!(self.url.scheme(), "http" | "https")
            || self.url.host_str().is_none()
            || !self.url.username().is_empty()
            || self.url.password().is_some()
            || self.url.fragment().is_some()
        {
            return Err(SourceError::InvalidBinding);
        }
        match (self.method, self.payload_sha256.as_deref()) {
            (HttpMethod::Get, None) => Ok(()),
            (HttpMethod::Post | HttpMethod::Put, Some(digest)) if is_lower_hex(digest, 64) => {
                Ok(())
            }
            _ => Err(SourceError::InvalidBinding),
        }
    }
}

pub trait Nip98Authorizer {
    type Error;

    fn authorization(&mut self, binding: &Nip98Binding) -> Result<String, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: Url,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait HttpTransport {
    type Error;

    fn execute(&mut self, request: HttpRequest) -> Result<HttpResponse, Self::Error>;
}

/// Zero-redirect production HTTP transport with bounded response reads.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
    max_response_bytes: usize,
}

impl ReqwestTransport {
    pub fn new(
        connect_timeout: std::time::Duration,
        request_timeout: std::time::Duration,
        max_response_bytes: usize,
    ) -> Result<Self, TransportError> {
        if connect_timeout.is_zero() || request_timeout.is_zero() || max_response_bytes == 0 {
            return Err(TransportError::InvalidConfig);
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(Self {
            client,
            max_response_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("HTTP transport configuration is invalid")]
    InvalidConfig,
    #[error("HTTP transport is unavailable")]
    Unavailable,
    #[error("HTTP response exceeds the byte limit")]
    Oversized,
}

impl HttpTransport for ReqwestTransport {
    type Error = TransportError;

    fn execute(&mut self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
        };
        let mut builder = self.client.request(method, request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let mut response = builder
            .body(request.body)
            .send()
            .map_err(|_| TransportError::Unavailable)?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(TransportError::Oversized);
        }
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .by_ref()
            .take(self.max_response_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| TransportError::Unavailable)?;
        if body.len() > self.max_response_bytes {
            return Err(TransportError::Oversized);
        }
        Ok(HttpResponse { status, body })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SourceError {
    #[error("relay source configuration is invalid")]
    InvalidConfig,
    #[error("relay source configuration is unavailable")]
    ConfigUnavailable,
    #[error("relay source configuration metadata is insecure")]
    InsecureConfig,
    #[error("NIP-98 request binding is invalid")]
    InvalidBinding,
    #[error("NIP-98 authorization failed")]
    Authorization,
    #[error("relay transport failed")]
    Transport,
    #[error("relay refused the operation")]
    RelayRefused,
    #[error("relay response is invalid")]
    InvalidResponse,
    #[error("relay returned an invalid CI request")]
    InvalidRequest,
}

/// Synchronous production adapter over an injected HTTP client.
pub struct AuthenticatedRelay<T, A> {
    base_url: Url,
    transport: T,
    authorizer: A,
}

impl<T, A> AuthenticatedRelay<T, A> {
    fn validate_base_url(value: &str) -> Result<(), SourceError> {
        let base_url = Url::parse(value).map_err(|_| SourceError::InvalidConfig)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.path() != "/"
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(SourceError::InvalidConfig);
        }
        Ok(())
    }

    pub fn new(base_url: Url, transport: T, authorizer: A) -> Result<Self, SourceError> {
        Self::validate_base_url(base_url.as_str())?;
        Ok(Self {
            base_url,
            transport,
            authorizer,
        })
    }

    pub fn into_parts(self) -> (T, A) {
        (self.transport, self.authorizer)
    }
}

impl<T, A> AuthenticatedRelay<T, A>
where
    T: HttpTransport,
    A: Nip98Authorizer,
{
    fn endpoint(&self, path: &str) -> Result<Url, SourceError> {
        self.base_url
            .join(path)
            .map_err(|_| SourceError::InvalidConfig)
    }

    fn request(
        &mut self,
        method: HttpMethod,
        url: Url,
        body: Vec<u8>,
    ) -> Result<HttpResponse, SourceError> {
        let payload_sha256 =
            (method != HttpMethod::Get).then(|| hex::encode(Sha256::digest(&body)));
        let binding = Nip98Binding {
            method,
            url: url.clone(),
            payload_sha256,
        };
        binding.validate()?;
        let authorization = self
            .authorizer
            .authorization(&binding)
            .map_err(|_| SourceError::Authorization)?;
        if authorization.is_empty() || authorization.contains(['\r', '\n']) {
            return Err(SourceError::Authorization);
        }
        let mut headers = BTreeMap::new();
        headers.insert("authorization".to_owned(), authorization);
        headers.insert("accept".to_owned(), "application/json".to_owned());
        headers.insert("content-length".to_owned(), body.len().to_string());
        match method {
            HttpMethod::Post => {
                headers.insert("content-type".to_owned(), "application/json".to_owned());
            }
            HttpMethod::Put => {
                headers.insert(
                    "content-type".to_owned(),
                    "application/octet-stream".to_owned(),
                );
            }
            HttpMethod::Get => {}
        }
        let response = self
            .transport
            .execute(HttpRequest {
                method,
                url,
                headers,
                body,
            })
            .map_err(|_| SourceError::Transport)?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(SourceError::InvalidResponse);
        }
        if !(200..300).contains(&response.status) {
            return Err(SourceError::RelayRefused);
        }
        Ok(response)
    }

    fn put_object(&mut self, path: &str, bytes: &[u8]) -> Result<StoredObject, SourceError> {
        let url = self.endpoint(path)?;
        let response = self.request(HttpMethod::Put, url.clone(), bytes.to_vec())?;
        let stored: StoredObjectWire =
            serde_json::from_slice(&response.body).map_err(|_| SourceError::InvalidResponse)?;
        stored.validate()?;
        if Url::parse(&stored.url).map_err(|_| SourceError::InvalidResponse)? != url {
            return Err(SourceError::InvalidResponse);
        }
        Ok(StoredObject {
            url: stored.url,
            sha256: stored.sha256,
            byte_length: stored.byte_length,
        })
    }
}

impl<T, A> RelayControl for AuthenticatedRelay<T, A>
where
    T: HttpTransport,
    A: Nip98Authorizer,
{
    type Error = SourceError;

    fn next_accepted(
        &mut self,
        channel_id: &str,
        after_cursor: u64,
    ) -> Result<Option<AcceptedRequest>, Self::Error> {
        if channel_id.is_empty() {
            return Err(SourceError::InvalidConfig);
        }
        let mut url = self.endpoint("ci/control/accepted")?;
        url.query_pairs_mut()
            .append_pair("channel_id", channel_id)
            .append_pair("after_cursor", &after_cursor.to_string())
            .append_pair("limit", "1");
        let response = self.request(HttpMethod::Get, url, Vec::new())?;
        let wire: AcceptedResponse =
            serde_json::from_slice(&response.body).map_err(|_| SourceError::InvalidResponse)?;
        let Some(item) = wire.accepted else {
            return Ok(None);
        };
        if item.channel_id != channel_id || item.watch_cursor <= after_cursor {
            return Err(SourceError::InvalidRequest);
        }
        let event: nostr::Event =
            serde_json::from_value(item.event).map_err(|_| SourceError::InvalidRequest)?;
        let event_id = event.id.to_hex();
        let envelope = match validate_signed_ci_event(&event, channel_id, &HashSet::new())
            .map_err(|_| SourceError::InvalidRequest)?
        {
            ValidatedCiEnvelope::Request(envelope) => envelope,
            _ => return Err(SourceError::InvalidRequest),
        };
        Ok(Some(AcceptedRequest {
            channel_id: item.channel_id,
            watch_cursor: item.watch_cursor,
            event_id,
            envelope,
        }))
    }

    fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
        if !is_lower_hex(&event.event_id, 64) {
            return Err(SourceError::InvalidRequest);
        }
        let event_value: nostr::Event = serde_json::from_value(event.signed_event.clone())
            .map_err(|_| SourceError::InvalidRequest)?;
        event_value
            .verify()
            .map_err(|_| SourceError::InvalidRequest)?;
        if event_value.id.to_hex() != event.event_id
            || event_value.kind.as_u16() as u32 != event.kind
            || event_value.content != event.content
        {
            return Err(SourceError::InvalidRequest);
        }
        let body =
            serde_json::to_vec(&event.signed_event).map_err(|_| SourceError::InvalidRequest)?;
        let url = self.endpoint("events")?;
        let response = self.request(HttpMethod::Post, url, body)?;
        let reply: PublishResponse =
            serde_json::from_slice(&response.body).map_err(|_| SourceError::InvalidResponse)?;
        let exact_duplicate = !reply.accepted && reply.message.starts_with("duplicate:");
        if reply.event_id != event.event_id || (!reply.accepted && !exact_duplicate) {
            return Err(SourceError::RelayRefused);
        }
        Ok(reply.event_id)
    }

    fn put_log(
        &mut self,
        accepted: &AcceptedRequest,
        job: &JobCompletion,
        bytes: &[u8],
    ) -> Result<StoredObject, Self::Error> {
        self.put_object(
            &format!(
                "ci/logs/{}/{}/{}/{}/{}",
                accepted.event_id,
                accepted.envelope.run_id,
                job.metadata.job_id,
                job.attempt,
                job.log.sha256
            ),
            bytes,
        )
    }

    fn put_artifact(
        &mut self,
        accepted: &AcceptedRequest,
        job: &JobCompletion,
        artifact: &ArtifactCompletion,
        bytes: &[u8],
    ) -> Result<StoredObject, Self::Error> {
        self.put_object(
            &format!(
                "ci/artifacts/{}/{}/{}/{}/{}/{}",
                accepted.event_id,
                accepted.envelope.run_id,
                job.metadata.job_id,
                job.attempt,
                artifact.artifact_id,
                artifact.descriptor.sha256
            ),
            bytes,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedResponse {
    accepted: Option<AcceptedWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedWire {
    channel_id: String,
    watch_cursor: u64,
    event: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishResponse {
    event_id: String,
    accepted: bool,
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredObjectWire {
    url: String,
    sha256: String,
    byte_length: u64,
}

impl StoredObjectWire {
    fn validate(&self) -> Result<(), SourceError> {
        let url = Url::parse(&self.url).map_err(|_| SourceError::InvalidResponse)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !is_lower_hex(&self.sha256, 64)
        {
            return Err(SourceError::InvalidResponse);
        }
        Ok(())
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_config_path(path: &Path) -> Result<(), SourceError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(SourceError::InvalidConfig);
    }
    Ok(())
}

fn validate_config_metadata(
    metadata: &fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), SourceError> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != CONFIG_MODE
        || metadata.uid() != expected_owner_uid
        || metadata.nlink() != 1
    {
        return Err(SourceError::InsecureConfig);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::mpsc;
    use std::thread;

    use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
    use buzz_core::kind::KIND_CI_REQUEST;
    use nostr::{EventBuilder, Keys, Kind};

    use super::*;

    #[derive(Default)]
    struct RecordingAuth {
        bindings: Vec<Nip98Binding>,
    }

    impl Nip98Authorizer for RecordingAuth {
        type Error = ();

        fn authorization(&mut self, binding: &Nip98Binding) -> Result<String, Self::Error> {
            self.bindings.push(binding.clone());
            Ok("Nostr synthetic".to_owned())
        }
    }

    struct RecordingTransport {
        response: HttpResponse,
        requests: Vec<HttpRequest>,
    }

    impl HttpTransport for RecordingTransport {
        type Error = ();

        fn execute(&mut self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            self.requests.push(request);
            Ok(self.response.clone())
        }
    }

    #[test]
    fn auth_is_bound_to_exact_method_url_and_payload() {
        let bytes = b"log bytes";
        let digest = hex::encode(Sha256::digest(bytes));
        let response = StoredObjectWire {
            url: "https://relay.example/ci/logs/id/run/job/1".to_owned(),
            sha256: digest.clone(),
            byte_length: bytes.len() as u64,
        };
        let transport = RecordingTransport {
            response: HttpResponse {
                status: 201,
                body: serde_json::to_vec(&response).expect("response"),
            },
            requests: Vec::new(),
        };
        let mut relay = AuthenticatedRelay::new(
            Url::parse("https://relay.example/").expect("url"),
            transport,
            RecordingAuth::default(),
        )
        .expect("relay");
        let stored = relay
            .put_object("ci/logs/id/run/job/1", bytes)
            .expect("put");
        assert_eq!(stored.sha256, digest);
        let (transport, authorizer) = relay.into_parts();
        assert_eq!(transport.requests.len(), 1);
        assert_eq!(authorizer.bindings.len(), 1);
        let request = &transport.requests[0];
        let binding = &authorizer.bindings[0];
        assert_eq!(binding.method, HttpMethod::Put);
        assert_eq!(binding.url, request.url);
        assert_eq!(binding.payload_sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(request.body, bytes);
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Nostr synthetic")
        );
    }

    #[test]
    fn relay_refusal_is_terminal_and_does_not_parse_body() {
        let transport = RecordingTransport {
            response: HttpResponse {
                status: 403,
                body: b"secret server detail".to_vec(),
            },
            requests: Vec::new(),
        };
        let mut relay = AuthenticatedRelay::new(
            Url::parse("https://relay.example/").expect("url"),
            transport,
            RecordingAuth::default(),
        )
        .expect("relay");
        assert_eq!(
            relay.put_object("ci/logs/id", b"body").unwrap_err(),
            SourceError::RelayRefused
        );
    }

    #[test]
    fn reqwest_transport_executes_one_bounded_zero_redirect_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let (sent, received) = mpsc::channel();
        let fixture = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept fixture request");
            let mut request = [0_u8; 4096];
            let length = socket.read(&mut request).expect("read fixture request");
            sent.send(String::from_utf8_lossy(&request[..length]).into_owned())
                .expect("record request");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                )
                .expect("write fixture response");
        });
        let mut transport = ReqwestTransport::new(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
            128,
        )
        .expect("transport");
        let response = transport
            .execute(HttpRequest {
                method: HttpMethod::Put,
                url: Url::parse(&format!("http://{address}/ci/logs/test")).expect("url"),
                headers: BTreeMap::from([
                    ("authorization".to_owned(), "Nostr synthetic".to_owned()),
                    (
                        "content-type".to_owned(),
                        "application/octet-stream".to_owned(),
                    ),
                ]),
                body: b"fixture".to_vec(),
            })
            .expect("request");
        fixture.join().expect("fixture thread");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        let request = received.recv().expect("recorded request");
        assert!(request.starts_with("PUT /ci/logs/test HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: nostr synthetic"));
    }

    #[test]
    fn exact_duplicate_publication_reconciles_as_idempotent_success() {
        let keys = Keys::parse(&"02".repeat(32)).expect("synthetic key");
        let event = EventBuilder::new(Kind::Custom(46101), "{}")
            .sign_with_keys(&keys)
            .expect("signed event");
        let event_id = event.id.to_hex();
        let signed = SignedCiEvent {
            event_id: event_id.clone(),
            kind: 46101,
            content: "{}".to_owned(),
            tags: serde_json::to_value(&event.tags).expect("tags"),
            signed_event: serde_json::to_value(event).expect("event"),
        };
        let transport = RecordingTransport {
            response: HttpResponse {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({
                    "event_id": event_id,
                    "accepted": false,
                    "message": "duplicate:"
                }))
                .expect("response"),
            },
            requests: Vec::new(),
        };
        let mut relay = AuthenticatedRelay::new(
            Url::parse("https://relay.example/").expect("url"),
            transport,
            RecordingAuth::default(),
        )
        .expect("relay");
        assert_eq!(relay.publish(&signed).expect("idempotent replay"), event_id);
    }

    #[test]
    fn accepted_source_verifies_signature_envelope_channel_and_cursor() {
        let keys = Keys::parse(&"01".repeat(32)).expect("synthetic key");
        let channel = "123e4567-e89b-12d3-a456-426614174099";
        let envelope = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
            pr_root_event_id: "33".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_owned(),
            immutable_source_ref: "refs/nostr/source".to_owned(),
            tip_oid: "44".repeat(20),
            source_branch: "feature".to_owned(),
            base_ref: "refs/heads/main".to_owned(),
            base_oid: "55".repeat(20),
            workflow_id: "ci".to_owned(),
            workflow_digest: "66".repeat(32),
            job_ids: vec!["test".to_owned()],
            run_id: "123e4567-e89b-12d3-a456-426614174011".to_owned(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "33".repeat(32),
            actor: keys.public_key().to_hex(),
            timeout_seconds: 30,
            idempotency_key: "123e4567-e89b-12d3-a456-426614174012".to_owned(),
            issued_at: 10,
            expires_at: 40,
        };
        let content = serde_json::to_string(&envelope).expect("content");
        let tags = request_tags(channel, &envelope).expect("tags");
        let event = EventBuilder::new(Kind::Custom(KIND_CI_REQUEST as u16), content)
            .tags(tags)
            .sign_with_keys(&keys)
            .expect("sign request");
        let transport = RecordingTransport {
            response: HttpResponse {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({
                    "accepted": {
                        "channel_id": channel,
                        "watch_cursor": 8,
                        "event": event
                    }
                }))
                .expect("response"),
            },
            requests: Vec::new(),
        };
        let mut relay = AuthenticatedRelay::new(
            Url::parse("https://relay.example/").expect("url"),
            transport,
            RecordingAuth::default(),
        )
        .expect("relay");
        let accepted = relay
            .next_accepted(channel, 7)
            .expect("source")
            .expect("accepted");
        assert_eq!(accepted.event_id, event.id.to_hex());
        assert_eq!(accepted.envelope, envelope);
        assert_eq!(accepted.watch_cursor, 8);
        let (transport, authorizer) = relay.into_parts();
        assert_eq!(transport.requests[0].method, HttpMethod::Get);
        assert_eq!(authorizer.bindings[0].url, transport.requests[0].url);
        assert_eq!(authorizer.bindings[0].payload_sha256, None);
    }

    #[test]
    fn malformed_bindings_fail_closed() {
        let cases = [
            Nip98Binding {
                method: HttpMethod::Get,
                url: Url::parse("https://relay.example/a").expect("url"),
                payload_sha256: Some("11".repeat(32)),
            },
            Nip98Binding {
                method: HttpMethod::Post,
                url: Url::parse("https://user@relay.example/a").expect("url"),
                payload_sha256: Some("11".repeat(32)),
            },
            Nip98Binding {
                method: HttpMethod::Put,
                url: Url::parse("https://relay.example/a").expect("url"),
                payload_sha256: None,
            },
        ];
        for binding in cases {
            assert_eq!(binding.validate(), Err(SourceError::InvalidBinding));
        }
    }

    fn valid_config_json(root: &Path) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "relay_base_url": "https://relay.example/community/",
            "channel_id": "channel",
            "store_root": root.join("store"),
            "keyholder": {
                "keyholder_socket": "/run/buzzci/keyholder.sock",
                "keyholder_uid": fs::metadata(root).expect("metadata").uid(),
                "keyholder_gid": fs::metadata(root).expect("metadata").gid(),
                "keyholder_selectors": {
                    "ci_event": {
                        "public_key": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        "generation": 1
                    },
                    "nip98": {
                        "public_key": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                        "generation": 1
                    },
                    "manifest": {
                        "public_key": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                        "generation": 1
                    }
                },
                "keyholder_timeout_millis": 500,
                "keyholder_transport_attempts": 2
            }
        })
    }

    #[test]
    fn config_loader_rejects_missing_unknown_and_insecure_files() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(directory.path()).expect("root");
        let path = root.join("controld.json");
        let uid = fs::metadata(&root).expect("metadata").uid();

        let mut missing = valid_config_json(&root);
        missing.as_object_mut().expect("object").remove("keyholder");
        fs::write(&path, serde_json::to_vec(&missing).expect("json")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            RelaySourceConfig::load(&path, uid),
            Err(SourceError::InvalidConfig)
        );

        let mut unknown = valid_config_json(&root);
        unknown
            .as_object_mut()
            .expect("object")
            .insert("secret".to_owned(), serde_json::json!("forbidden"));
        fs::write(&path, serde_json::to_vec(&unknown).expect("json")).expect("write");
        assert_eq!(
            RelaySourceConfig::load(&path, uid),
            Err(SourceError::InvalidConfig)
        );

        fs::write(
            &path,
            serde_json::to_vec(&valid_config_json(&root)).expect("json"),
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("broad mode");
        assert_eq!(
            RelaySourceConfig::load(&path, uid),
            Err(SourceError::InsecureConfig)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            RelaySourceConfig::load(&path, uid.saturating_add(1)),
            Err(SourceError::InsecureConfig)
        );

        let linked = root.join("linked.json");
        symlink(&path, &linked).expect("symlink");
        assert_eq!(
            RelaySourceConfig::load(&linked, uid),
            Err(SourceError::InsecureConfig)
        );
    }

    #[test]
    fn active_source_config_rejects_local_secret_descriptors() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(directory.path()).expect("root");
        let mut value = valid_config_json(&root);
        let object = value.as_object_mut().expect("object");
        object.remove("keyholder");
        object.insert(
            "key".to_owned(),
            serde_json::json!({
                "path": root.join("ci-status.key"),
                "expected_owner_uid": fs::metadata(&root).expect("metadata").uid(),
                "expected_pubkey": "11".repeat(32)
            }),
        );
        assert!(serde_json::from_value::<RelaySourceConfig>(value).is_err());
    }
}
