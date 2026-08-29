use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url as ParsedUrl;
use uuid::Uuid;

use buzz_ci_broker_protocol::v2::{
    decode_admission_signature_message, AdmissionSignatureAlgorithm,
};

use crate::{
    BackendError, DescribeRequest, DescribeResponse, ErrorCode, ErrorResponse, HttpMethod,
    KeySelector, KeyholderServer, Nip98AuthorizeRequest, Operation, PeerIdentity, PeerPolicy,
    PublicIdentity, Request, Response, SelectorSet, SignCiEventRequest, SignManifestRequest,
    SignatureResponse, SigningBackend,
};

const CI_EVENT_KIND_MIN: u32 = 46_101;
const CI_EVENT_KIND_MAX: u32 = 46_106;
const NIP98_EVENT_KIND: u32 = 27_235;
const NIP98_TIMESTAMP_TOLERANCE_SECONDS: u64 = 60;

/// Closed operation policy and public selector state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningPolicy {
    peer_policy: PeerPolicy,
    selectors: SelectorSet,
    nip98_origin: String,
}

impl SigningPolicy {
    /// Construct and validate the complete production policy.
    pub fn new(
        peer_policy: PeerPolicy,
        selectors: SelectorSet,
        nip98_origin: String,
    ) -> Result<Self, ServiceError> {
        let nip98_origin = Self::validate_nip98_origin(&nip98_origin)?;
        Ok(Self {
            peer_policy,
            selectors,
            nip98_origin,
        })
    }

    pub(crate) fn validate_nip98_origin(value: &str) -> Result<String, ServiceError> {
        let parsed = ParsedUrl::parse(value).map_err(|_| ServiceError::InvalidRequest)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ServiceError::InvalidRequest);
        }
        let origin = parsed.origin().ascii_serialization();
        if origin == "null" {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(origin)
    }

    fn authorize_nip98(&self, request: &Nip98AuthorizeRequest) -> Result<(), ServiceError> {
        let parsed =
            ParsedUrl::parse(request.url.as_str()).map_err(|_| ServiceError::InvalidRequest)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.origin().ascii_serialization() != self.nip98_origin
        {
            return Err(ServiceError::PolicyDenied);
        }
        let path = parsed.path();
        if path.contains('%') || path.contains("//") || path.ends_with('/') {
            return Err(ServiceError::PolicyDenied);
        }
        if request.method == HttpMethod::Get {
            return authorize_accepted_read(&parsed, request);
        }
        if parsed.query().is_some()
            || !matches!(request.payload_digest, Some(digest) if digest != [0; 32])
        {
            return Err(ServiceError::PolicyDenied);
        }
        let segments = path
            .strip_prefix('/')
            .ok_or(ServiceError::PolicyDenied)?
            .split('/')
            .collect::<Vec<_>>();
        let allowed = match (request.method, segments.as_slice()) {
            (HttpMethod::Post, ["events"]) => true,
            (HttpMethod::Put, ["ci", "logs", fields @ ..]) => fields.len() == 5,
            (HttpMethod::Put, ["ci", "artifacts", fields @ ..]) => fields.len() == 6,
            _ => false,
        };
        if !allowed
            || segments.iter().any(|segment| {
                segment.is_empty()
                    || *segment == "."
                    || *segment == ".."
                    || !segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
        {
            return Err(ServiceError::PolicyDenied);
        }
        Ok(())
    }
}

fn authorize_accepted_read(
    parsed: &ParsedUrl,
    request: &Nip98AuthorizeRequest,
) -> Result<(), ServiceError> {
    if parsed.path() != "/ci/control/accepted" || request.payload_digest.is_some() {
        return Err(ServiceError::PolicyDenied);
    }
    let query = parsed.query().ok_or(ServiceError::PolicyDenied)?;
    let mut fields = query.split('&');
    let channel_id = fields
        .next()
        .and_then(|field| field.strip_prefix("channel_id="))
        .ok_or(ServiceError::PolicyDenied)?;
    let after_cursor = fields
        .next()
        .and_then(|field| field.strip_prefix("after_cursor="))
        .ok_or(ServiceError::PolicyDenied)?;
    if fields.next() != Some("limit=1") || fields.next().is_some() {
        return Err(ServiceError::PolicyDenied);
    }
    let channel_uuid = Uuid::parse_str(channel_id).map_err(|_| ServiceError::PolicyDenied)?;
    let cursor = after_cursor
        .parse::<u64>()
        .map_err(|_| ServiceError::PolicyDenied)?;
    if channel_uuid.hyphenated().to_string() != channel_id
        || cursor.to_string() != after_cursor
        || cursor > buzz_ci_broker_protocol::MAX_SAFE_INTEGER
    {
        return Err(ServiceError::PolicyDenied);
    }
    Ok(())
}

/// Sanitized service failure mapped to the closed public protocol errors.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    /// Peer credentials or operation are not authorized.
    #[error("keyholder request is unauthorized")]
    Unauthorized,
    /// The request violates the fixed signing policy.
    #[error("keyholder signing policy denied the request")]
    PolicyDenied,
    /// The request selected an inactive generation.
    #[error("keyholder generation is stale")]
    StaleGeneration { current: u64 },
    /// Public request bytes are not canonical or structurally valid.
    #[error("keyholder request is invalid")]
    InvalidRequest,
    /// The signing backend is unavailable or does not match policy.
    #[error("keyholder signing backend is unavailable")]
    Unavailable,
}

impl From<BackendError> for ServiceError {
    fn from(_: BackendError) -> Self {
        Self::Unavailable
    }
}

/// Policy-enforcing production keyholder over an injected signing backend.
pub struct ProductionKeyholder<B> {
    policy: SigningPolicy,
    backend: B,
}

impl<B: SigningBackend> ProductionKeyholder<B> {
    /// Construct a service only if every loaded key matches its public selector.
    pub fn new(policy: SigningPolicy, backend: B) -> Result<Self, ServiceError> {
        for selector in [
            KeySelector::CiEvent,
            KeySelector::Nip98,
            KeySelector::Manifest,
        ] {
            if backend.public_key(selector)? != policy.selectors.identity(selector).public_key {
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(Self { policy, backend })
    }

    /// Exact operating-system peer policy enforced by this service.
    pub const fn peer_policy(&self) -> PeerPolicy {
        self.policy.peer_policy
    }

    /// Dispatch one already-framed request and always return a bound public response.
    pub fn handle(&self, peer: PeerIdentity, request: Request) -> Response {
        let operation = request.operation();
        let result = match request {
            Request::Describe(request) => self.describe(peer, request).map(Response::Describe),
            Request::SignCiEvent(request) => {
                self.sign_ci_event(peer, request).map(Response::SignCiEvent)
            }
            Request::Nip98Authorize(request) => self
                .nip98_authorize(peer, request)
                .map(Response::Nip98Authorize),
            Request::SignManifest(request) => self
                .sign_manifest(peer, request)
                .map(Response::SignManifest),
        };
        result.unwrap_or_else(|error| Response::Error {
            operation,
            error: self.public_error(&error),
        })
    }

    fn authorize(&self, peer: PeerIdentity, operation: Operation) -> Result<(), ServiceError> {
        self.policy
            .peer_policy
            .authorizes(peer, operation)
            .then_some(())
            .ok_or(ServiceError::Unauthorized)
    }

    fn identity_for_generation(
        &self,
        selector: KeySelector,
        expected_generation: u64,
    ) -> Result<PublicIdentity, ServiceError> {
        let identity = self.policy.selectors.identity(selector);
        if identity.generation != expected_generation {
            return Err(ServiceError::StaleGeneration {
                current: identity.generation,
            });
        }
        Ok(identity)
    }

    fn signature(
        &self,
        selector: KeySelector,
        identity: PublicIdentity,
        digest: [u8; 32],
    ) -> Result<SignatureResponse, ServiceError> {
        if digest == [0; 32] {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(SignatureResponse {
            identity,
            signed_digest: digest,
            signature: self.backend.sign_digest(selector, digest)?,
        })
    }
}

impl<B: SigningBackend> KeyholderServer for ProductionKeyholder<B> {
    type Error = ServiceError;

    fn describe(
        &self,
        peer: PeerIdentity,
        _: DescribeRequest,
    ) -> Result<DescribeResponse, Self::Error> {
        self.authorize(peer, Operation::Describe)?;
        Ok(DescribeResponse {
            ci_event: self.policy.selectors.ci_event(),
            nip98: self.policy.selectors.nip98(),
            manifest: self.policy.selectors.manifest(),
            peer_policy: self.policy.peer_policy,
        })
    }

    fn sign_ci_event(
        &self,
        peer: PeerIdentity,
        request: SignCiEventRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        self.authorize(peer, Operation::SignCiEvent)?;
        let identity =
            self.identity_for_generation(KeySelector::CiEvent, request.expected_generation)?;
        if !(CI_EVENT_KIND_MIN..=CI_EVENT_KIND_MAX).contains(&request.event_kind) {
            return Err(ServiceError::PolicyDenied);
        }
        validate_ci_event(
            request.canonical_event.as_bytes(),
            identity.public_key,
            request.event_kind,
        )?;
        self.signature(
            KeySelector::CiEvent,
            identity,
            Sha256::digest(request.canonical_event.as_bytes()).into(),
        )
    }

    fn nip98_authorize(
        &self,
        peer: PeerIdentity,
        request: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        self.authorize(peer, Operation::Nip98Authorize)?;
        let identity =
            self.identity_for_generation(KeySelector::Nip98, request.expected_generation)?;
        self.policy.authorize_nip98(&request)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceError::Unavailable)?
            .as_secs();
        if now.abs_diff(request.created_at) > NIP98_TIMESTAMP_TOLERANCE_SECONDS {
            return Err(ServiceError::PolicyDenied);
        }
        let digest = nip98_event_digest(identity.public_key, &request)?;
        self.signature(KeySelector::Nip98, identity, digest)
    }

    fn sign_manifest(
        &self,
        peer: PeerIdentity,
        request: SignManifestRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        self.authorize(peer, Operation::SignManifest)?;
        let identity =
            self.identity_for_generation(KeySelector::Manifest, request.expected_generation)?;
        match request.manifest_kind {
            crate::ManifestKind::LaneActivationV1 => Err(ServiceError::PolicyDenied),
            crate::ManifestKind::JobIntentV2 => {
                let admission =
                    decode_admission_signature_message(request.canonical_manifest.as_bytes())
                        .map_err(|_| ServiceError::InvalidRequest)?;
                if admission.admission_signature_algorithm
                    != AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256
                    || admission.admission_key_generation != identity.generation
                {
                    return Err(ServiceError::PolicyDenied);
                }
                self.signature(
                    KeySelector::Manifest,
                    identity,
                    Sha256::digest(request.canonical_manifest.as_bytes()).into(),
                )
            }
        }
    }

    fn public_error(&self, error: &Self::Error) -> ErrorResponse {
        match error {
            ServiceError::Unauthorized => ErrorResponse {
                code: ErrorCode::Unauthorized,
                current_generation: 0,
            },
            ServiceError::PolicyDenied => ErrorResponse {
                code: ErrorCode::PolicyDenied,
                current_generation: 0,
            },
            ServiceError::StaleGeneration { current } => ErrorResponse {
                code: ErrorCode::StaleGeneration,
                current_generation: *current,
            },
            ServiceError::InvalidRequest => ErrorResponse {
                code: ErrorCode::InvalidRequest,
                current_generation: 0,
            },
            ServiceError::Unavailable => ErrorResponse {
                code: ErrorCode::Unavailable,
                current_generation: 0,
            },
        }
    }
}

fn validate_ci_event(
    bytes: &[u8],
    expected_public_key: [u8; 32],
    expected_kind: u32,
) -> Result<(), ServiceError> {
    let value = validate_canonical_json(bytes)?;
    let fields = value.as_array().ok_or(ServiceError::InvalidRequest)?;
    if fields.len() != 6
        || fields[0].as_u64() != Some(0)
        || fields[1].as_str() != Some(hex::encode(expected_public_key).as_str())
        || fields[2].as_u64().is_none()
        || fields[3].as_u64() != Some(u64::from(expected_kind))
        || !fields[4].is_array()
        || fields[5].as_str().is_none()
    {
        return Err(ServiceError::InvalidRequest);
    }
    let tags = fields[4].as_array().ok_or(ServiceError::InvalidRequest)?;
    if tags.iter().any(|tag| {
        tag.as_array()
            .is_none_or(|values| values.is_empty() || values.iter().any(|value| !value.is_string()))
    }) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(())
}

fn validate_canonical_json(bytes: &[u8]) -> Result<serde_json::Value, ServiceError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::InvalidRequest)?;
    let mut canonical = Vec::with_capacity(bytes.len());
    append_canonical_json(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(value)
}

fn append_canonical_json(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), ServiceError> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {
            serde_json::to_writer(output, value).map_err(|_| ServiceError::InvalidRequest)?;
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| ServiceError::InvalidRequest)?;
                output.push(b':');
                append_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn nip98_event_digest(
    public_key: [u8; 32],
    request: &Nip98AuthorizeRequest,
) -> Result<[u8; 32], ServiceError> {
    let mut tags = vec![
        serde_json::json!(["u", request.url.as_str()]),
        serde_json::json!(["method", http_method(request.method)]),
    ];
    if let Some(payload_digest) = request.payload_digest {
        tags.push(serde_json::json!(["payload", hex::encode(payload_digest)]));
    }
    tags.push(serde_json::json!(["nonce", hex::encode(request.nonce)]));
    let event = serde_json::json!([
        0,
        hex::encode(public_key),
        request.created_at,
        NIP98_EVENT_KIND,
        tags,
        ""
    ]);
    let canonical = serde_json::to_vec(&event).map_err(|_| ServiceError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}

const fn http_method(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use buzz_ci_broker_protocol::v2::{
        admission_signature_message, AdmissionSignatureAlgorithm, AdmitAttemptRequest,
    };
    use buzz_ci_broker_protocol::{GitOid, TrustClass};

    use super::*;
    use crate::{CanonicalPayload, ManifestKind, OperationSet, Url};

    #[derive(Debug)]
    struct FakeBackend {
        public_keys: [[u8; 32]; 3],
        calls: RefCell<Vec<(KeySelector, [u8; 32])>>,
    }

    impl SigningBackend for FakeBackend {
        fn public_key(&self, selector: KeySelector) -> Result<[u8; 32], BackendError> {
            Ok(self.public_keys[index(selector)])
        }

        fn sign_digest(
            &self,
            selector: KeySelector,
            digest: [u8; 32],
        ) -> Result<[u8; 64], BackendError> {
            self.calls.borrow_mut().push((selector, digest));
            let mut signature = [0_u8; 64];
            signature[..32].copy_from_slice(&digest);
            signature[32] = index(selector) as u8 + 1;
            Ok(signature)
        }
    }

    const fn index(selector: KeySelector) -> usize {
        match selector {
            KeySelector::CiEvent => 0,
            KeySelector::Nip98 => 1,
            KeySelector::Manifest => 2,
        }
    }

    fn service(operations: OperationSet) -> ProductionKeyholder<FakeBackend> {
        let public_keys = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];
        let selectors = SelectorSet::new(
            PublicIdentity {
                public_key: public_keys[0],
                generation: 7,
            },
            PublicIdentity {
                public_key: public_keys[1],
                generation: 8,
            },
            PublicIdentity {
                public_key: public_keys[2],
                generation: 9,
            },
        )
        .expect("selectors");
        let policy = SigningPolicy::new(
            PeerPolicy {
                uid: 1000,
                gid: 1001,
                allowed_operations: operations,
            },
            selectors,
            "https://relay.example.test".to_owned(),
        )
        .expect("policy");
        ProductionKeyholder::new(
            policy,
            FakeBackend {
                public_keys,
                calls: RefCell::new(Vec::new()),
            },
        )
        .expect("service")
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            gid: 1001,
        }
    }

    fn admission_message(generation: u64) -> Vec<u8> {
        admission_signature_message(&AdmitAttemptRequest {
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
            issued_at: 100,
            expires_at: 200,
            lane_epoch: 4,
            admission_key_generation: generation,
            wall_timeout_seconds: 60,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
        })
    }

    #[test]
    fn exact_peer_operation_and_generation_are_required_before_signing() {
        let service = service(OperationSet::only(Operation::SignManifest));
        let manifest = || SignManifestRequest {
            expected_generation: 9,
            manifest_kind: ManifestKind::JobIntentV2,
            canonical_manifest: CanonicalPayload::new(admission_message(9)).expect("payload"),
        };
        assert!(matches!(
            service.handle(
                PeerIdentity {
                    uid: 1000,
                    gid: 1002
                },
                Request::SignManifest(manifest())
            ),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::Unauthorized,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            service.handle(peer(), Request::Describe(DescribeRequest)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::Unauthorized,
                    ..
                },
                ..
            }
        ));
        let mut stale = manifest();
        stale.expected_generation = 8;
        assert!(matches!(
            service.handle(peer(), Request::SignManifest(stale)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::StaleGeneration,
                    current_generation: 9
                },
                ..
            }
        ));
        assert!(service.backend.calls.borrow().is_empty());
        assert!(matches!(
            service.handle(peer(), Request::SignManifest(manifest())),
            Response::SignManifest(_)
        ));
        assert_eq!(service.backend.calls.borrow().len(), 1);

        let wrong_embedded_generation = SignManifestRequest {
            expected_generation: 9,
            manifest_kind: ManifestKind::JobIntentV2,
            canonical_manifest: CanonicalPayload::new(admission_message(8)).expect("payload"),
        };
        assert!(matches!(
            service.handle(peer(), Request::SignManifest(wrong_embedded_generation)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::PolicyDenied,
                    ..
                },
                ..
            }
        ));

        let static_lane = SignManifestRequest {
            expected_generation: 9,
            manifest_kind: ManifestKind::LaneActivationV1,
            canonical_manifest: CanonicalPayload::new(br#"{"lane":"one"}"#.to_vec())
                .expect("payload"),
        };
        assert!(matches!(
            service.handle(peer(), Request::SignManifest(static_lane)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::PolicyDenied,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn ci_event_must_be_exact_canonical_preimage_for_the_selected_key_and_kind() {
        let service = service(OperationSet::only(Operation::SignCiEvent));
        let event = serde_json::to_vec(&serde_json::json!([
            0,
            hex::encode([1_u8; 32]),
            1_800_000_000_u64,
            46_101,
            [["d", "run"]],
            "{}"
        ]))
        .expect("canonical event");
        let response = service.handle(
            peer(),
            Request::SignCiEvent(SignCiEventRequest {
                expected_generation: 7,
                event_kind: 46_101,
                canonical_event: CanonicalPayload::new(event.clone()).expect("payload"),
            }),
        );
        let Response::SignCiEvent(signature) = response else {
            panic!("event should sign");
        };
        assert_eq!(signature.signed_digest, Sha256::digest(&event).as_slice());

        let noncanonical = format!(" {}", String::from_utf8(event).expect("UTF-8"));
        assert!(matches!(
            service.handle(
                peer(),
                Request::SignCiEvent(SignCiEventRequest {
                    expected_generation: 7,
                    event_kind: 46_101,
                    canonical_event: CanonicalPayload::new(noncanonical.into_bytes())
                        .expect("payload"),
                })
            ),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::InvalidRequest,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn nip98_is_bound_to_the_exact_https_origin_and_canonical_event_digest() {
        let service = service(OperationSet::only(Operation::Nip98Authorize));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let request = Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Post,
            url: Url::new("https://relay.example.test/events".to_owned()).expect("url"),
            payload_digest: Some([4_u8; 32]),
            created_at: now,
            nonce: [5_u8; 16],
        };
        let expected = nip98_event_digest([2_u8; 32], &request).expect("digest");
        let response = service.handle(peer(), Request::Nip98Authorize(request));
        let Response::Nip98Authorize(signature) = response else {
            panic!("authorization should sign");
        };
        assert_eq!(signature.signed_digest, expected);

        let accepted_read_url = "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1";
        let accepted_read = Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Get,
            url: Url::new(accepted_read_url.to_owned()).expect("url"),
            payload_digest: None,
            created_at: now,
            nonce: [6; 16],
        };
        let expected = nip98_event_digest([2; 32], &accepted_read).expect("digest");
        let response = service.handle(peer(), Request::Nip98Authorize(accepted_read));
        let Response::Nip98Authorize(signature) = response else {
            panic!("accepted read should sign");
        };
        assert_eq!(signature.signed_digest, expected);

        for (index, url) in [
            "https://relay.example.test/ci/control/accepted?after_cursor=42&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&after_cursor=43&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1&extra=1",
            "https://relay.example.test/ci/control/accepted?after_cursor=42&channel_id=123e4567-e89b-12d3-a456-426614174000&limit=1",
            "https://relay.example.test/ci/control/accepted/other?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123E4567-E89B-12D3-A456-426614174000&after_cursor=42&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567e89b12d3a456426614174000&after_cursor=42&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=042&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=9007199254740992&limit=1",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=2",
            "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1#fragment",
        ]
        .into_iter()
        .enumerate()
        {
            let denied = Nip98AuthorizeRequest {
                expected_generation: 8,
                method: HttpMethod::Get,
                url: Url::new(url.to_owned()).expect("url"),
                payload_digest: None,
                created_at: now,
                nonce: [u8::try_from(index + 20).expect("bounded index"); 16],
            };
            assert!(matches!(
                service.handle(peer(), Request::Nip98Authorize(denied)),
                Response::Error {
                    error: ErrorResponse {
                        code: ErrorCode::PolicyDenied,
                        ..
                    },
                    ..
                }
            ));
        }

        let payload_on_get = Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Get,
            url: Url::new(accepted_read_url.to_owned()).expect("url"),
            payload_digest: Some([9; 32]),
            created_at: now,
            nonce: [40; 16],
        };
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(payload_on_get)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::PolicyDenied,
                    ..
                },
                ..
            }
        ));

        for denied in [
            Nip98AuthorizeRequest {
                expected_generation: 8,
                method: HttpMethod::Get,
                url: Url::new("https://relay.example.test/events".to_owned()).expect("url"),
                payload_digest: Some([4; 32]),
                created_at: now,
                nonce: [8; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                method: HttpMethod::Post,
                url: Url::new("https://relay.example.test/events?drift=1".to_owned()).expect("url"),
                payload_digest: Some([4; 32]),
                created_at: now,
                nonce: [9; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                method: HttpMethod::Put,
                url: Url::new("https://relay.example.test/ci/logs/a/b/c/d/e".to_owned())
                    .expect("url"),
                payload_digest: None,
                created_at: now,
                nonce: [10; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                method: HttpMethod::Put,
                url: Url::new("https://relay.example.test/ci/artifacts/a/b/c/d/e/f".to_owned())
                    .expect("url"),
                payload_digest: Some([0; 32]),
                created_at: now,
                nonce: [11; 16],
            },
        ] {
            assert!(matches!(
                service.handle(peer(), Request::Nip98Authorize(denied)),
                Response::Error {
                    error: ErrorResponse {
                        code: ErrorCode::PolicyDenied,
                        ..
                    },
                    ..
                }
            ));
        }

        let denied = Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Get,
            url: Url::new("https://other.example.test/".to_owned()).expect("url"),
            payload_digest: None,
            created_at: now,
            nonce: [6_u8; 16],
        };
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(denied)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::PolicyDenied,
                    ..
                },
                ..
            }
        ));

        let stale = Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Get,
            url: Url::new(accepted_read_url.to_owned()).expect("url"),
            payload_digest: None,
            created_at: now.saturating_sub(NIP98_TIMESTAMP_TOLERANCE_SECONDS + 1),
            nonce: [7_u8; 16],
        };
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(stale)),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::PolicyDenied,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn backend_public_key_mismatch_prevents_service_construction() {
        let selectors = SelectorSet::new(
            PublicIdentity {
                public_key: [9_u8; 32],
                generation: 1,
            },
            PublicIdentity {
                public_key: [2_u8; 32],
                generation: 1,
            },
            PublicIdentity {
                public_key: [3_u8; 32],
                generation: 1,
            },
        )
        .expect("selectors");
        let policy = SigningPolicy::new(
            PeerPolicy {
                uid: 1,
                gid: 1,
                allowed_operations: OperationSet::ALL,
            },
            selectors,
            "https://relay.example.test".to_owned(),
        )
        .expect("policy");
        let backend = FakeBackend {
            public_keys: [[1_u8; 32], [2_u8; 32], [3_u8; 32]],
            calls: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            ProductionKeyholder::new(policy, backend),
            Err(ServiceError::Unavailable)
        ));
    }
}
