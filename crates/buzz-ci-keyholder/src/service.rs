use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url as ParsedUrl;
use uuid::Uuid;

use buzz_ci_acceptance_ctl::acceptance_binding::{
    validate_acceptance_event_templates, ValidatedAcceptanceBinding,
};
use buzz_ci_broker_protocol::v2::{
    decode_admission_signature_message, AdmissionSignatureAlgorithm,
};

use crate::{
    AcceptanceMutation, BackendError, CanonicalPayload, DescribeAcceptanceResponse,
    DescribeRequest, DescribeResponse, ErrorCode, ErrorResponse, HttpMethod, KeySelector,
    KeyholderServer, Nip98AuthorizeRequest, Nip98Signer, Operation, PeerIdentity, PeerPolicy,
    PublicIdentity, Request, Response, SelectorSet, SignAcceptanceMutationRequest,
    SignCiEventRequest, SignManifestRequest, SignatureResponse, SigningBackend,
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
    acceptance: Option<AcceptanceSigningPolicy>,
}

/// Four exact public event templates authorized for one activation scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceSigningPolicy {
    actor: PublicIdentity,
    scenario_sha256: [u8; 32],
    event_ids: [[u8; 32]; 4],
    granted_ci_signer: [u8; 32],
}

impl AcceptanceSigningPolicy {
    /// Validate the actor, scenario, and complete Run/Grant/Rerun/Tombstone template set.
    pub fn new(
        actor: PublicIdentity,
        scenario_sha256: [u8; 32],
        templates: [CanonicalPayload; 4],
    ) -> Result<Self, ServiceError> {
        if actor.public_key == [0; 32] || actor.generation == 0 || scenario_sha256 == [0; 32] {
            return Err(ServiceError::InvalidRequest);
        }
        let validated = validate_acceptance_event_templates(
            actor.public_key,
            templates.each_ref().map(CanonicalPayload::as_bytes),
        )
        .map_err(|_| ServiceError::InvalidRequest)?;
        Ok(Self {
            actor,
            scenario_sha256,
            event_ids: validated.event_ids(),
            granted_ci_signer: validated.granted_ci_signer(),
        })
    }

    pub(crate) fn from_validated(
        actor: PublicIdentity,
        validated: ValidatedAcceptanceBinding,
    ) -> Self {
        Self {
            actor,
            scenario_sha256: validated.scenario_sha256(),
            event_ids: validated.event_ids(),
            granted_ci_signer: validated.granted_ci_signer(),
        }
    }

    /// Dedicated acceptance actor identity.
    pub const fn actor(&self) -> PublicIdentity {
        self.actor
    }

    /// Exact activation scenario digest.
    pub const fn scenario_sha256(&self) -> [u8; 32] {
        self.scenario_sha256
    }

    /// Event IDs in Run, Grant, Rerun, Tombstone order.
    pub const fn event_ids(&self) -> [[u8; 32]; 4] {
        self.event_ids
    }

    fn event_id(&self, mutation: AcceptanceMutation) -> [u8; 32] {
        self.event_ids[mutation_index(mutation)]
    }
}

const fn mutation_index(mutation: AcceptanceMutation) -> usize {
    match mutation {
        AcceptanceMutation::Run => 0,
        AcceptanceMutation::Grant => 1,
        AcceptanceMutation::Rerun => 2,
        AcceptanceMutation::Tombstone => 3,
    }
}

impl SigningPolicy {
    /// Construct and validate the complete production policy.
    pub fn new(
        peer_policy: PeerPolicy,
        selectors: SelectorSet,
        nip98_origin: String,
    ) -> Result<Self, ServiceError> {
        if peer_policy
            .allowed_operations
            .contains(Operation::DescribeAcceptance)
            || peer_policy
                .allowed_operations
                .contains(Operation::SignAcceptanceMutation)
        {
            return Err(ServiceError::InvalidRequest);
        }
        Self::new_base(peer_policy, selectors, nip98_origin)
    }

    fn new_base(
        peer_policy: PeerPolicy,
        selectors: SelectorSet,
        nip98_origin: String,
    ) -> Result<Self, ServiceError> {
        let nip98_origin = Self::validate_nip98_origin(&nip98_origin)?;
        Ok(Self {
            peer_policy,
            selectors,
            nip98_origin,
            acceptance: None,
        })
    }

    /// Construct the production policy with a distinct activation-only actor.
    pub fn new_with_acceptance(
        peer_policy: PeerPolicy,
        selectors: SelectorSet,
        nip98_origin: String,
        acceptance: AcceptanceSigningPolicy,
    ) -> Result<Self, ServiceError> {
        if !peer_policy
            .allowed_operations
            .contains(Operation::DescribeAcceptance)
            || !peer_policy
                .allowed_operations
                .contains(Operation::SignAcceptanceMutation)
        {
            return Err(ServiceError::InvalidRequest);
        }
        let mut policy = Self::new_base(peer_policy, selectors, nip98_origin)?;
        if [
            selectors.ci_event().public_key,
            selectors.nip98().public_key,
            selectors.manifest().public_key,
        ]
        .contains(&acceptance.actor.public_key)
            || acceptance.granted_ci_signer != selectors.ci_event().public_key
        {
            return Err(ServiceError::InvalidRequest);
        }
        policy.acceptance = Some(acceptance);
        Ok(policy)
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
            if request.signer != Nip98Signer::Nip98 {
                return Err(ServiceError::PolicyDenied);
            }
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
        // A publish token is signed by the event's own signer: the relay stores
        // an event only when `event.pubkey` equals the token pubkey, so a
        // `nip98.key` token can never carry a publish. The exact-event query
        // that reconciles a refused CI publication reads back the CI event as
        // its author, so it is signed by the `ci-event.key` selector alone.
        // Every other route is authorized as a CI signer, which stays the
        // `nip98.key` identity.
        let allowed = match (request.method, segments.as_slice()) {
            (HttpMethod::Post, ["events"]) => request.signer != Nip98Signer::Nip98,
            (HttpMethod::Post, ["query"]) => request.signer == Nip98Signer::CiEvent,
            (HttpMethod::Put, ["ci", "logs", fields @ ..]) => {
                fields.len() == 5 && request.signer == Nip98Signer::Nip98
            }
            (HttpMethod::Put, ["ci", "artifacts", fields @ ..]) => {
                fields.len() == 6 && request.signer == Nip98Signer::Nip98
            }
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
        if let Some(acceptance) = &policy.acceptance {
            if backend.acceptance_public_key()? != acceptance.actor.public_key {
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
            Request::DescribeAcceptance(_) => self
                .describe_acceptance(peer)
                .map(Response::DescribeAcceptance),
            Request::SignCiEvent(request) => {
                self.sign_ci_event(peer, request).map(Response::SignCiEvent)
            }
            Request::Nip98Authorize(request) => self
                .nip98_authorize(peer, request)
                .map(Response::Nip98Authorize),
            Request::SignManifest(request) => self
                .sign_manifest(peer, request)
                .map(Response::SignManifest),
            Request::SignAcceptanceMutation(request) => self
                .sign_acceptance_mutation(peer, request)
                .map(Response::SignAcceptanceMutation),
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

    fn acceptance_actor_for_generation(
        &self,
        expected_generation: u64,
    ) -> Result<PublicIdentity, ServiceError> {
        let actor = self
            .policy
            .acceptance
            .as_ref()
            .ok_or(ServiceError::PolicyDenied)?
            .actor;
        if actor.generation != expected_generation {
            return Err(ServiceError::StaleGeneration {
                current: actor.generation,
            });
        }
        Ok(actor)
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

    fn sign_acceptance_mutation(
        &self,
        peer: PeerIdentity,
        request: SignAcceptanceMutationRequest,
    ) -> Result<SignatureResponse, ServiceError> {
        self.authorize(peer, Operation::SignAcceptanceMutation)?;
        let policy = self
            .policy
            .acceptance
            .as_ref()
            .ok_or(ServiceError::PolicyDenied)?;
        if request.scenario_sha256 != policy.scenario_sha256 {
            return Err(ServiceError::PolicyDenied);
        }
        if request.expected_generation != policy.actor.generation {
            return Err(ServiceError::StaleGeneration {
                current: policy.actor.generation,
            });
        }
        let digest = policy.event_id(request.mutation);
        Ok(SignatureResponse {
            identity: policy.actor,
            signed_digest: digest,
            signature: self.backend.sign_acceptance_digest(digest)?,
        })
    }

    fn describe_acceptance(
        &self,
        peer: PeerIdentity,
    ) -> Result<DescribeAcceptanceResponse, ServiceError> {
        self.authorize(peer, Operation::DescribeAcceptance)?;
        let policy = self
            .policy
            .acceptance
            .as_ref()
            .ok_or(ServiceError::PolicyDenied)?;
        Ok(DescribeAcceptanceResponse {
            actor: policy.actor(),
            scenario_sha256: policy.scenario_sha256(),
            event_ids: policy.event_ids(),
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
        let identity = match request.signer {
            Nip98Signer::Nip98 => {
                self.identity_for_generation(KeySelector::Nip98, request.expected_generation)?
            }
            Nip98Signer::CiEvent => {
                self.identity_for_generation(KeySelector::CiEvent, request.expected_generation)?
            }
            Nip98Signer::AcceptanceActor => {
                self.acceptance_actor_for_generation(request.expected_generation)?
            }
        };
        self.policy.authorize_nip98(&request)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceError::Unavailable)?
            .as_secs();
        if now.abs_diff(request.created_at) > NIP98_TIMESTAMP_TOLERANCE_SECONDS {
            return Err(ServiceError::PolicyDenied);
        }
        let digest = nip98_event_digest(identity.public_key, &request)?;
        match request.signer {
            Nip98Signer::Nip98 => self.signature(KeySelector::Nip98, identity, digest),
            Nip98Signer::CiEvent => self.signature(KeySelector::CiEvent, identity, digest),
            Nip98Signer::AcceptanceActor => {
                if digest == [0; 32] {
                    return Err(ServiceError::InvalidRequest);
                }
                Ok(SignatureResponse {
                    identity,
                    signed_digest: digest,
                    signature: self.backend.sign_acceptance_digest(digest)?,
                })
            }
        }
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
pub(crate) mod tests {
    use std::cell::RefCell;

    use buzz_ci_broker_protocol::v2::{
        admission_signature_message, AdmissionSignatureAlgorithm, AdmitAttemptRequest,
    };
    use buzz_ci_broker_protocol::{GitOid, TrustClass};
    use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType};
    use buzz_core::kind::{KIND_CI_GRANT, KIND_CI_REQUEST, KIND_DELETION};

    use super::*;
    use crate::{CanonicalPayload, ManifestKind, OperationSet, Url};

    #[derive(Debug)]
    struct FakeBackend {
        public_keys: [[u8; 32]; 3],
        calls: RefCell<Vec<(KeySelector, [u8; 32])>>,
        acceptance_calls: RefCell<Vec<[u8; 32]>>,
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

        fn acceptance_public_key(&self) -> Result<[u8; 32], BackendError> {
            Ok([4; 32])
        }

        fn sign_acceptance_digest(&self, digest: [u8; 32]) -> Result<[u8; 64], BackendError> {
            self.acceptance_calls.borrow_mut().push(digest);
            let mut signature = [0; 64];
            signature[..32].copy_from_slice(&digest);
            signature[32] = 4;
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
                acceptance_calls: RefCell::new(Vec::new()),
            },
        )
        .expect("service")
    }

    pub(crate) fn acceptance_templates() -> [CanonicalPayload; 4] {
        let actor = hex::encode([4; 32]);
        let channel = "123e4567-e89b-12d3-a456-426614174099";
        let mut run = CiRequestEnvelope {
            schema_version: buzz_core::ci::CI_SCHEMA_VERSION,
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
            actor: actor.clone(),
            timeout_seconds: 30,
            idempotency_key: "run-key".to_owned(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_300,
        };
        let run_tags = request_tags(channel, &run).expect("run tags");
        let run_event = serde_json::json!([
            0,
            actor,
            1_800_000_000_u64,
            KIND_CI_REQUEST,
            run_tags,
            serde_json::to_string(&run).expect("run content")
        ]);
        let grant_event = serde_json::json!([
            0,
            hex::encode([4; 32]),
            1_800_000_001_u64,
            KIND_CI_GRANT,
            [["h", channel]],
            serde_json::to_string(&serde_json::json!({
                "schema_version": 1,
                "target_repo_a": run.target_repo_a,
                "signer_pubkey": hex::encode([1; 32]),
                "valid_from": 1_800_000_001_i64,
                "valid_until": 1_800_000_600_i64
            }))
            .expect("grant content")
        ]);
        run.request_type = CiRequestType::Rerun;
        run.attempt = 2;
        run.parent_attempt = Some(1);
        run.parent_run_id = Some(run.run_id.clone());
        run.idempotency_key = "rerun-key".to_owned();
        run.issued_at += 10;
        run.expires_at += 10;
        let rerun_tags = request_tags(channel, &run).expect("rerun tags");
        let rerun_event = serde_json::json!([
            0,
            hex::encode([4; 32]),
            1_800_000_010_u64,
            KIND_CI_REQUEST,
            rerun_tags,
            serde_json::to_string(&run).expect("rerun content")
        ]);
        let rerun_bytes = serde_json::to_vec(&rerun_event).expect("rerun bytes");
        let tombstone_event = serde_json::json!([
            0,
            hex::encode([4; 32]),
            1_800_000_020_u64,
            KIND_DELETION,
            [["e", hex::encode(Sha256::digest(&rerun_bytes))]],
            ""
        ]);
        [run_event, grant_event, rerun_event, tombstone_event].map(|value| {
            CanonicalPayload::new(serde_json::to_vec(&value).expect("template bytes"))
                .expect("template")
        })
    }

    fn acceptance_service() -> ProductionKeyholder<FakeBackend> {
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
        let acceptance = AcceptanceSigningPolicy::new(
            PublicIdentity {
                public_key: [4; 32],
                generation: 10,
            },
            [9; 32],
            acceptance_templates(),
        )
        .expect("acceptance policy");
        let policy = SigningPolicy::new_with_acceptance(
            PeerPolicy {
                uid: 1000,
                gid: 1001,
                allowed_operations: OperationSet::only(Operation::Describe)
                    .union(OperationSet::only(Operation::Nip98Authorize))
                    .union(OperationSet::only(Operation::DescribeAcceptance))
                    .union(OperationSet::only(Operation::SignAcceptanceMutation)),
            },
            selectors,
            "https://relay.example.test".to_owned(),
            acceptance,
        )
        .expect("policy");
        ProductionKeyholder::new(
            policy,
            FakeBackend {
                public_keys,
                calls: RefCell::new(Vec::new()),
                acceptance_calls: RefCell::new(Vec::new()),
            },
        )
        .expect("service")
    }

    #[test]
    fn acceptance_mutations_sign_only_the_four_described_event_ids() {
        let service = acceptance_service();
        let Response::DescribeAcceptance(description) = service.handle(
            peer(),
            Request::DescribeAcceptance(crate::DescribeAcceptanceRequest),
        ) else {
            panic!("description");
        };
        assert_eq!(
            description.actor,
            PublicIdentity {
                public_key: [4; 32],
                generation: 10
            }
        );
        assert_eq!(description.scenario_sha256, [9; 32]);
        let ids = description.event_ids;
        for (index, mutation) in [
            AcceptanceMutation::Run,
            AcceptanceMutation::Grant,
            AcceptanceMutation::Rerun,
            AcceptanceMutation::Tombstone,
        ]
        .into_iter()
        .enumerate()
        {
            let response = service.handle(
                peer(),
                Request::SignAcceptanceMutation(SignAcceptanceMutationRequest {
                    expected_generation: 10,
                    scenario_sha256: [9; 32],
                    mutation,
                }),
            );
            let Response::SignAcceptanceMutation(signature) = response else {
                panic!("mutation should sign");
            };
            assert_eq!(signature.signed_digest, ids[index]);
            assert_eq!(signature.identity.public_key, [4; 32]);
        }
        assert_eq!(service.backend.acceptance_calls.borrow().as_slice(), &ids);
        assert!(service.backend.calls.borrow().is_empty());
    }

    #[test]
    fn acceptance_generation_scenario_and_template_drift_fail_closed() {
        let service = acceptance_service();
        for request in [
            SignAcceptanceMutationRequest {
                expected_generation: 9,
                scenario_sha256: [9; 32],
                mutation: AcceptanceMutation::Run,
            },
            SignAcceptanceMutationRequest {
                expected_generation: 10,
                scenario_sha256: [8; 32],
                mutation: AcceptanceMutation::Run,
            },
        ] {
            assert!(matches!(
                service.handle(peer(), Request::SignAcceptanceMutation(request)),
                Response::Error { .. }
            ));
        }
        assert!(service.backend.acceptance_calls.borrow().is_empty());

        let mut templates = acceptance_templates();
        let mut tombstone: serde_json::Value =
            serde_json::from_slice(templates[3].as_bytes()).expect("tombstone");
        tombstone[4] = serde_json::json!([["e", "11".repeat(32)]]);
        templates[3] =
            CanonicalPayload::new(serde_json::to_vec(&tombstone).expect("bytes")).expect("payload");
        assert!(AcceptanceSigningPolicy::new(
            PublicIdentity {
                public_key: [4; 32],
                generation: 10,
            },
            [9; 32],
            templates,
        )
        .is_err());
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
            expected_generation: 7,
            signer: Nip98Signer::CiEvent,
            method: HttpMethod::Post,
            url: Url::new("https://relay.example.test/events".to_owned()).expect("url"),
            payload_digest: Some([4_u8; 32]),
            created_at: now,
            nonce: [5_u8; 16],
        };
        let expected = nip98_event_digest([1_u8; 32], &request).expect("digest");
        let response = service.handle(peer(), Request::Nip98Authorize(request));
        let Response::Nip98Authorize(signature) = response else {
            panic!("authorization should sign");
        };
        assert_eq!(signature.signed_digest, expected);
        assert_eq!(signature.identity.public_key, [1_u8; 32]);
        assert_eq!(
            service.backend.calls.borrow().last(),
            Some(&(KeySelector::CiEvent, expected))
        );

        let accepted_read_url = "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1";
        let accepted_read = Nip98AuthorizeRequest {
            expected_generation: 8,
            signer: Nip98Signer::Nip98,
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
                signer: Nip98Signer::Nip98,
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
            signer: Nip98Signer::Nip98,
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
                signer: Nip98Signer::Nip98,
                method: HttpMethod::Get,
                url: Url::new("https://relay.example.test/events".to_owned()).expect("url"),
                payload_digest: Some([4; 32]),
                created_at: now,
                nonce: [8; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                signer: Nip98Signer::Nip98,
                method: HttpMethod::Post,
                url: Url::new("https://relay.example.test/events?drift=1".to_owned()).expect("url"),
                payload_digest: Some([4; 32]),
                created_at: now,
                nonce: [9; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                signer: Nip98Signer::Nip98,
                method: HttpMethod::Put,
                url: Url::new("https://relay.example.test/ci/logs/a/b/c/d/e".to_owned())
                    .expect("url"),
                payload_digest: None,
                created_at: now,
                nonce: [10; 16],
            },
            Nip98AuthorizeRequest {
                expected_generation: 8,
                signer: Nip98Signer::Nip98,
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
            signer: Nip98Signer::Nip98,
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
            signer: Nip98Signer::Nip98,
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

    fn publish_request(
        signer: Nip98Signer,
        generation: u64,
        nonce: u8,
        now: u64,
    ) -> Nip98AuthorizeRequest {
        Nip98AuthorizeRequest {
            expected_generation: generation,
            signer,
            method: HttpMethod::Post,
            url: Url::new("https://relay.example.test/events".to_owned()).expect("url"),
            payload_digest: Some([4_u8; 32]),
            created_at: now,
            nonce: [nonce; 16],
        }
    }

    fn denied_with(response: Response, code: ErrorCode) -> bool {
        matches!(response, Response::Error { error, .. } if error.code == code)
    }

    #[test]
    fn publish_tokens_follow_the_event_signer_and_other_routes_keep_the_nip98_key() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let service = service(OperationSet::only(Operation::Nip98Authorize));

        // The relay refuses a publish whose token pubkey differs from the
        // event pubkey, and nip98.key signs no event: deny it up front.
        assert!(denied_with(
            service.handle(
                peer(),
                Request::Nip98Authorize(publish_request(Nip98Signer::Nip98, 8, 50, now))
            ),
            ErrorCode::PolicyDenied
        ));
        // The event signers never authorize reads or evidence writes.
        let accepted_read_url = "https://relay.example.test/ci/control/accepted?channel_id=123e4567-e89b-12d3-a456-426614174000&after_cursor=42&limit=1";
        for (signer, generation) in [
            (Nip98Signer::CiEvent, 7),
            (Nip98Signer::AcceptanceActor, 10),
        ] {
            let read = Nip98AuthorizeRequest {
                expected_generation: generation,
                signer,
                method: HttpMethod::Get,
                url: Url::new(accepted_read_url.to_owned()).expect("url"),
                payload_digest: None,
                created_at: now,
                nonce: [51; 16],
            };
            let put = Nip98AuthorizeRequest {
                expected_generation: generation,
                signer,
                method: HttpMethod::Put,
                url: Url::new("https://relay.example.test/ci/logs/a/b/c/d/e".to_owned())
                    .expect("url"),
                payload_digest: Some([4; 32]),
                created_at: now,
                nonce: [52; 16],
            };
            for request in [read, put] {
                let response = service.handle(peer(), Request::Nip98Authorize(request));
                assert!(matches!(response, Response::Error { .. }), "{signer:?}");
            }
        }
        // Without an activation binding there is no actor to sign with.
        assert!(denied_with(
            service.handle(
                peer(),
                Request::Nip98Authorize(publish_request(Nip98Signer::AcceptanceActor, 10, 53, now))
            ),
            ErrorCode::PolicyDenied
        ));
        assert!(service.backend.calls.borrow().is_empty());
        assert!(service.backend.acceptance_calls.borrow().is_empty());

        // With the binding, the actor signs a publish token under its own
        // identity and generation, through the acceptance credential.
        let service = acceptance_service();
        let request = publish_request(Nip98Signer::AcceptanceActor, 10, 54, now);
        let expected = nip98_event_digest([4_u8; 32], &request).expect("digest");
        let Response::Nip98Authorize(signature) =
            service.handle(peer(), Request::Nip98Authorize(request))
        else {
            panic!("actor publish token should sign");
        };
        assert_eq!(signature.identity.public_key, [4_u8; 32]);
        assert_eq!(signature.identity.generation, 10);
        assert_eq!(signature.signed_digest, expected);
        assert_eq!(
            service.backend.acceptance_calls.borrow().as_slice(),
            &[expected]
        );
        assert!(service.backend.calls.borrow().is_empty());
        assert!(matches!(
            service.handle(
                peer(),
                Request::Nip98Authorize(publish_request(Nip98Signer::AcceptanceActor, 9, 55, now))
            ),
            Response::Error {
                error: ErrorResponse {
                    code: ErrorCode::StaleGeneration,
                    current_generation: 10,
                },
                ..
            }
        ));
        assert!(denied_with(
            service.handle(
                peer(),
                Request::Nip98Authorize(publish_request(Nip98Signer::Nip98, 8, 56, now))
            ),
            ErrorCode::PolicyDenied
        ));
    }

    fn query_request(
        signer: Nip98Signer,
        generation: u64,
        url: &str,
        payload_digest: Option<[u8; 32]>,
        nonce: u8,
        now: u64,
    ) -> Nip98AuthorizeRequest {
        Nip98AuthorizeRequest {
            expected_generation: generation,
            signer,
            method: HttpMethod::Post,
            url: Url::new(url.to_owned()).expect("url"),
            payload_digest,
            created_at: now,
            nonce: [nonce; 16],
        }
    }

    #[test]
    fn exact_event_query_tokens_are_signed_by_the_ci_event_key_and_nothing_else_opens() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let query_url = "https://relay.example.test/query";
        let service = service(OperationSet::only(Operation::Nip98Authorize));

        // The controld principal reads back its own refused publication as
        // the event author: signer `ci_event` at its generation, with the
        // filter body digest bound into the token.
        let request = query_request(Nip98Signer::CiEvent, 7, query_url, Some([4; 32]), 60, now);
        let expected = nip98_event_digest([1_u8; 32], &request).expect("digest");
        let Response::Nip98Authorize(signature) =
            service.handle(peer(), Request::Nip98Authorize(request))
        else {
            panic!("exact-event query token should sign");
        };
        assert_eq!(signature.identity.public_key, [1_u8; 32]);
        assert_eq!(signature.identity.generation, 7);
        assert_eq!(signature.signed_digest, expected);
        assert_eq!(
            service.backend.calls.borrow().as_slice(),
            &[(KeySelector::CiEvent, expected)]
        );

        // The query never opens for the nip98 key, for the acceptance actor,
        // without a payload digest, with a query string, on a nested or
        // unrelated path, or on another method.
        let denied = [
            query_request(Nip98Signer::Nip98, 8, query_url, Some([4; 32]), 61, now),
            query_request(Nip98Signer::CiEvent, 7, query_url, None, 62, now),
            query_request(Nip98Signer::CiEvent, 7, query_url, Some([0; 32]), 63, now),
            query_request(
                Nip98Signer::CiEvent,
                7,
                "https://relay.example.test/query?limit=1",
                Some([4; 32]),
                64,
                now,
            ),
            query_request(
                Nip98Signer::CiEvent,
                7,
                "https://relay.example.test/query/extra",
                Some([4; 32]),
                65,
                now,
            ),
            query_request(
                Nip98Signer::CiEvent,
                7,
                "https://relay.example.test/admin",
                Some([4; 32]),
                66,
                now,
            ),
            query_request(
                Nip98Signer::CiEvent,
                7,
                "https://relay.example.test/count",
                Some([4; 32]),
                67,
                now,
            ),
            query_request(
                Nip98Signer::CiEvent,
                7,
                "https://other.example.test/query",
                Some([4; 32]),
                68,
                now,
            ),
            Nip98AuthorizeRequest {
                method: HttpMethod::Put,
                ..query_request(Nip98Signer::CiEvent, 7, query_url, Some([4; 32]), 69, now)
            },
            Nip98AuthorizeRequest {
                method: HttpMethod::Head,
                ..query_request(Nip98Signer::CiEvent, 7, query_url, Some([4; 32]), 70, now)
            },
        ];
        for request in denied {
            let label = format!(
                "{:?} {:?} {}",
                request.signer,
                request.method,
                request.url.as_str()
            );
            assert!(
                denied_with(
                    service.handle(peer(), Request::Nip98Authorize(request)),
                    ErrorCode::PolicyDenied
                ),
                "{label}"
            );
        }
        assert_eq!(service.backend.calls.borrow().len(), 1);

        // Even with the activation binding loaded, the actor may publish its
        // frozen events but never query.
        let service = acceptance_service();
        assert!(denied_with(
            service.handle(
                peer(),
                Request::Nip98Authorize(query_request(
                    Nip98Signer::AcceptanceActor,
                    10,
                    query_url,
                    Some([4; 32]),
                    71,
                    now
                ))
            ),
            ErrorCode::PolicyDenied
        ));
        assert!(service.backend.acceptance_calls.borrow().is_empty());
        assert!(service.backend.calls.borrow().is_empty());
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
                allowed_operations: OperationSet::from_bits(0b1111)
                    .expect("compatibility operations"),
            },
            selectors,
            "https://relay.example.test".to_owned(),
        )
        .expect("policy");
        let backend = FakeBackend {
            public_keys: [[1_u8; 32], [2_u8; 32], [3_u8; 32]],
            calls: RefCell::new(Vec::new()),
            acceptance_calls: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            ProductionKeyholder::new(policy, backend),
            Err(ServiceError::Unavailable)
        ));
    }
}
