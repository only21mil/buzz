use std::fmt;

/// Largest canonical event or manifest payload accepted for signing.
pub const MAX_CANONICAL_PAYLOAD_SIZE: usize = 48 * 1024;
/// Largest NIP-98 URL accepted by the protocol.
pub const MAX_URL_SIZE: usize = 4096;
/// Largest exact-event query filter bound into a `POST /query` token.
pub const MAX_QUERY_FILTER_SIZE: usize = 512;

/// Closed keyholder operation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    /// Describe public identities, generations, and peer policy.
    Describe = 1,
    /// Sign one canonical CI event.
    SignCiEvent = 2,
    /// Authorize one canonical NIP-98 request.
    Nip98Authorize = 3,
    /// Sign one canonical CI manifest.
    SignManifest = 4,
    /// Describe activation-bound acceptance mutation authority.
    DescribeAcceptance = 5,
    /// Sign one activation-bound acceptance mutation template.
    SignAcceptanceMutation = 6,
}

impl TryFrom<u8> for Operation {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Describe),
            2 => Ok(Self::SignCiEvent),
            3 => Ok(Self::Nip98Authorize),
            4 => Ok(Self::SignManifest),
            5 => Ok(Self::DescribeAcceptance),
            6 => Ok(Self::SignAcceptanceMutation),
            _ => Err(()),
        }
    }
}

/// Closed set of operations allowed for one exact peer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSet(u8);

impl OperationSet {
    /// No operations.
    pub const NONE: Self = Self(0);
    /// All protocol operations.
    pub const ALL: Self = Self(0b11_1111);

    /// Construct a set from known operation bits.
    pub fn from_bits(bits: u8) -> Option<Self> {
        (bits & !Self::ALL.0 == 0).then_some(Self(bits))
    }

    /// Construct a set containing one operation.
    pub const fn only(operation: Operation) -> Self {
        Self(1 << (operation as u8 - 1))
    }

    /// Return the canonical bit representation.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Return whether the operation is allowed.
    pub const fn contains(self, operation: Operation) -> bool {
        self.0 & (1 << (operation as u8 - 1)) != 0
    }

    /// Return the union of two operation sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Public operating-system credentials established by a future transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Effective user identifier.
    pub uid: u32,
    /// Effective group identifier.
    pub gid: u32,
}

/// Exact peer credentials and operations accepted by a keyholder instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    /// Required effective user identifier.
    pub uid: u32,
    /// Required effective group identifier.
    pub gid: u32,
    /// Closed operations granted to the exact peer.
    pub allowed_operations: OperationSet,
}

impl PeerPolicy {
    /// Return whether exact peer credentials may invoke an operation.
    pub const fn authorizes(self, peer: PeerIdentity, operation: Operation) -> bool {
        self.uid == peer.uid && self.gid == peer.gid && self.allowed_operations.contains(operation)
    }
}

/// Validated canonical bytes supplied to a signing operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPayload(Vec<u8>);

impl CanonicalPayload {
    /// Validate a non-empty payload within the protocol limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValueError> {
        if bytes.is_empty() {
            return Err(ValueError::Empty);
        }
        if bytes.len() > MAX_CANONICAL_PAYLOAD_SIZE {
            return Err(ValueError::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Validated URL bytes for a NIP-98 authorization operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url(String);

impl Url {
    /// Validate a non-empty, bounded URL without control or NUL characters.
    pub fn new(value: String) -> Result<Self, ValueError> {
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > MAX_URL_SIZE {
            return Err(ValueError::TooLarge);
        }
        if value.chars().any(char::is_control) {
            return Err(ValueError::InvalidText);
        }
        Ok(Self(value))
    }

    /// Borrow the validated URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Literal `POST /query` request body bound into a NIP-98 token.
///
/// The keyholder derives the payload digest from these bytes itself and
/// checks their shape against the exact-event read-back before it signs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryFilter(Vec<u8>);

impl QueryFilter {
    /// Validate a non-empty filter within the protocol limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValueError> {
        if bytes.is_empty() {
            return Err(ValueError::Empty);
        }
        if bytes.len() > MAX_QUERY_FILTER_SIZE {
            return Err(ValueError::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact filter bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Validation failure for a bounded public value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// The value must not be empty.
    Empty,
    /// The value exceeds its explicit protocol limit.
    TooLarge,
    /// Text contains a forbidden control character.
    InvalidText,
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "value is empty",
            Self::TooLarge => "value exceeds protocol limit",
            Self::InvalidText => "text contains a forbidden control character",
        })
    }
}

impl std::error::Error for ValueError {}

/// Closed HTTP method set accepted by NIP-98 authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HttpMethod {
    /// GET.
    Get = 1,
    /// HEAD.
    Head = 2,
    /// POST.
    Post = 3,
    /// PUT.
    Put = 4,
    /// PATCH.
    Patch = 5,
    /// DELETE.
    Delete = 6,
    /// OPTIONS.
    Options = 7,
}

impl TryFrom<u8> for HttpMethod {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Get),
            2 => Ok(Self::Head),
            3 => Ok(Self::Post),
            4 => Ok(Self::Put),
            5 => Ok(Self::Patch),
            6 => Ok(Self::Delete),
            7 => Ok(Self::Options),
            _ => Err(()),
        }
    }
}

/// Closed set of keys that may sign one NIP-98 authorization event.
///
/// The relay's `POST /events` stores an event only when its `pubkey` equals
/// the NIP-98 token pubkey, so the token for a publish is signed by the key
/// that signed the event. Every other route keeps the dedicated NIP-98 key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Nip98Signer {
    /// The `nip98.key` selector: accepted reads and evidence object writes.
    Nip98 = 1,
    /// The `ci-event.key` selector: `POST /events` carrying a kind 46101 to
    /// 46106 event it signed, and `POST /query` reading back one exact event
    /// it signed after the relay refused the publish.
    CiEvent = 2,
    /// The activation-bound acceptance actor: `POST /events` carrying one of
    /// the four frozen acceptance events.
    AcceptanceActor = 3,
}

impl TryFrom<u8> for Nip98Signer {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Nip98),
            2 => Ok(Self::CiEvent),
            3 => Ok(Self::AcceptanceActor),
            _ => Err(()),
        }
    }
}

/// Closed manifest domains accepted by the manifest signing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ManifestKind {
    /// Static root-owned lane activation policy. Production signing refuses
    /// this kind because activation authority is provisioned, not minted.
    LaneActivationV1 = 1,
    /// Immutable pre-admission JobIntentV2 admission message.
    JobIntentV2 = 2,
}

/// Closed activation acceptance mutation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcceptanceMutation {
    /// Actor-authored kind 46100 initial run request.
    Run = 1,
    /// Owner/admin-authored kind 46107 CI signer grant.
    Grant = 2,
    /// Actor-authored kind 46100 failed-job rerun request.
    Rerun = 3,
    /// Actor-authored kind 5 tombstone of the rerun request.
    Tombstone = 4,
}

impl TryFrom<u8> for AcceptanceMutation {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Run),
            2 => Ok(Self::Grant),
            3 => Ok(Self::Rerun),
            4 => Ok(Self::Tombstone),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for ManifestKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LaneActivationV1),
            2 => Ok(Self::JobIntentV2),
            _ => Err(()),
        }
    }
}

/// Empty public-identity query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DescribeRequest;

/// Empty acceptance-authority description query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DescribeAcceptanceRequest;

/// Request to sign a canonical unsigned CI event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignCiEventRequest {
    /// Required active key generation.
    pub expected_generation: u64,
    /// Exact Nostr event kind, checked by the signing policy.
    pub event_kind: u32,
    /// Canonical unsigned event bytes checked and hashed by the signer.
    pub canonical_event: CanonicalPayload,
}

/// Request to authorize one exact NIP-98 HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nip98AuthorizeRequest {
    /// Required active key generation.
    pub expected_generation: u64,
    /// Closed HTTP method.
    pub method: HttpMethod,
    /// Exact request URL.
    pub url: Url,
    /// Optional SHA-256 payload digest.
    pub payload_digest: Option<[u8; 32]>,
    /// Nostr event creation time.
    pub created_at: u64,
    /// Caller nonce included by the future NIP-98 event builder.
    pub nonce: [u8; 16],
    /// Key that signs the token; a `POST /events` token names the event's own signer.
    pub signer: Nip98Signer,
    /// Literal request body of a `POST /query` token; absent on every other route.
    pub query_filter: Option<QueryFilter>,
}

/// Request to sign one canonical CI manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignManifestRequest {
    /// Required active key generation.
    pub expected_generation: u64,
    /// Closed manifest domain.
    pub manifest_kind: ManifestKind,
    /// Canonical manifest bytes checked and hashed by the signer. For
    /// JobIntentV2 these are the exact broker v2 admission-signature message.
    pub canonical_manifest: CanonicalPayload,
}

/// Request to sign one exact activation-bound acceptance mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignAcceptanceMutationRequest {
    /// Required active acceptance-actor key generation.
    pub expected_generation: u64,
    /// Exact activation scenario digest configured at keyholder startup.
    pub scenario_sha256: [u8; 32],
    /// One closed preconfigured mutation template.
    pub mutation: AcceptanceMutation,
}

/// Closed request set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Query public state.
    Describe(DescribeRequest),
    /// Sign a CI event.
    SignCiEvent(SignCiEventRequest),
    /// Authorize a NIP-98 request.
    Nip98Authorize(Nip98AuthorizeRequest),
    /// Sign a CI manifest.
    SignManifest(SignManifestRequest),
    /// Query activation-bound acceptance authority.
    DescribeAcceptance(DescribeAcceptanceRequest),
    /// Sign one preconfigured acceptance mutation.
    SignAcceptanceMutation(SignAcceptanceMutationRequest),
}

impl Request {
    /// Return the closed operation identifier.
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Describe(_) => Operation::Describe,
            Self::SignCiEvent(_) => Operation::SignCiEvent,
            Self::Nip98Authorize(_) => Operation::Nip98Authorize,
            Self::SignManifest(_) => Operation::SignManifest,
            Self::DescribeAcceptance(_) => Operation::DescribeAcceptance,
            Self::SignAcceptanceMutation(_) => Operation::SignAcceptanceMutation,
        }
    }
}

/// One public signing identity at one exact generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicIdentity {
    /// X-only secp256k1 public key.
    pub public_key: [u8; 32],
    /// One-based key generation.
    pub generation: u64,
}

/// Public keyholder state returned by `describe`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescribeResponse {
    /// CI event signing identity.
    pub ci_event: PublicIdentity,
    /// NIP-98 authorization identity.
    pub nip98: PublicIdentity,
    /// Manifest signing identity.
    pub manifest: PublicIdentity,
    /// Exact peer policy enforced by the future service transport.
    pub peer_policy: PeerPolicy,
}

/// Public activation-bound authority returned by `describe_acceptance`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescribeAcceptanceResponse {
    /// Dedicated acceptance actor identity and generation.
    pub actor: PublicIdentity,
    /// Exact activation scenario digest.
    pub scenario_sha256: [u8; 32],
    /// Event IDs in Run, Grant, Rerun, Tombstone order.
    pub event_ids: [[u8; 32]; 4],
}

/// Public result of a successful signing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureResponse {
    /// Identity and generation that produced the signature.
    pub identity: PublicIdentity,
    /// Digest actually signed after operation-specific validation.
    pub signed_digest: [u8; 32],
    /// BIP-340 Schnorr signature.
    pub signature: [u8; 64],
}

/// Closed public failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    /// Peer credentials or operation are not authorized.
    Unauthorized = 1,
    /// Request is structurally valid but violates signing policy.
    PolicyDenied = 2,
    /// Requested generation is no longer current.
    StaleGeneration = 3,
    /// Operation-specific public input is invalid.
    InvalidRequest = 4,
    /// Keyholder could not complete the operation.
    Unavailable = 5,
}

impl TryFrom<u16> for ErrorCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Unauthorized),
            2 => Ok(Self::PolicyDenied),
            3 => Ok(Self::StaleGeneration),
            4 => Ok(Self::InvalidRequest),
            5 => Ok(Self::Unavailable),
            _ => Err(()),
        }
    }
}

/// Public error response without backend or secret details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorResponse {
    /// Closed error code.
    pub code: ErrorCode,
    /// Current public generation when it is safe and relevant, otherwise zero.
    pub current_generation: u64,
}

/// Closed response set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response {
    /// Public identity description.
    Describe(DescribeResponse),
    /// CI event signature.
    SignCiEvent(SignatureResponse),
    /// NIP-98 authorization signature.
    Nip98Authorize(SignatureResponse),
    /// Manifest signature.
    SignManifest(SignatureResponse),
    /// Acceptance authority description.
    DescribeAcceptance(DescribeAcceptanceResponse),
    /// Acceptance mutation signature.
    SignAcceptanceMutation(SignatureResponse),
    /// Public failure bound to its attempted operation.
    Error {
        /// Operation that failed.
        operation: Operation,
        /// Sanitized public failure.
        error: ErrorResponse,
    },
}

impl Response {
    /// Return the operation to which this response is bound.
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Describe(_) => Operation::Describe,
            Self::SignCiEvent(_) => Operation::SignCiEvent,
            Self::Nip98Authorize(_) => Operation::Nip98Authorize,
            Self::SignManifest(_) => Operation::SignManifest,
            Self::DescribeAcceptance(_) => Operation::DescribeAcceptance,
            Self::SignAcceptanceMutation(_) => Operation::SignAcceptanceMutation,
            Self::Error { operation, .. } => *operation,
        }
    }
}
