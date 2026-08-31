//! Bounded protocol and fail-closed local service for an isolated Buzz CI
//! signing keyholder.
//!
//! Signing keys come only from fixed systemd credential names. Callers select
//! an operation and expected generation, never a key path or arbitrary signing
//! domain.

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod ipc;
mod receipt;
mod selector;
mod service;
mod traits;
mod types;

pub use backend::{BackendError, Secp256k1Backend, SigningBackend};
pub use codec::{
    decode_request, decode_response, encode_request, encode_response, DecodeError, EncodeError,
    EncodedFrame, FrameHeader, HEADER_SIZE, MAGIC, MAX_BODY_SIZE, MAX_FIELD_COUNT, MAX_FIELD_SIZE,
    MAX_FRAME_SIZE, PROTOCOL_VERSION,
};
pub use config::{
    AcceptanceBindingConfig, ConfigError, KeyholderConfig, ACCEPTANCE_CREDENTIAL_SELECTOR,
    CONFIG_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
pub use ipc::serve_connection;
pub use ipc::{
    read_request_frame, ConnectionError, IO_TIMEOUT, KEYHOLDER_SOCKET_PATH, SYSTEMD_FD_NAME,
    SYSTEMD_LISTEN_FD,
};
#[cfg(target_os = "linux")]
pub use ipc::{validate_systemd_environment, validate_systemd_listener, ActivationError};
pub use receipt::{
    acceptance_signing_policy, AcceptanceBindingReceipt, AcceptanceReceiptIdentity,
    AcceptanceReceiptPolicy, ReceiptError, ACCEPTANCE_BINDING_PATH, ACCEPTANCE_BINDING_SCHEMA,
};
pub use selector::{KeySelector, SelectorSet};
pub use service::{AcceptanceSigningPolicy, ProductionKeyholder, ServiceError, SigningPolicy};
pub use traits::{KeyholderClient, KeyholderServer};
pub use types::{
    AcceptanceMutation, CanonicalPayload, DescribeAcceptanceRequest, DescribeAcceptanceResponse,
    DescribeRequest, DescribeResponse, ErrorCode, ErrorResponse, HttpMethod, ManifestKind,
    Nip98AuthorizeRequest, Operation, OperationSet, PeerIdentity, PeerPolicy, PublicIdentity,
    Request, Response, SignAcceptanceMutationRequest, SignCiEventRequest, SignManifestRequest,
    SignatureResponse, Url, ValueError, MAX_CANONICAL_PAYLOAD_SIZE, MAX_URL_SIZE,
};
