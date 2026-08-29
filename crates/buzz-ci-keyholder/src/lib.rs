//! Dependency-free protocol foundation for an isolated Buzz CI signing
//! keyholder.
//!
//! The crate defines bounded public messages and transport-neutral traits. It
//! deliberately contains no secret discovery, raw-key loading, signing
//! implementation, socket listener, or production wiring.

#![forbid(unsafe_code)]

mod codec;
mod traits;
mod types;

pub use codec::{
    decode_request, decode_response, encode_request, encode_response, DecodeError, EncodeError,
    EncodedFrame, FrameHeader, HEADER_SIZE, MAGIC, MAX_BODY_SIZE, MAX_FIELD_COUNT, MAX_FIELD_SIZE,
    MAX_FRAME_SIZE, PROTOCOL_VERSION,
};
pub use traits::{KeyholderClient, KeyholderServer};
pub use types::{
    CanonicalPayload, DescribeRequest, DescribeResponse, ErrorCode, ErrorResponse, HttpMethod,
    ManifestKind, Nip98AuthorizeRequest, Operation, OperationSet, PeerIdentity, PeerPolicy,
    PublicIdentity, Request, Response, SignCiEventRequest, SignManifestRequest, SignatureResponse,
    Url, ValueError, MAX_CANONICAL_PAYLOAD_SIZE, MAX_URL_SIZE,
};
