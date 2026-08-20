//! Fail-closed Docker-compatible API admission policy for Buzz CI.
//!
//! The crate combines a closed policy/state machine with a bounded inherited-
//! descriptor Unix transport. A trusted broker must still pass the already-open
//! executor listener and rootless-runtime connection, bind both to the validated
//! lease, and terminate/reconcile the attempt whenever the transport reports an
//! ambiguous post-upstream failure. Unsupported Docker framing and streaming
//! routes fail closed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod contract;
mod policy;
mod route;
mod state;
mod transport;

pub use contract::{
    AllowedMount, EngineKind, IsolationLimits, IsolationProfile, NetworkPolicy, PolicyManifest,
};
pub use policy::{
    Admission, CanonicalCreate, CanonicalExec, EffectiveContainerSpec, ProxyPolicy, VerifiedStart,
};
pub use route::{CanonicalRoute, DockerMethod, DockerRoute};
pub use state::{AttemptPhase, ObjectLedger};
pub use transport::{
    ArchiveDirection, ArchiveGrant, HijackGrant, InheritedOneShotConnector, InheritedProxy,
    OneShotUpstreamConnector, TransportLimits, UpstreamCapability,
};

use thiserror::Error;

/// A fail-closed proxy refusal.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProxyError {
    /// The immutable manifest is malformed.
    #[error("invalid policy manifest: {0}")]
    InvalidManifest(String),
    /// The HTTP method/path/query is not an exact admitted Docker route.
    #[error("route refused: {0}")]
    RouteRefused(String),
    /// A request conflicts with the installed isolation policy.
    #[error("policy refused: {0}")]
    PolicyRefused(String),
    /// The request violates attempt phase or object ownership.
    #[error("state refused: {0}")]
    StateRefused(String),
    /// The bounded JSON body is malformed.
    #[error("invalid Docker request: {0}")]
    InvalidRequest(String),
    /// The inherited Unix transport or bounded HTTP exchange failed closed.
    #[error("transport refused: {0}")]
    Transport(String),
}
