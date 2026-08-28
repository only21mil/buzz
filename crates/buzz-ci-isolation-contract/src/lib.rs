//! Shared attempt/lease contract for Buzz CI isolation.
//!
//! The wire fields mirror the frozen protocol v1.4 contract identified by
//! `ac335626526aba0a0c429e6fbbe387600155d539f456075375cb6f11fb0a18d1`
//! at binding anchor `c3214118c4d26414da00c507e58a229566caba0f`.
//! The internal `source_sha` field maps to protocol `tip_oid` and tag `c`.
//! This crate does not authenticate the accepted request or open host
//! resources. It joins already-authorized request identity to broker-issued
//! lease capabilities and validates their Phase-1 consistency.
//!
//! Consumers must not use [`AttemptLeaseBinding`] directly for execution. Call
//! [`AttemptLeaseBinding::validate_phase1`] and pass only the resulting
//! [`ValidatedAttemptLeaseBinding`] across the materializer/proxy boundary.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod binding;
mod error;
mod handle;
mod profile;

pub use binding::{
    AttemptLeaseBinding, Phase1ValidationContext, PrincipalUids, TeardownLeaseIdentity,
    ValidatedAttemptLeaseBinding,
};
pub use error::ContractError;
pub use handle::{
    BrokerObjectHandle, CgroupHandle, NetnsHandle, QuotaBackend, QuotaHandle,
    RuntimeEndpointIdentity, WorkspaceHandle,
};
pub use profile::{
    EngineKind, IsolationProfile, NetworkPolicy, ResourceLimits, PHASE1_SECCOMP_PROFILE_DIGEST,
    PHASE1_SECCOMP_PROFILE_PATH,
};
