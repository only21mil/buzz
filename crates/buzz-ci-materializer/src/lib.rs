//! Credential-free, fail-closed source materialization for Buzz CI.
//!
//! This crate deliberately does not subscribe to Buzz, hold a runner key, or
//! accept a caller-selected executable, destination, proxy, or credential.
//! A trusted broker resolves a repository coordinate through [`RootOwnedPolicy`]
//! and grants a private [`MaterializationSlot`]. The materializer fetches raw
//! Git objects into that slot and publishes only a digest-verified tree.

mod backend;
mod execute;
mod manifest;
mod plan;
mod tree;

pub use execute::{
    execute_materialization, CleanupProof, CommandExecution, CommandOutput, GitBackend, PendingSeal,
};
pub use manifest::{
    MaterializationLimits, MaterializationManifest, MaterializationReceipt, Sha256Digest,
};
pub use plan::{CommandSpec, GitOperation, MaterializationSlot, NetworkScope, RootOwnedPolicy};

use thiserror::Error;

/// A fail-closed materialization error.
#[derive(Debug, Error)]
pub enum MaterializeError {
    /// A signed manifest field is malformed or outside the frozen policy.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// A broker-owned policy or slot is malformed.
    #[error("invalid broker policy: {0}")]
    InvalidPolicy(String),
    /// The repository requested a feature that Phase 1 intentionally refuses.
    #[error("unsupported repository feature: {0}")]
    UnsupportedFeature(String),
    /// A materialization limit would be exceeded.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    /// Materialized bytes do not match the signed digest.
    #[error("digest mismatch for {field}: expected {expected}, got {actual}")]
    DigestMismatch {
        /// The digest-bound field.
        field: &'static str,
        /// The signed expected digest.
        expected: String,
        /// The observed digest.
        actual: String,
    },
    /// A bounded Git command returned a non-zero status.
    #[error("Git command failed: {stderr}")]
    CommandFailed {
        /// Bounded diagnostic output.
        stderr: String,
    },
    /// Filesystem publication failed.
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}
pub use backend::{
    ConfinedGitProcessResult, GitCommandLog, GitCommandResultLog, GitHostObservation,
    GitHostObserver, ProcessGitBackend,
};
