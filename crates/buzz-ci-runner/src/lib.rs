//! Unprivileged Buzz CI broker-v2 proxy and dormant service transport.
//!
//! Production execution and evidence ownership stay inside execd. The runner
//! forwards authenticated, bounded v2 frames without executing jobs locally.

#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod proxy_v2;
pub mod service;
pub mod transport;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    #[error("invalid public CI request")]
    InvalidRequest,
    #[error("request is not authorized by owner-configured policy")]
    Unauthorized,
    #[error("request does not carry accepted reviewed trust")]
    UnacceptedTrust,
    #[error("external fork requests are not accepted")]
    ExternalFork,
    #[error("request has expired")]
    ExpiredRequest,
    #[error("manifest binding does not match the authenticated request")]
    InvalidBinding,
    #[error("invalid hex field")]
    InvalidHex,
    #[error("invalid UUID field")]
    InvalidUuid,
    #[error("timeout does not fit the broker protocol")]
    InvalidTimeout,
    #[error("broker receipt does not prove an empty terminal lease")]
    TeardownNotProven,
    #[error("invalid teardown attestation")]
    InvalidAttestation,
    #[error("broker socket is unavailable")]
    BrokerUnavailable,
    #[error("broker transport failed")]
    TransportFailure,
    #[error("broker returned an invalid response")]
    InvalidBrokerResponse,
    #[error("broker rejected the request")]
    BrokerRejected,
    #[error("workflow execution backend is unavailable")]
    ExecutionBackendUnavailable,
    #[error("workflow execution failed")]
    ExecutionFailed,
    #[error("workflow execution did not produce valid bounded evidence")]
    InvalidExecutionEvidence,
}
