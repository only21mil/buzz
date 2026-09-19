//! Shared activation fixtures. Callers retain their exact coordinates and time windows.

use crate::activation::{
    ActivationGrant, FixtureJobCoordinates, HostActivationCoordinates, QualificationPermit,
    VerifiedSigner,
};
use buzz_ci_broker_protocol::GitOid;

pub(crate) fn host(seed: u8) -> HostActivationCoordinates {
    HostActivationCoordinates {
        integrated_candidate_sha: GitOid::Sha256([seed; 32]),
        broker_build_identity: [seed + 1; 32],
        host_profile_digest: [seed + 2; 32],
        suite_identity: [seed + 3; 32],
    }
}

pub(crate) fn fixture_job(seed: u8) -> FixtureJobCoordinates {
    FixtureJobCoordinates {
        request_digest: [seed; 32],
        manifest_digest: [seed + 1; 32],
        isolation_profile_digest: [seed + 2; 32],
        source_oid: GitOid::Sha256([seed + 3; 32]),
        base_oid: GitOid::Sha256([seed + 4; 32]),
        test_identity: [seed + 5; 32],
    }
}

pub(crate) fn permit(
    host: HostActivationCoordinates,
    fixture_job: FixtureJobCoordinates,
    not_before: u64,
    expires_at: u64,
) -> QualificationPermit {
    QualificationPermit {
        authorized_by: VerifiedSigner([1; 32]),
        host,
        fixture_job,
        fixture_identity: [14; 32],
        fixture_signer: VerifiedSigner([2; 32]),
        nonce: [15; 32],
        not_before,
        expires_at,
        directive: None,
    }
}

pub(crate) fn grant(
    host: HostActivationCoordinates,
    minimum_admission_interval_seconds: u64,
    expires_at: u64,
) -> ActivationGrant {
    ActivationGrant {
        authorized_by: VerifiedSigner([1; 32]),
        host,
        security_records_passed: 17,
        security_records_total: 17,
        probes_passed: 12,
        probes_total: 12,
        evidence_set_digest: [16; 32],
        blocker_closure_digest: [17; 32],
        all_blockers_closed: true,
        ordinary_signer: VerifiedSigner([3; 32]),
        max_capacity: 1,
        minimum_admission_interval_seconds,
        expires_at,
    }
}
