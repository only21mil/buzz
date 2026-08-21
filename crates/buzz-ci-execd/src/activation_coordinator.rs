//! Root-owned publication of qualification permits and activation state.
//!
//! The daemon consumes the existing authority and state files. This module
//! adds no daemon protocol. It rotates the byte-exact root permit for each
//! sealed case, then publishes the reconciled ordinary grant after fresh host
//! proofs. A filesystem lock prevents readers from observing either half of a
//! revision, and a durable marker makes interrupted publication fail closed.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use nix::fcntl::FlockArg;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    activation::{
        ActivationController, ActivationError, ActivationState, DurableStateSnapshot,
        QualificationPermit,
    },
    runtime::{
        acquire_runtime_lock, persist_to_validated_path, read_artifact_for_owner,
        validate_directory_for_owner, AuthorityFile, RootOrdinaryAuthority, RuntimeLoadError,
        RuntimePaths, StateFile, AUTHORITY_MODE, COORDINATOR_LOCK_FILE, COORDINATOR_MARKER_FILE,
        MAX_AUTHORITY_BYTES, MAX_STATE_BYTES, STATE_MODE,
    },
    seccomp::SeccompLeaseEvidence,
};

/// Fresh host evidence required before the coordinator can publish Ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationReconciliationProofs {
    pub seccomp_evidence: SeccompLeaseEvidence,
    pub host_profile_digest: [u8; 32],
    pub cleanup_proof_digest: [u8; 32],
    pub dns_proof_digest: [u8; 32],
    pub observed_at: u64,
}

/// Closed lifecycle information returned by a secure pair read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorStatus {
    pub state: ActivationState,
    pub ordinary_capacity: u8,
    pub authority_revision: u64,
    pub state_revision: u64,
}

/// Root-side durable authority and state coordinator.
pub struct ActivationAuthorityCoordinator {
    paths: RuntimePaths,
    expected_uid: u32,
}

impl ActivationAuthorityCoordinator {
    /// Construct the canonical root-owned coordinator.
    pub fn production() -> Self {
        Self {
            paths: RuntimePaths::canonical(),
            expected_uid: 0,
        }
    }

    /// Rotate to one exact sealed-case permit and reset its isolated state
    /// lineage to Qualifying. The caller restarts execd after this commit.
    pub fn rotate_case(
        &self,
        permit: QualificationPermit,
        now: u64,
    ) -> Result<CoordinatorStatus, CoordinatorError> {
        if now < permit.not_before || now >= permit.expires_at {
            return Err(CoordinatorError::Stale);
        }
        self.ensure_lock_file()?;
        let _lock = acquire_runtime_lock(&self.paths, FlockArg::LockExclusive, self.expected_uid)?;
        let pair = self.load_pair(now)?;
        if permit.authorized_by != pair.authority.root()
            || pair.snapshot.active_lease.is_some()
            || pair
                .snapshot
                .qualification
                .is_some_and(|qualification| qualification.active_lease.is_some())
            || !matches!(
                pair.snapshot.state,
                ActivationState::Unprovisioned
                    | ActivationState::Reconciling
                    | ActivationState::Quarantined
            )
        {
            return Err(CoordinatorError::UnsafeTransition);
        }

        let authority_revision = pair
            .authority
            .revision()
            .checked_add(1)
            .ok_or(CoordinatorError::RevisionExhausted)?;
        let state_revision = pair
            .state_revision
            .checked_add(1)
            .ok_or(CoordinatorError::RevisionExhausted)?;
        let mut controller = ActivationController::new(pair.authority.root());
        controller.start_qualification(permit)?;
        self.publish_pair(
            AuthorityFile::encode(
                authority_revision,
                pair.authority.root(),
                Some(permit),
                None,
            )?,
            controller.snapshot(),
            authority_revision,
            state_revision,
        )?;
        Ok(CoordinatorStatus {
            state: ActivationState::Qualifying,
            ordinary_capacity: 0,
            authority_revision,
            state_revision,
        })
    }

    /// Reconcile a completed qualification lineage into the exact ordinary
    /// grant. Every proof must be fresh for this invocation.
    pub fn publish_ready(
        &self,
        ordinary: RootOrdinaryAuthority,
        proofs: ActivationReconciliationProofs,
        now: u64,
    ) -> Result<CoordinatorStatus, CoordinatorError> {
        if proofs.observed_at != now
            || proofs.cleanup_proof_digest == [0; 32]
            || proofs.dns_proof_digest == [0; 32]
            || proofs.host_profile_digest != ordinary.grant.host.host_profile_digest
        {
            return Err(CoordinatorError::IncompleteProofs);
        }
        self.ensure_lock_file()?;
        let _lock = acquire_runtime_lock(&self.paths, FlockArg::LockExclusive, self.expected_uid)?;
        let pair = self.load_pair(now)?;
        let permit = pair
            .snapshot
            .qualification
            .ok_or(CoordinatorError::UnsafeTransition)?
            .permit;
        let mut controller =
            ActivationController::resume_reconciliation(pair.authority.root(), pair.snapshot)?;
        controller.reconcile_activation(
            ordinary.grant,
            proofs.seccomp_evidence,
            proofs.host_profile_digest,
            now,
        )?;

        let authority_revision = pair
            .authority
            .revision()
            .checked_add(1)
            .ok_or(CoordinatorError::RevisionExhausted)?;
        let state_revision = pair
            .state_revision
            .checked_add(1)
            .ok_or(CoordinatorError::RevisionExhausted)?;
        self.publish_pair(
            AuthorityFile::encode(
                authority_revision,
                pair.authority.root(),
                Some(permit),
                Some(ordinary),
            )?,
            controller.snapshot(),
            authority_revision,
            state_revision,
        )?;
        Ok(CoordinatorStatus {
            state: ActivationState::Ready,
            ordinary_capacity: 1,
            authority_revision,
            state_revision,
        })
    }

    /// Read the exact durable pair while holding the shared publication lock.
    pub fn status(&self, now: u64) -> Result<CoordinatorStatus, CoordinatorError> {
        let _lock = acquire_runtime_lock(&self.paths, FlockArg::LockShared, self.expected_uid)?;
        let pair = self.load_pair(now)?;
        Ok(CoordinatorStatus {
            state: pair.snapshot.state,
            ordinary_capacity: u8::from(
                pair.snapshot.state == ActivationState::Ready
                    && pair
                        .snapshot
                        .activation
                        .is_some_and(|grant| now < grant.expires_at),
            ),
            authority_revision: pair.authority.revision(),
            state_revision: pair.state_revision,
        })
    }

    fn ensure_lock_file(&self) -> Result<(), CoordinatorError> {
        validate_directory_for_owner(&self.paths.activation_root, self.expected_uid)?;
        let path = self.paths.activation_root.join(COORDINATOR_LOCK_FILE);
        if path
            .try_exists()
            .map_err(|_| CoordinatorError::Persistence)?
        {
            return Ok(());
        }
        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .mode(STATE_MODE)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        let mut file = options
            .open(&path)
            .map_err(|_| CoordinatorError::Persistence)?;
        file.write_all(b"1")
            .and_then(|()| file.sync_all())
            .map_err(|_| CoordinatorError::Persistence)?;
        sync_directory(&self.paths.activation_root)?;
        Ok(())
    }

    fn load_pair(&self, now: u64) -> Result<LoadedPair, CoordinatorError> {
        let marker = self.paths.activation_root.join(COORDINATOR_MARKER_FILE);
        if marker.try_exists().unwrap_or(true) {
            return Err(CoordinatorError::RestartAmbiguous);
        }
        let authority_bytes = read_artifact_for_owner(
            &self.paths.authority_root,
            &self.paths.authority_file,
            AUTHORITY_MODE,
            MAX_AUTHORITY_BYTES,
            self.expected_uid,
        )?;
        let authority_disk: AuthorityFile = serde_json::from_slice(&authority_bytes)
            .map_err(|_| CoordinatorError::Runtime(RuntimeLoadError::Malformed))?;
        let authority = authority_disk.decode()?;
        let authority_sha256 = Sha256::digest(&authority_bytes).into();
        let state_bytes = read_artifact_for_owner(
            &self.paths.activation_root,
            &self.paths.state_file,
            STATE_MODE,
            MAX_STATE_BYTES,
            self.expected_uid,
        )?;
        let state_disk: StateFile = serde_json::from_slice(&state_bytes)
            .map_err(|_| CoordinatorError::Runtime(RuntimeLoadError::Malformed))?;
        let state_revision = state_disk.revision();
        let snapshot = state_disk.decode(&authority, authority_sha256, now)?;
        Ok(LoadedPair {
            authority,
            snapshot,
            state_revision,
        })
    }

    fn publish_pair(
        &self,
        authority: AuthorityFile,
        snapshot: DurableStateSnapshot,
        authority_revision: u64,
        state_revision: u64,
    ) -> Result<(), CoordinatorError> {
        let marker = self.paths.activation_root.join(COORDINATOR_MARKER_FILE);
        create_marker(&marker)?;
        sync_directory(&self.paths.activation_root)?;

        let authority_bytes =
            serde_json::to_vec(&authority).map_err(|_| CoordinatorError::Persistence)?;
        if authority_bytes.len() as u64 > MAX_AUTHORITY_BYTES {
            return Err(CoordinatorError::Persistence);
        }
        atomic_write(
            &self.paths.authority_root,
            &self.paths.authority_file,
            ".authority-v1.json.tmp",
            AUTHORITY_MODE,
            &authority_bytes,
        )?;
        let authority_sha256 = Sha256::digest(&authority_bytes).into();
        persist_to_validated_path(
            &self.paths.activation_root,
            &self.paths.state_file,
            snapshot,
            state_revision,
            authority_revision,
            authority_sha256,
        )?;
        fs::remove_file(marker).map_err(|_| CoordinatorError::Persistence)?;
        sync_directory(&self.paths.activation_root)?;
        Ok(())
    }
}

struct LoadedPair {
    authority: crate::runtime::ServiceAuthority,
    snapshot: DurableStateSnapshot,
    state_revision: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CoordinatorError {
    #[error("authority or state failed validation: {0}")]
    Runtime(#[from] RuntimeLoadError),
    #[error("activation transition was rejected: {0:?}")]
    Activation(ActivationError),
    #[error("root publication was interrupted; explicit recovery is required")]
    RestartAmbiguous,
    #[error("permit or grant is stale")]
    Stale,
    #[error("the requested root transition is unsafe")]
    UnsafeTransition,
    #[error("fresh cleanup, DNS, seccomp, or host proof is incomplete")]
    IncompleteProofs,
    #[error("authority or state revision is exhausted")]
    RevisionExhausted,
    #[error("authority/state publication failed and remains quarantined")]
    Persistence,
}

impl From<ActivationError> for CoordinatorError {
    fn from(error: ActivationError) -> Self {
        Self::Activation(error)
    }
}

fn create_marker(path: &Path) -> Result<(), CoordinatorError> {
    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(STATE_MODE)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut marker = options
        .open(path)
        .map_err(|_| CoordinatorError::RestartAmbiguous)?;
    marker
        .write_all(b"pending-v1")
        .and_then(|()| marker.sync_all())
        .map_err(|_| CoordinatorError::Persistence)
}

fn atomic_write(
    directory: &Path,
    destination: &Path,
    temporary_name: &str,
    mode: u32,
    bytes: &[u8],
) -> Result<(), CoordinatorError> {
    let temporary = directory.join(temporary_name);
    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options
        .open(&temporary)
        .map_err(|_| CoordinatorError::Persistence)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CoordinatorError::Persistence)?;
    fs::rename(temporary, destination).map_err(|_| CoordinatorError::Persistence)?;
    sync_directory(directory)
}

fn sync_directory(path: &Path) -> Result<(), CoordinatorError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CoordinatorError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use buzz_ci_broker_protocol::{AdmitAttemptRequest, GitOid, TrustClass};
    use tempfile::TempDir;

    use crate::{
        activation::{
            ActivationGrant, FixtureJobCoordinates, HostActivationCoordinates,
            QualificationOutcome, VerifiedSigner, REQUIRED_PROBES, REQUIRED_SECURITY_RECORDS,
        },
        runtime::DIRECTORY_MODE,
        seccomp::{SeccompFileReadback, SeccompFileType, SeccompSeedPlan, SECCOMP_PROFILE_MODE},
    };

    const ROOT: VerifiedSigner = VerifiedSigner([1; 32]);
    const FIXTURE: VerifiedSigner = VerifiedSigner([2; 32]);
    const ORDINARY: VerifiedSigner = VerifiedSigner([3; 32]);

    struct Fixture {
        _temp: TempDir,
        coordinator: ActivationAuthorityCoordinator,
    }

    fn host() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([4; 32]),
            broker_build_identity: [5; 32],
            host_profile_digest: [6; 32],
            suite_identity: [7; 32],
        }
    }

    fn permit(identity: u8) -> QualificationPermit {
        QualificationPermit {
            authorized_by: ROOT,
            host: host(),
            fixture_job: FixtureJobCoordinates {
                request_digest: [identity; 32],
                manifest_digest: [9; 32],
                isolation_profile_digest: [10; 32],
                source_oid: GitOid::Sha256([11; 32]),
                base_oid: GitOid::Sha256([12; 32]),
                test_identity: [identity; 32],
            },
            fixture_identity: [identity; 32],
            fixture_signer: FIXTURE,
            nonce: [identity.wrapping_add(40); 32],
            not_before: 10,
            expires_at: 100,
            directive: None,
        }
    }

    fn ordinary(evidence: [u8; 32]) -> RootOrdinaryAuthority {
        let request = AdmitAttemptRequest {
            signed_request_digest: [18; 32],
            actor_pubkey: ORDINARY.0,
            audience_digest: [19; 32],
            idempotency_digest: [20; 32],
            source_pin_event_id: [21; 32],
            workflow_digest: [22; 32],
            job_manifest_digest: [23; 32],
            isolation_profile_digest: [24; 32],
            run_id: [25; 16],
            tip_oid: GitOid::Sha256([26; 32]),
            base_oid: GitOid::Sha256([27; 32]),
            issued_at: 20,
            expires_at: 90,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        };
        RootOrdinaryAuthority {
            grant: ActivationGrant {
                authorized_by: ROOT,
                host: host(),
                security_records_passed: REQUIRED_SECURITY_RECORDS,
                security_records_total: REQUIRED_SECURITY_RECORDS,
                probes_passed: REQUIRED_PROBES,
                probes_total: REQUIRED_PROBES,
                evidence_set_digest: evidence,
                blocker_closure_digest: [28; 32],
                all_blockers_closed: true,
                ordinary_signer: ORDINARY,
                max_capacity: 1,
                minimum_admission_interval_seconds: 5,
                expires_at: 90,
            },
            request,
            job_identity: [29; 32],
            lease_id: [30; 16],
            nonce: [31; 32],
            authenticated_signer: ORDINARY,
        }
    }

    fn proofs() -> ActivationReconciliationProofs {
        let plan = SeccompSeedPlan::phase1();
        let path = plan.destination_path();
        let readback = SeccompFileReadback {
            path: path.into(),
            canonical_path: path.into(),
            file_type: SeccompFileType::Regular,
            link_count: 1,
            owner_uid: 0,
            owner_gid: 0,
            mode: SECCOMP_PROFILE_MODE,
            digest: plan.expected_digest().into(),
        };
        ActivationReconciliationProofs {
            seccomp_evidence: plan.readiness(&readback).unwrap(),
            host_profile_digest: host().host_profile_digest,
            cleanup_proof_digest: [32; 32],
            dns_proof_digest: [33; 32],
            observed_at: 20,
        }
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let authority_root = temp.path().join("authority");
        let activation_root = temp.path().join("activation");
        fs::create_dir(&authority_root).unwrap();
        fs::create_dir(&activation_root).unwrap();
        fs::set_permissions(&authority_root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        fs::set_permissions(&activation_root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let paths = RuntimePaths {
            authority_file: authority_root.join("authority-v1.json"),
            state_file: activation_root.join("state-v1.json"),
            authority_root,
            activation_root,
        };
        let authority = AuthorityFile::encode(1, ROOT, None, None).unwrap();
        let bytes = serde_json::to_vec(&authority).unwrap();
        fs::write(&paths.authority_file, &bytes).unwrap();
        fs::set_permissions(
            &paths.authority_file,
            fs::Permissions::from_mode(AUTHORITY_MODE),
        )
        .unwrap();
        persist_to_validated_path(
            &paths.activation_root,
            &paths.state_file,
            ActivationController::new(ROOT).snapshot(),
            1,
            1,
            Sha256::digest(bytes).into(),
        )
        .unwrap();
        Fixture {
            _temp: temp,
            coordinator: ActivationAuthorityCoordinator {
                paths,
                expected_uid: nix::unistd::geteuid().as_raw(),
            },
        }
    }

    fn finish_case(coordinator: &ActivationAuthorityCoordinator, permit: QualificationPermit) {
        let _lock = acquire_runtime_lock(
            &coordinator.paths,
            FlockArg::LockExclusive,
            coordinator.expected_uid,
        )
        .unwrap();
        let pair = coordinator.load_pair(20).unwrap();
        let mut controller = ActivationController::restore(ROOT, pair.snapshot, None).controller;
        let lease = controller
            .admit_qualification_request(crate::runtime::qualification_request(permit), FIXTURE, 20)
            .unwrap();
        controller
            .finish_qualification(
                lease,
                QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                },
            )
            .unwrap();
        persist_to_validated_path(
            &coordinator.paths.activation_root,
            &coordinator.paths.state_file,
            controller.snapshot(),
            pair.state_revision + 1,
            pair.authority.revision(),
            Sha256::digest(fs::read(&coordinator.paths.authority_file).unwrap()).into(),
        )
        .unwrap();
    }

    #[test]
    fn full_unprovisioned_to_ready_path_uses_rotated_root_authority() {
        let fixture = fixture();
        let permit = permit(14);
        let qualifying = fixture.coordinator.rotate_case(permit, 20).unwrap();
        assert_eq!(qualifying.state, ActivationState::Qualifying);
        assert_eq!(qualifying.ordinary_capacity, 0);
        finish_case(&fixture.coordinator, permit);
        let ready = fixture
            .coordinator
            .publish_ready(ordinary([16; 32]), proofs(), 20)
            .unwrap();
        assert_eq!(ready.state, ActivationState::Ready);
        assert_eq!(ready.ordinary_capacity, 1);
        assert_eq!(fixture.coordinator.status(20).unwrap(), ready);
    }

    #[test]
    fn distinct_case_identities_rotate_into_isolated_lineages() {
        let fixture = fixture();
        let first = permit(14);
        fixture.coordinator.rotate_case(first, 20).unwrap();
        finish_case(&fixture.coordinator, first);
        let second = permit(15);
        let rotated = fixture.coordinator.rotate_case(second, 20).unwrap();
        assert_eq!(rotated.state, ActivationState::Qualifying);
        let pair = fixture.coordinator.load_pair(20).unwrap();
        assert_eq!(
            pair.snapshot.qualification.unwrap().permit.fixture_identity,
            second.fixture_identity
        );
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn interrupted_publication_marker_quarantines_restart() {
        let fixture = fixture();
        fixture.coordinator.ensure_lock_file().unwrap();
        create_marker(
            &fixture
                .coordinator
                .paths
                .activation_root
                .join(COORDINATOR_MARKER_FILE),
        )
        .unwrap();
        assert_eq!(
            fixture.coordinator.status(20),
            Err(CoordinatorError::RestartAmbiguous)
        );
    }

    #[test]
    fn mismatch_stale_mode_and_owner_fail_closed() {
        let test_fixture = fixture();
        let mut stale = permit(14);
        stale.expires_at = 20;
        assert_eq!(
            test_fixture.coordinator.rotate_case(stale, 20),
            Err(CoordinatorError::Stale)
        );

        let stale_fixture = fixture();
        stale_fixture
            .coordinator
            .rotate_case(permit(14), 20)
            .unwrap();
        assert!(matches!(
            stale_fixture.coordinator.status(100),
            Err(CoordinatorError::Runtime(RuntimeLoadError::Stale))
        ));

        test_fixture.coordinator.ensure_lock_file().unwrap();
        fs::set_permissions(
            &test_fixture.coordinator.paths.authority_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            test_fixture.coordinator.status(20),
            Err(CoordinatorError::Runtime(RuntimeLoadError::UnsafeMetadata))
        ));
        fs::set_permissions(
            &test_fixture.coordinator.paths.authority_file,
            fs::Permissions::from_mode(AUTHORITY_MODE),
        )
        .unwrap();

        let actual_uid = test_fixture
            .coordinator
            .paths
            .authority_file
            .metadata()
            .unwrap()
            .uid();
        assert_eq!(
            crate::runtime::validate_file_for_owner(
                &test_fixture
                    .coordinator
                    .paths
                    .authority_file
                    .metadata()
                    .unwrap(),
                AUTHORITY_MODE,
                MAX_AUTHORITY_BYTES,
                actual_uid.wrapping_add(1),
            ),
            Err(RuntimeLoadError::UnsafeMetadata)
        );
        let wrong_owner = ActivationAuthorityCoordinator {
            paths: test_fixture.coordinator.paths.clone(),
            expected_uid: actual_uid.wrapping_add(1),
        };
        assert!(matches!(
            wrong_owner.status(20),
            Err(CoordinatorError::Runtime(RuntimeLoadError::UnsafeMetadata))
        ));

        let mut authority: serde_json::Value = serde_json::from_slice(
            &fs::read(&test_fixture.coordinator.paths.authority_file).unwrap(),
        )
        .unwrap();
        authority["revision"] = serde_json::json!(99);
        fs::set_permissions(
            &test_fixture.coordinator.paths.authority_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            &test_fixture.coordinator.paths.authority_file,
            serde_json::to_vec(&authority).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            &test_fixture.coordinator.paths.authority_file,
            fs::Permissions::from_mode(AUTHORITY_MODE),
        )
        .unwrap();
        assert!(matches!(
            test_fixture.coordinator.status(20),
            Err(CoordinatorError::Runtime(RuntimeLoadError::BindingMismatch))
        ));
    }

    #[test]
    fn ready_requires_complete_fresh_proofs_and_exact_grant() {
        let fixture = fixture();
        let permit = permit(14);
        fixture.coordinator.rotate_case(permit, 20).unwrap();
        finish_case(&fixture.coordinator, permit);
        for incomplete in [
            ActivationReconciliationProofs {
                cleanup_proof_digest: [0; 32],
                ..proofs()
            },
            ActivationReconciliationProofs {
                dns_proof_digest: [0; 32],
                ..proofs()
            },
            ActivationReconciliationProofs {
                observed_at: 19,
                ..proofs()
            },
        ] {
            assert_eq!(
                fixture
                    .coordinator
                    .publish_ready(ordinary([16; 32]), incomplete, 20),
                Err(CoordinatorError::IncompleteProofs)
            );
        }
        assert!(matches!(
            fixture
                .coordinator
                .publish_ready(ordinary([99; 32]), proofs(), 20),
            Err(CoordinatorError::Activation(ActivationError::InvalidGrant))
        ));
        assert_eq!(fixture.coordinator.status(20).unwrap().ordinary_capacity, 0);
    }
}
