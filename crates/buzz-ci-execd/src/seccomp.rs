//! Fail-closed plan and readback checks for the Phase-1 seccomp profile.
//!
//! This module describes the privileged installation boundary without mutating
//! the host. The root-owned activation code must execute every plan action,
//! then pass a fresh no-follow readback to [`SeccompSeedPlan::readiness`].

use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};

/// Fedora's packaged container seccomp profile used as the only seed source.
pub const FEDORA_SECCOMP_SOURCE_PATH: &str = "/usr/share/containers/seccomp.json";

/// Root-owned directory that contains the content-addressed profile.
pub const SECCOMP_PROFILE_DIRECTORY: &str = "/var/lib/buzzci/seccomp/v1/sha256";

/// Final profile mode. No principal may modify installed bytes in place.
pub const SECCOMP_PROFILE_MODE: u32 = 0o444;

/// Source mode shipped by Fedora. Only root may replace the package file.
pub const FEDORA_SECCOMP_SOURCE_MODE: u32 = 0o644;

/// One mandatory action in the privileged atomic seed sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompSeedAction {
    /// Open the Fedora source through exact root-owned directory descriptors
    /// with no-follow semantics.
    OpenSourceNoFollow,
    /// Verify source path, canonical path, type, link count, owner, mode, and
    /// content digest before copying any bytes.
    VerifySource,
    /// Open or create the exact destination directory chain as root-owned
    /// non-writable-by-group-or-other directories, rejecting links.
    OpenDestinationDirectoriesNoFollow,
    /// Create an executor-chosen unpredictable temporary regular file with
    /// exclusive and no-follow flags inside the final directory.
    CreateExclusiveTemporaryFile,
    /// Copy the source while hashing, then require the expected digest.
    CopyAndVerifyDigest,
    /// Set owner `0:0`, set mode `0444`, and fsync the temporary file.
    SealTemporaryFile,
    /// Atomically rename the temporary file to the exact content-addressed
    /// destination name and fsync the containing directory.
    RenameAndSyncDirectory,
    /// Reopen the final file without following links and perform the complete
    /// readiness readback.
    VerifyInstalledReadback,
}

const SEED_ACTIONS: [SeccompSeedAction; 8] = [
    SeccompSeedAction::OpenSourceNoFollow,
    SeccompSeedAction::VerifySource,
    SeccompSeedAction::OpenDestinationDirectoriesNoFollow,
    SeccompSeedAction::CreateExclusiveTemporaryFile,
    SeccompSeedAction::CopyAndVerifyDigest,
    SeccompSeedAction::SealTemporaryFile,
    SeccompSeedAction::RenameAndSyncDirectory,
    SeccompSeedAction::VerifyInstalledReadback,
];

/// Immutable Phase-1 seccomp seed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompSeedPlan;

impl SeccompSeedPlan {
    /// Return the only accepted Phase-1 plan.
    pub const fn phase1() -> Self {
        Self
    }

    /// Exact Fedora source path.
    pub const fn source_path(self) -> &'static str {
        FEDORA_SECCOMP_SOURCE_PATH
    }

    /// Exact content-addressed destination path.
    pub const fn destination_path(self) -> &'static str {
        PHASE1_SECCOMP_PROFILE_PATH
    }

    /// Expected SHA-256 of both source and installed bytes.
    pub const fn expected_digest(self) -> &'static str {
        PHASE1_SECCOMP_PROFILE_DIGEST
    }

    /// Required ordered atomic seed actions.
    pub const fn actions(self) -> &'static [SeccompSeedAction] {
        &SEED_ACTIONS
    }

    /// Verify a fresh no-follow readback of Fedora's packaged source.
    pub fn verify_source(self, readback: &SeccompFileReadback) -> Result<(), SeccompReadbackError> {
        verify_common(
            readback,
            FEDORA_SECCOMP_SOURCE_PATH,
            FEDORA_SECCOMP_SOURCE_MODE,
        )
    }

    /// Verify the installed file and return the exact lease evidence. Any
    /// missing or mismatched observation keeps readiness closed.
    pub fn readiness(
        self,
        readback: &SeccompFileReadback,
    ) -> Result<SeccompLeaseEvidence, SeccompReadbackError> {
        verify_common(readback, PHASE1_SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_MODE)?;
        Ok(SeccompLeaseEvidence {
            path: PHASE1_SECCOMP_PROFILE_PATH,
            digest: PHASE1_SECCOMP_PROFILE_DIGEST,
        })
    }
}

/// File type observed through a no-follow metadata readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompFileType {
    /// Ordinary regular file.
    Regular,
    /// Symbolic link, always rejected.
    Symlink,
    /// Directory, device, socket, FIFO, or another non-regular type.
    Other,
}

/// Fresh metadata and digest evidence for one exact path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompFileReadback {
    /// Path requested by the trusted activation code.
    pub path: String,
    /// Canonical path obtained from the already-open descriptor. It must equal
    /// `path`; any linked parent or final component is rejected.
    pub canonical_path: String,
    /// Type from no-follow metadata.
    pub file_type: SeccompFileType,
    /// Hard-link count. Phase 1 requires exactly one.
    pub link_count: u64,
    /// Numeric owner UID.
    pub owner_uid: u32,
    /// Numeric owner GID.
    pub owner_gid: u32,
    /// Permission bits only, with file-type bits removed.
    pub mode: u32,
    /// Lowercase SHA-256 hex computed from the already-open file.
    pub digest: String,
}

/// Path and digest persisted into each validated lease record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompLeaseEvidence {
    /// Exact installed profile path.
    pub path: &'static str,
    /// Exact installed profile digest.
    pub digest: &'static str,
}

/// Exact reason host readiness remained closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompReadbackError {
    /// Requested path differed from the plan.
    WrongPath,
    /// Canonical descriptor path differed, proving a linked component or path
    /// substitution.
    LinkedPath,
    /// Object was absent or not a regular file.
    NotRegular,
    /// Object had another hard link.
    WrongLinkCount,
    /// Object was not owned by root:root.
    WrongOwner,
    /// Permission bits differed from the exact source or installed mode.
    WrongMode,
    /// Content digest differed from the pinned source digest.
    WrongDigest,
}

fn verify_common(
    readback: &SeccompFileReadback,
    expected_path: &str,
    expected_mode: u32,
) -> Result<(), SeccompReadbackError> {
    if readback.path != expected_path {
        return Err(SeccompReadbackError::WrongPath);
    }
    if readback.canonical_path != expected_path {
        return Err(SeccompReadbackError::LinkedPath);
    }
    if readback.file_type != SeccompFileType::Regular {
        return Err(SeccompReadbackError::NotRegular);
    }
    if readback.link_count != 1 {
        return Err(SeccompReadbackError::WrongLinkCount);
    }
    if readback.owner_uid != 0 || readback.owner_gid != 0 {
        return Err(SeccompReadbackError::WrongOwner);
    }
    if readback.mode != expected_mode {
        return Err(SeccompReadbackError::WrongMode);
    }
    if readback.digest != PHASE1_SECCOMP_PROFILE_DIGEST {
        return Err(SeccompReadbackError::WrongDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readback(path: &str, mode: u32) -> SeccompFileReadback {
        SeccompFileReadback {
            path: path.into(),
            canonical_path: path.into(),
            file_type: SeccompFileType::Regular,
            link_count: 1,
            owner_uid: 0,
            owner_gid: 0,
            mode,
            digest: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
        }
    }

    #[test]
    fn plan_is_exact_and_atomic() {
        let plan = SeccompSeedPlan::phase1();
        assert_eq!(plan.source_path(), FEDORA_SECCOMP_SOURCE_PATH);
        assert_eq!(plan.destination_path(), PHASE1_SECCOMP_PROFILE_PATH);
        assert_eq!(plan.expected_digest(), PHASE1_SECCOMP_PROFILE_DIGEST);
        assert_eq!(plan.actions(), &SEED_ACTIONS);
        assert_eq!(
            plan.actions().last(),
            Some(&SeccompSeedAction::VerifyInstalledReadback)
        );
    }

    #[test]
    fn exact_source_and_installed_readbacks_open_readiness() {
        let plan = SeccompSeedPlan::phase1();
        plan.verify_source(&readback(
            FEDORA_SECCOMP_SOURCE_PATH,
            FEDORA_SECCOMP_SOURCE_MODE,
        ))
        .unwrap();
        let evidence = plan
            .readiness(&readback(PHASE1_SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_MODE))
            .unwrap();
        assert_eq!(evidence.path, PHASE1_SECCOMP_PROFILE_PATH);
        assert_eq!(evidence.digest, PHASE1_SECCOMP_PROFILE_DIGEST);
    }

    #[test]
    fn links_paths_digests_modes_and_owners_fail_closed() {
        let plan = SeccompSeedPlan::phase1();
        let valid = readback(PHASE1_SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_MODE);
        let mut cases = Vec::new();

        let mut wrong_path = valid.clone();
        wrong_path.path = format!("{}.other", PHASE1_SECCOMP_PROFILE_PATH);
        cases.push((wrong_path, SeccompReadbackError::WrongPath));

        let mut linked_path = valid.clone();
        linked_path.canonical_path = "/tmp/redirected-seccomp.json".into();
        cases.push((linked_path, SeccompReadbackError::LinkedPath));

        let mut symlink = valid.clone();
        symlink.file_type = SeccompFileType::Symlink;
        cases.push((symlink, SeccompReadbackError::NotRegular));

        let mut hard_link = valid.clone();
        hard_link.link_count = 2;
        cases.push((hard_link, SeccompReadbackError::WrongLinkCount));

        let mut owner = valid.clone();
        owner.owner_uid = 1_000;
        cases.push((owner, SeccompReadbackError::WrongOwner));

        let mut mode = valid.clone();
        mode.mode = 0o644;
        cases.push((mode, SeccompReadbackError::WrongMode));

        let mut digest = valid;
        digest.digest = "0".repeat(64);
        cases.push((digest, SeccompReadbackError::WrongDigest));

        for (candidate, expected) in cases {
            assert_eq!(plan.readiness(&candidate), Err(expected));
        }
    }

    #[test]
    fn unconfined_or_unknown_destination_types_never_open_readiness() {
        let plan = SeccompSeedPlan::phase1();
        for file_type in [SeccompFileType::Symlink, SeccompFileType::Other] {
            let mut candidate = readback(PHASE1_SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_MODE);
            candidate.file_type = file_type;
            assert_eq!(
                plan.readiness(&candidate),
                Err(SeccompReadbackError::NotRegular)
            );
        }
    }
}
