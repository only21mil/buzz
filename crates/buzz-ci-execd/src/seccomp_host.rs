//! Code-only host plan for installing and linking the Phase-1 seccomp profile.
//!
//! This module performs no I/O. Trusted host code executes the closed plan and
//! supplies a fresh readback. Only [`SeccompHostPlan::readiness`] can produce
//! the opaque proof used by later activation code.

use crate::seccomp::{
    SeccompFileReadback, SeccompLeaseEvidence, SeccompReadbackError, SeccompSeedAction,
    SeccompSeedPlan, SECCOMP_PROFILE_DIRECTORY, SECCOMP_PROFILE_MODE,
};

/// Exact owner required for installed directories and files.
pub const SECCOMP_OWNER_UID: u32 = 0;
/// Exact group required for installed directories and files.
pub const SECCOMP_OWNER_GID: u32 = 0;
/// Exact traverse-only mode for the immutable profile chain.
///
/// The installed profile is public input, while activation receipts remain in
/// a separate private tree. Execute-only access lets the job principal open
/// the one compiled profile path without listing sibling names.
pub const SECCOMP_DIRECTORY_MODE: u32 = 0o711;

const DIRECTORY_SPECS: [SeccompDirectorySpec; 4] = [
    SeccompDirectorySpec::new("/var/lib/buzzci"),
    SeccompDirectorySpec::new("/var/lib/buzzci/seccomp"),
    SeccompDirectorySpec::new("/var/lib/buzzci/seccomp/v1"),
    SeccompDirectorySpec::new(SECCOMP_PROFILE_DIRECTORY),
];

/// One fixed directory in the install plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompDirectorySpec {
    path: &'static str,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}

impl SeccompDirectorySpec {
    const fn new(path: &'static str) -> Self {
        Self {
            path,
            owner_uid: SECCOMP_OWNER_UID,
            owner_gid: SECCOMP_OWNER_GID,
            mode: SECCOMP_DIRECTORY_MODE,
        }
    }

    /// Exact absolute path.
    pub const fn path(self) -> &'static str {
        self.path
    }

    /// Required numeric owner UID.
    pub const fn owner_uid(self) -> u32 {
        self.owner_uid
    }

    /// Required numeric owner GID.
    pub const fn owner_gid(self) -> u32 {
        self.owner_gid
    }

    /// Required permission bits.
    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// Pinned digest at each stage of the profile install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompArtifactDigests {
    source: &'static str,
    build: &'static str,
    install: &'static str,
}

impl SeccompArtifactDigests {
    /// Digest verified on the packaged source descriptor.
    pub const fn source(self) -> &'static str {
        self.source
    }

    /// Digest computed while copying into the sealed temporary file.
    pub const fn build(self) -> &'static str {
        self.build
    }

    /// Digest verified after the final no-follow reopen.
    pub const fn install(self) -> &'static str {
        self.install
    }
}

/// Closed host plan. It accepts no caller-selected path or profile bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompHostPlan {
    seed: SeccompSeedPlan,
}

impl SeccompHostPlan {
    /// Construct the sole reviewed Phase-1 plan.
    pub const fn phase1() -> Self {
        Self {
            seed: SeccompSeedPlan::phase1(),
        }
    }

    /// Packaged source path inherited from the readiness contract.
    pub const fn source_path(self) -> &'static str {
        self.seed.source_path()
    }

    /// Final content-addressed install path.
    pub const fn install_path(self) -> &'static str {
        self.seed.destination_path()
    }

    /// Exact source, build, and installed digests.
    pub const fn digests(self) -> SeccompArtifactDigests {
        let digest = self.seed.expected_digest();
        SeccompArtifactDigests {
            source: digest,
            build: digest,
            install: digest,
        }
    }

    /// Ordered seed actions inherited unchanged from the readiness contract.
    pub const fn actions(self) -> &'static [SeccompSeedAction] {
        self.seed.actions()
    }

    /// Exact directory chain the executor may create or inspect.
    pub const fn directories(self) -> &'static [SeccompDirectorySpec; 4] {
        &DIRECTORY_SPECS
    }

    /// Verify all host and OCI observations. Any missing or drifted fact
    /// returns an error and produces no readiness proof.
    pub fn readiness(
        self,
        readback: &SeccompHostReadback,
    ) -> Result<SeccompHostReadiness, SeccompHostError> {
        self.seed
            .verify_source(&readback.source)
            .map_err(SeccompHostError::Source)?;
        verify_directories(&readback.directories)?;
        verify_atomic_install(self, &readback.atomic_install)?;
        let lease_evidence = self
            .seed
            .readiness(&readback.installed)
            .map_err(SeccompHostError::Installed)?;
        verify_oci_link(self, &readback.oci_prestart)?;
        Ok(SeccompHostReadiness {
            lease_evidence,
            oci_prestart_linked: true,
        })
    }
}

/// File-system object kind observed without following links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompHostFileType {
    /// Directory.
    Directory,
    /// Regular file.
    Regular,
    /// Symbolic link.
    Symlink,
    /// Device, socket, FIFO, or another unsupported type.
    Other,
}

/// Fresh readback of one exact broker-owned directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompDirectoryReadback {
    pub path: String,
    pub canonical_path: String,
    pub file_type: SeccompHostFileType,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u32,
    pub opened_no_follow: bool,
}

/// Readback of the atomic copy, seal, rename, and sync sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompAtomicInstallReadback {
    pub actions: Vec<SeccompSeedAction>,
    pub source_digest: String,
    pub build_digest: String,
    pub install_digest: String,
    pub temporary_file_type: SeccompHostFileType,
    pub temporary_link_count: u64,
    pub temporary_owner_uid: u32,
    pub temporary_owner_gid: u32,
    pub temporary_mode: u32,
    pub source_opened_no_follow: bool,
    pub temporary_created_exclusive: bool,
    pub temporary_opened_no_follow: bool,
    pub copied_from_verified_source: bool,
    pub temporary_file_fsynced: bool,
    pub atomic_rename_noreplace: bool,
    pub destination_directory_fsynced: bool,
    pub installed_reopened_no_follow: bool,
}

/// OCI linkage observed before any container start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciPrestartSeccompReadback {
    pub profile_path: String,
    pub profile_digest: String,
    pub linked_before_start: bool,
    pub no_new_privileges: bool,
    pub unconfined_fallback: bool,
}

/// Complete fresh host observation consumed as one readiness decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompHostReadback {
    pub source: SeccompFileReadback,
    pub directories: [SeccompDirectoryReadback; 4],
    pub atomic_install: SeccompAtomicInstallReadback,
    pub installed: SeccompFileReadback,
    pub oci_prestart: OciPrestartSeccompReadback,
}

/// Opaque proof that installation and OCI linkage matched the reviewed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompHostReadiness {
    lease_evidence: SeccompLeaseEvidence,
    oci_prestart_linked: bool,
}

impl SeccompHostReadiness {
    /// Existing activation evidence, available only after complete readback.
    pub const fn lease_evidence(self) -> SeccompLeaseEvidence {
        self.lease_evidence
    }

    /// Whether exact OCI linkage was observed before container start.
    pub const fn oci_prestart_linked(self) -> bool {
        self.oci_prestart_linked
    }
}

/// Exact reason host readiness remained closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompHostError {
    /// Packaged source readback failed the existing contract.
    Source(SeccompReadbackError),
    /// Destination directory path or canonical path drifted.
    DirectoryPath,
    /// Destination directory type drifted.
    DirectoryType,
    /// Destination directory owner drifted.
    DirectoryOwner,
    /// Destination directory mode drifted.
    DirectoryMode,
    /// A directory was opened without no-follow enforcement.
    DirectoryFollowed,
    /// Atomic seed actions were missing, reordered, or extended.
    AtomicSequence,
    /// Source, build, or install digest drifted.
    DigestDrift,
    /// Temporary file metadata drifted.
    TemporaryFile,
    /// Exclusive/no-follow source or temporary creation was not proved.
    UnsafeOpen,
    /// Copy did not originate from the verified source descriptor.
    UnverifiedCopy,
    /// Temporary file fsync did not precede rename.
    TemporaryFileNotSynced,
    /// Atomic no-replace rename was not proved.
    RenameNotAtomic,
    /// Containing directory fsync after rename was not proved.
    DirectoryNotSynced,
    /// Final file was not reopened with no-follow semantics.
    InstalledFileFollowed,
    /// Installed readback failed the existing readiness contract.
    Installed(SeccompReadbackError),
    /// OCI prestart path, digest, ordering, or hardening drifted.
    OciPrestartDrift,
}

fn verify_directories(readbacks: &[SeccompDirectoryReadback; 4]) -> Result<(), SeccompHostError> {
    for (expected, observed) in DIRECTORY_SPECS.into_iter().zip(readbacks) {
        if observed.path != expected.path || observed.canonical_path != expected.path {
            return Err(SeccompHostError::DirectoryPath);
        }
        if observed.file_type != SeccompHostFileType::Directory {
            return Err(SeccompHostError::DirectoryType);
        }
        if observed.owner_uid != expected.owner_uid || observed.owner_gid != expected.owner_gid {
            return Err(SeccompHostError::DirectoryOwner);
        }
        if observed.mode != expected.mode {
            return Err(SeccompHostError::DirectoryMode);
        }
        if !observed.opened_no_follow {
            return Err(SeccompHostError::DirectoryFollowed);
        }
    }
    Ok(())
}

fn verify_atomic_install(
    plan: SeccompHostPlan,
    observed: &SeccompAtomicInstallReadback,
) -> Result<(), SeccompHostError> {
    if observed.actions != plan.actions() {
        return Err(SeccompHostError::AtomicSequence);
    }
    let digests = plan.digests();
    if observed.source_digest != digests.source
        || observed.build_digest != digests.build
        || observed.install_digest != digests.install
    {
        return Err(SeccompHostError::DigestDrift);
    }
    if observed.temporary_file_type != SeccompHostFileType::Regular
        || observed.temporary_link_count != 1
        || observed.temporary_owner_uid != SECCOMP_OWNER_UID
        || observed.temporary_owner_gid != SECCOMP_OWNER_GID
        || observed.temporary_mode != SECCOMP_PROFILE_MODE
    {
        return Err(SeccompHostError::TemporaryFile);
    }
    if !observed.source_opened_no_follow
        || !observed.temporary_created_exclusive
        || !observed.temporary_opened_no_follow
    {
        return Err(SeccompHostError::UnsafeOpen);
    }
    if !observed.copied_from_verified_source {
        return Err(SeccompHostError::UnverifiedCopy);
    }
    if !observed.temporary_file_fsynced {
        return Err(SeccompHostError::TemporaryFileNotSynced);
    }
    if !observed.atomic_rename_noreplace {
        return Err(SeccompHostError::RenameNotAtomic);
    }
    if !observed.destination_directory_fsynced {
        return Err(SeccompHostError::DirectoryNotSynced);
    }
    if !observed.installed_reopened_no_follow {
        return Err(SeccompHostError::InstalledFileFollowed);
    }
    Ok(())
}

fn verify_oci_link(
    plan: SeccompHostPlan,
    observed: &OciPrestartSeccompReadback,
) -> Result<(), SeccompHostError> {
    if observed.profile_path != plan.install_path()
        || observed.profile_digest != plan.digests().install
        || !observed.linked_before_start
        || !observed.no_new_privileges
        || observed.unconfined_fallback
    {
        return Err(SeccompHostError::OciPrestartDrift);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::{SeccompFileType, FEDORA_SECCOMP_SOURCE_MODE, FEDORA_SECCOMP_SOURCE_PATH};

    fn file(path: &str, mode: u32) -> SeccompFileReadback {
        SeccompFileReadback {
            path: path.into(),
            canonical_path: path.into(),
            file_type: SeccompFileType::Regular,
            link_count: 1,
            owner_uid: SECCOMP_OWNER_UID,
            owner_gid: SECCOMP_OWNER_GID,
            mode,
            digest: SeccompHostPlan::phase1().digests().install.into(),
        }
    }

    fn directory(spec: SeccompDirectorySpec) -> SeccompDirectoryReadback {
        SeccompDirectoryReadback {
            path: spec.path.into(),
            canonical_path: spec.path.into(),
            file_type: SeccompHostFileType::Directory,
            owner_uid: spec.owner_uid,
            owner_gid: spec.owner_gid,
            mode: spec.mode,
            opened_no_follow: true,
        }
    }

    fn valid_readback() -> SeccompHostReadback {
        let plan = SeccompHostPlan::phase1();
        let [first, second, third, fourth] = *plan.directories();
        SeccompHostReadback {
            source: file(FEDORA_SECCOMP_SOURCE_PATH, FEDORA_SECCOMP_SOURCE_MODE),
            directories: [
                directory(first),
                directory(second),
                directory(third),
                directory(fourth),
            ],
            atomic_install: SeccompAtomicInstallReadback {
                actions: plan.actions().to_vec(),
                source_digest: plan.digests().source.into(),
                build_digest: plan.digests().build.into(),
                install_digest: plan.digests().install.into(),
                temporary_file_type: SeccompHostFileType::Regular,
                temporary_link_count: 1,
                temporary_owner_uid: SECCOMP_OWNER_UID,
                temporary_owner_gid: SECCOMP_OWNER_GID,
                temporary_mode: SECCOMP_PROFILE_MODE,
                source_opened_no_follow: true,
                temporary_created_exclusive: true,
                temporary_opened_no_follow: true,
                copied_from_verified_source: true,
                temporary_file_fsynced: true,
                atomic_rename_noreplace: true,
                destination_directory_fsynced: true,
                installed_reopened_no_follow: true,
            },
            installed: file(plan.install_path(), SECCOMP_PROFILE_MODE),
            oci_prestart: OciPrestartSeccompReadback {
                profile_path: plan.install_path().into(),
                profile_digest: plan.digests().install.into(),
                linked_before_start: true,
                no_new_privileges: true,
                unconfined_fallback: false,
            },
        }
    }

    #[test]
    fn plan_is_closed_and_inherits_the_reviewed_contract() {
        let plan = SeccompHostPlan::phase1();
        assert_eq!(plan.source_path(), FEDORA_SECCOMP_SOURCE_PATH);
        assert_eq!(plan.install_path(), plan.seed.destination_path());
        assert_eq!(plan.digests().source(), plan.seed.expected_digest());
        assert_eq!(plan.digests().build(), plan.seed.expected_digest());
        assert_eq!(plan.digests().install(), plan.seed.expected_digest());
        assert_eq!(plan.actions(), plan.seed.actions());
        assert_eq!(plan.directories(), &DIRECTORY_SPECS);
    }

    #[test]
    fn exact_install_and_oci_readback_alone_opens_readiness() {
        let plan = SeccompHostPlan::phase1();
        let ready = plan.readiness(&valid_readback()).expect("host ready");
        assert!(ready.oci_prestart_linked());
        assert_eq!(ready.lease_evidence().path(), plan.install_path());
        assert_eq!(ready.lease_evidence().digest(), plan.digests().install());
    }

    #[test]
    fn path_type_owner_mode_and_digest_drift_stay_unready() {
        let plan = SeccompHostPlan::phase1();

        let mut path = valid_readback();
        path.directories[0].canonical_path = "/tmp/buzzci".into();
        assert_eq!(plan.readiness(&path), Err(SeccompHostError::DirectoryPath));

        let mut file_type = valid_readback();
        file_type.directories[1].file_type = SeccompHostFileType::Symlink;
        assert_eq!(
            plan.readiness(&file_type),
            Err(SeccompHostError::DirectoryType)
        );

        let mut owner = valid_readback();
        owner.directories[2].owner_uid = 1000;
        assert_eq!(
            plan.readiness(&owner),
            Err(SeccompHostError::DirectoryOwner)
        );

        let mut mode = valid_readback();
        mode.directories[3].mode = 0o775;
        assert_eq!(plan.readiness(&mode), Err(SeccompHostError::DirectoryMode));

        let mut digest = valid_readback();
        digest.atomic_install.build_digest = "00".repeat(32);
        assert_eq!(plan.readiness(&digest), Err(SeccompHostError::DigestDrift));
    }

    #[test]
    fn incomplete_atomic_install_never_opens_readiness() {
        let plan = SeccompHostPlan::phase1();

        let mut reordered = valid_readback();
        reordered.atomic_install.actions.swap(0, 1);
        assert_eq!(
            plan.readiness(&reordered),
            Err(SeccompHostError::AtomicSequence)
        );

        let checks: [fn(&mut SeccompAtomicInstallReadback); 8] = [
            |value| value.source_opened_no_follow = false,
            |value| value.temporary_created_exclusive = false,
            |value| value.temporary_opened_no_follow = false,
            |value| value.copied_from_verified_source = false,
            |value| value.temporary_file_fsynced = false,
            |value| value.atomic_rename_noreplace = false,
            |value| value.destination_directory_fsynced = false,
            |value| value.installed_reopened_no_follow = false,
        ];
        for drift in checks {
            let mut readback = valid_readback();
            drift(&mut readback.atomic_install);
            assert!(plan.readiness(&readback).is_err());
        }
    }

    #[test]
    fn oci_drift_and_unconfined_fallback_stay_unready() {
        let plan = SeccompHostPlan::phase1();
        let mut cases = Vec::new();

        let mut wrong_path = valid_readback();
        wrong_path.oci_prestart.profile_path = "/etc/seccomp/other.json".into();
        cases.push(wrong_path);

        let mut wrong_digest = valid_readback();
        wrong_digest.oci_prestart.profile_digest = "00".repeat(32);
        cases.push(wrong_digest);

        let mut after_start = valid_readback();
        after_start.oci_prestart.linked_before_start = false;
        cases.push(after_start);

        let mut privileges = valid_readback();
        privileges.oci_prestart.no_new_privileges = false;
        cases.push(privileges);

        let mut unconfined = valid_readback();
        unconfined.oci_prestart.unconfined_fallback = true;
        cases.push(unconfined);

        for readback in cases {
            assert_eq!(
                plan.readiness(&readback),
                Err(SeccompHostError::OciPrestartDrift)
            );
        }
    }

    #[test]
    fn existing_file_contract_drift_propagates_without_a_proof() {
        let plan = SeccompHostPlan::phase1();
        let mut source = valid_readback();
        source.source.file_type = SeccompFileType::Symlink;
        assert_eq!(
            plan.readiness(&source),
            Err(SeccompHostError::Source(SeccompReadbackError::NotRegular))
        );

        let mut installed = valid_readback();
        installed.installed.link_count = 2;
        assert_eq!(
            plan.readiness(&installed),
            Err(SeccompHostError::Installed(
                SeccompReadbackError::WrongLinkCount
            ))
        );
    }
}
