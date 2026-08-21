//! Root-owned activation adapter for the fixed Phase-1 seccomp profile.
//!
//! The adapter installs through [`crate::seccomp_exec::install_phase1`], then
//! performs a separate descriptor-based readback before releasing startup
//! evidence or the retained install capability.

use crate::seccomp::{SeccompLeaseEvidence, SeccompReadbackError, SeccompSeedPlan};
use crate::seccomp_exec::{
    fresh_phase1_readback, install_phase1, FreshSeccompReadback, SeccompExecError,
    SeccompInstallDisposition, SeccompInstallReceipt,
};
use crate::seccomp_host::{SeccompHostFileType, SeccompHostPlan};

/// Stateless production entry point for Phase-1 seccomp activation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SeccompActivationAdapter;

impl SeccompActivationAdapter {
    /// Construct the sole production adapter.
    pub const fn production() -> Self {
        Self
    }

    /// Install or reuse the fixed profile, then require a fresh persisted
    /// readback before returning either startup evidence or install authority.
    pub fn activate(self) -> Result<SeccompStartupProof, SeccompActivationError> {
        let install = install_phase1().map_err(SeccompActivationError::Install)?;
        let readback = fresh_phase1_readback(install).map_err(SeccompActivationError::Readback)?;
        validate_startup_readback(install, &readback)
    }
}

/// Startup proof released only after the install and independent readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompStartupProof {
    seccomp_evidence: SeccompLeaseEvidence,
    install_capability: SeccompInstallCapability,
}

impl SeccompStartupProof {
    /// Evidence suitable for `ReadyRestoreValidation.seccomp_evidence`.
    pub const fn seccomp_evidence(self) -> SeccompLeaseEvidence {
        self.seccomp_evidence
    }

    /// Retained authority for later per-job OCI linkage.
    pub const fn install_capability(self) -> SeccompInstallCapability {
        self.install_capability
    }
}

/// Opaque retained install authority. No public constructor exposes an
/// unverified [`SeccompInstallReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompInstallCapability {
    receipt: SeccompInstallReceipt,
}

impl SeccompInstallCapability {
    /// Whether activation installed new bytes or reused an exact sealed file.
    pub const fn disposition(self) -> SeccompInstallDisposition {
        self.receipt.disposition()
    }

    /// Exact profile path bound to the retained receipt.
    pub const fn profile_path(self) -> &'static str {
        self.receipt.profile_path()
    }

    /// Digest of the exact persisted install receipt bytes.
    pub fn receipt_digest(self) -> String {
        self.receipt.install_receipt_digest()
    }
}

/// Closed activation failure. Every variant withholds both proof types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SeccompActivationError {
    #[error("seccomp install failed: {0:?}")]
    Install(SeccompExecError),
    #[error("fresh seccomp readback failed: {0:?}")]
    Readback(SeccompExecError),
    #[error("packaged seccomp source drifted: {0:?}")]
    Source(SeccompReadbackError),
    #[error("seccomp destination directory path drifted")]
    DirectoryPath,
    #[error("seccomp destination directory type drifted")]
    DirectoryType,
    #[error("seccomp destination directory owner drifted")]
    DirectoryOwner,
    #[error("seccomp destination directory mode drifted")]
    DirectoryMode,
    #[error("seccomp destination directory was not opened no-follow")]
    DirectoryFollowed,
    #[error("seccomp install receipt is not bound to the pinned profile")]
    InstallReceiptDrift,
    #[error("installed seccomp profile drifted: {0:?}")]
    Installed(SeccompReadbackError),
}

fn validate_startup_readback(
    install: SeccompInstallReceipt,
    readback: &FreshSeccompReadback,
) -> Result<SeccompStartupProof, SeccompActivationError> {
    let seed = SeccompSeedPlan::phase1();
    seed.verify_source(readback.source())
        .map_err(SeccompActivationError::Source)?;

    for (expected, observed) in SeccompHostPlan::phase1()
        .directories()
        .iter()
        .zip(readback.directories())
    {
        if observed.path != expected.path() || observed.canonical_path != expected.path() {
            return Err(SeccompActivationError::DirectoryPath);
        }
        if observed.file_type != SeccompHostFileType::Directory {
            return Err(SeccompActivationError::DirectoryType);
        }
        if observed.owner_uid != expected.owner_uid() || observed.owner_gid != expected.owner_gid()
        {
            return Err(SeccompActivationError::DirectoryOwner);
        }
        if observed.mode != expected.mode() {
            return Err(SeccompActivationError::DirectoryMode);
        }
        if !observed.opened_no_follow {
            return Err(SeccompActivationError::DirectoryFollowed);
        }
    }

    let expected_digest = seed.expected_digest();
    if install.source_digest() != expected_digest
        || install.build_digest() != expected_digest
        || install.install_digest() != expected_digest
        || !install.has_persisted_receipt()
    {
        return Err(SeccompActivationError::InstallReceiptDrift);
    }
    let seccomp_evidence = seed
        .readiness(readback.installed())
        .map_err(SeccompActivationError::Installed)?;
    Ok(SeccompStartupProof {
        seccomp_evidence,
        install_capability: SeccompInstallCapability { receipt: install },
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    use nix::unistd::{getegid, geteuid};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::seccomp::{FEDORA_SECCOMP_SOURCE_MODE, SECCOMP_PROFILE_MODE};
    use crate::seccomp_exec::{
        fresh_phase1_readback_mapped, fresh_phase1_readback_mapped_with_installed_owner,
        install_phase1_mapped, SECCOMP_INSTALL_RECEIPT_PATH,
    };

    const PROFILE: &[u8] = br#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}"#;

    struct Fixture {
        root: TempDir,
        digest: [u8; 32],
        owner_uid: u32,
        owner_gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir_all(root.path().join("usr/share/containers")).unwrap();
            fs::create_dir_all(root.path().join("var/lib")).unwrap();
            let source = root.path().join("usr/share/containers/seccomp.json");
            fs::write(&source, PROFILE).unwrap();
            fs::set_permissions(
                source,
                fs::Permissions::from_mode(FEDORA_SECCOMP_SOURCE_MODE),
            )
            .unwrap();
            Self {
                root,
                digest: Sha256::digest(PROFILE).into(),
                owner_uid: geteuid().as_raw(),
                owner_gid: getegid().as_raw(),
            }
        }

        fn activate(
            &self,
            timestamp: u64,
        ) -> Result<(SeccompInstallReceipt, FreshSeccompReadback), SeccompExecError> {
            let install = install_phase1_mapped(
                self.root.path(),
                self.digest,
                self.owner_uid,
                self.owner_gid,
                timestamp,
            )?;
            let readback = fresh_phase1_readback_mapped(self.root.path(), install)?;
            Ok((install, readback))
        }

        fn install(&self) -> SeccompInstallReceipt {
            install_phase1_mapped(
                self.root.path(),
                self.digest,
                self.owner_uid,
                self.owner_gid,
                100,
            )
            .unwrap()
        }

        fn profile_path(&self) -> PathBuf {
            self.root
                .path()
                .join("var/lib/buzzci/seccomp/v1/sha256")
                .join(format!("{}.json", hex::encode(self.digest)))
        }

        fn receipt_path(&self) -> PathBuf {
            self.root
                .path()
                .join(SECCOMP_INSTALL_RECEIPT_PATH.trim_start_matches('/'))
        }

        fn readback(
            &self,
            install: SeccompInstallReceipt,
        ) -> Result<FreshSeccompReadback, SeccompExecError> {
            fresh_phase1_readback_mapped(self.root.path(), install)
        }
    }

    fn assert_complete_readback(readback: &FreshSeccompReadback, fixture: &Fixture) {
        assert_eq!(readback.source().digest, hex::encode(fixture.digest));
        assert_eq!(readback.installed().digest, hex::encode(fixture.digest));
        assert_eq!(readback.directories().len(), 4);
        assert!(readback
            .directories()
            .iter()
            .all(|directory| directory.opened_no_follow));
    }

    #[test]
    fn fresh_install_reopens_profile_chain_and_receipt() {
        let fixture = Fixture::new();
        let (install, readback) = fixture.activate(100).unwrap();
        assert_eq!(install.disposition(), SeccompInstallDisposition::Installed);
        assert_complete_readback(&readback, &fixture);
        assert!(fixture.receipt_path().is_file());
    }

    #[test]
    fn existing_correct_profile_and_receipt_are_reused() {
        let fixture = Fixture::new();
        let (first, _) = fixture.activate(100).unwrap();
        let profile_before = fs::metadata(fixture.profile_path())
            .unwrap()
            .modified()
            .unwrap();
        let receipt_before = fs::read(fixture.receipt_path()).unwrap();

        let (second, readback) = fixture.activate(200).unwrap();
        assert_eq!(first.disposition(), SeccompInstallDisposition::Installed);
        assert_eq!(second.disposition(), SeccompInstallDisposition::Existing);
        assert_eq!(second.installed_at_unix_ns(), 100);
        assert_eq!(
            fs::metadata(fixture.profile_path())
                .unwrap()
                .modified()
                .unwrap(),
            profile_before
        );
        assert_eq!(fs::read(fixture.receipt_path()).unwrap(), receipt_before);
        assert_complete_readback(&readback, &fixture);
    }

    #[test]
    fn wrong_installed_digest_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        let profile = fixture.profile_path();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&profile, b"tampered profile").unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(SECCOMP_PROFILE_MODE)).unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::InstallDigest)
        );
    }

    #[test]
    fn symlinked_installed_profile_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        let profile = fixture.profile_path();
        fs::remove_file(&profile).unwrap();
        symlink(
            fixture
                .root
                .path()
                .join("usr/share/containers/seccomp.json"),
            &profile,
        )
        .unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::OpenInstalled)
        );
    }

    #[test]
    fn extra_profile_hardlink_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        fs::hard_link(
            fixture.profile_path(),
            fixture
                .root
                .path()
                .join("var/lib/buzzci/seccomp/v1/sha256/extra.json"),
        )
        .unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::InvalidInstalled)
        );
    }

    #[test]
    fn wrong_profile_owner_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        assert_eq!(
            fresh_phase1_readback_mapped_with_installed_owner(
                fixture.root.path(),
                install,
                fixture.owner_uid.wrapping_add(1),
                fixture.owner_gid,
            ),
            Err(SeccompExecError::InvalidInstalled)
        );
    }

    #[test]
    fn wrong_profile_mode_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        fs::set_permissions(fixture.profile_path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::InvalidInstalled)
        );
    }

    #[test]
    fn missing_receipt_fails_without_recreating_it() {
        let fixture = Fixture::new();
        let install = fixture.install();
        let receipt = fixture.receipt_path();
        fs::remove_file(&receipt).unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::OpenReceipt)
        );
        assert!(!receipt.exists());
    }

    #[test]
    fn tampered_receipt_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        let receipt = fixture.receipt_path();
        let mut bytes = fs::read(&receipt).unwrap();
        bytes.push(b'\n');
        fs::write(&receipt, bytes).unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::ReceiptDrift)
        );
    }

    #[test]
    fn wrong_receipt_mode_fails_fresh_readback() {
        let fixture = Fixture::new();
        let install = fixture.install();
        fs::set_permissions(fixture.receipt_path(), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            fixture.readback(install),
            Err(SeccompExecError::InvalidReceipt)
        );
    }
}
