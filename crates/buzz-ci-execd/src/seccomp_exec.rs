//! Concrete Linux filesystem executor for the fixed Phase-1 seccomp profile.
//!
//! Production entry points accept no paths or profile bytes. Every component is
//! opened relative to an already-open directory with no-follow semantics.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::GitOid;
use buzz_ci_policy_proxy::{CanonicalCreate, EffectiveContainerSpec, VerifiedStart};
use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat2, OFlag, RenameFlags};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode, SFlag};
use nix::unistd::{fchown, fsync, unlinkat, Gid, Uid, UnlinkatFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::activation::{LeaseToken, OrdinaryAdmission};
use crate::seccomp::{
    SeccompFileReadback, SeccompFileType, FEDORA_SECCOMP_SOURCE_MODE, SECCOMP_PROFILE_MODE,
};
use crate::seccomp_host::{
    SeccompDirectoryReadback, SeccompHostFileType, SeccompHostPlan, SECCOMP_DIRECTORY_MODE,
    SECCOMP_OWNER_GID, SECCOMP_OWNER_UID,
};
use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};

const SOURCE_COMPONENTS: [&str; 4] = ["usr", "share", "containers", "seccomp.json"];
const DESTINATION_PARENT_COMPONENTS: [&str; 2] = ["var", "lib"];
const DESTINATION_COMPONENTS: [&str; 4] = ["buzzci", "seccomp", "v1", "sha256"];
const MAX_PROFILE_BYTES: u64 = 1_048_576;
const MAX_RECEIPT_BYTES: u64 = 65_536;
const TEMP_ATTEMPTS: usize = 8;
const RECEIPT_COMPONENTS: [&str; 3] = ["buzzci", "activation", "receipts"];
const OCI_RECEIPT_DIRECTORY: &str = "oci";
const INSTALL_RECEIPT_NAME: &str = "seccomp.json";
const RECEIPT_MODE: u32 = 0o600;
const PRIVATE_RECEIPT_DIRECTORY_MODE: u32 = 0o700;

/// Fixed host-wide receipt written after the installed profile passes readback.
pub const SECCOMP_INSTALL_RECEIPT_PATH: &str = "/var/lib/buzzci/activation/receipts/seccomp.json";

/// Whether installation created the artifact or reused an exact sealed file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompInstallDisposition {
    /// A new temporary file was sealed and atomically installed.
    Installed,
    /// The exact content-addressed artifact already existed and passed readback.
    Existing,
}

/// Opaque receipt returned only after exact source and final-file validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompInstallReceipt {
    disposition: SeccompInstallDisposition,
    source_digest: [u8; 32],
    build_digest: [u8; 32],
    install_digest: [u8; 32],
    install_receipt_digest: [u8; 32],
    installed_at_unix_ns: u64,
    owner_uid: u32,
    owner_gid: u32,
}

impl SeccompInstallReceipt {
    /// Whether a new artifact was installed or an exact existing one was used.
    pub const fn disposition(self) -> SeccompInstallDisposition {
        self.disposition
    }

    /// Fixed production profile path.
    pub const fn profile_path(self) -> &'static str {
        PHASE1_SECCOMP_PROFILE_PATH
    }

    /// Lowercase SHA-256 of the verified source descriptor.
    pub fn source_digest(self) -> String {
        hex::encode(self.source_digest)
    }

    /// Lowercase SHA-256 computed while copying into the temporary file.
    pub fn build_digest(self) -> String {
        hex::encode(self.build_digest)
    }

    /// Lowercase SHA-256 from the final no-follow reopen.
    pub fn install_digest(self) -> String {
        hex::encode(self.install_digest)
    }

    /// SHA-256 of the exact persisted host-wide install receipt bytes.
    pub fn install_receipt_digest(self) -> String {
        hex::encode(self.install_receipt_digest)
    }

    /// Timestamp stored in the immutable host-wide install receipt.
    pub const fn installed_at_unix_ns(self) -> u64 {
        self.installed_at_unix_ns
    }

    pub(crate) fn has_persisted_receipt(self) -> bool {
        self.install_receipt_digest != [0; 32] && self.installed_at_unix_ns != 0
    }
}

/// Closed filesystem failure. No error permits an unconfined fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompExecError {
    OpenRoot,
    InvalidParentDirectory,
    CreateDestinationDirectory,
    InvalidDestinationDirectory,
    OpenSource,
    InvalidSource,
    SourceDigest,
    RandomName,
    CreateTemporary,
    CopyProfile,
    BuildDigest,
    SealTemporary,
    SyncTemporary,
    Rename,
    SyncDestinationDirectory,
    OpenInstalled,
    InvalidInstalled,
    InstallDigest,
    Clock,
    SerializeReceipt,
    CreateReceiptDirectory,
    InvalidReceiptDirectory,
    CreateReceiptTemporary,
    WriteReceipt,
    SealReceipt,
    SyncReceipt,
    RenameReceipt,
    SyncReceiptDirectory,
    OpenReceipt,
    InvalidReceipt,
    ReceiptDrift,
    ReadbackPath,
    OciCapabilityMismatch,
    OciPrestartDrift,
}

/// Install or verify the sole reviewed profile under the real host root.
///
/// This function performs host mutation when called and therefore belongs only
/// in the root execd activation path.
pub fn install_phase1() -> Result<SeccompInstallReceipt, SeccompExecError> {
    let root = open_root(Path::new("/"))?;
    let mut names = KernelTemporaryNames;
    let installed = install_from_root(&root, InstallContract::phase1(), &mut names)?;
    persist_install_receipt(&root, installed, &mut names, unix_time_ns()?)
}

/// Fresh descriptor-based observations made after the install path returns.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FreshSeccompReadback {
    source: SeccompFileReadback,
    directories: [SeccompDirectoryReadback; 4],
    installed: SeccompFileReadback,
}

impl FreshSeccompReadback {
    pub(crate) const fn source(&self) -> &SeccompFileReadback {
        &self.source
    }

    pub(crate) const fn directories(&self) -> &[SeccompDirectoryReadback; 4] {
        &self.directories
    }

    pub(crate) const fn installed(&self) -> &SeccompFileReadback {
        &self.installed
    }
}

/// Reopen and verify every persisted Phase-1 seccomp artifact under `/`.
pub(crate) fn fresh_phase1_readback(
    install: SeccompInstallReceipt,
) -> Result<FreshSeccompReadback, SeccompExecError> {
    fresh_phase1_readback_from_root(Path::new("/"), install)
}

#[cfg(test)]
pub(crate) fn install_phase1_mapped(
    root: &Path,
    expected_digest: [u8; 32],
    owner_uid: u32,
    owner_gid: u32,
    installed_at_unix_ns: u64,
) -> Result<SeccompInstallReceipt, SeccompExecError> {
    let root = open_root(root)?;
    let mut names = KernelTemporaryNames;
    let install = install_from_root(
        &root,
        InstallContract {
            expected_digest,
            final_name: format!("{}.json", hex::encode(expected_digest)),
            owner_uid,
            owner_gid,
        },
        &mut names,
    )?;
    persist_install_receipt(&root, install, &mut names, installed_at_unix_ns)
}

#[cfg(test)]
pub(crate) fn fresh_phase1_readback_mapped(
    root: &Path,
    install: SeccompInstallReceipt,
) -> Result<FreshSeccompReadback, SeccompExecError> {
    fresh_phase1_readback_from_root(root, install)
}

#[cfg(test)]
pub(crate) fn fresh_phase1_readback_mapped_with_installed_owner(
    root: &Path,
    install: SeccompInstallReceipt,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<FreshSeccompReadback, SeccompExecError> {
    fresh_phase1_readback_from_root_with_installed_owner(root, install, (owner_uid, owner_gid))
}

/// Opaque proof that an exact OCI prestart record was persisted and reopened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedOciPrestartLink {
    install: SeccompInstallReceipt,
    observation_digest: [u8; 32],
    lease_id: [u8; 16],
    generation: u64,
}

impl VerifiedOciPrestartLink {
    /// Exact install receipt bound to this verified prestart spec.
    pub const fn install_receipt(self) -> SeccompInstallReceipt {
        self.install
    }

    /// SHA-256 of the exact persisted per-job OCI observation bytes.
    pub fn observation_digest(self) -> String {
        hex::encode(self.observation_digest)
    }

    /// Lease identity taken from the opaque activation token.
    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    /// Lease generation taken from the opaque activation token.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Persist an OCI create-before-start observation bound to opaque policy and
/// activation capabilities.
pub fn persist_oci_prestart_observation(
    install: SeccompInstallReceipt,
    admission: &OrdinaryAdmission,
    lease: LeaseToken,
    create: &CanonicalCreate,
    verified_start: &VerifiedStart,
    effective: &EffectiveContainerSpec,
) -> Result<VerifiedOciPrestartLink, SeccompExecError> {
    let observed_at_unix_ns = unix_time_ns()?;
    let root = open_root(Path::new("/"))?;
    let mut names = KernelTemporaryNames;
    persist_oci_observation_from_root(
        &root,
        install,
        admission,
        lease,
        create,
        verified_start,
        effective,
        &mut names,
        observed_at_unix_ns,
        unix_time_ns()?,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallReceiptRecord {
    schema: String,
    source_path: String,
    source_sha256: String,
    build_sha256: String,
    final_path: String,
    final_sha256: String,
    installed_at_unix_ns: u64,
}

impl InstallReceiptRecord {
    fn from_install(install: SeccompInstallReceipt, installed_at_unix_ns: u64) -> Self {
        Self {
            schema: "buzz-ci-seccomp-install-v1".into(),
            source_path: crate::seccomp::FEDORA_SECCOMP_SOURCE_PATH.into(),
            source_sha256: hex::encode(install.source_digest),
            build_sha256: hex::encode(install.build_digest),
            final_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
            final_sha256: hex::encode(install.install_digest),
            installed_at_unix_ns,
        }
    }

    fn matches_install(&self, install: SeccompInstallReceipt) -> bool {
        self.schema == "buzz-ci-seccomp-install-v1"
            && self.source_path == crate::seccomp::FEDORA_SECCOMP_SOURCE_PATH
            && self.source_sha256 == hex::encode(install.source_digest)
            && self.build_sha256 == hex::encode(install.build_digest)
            && self.final_path == PHASE1_SECCOMP_PROFILE_PATH
            && self.final_sha256 == hex::encode(install.install_digest)
            && self.installed_at_unix_ns != 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OciObservationRecord {
    schema: String,
    candidate_oid: String,
    broker_build_sha256: String,
    host_profile_sha256: String,
    suite_sha256: String,
    signer_sha256: String,
    request_sha256: String,
    manifest_sha256: String,
    isolation_sha256: String,
    job_sha256: String,
    lease_id: String,
    generation: u64,
    canonical_create_sha256: String,
    effective_spec_sha256: String,
    security_options: Vec<String>,
    observed_at_unix_ns: u64,
    prestart_at_unix_ns: u64,
    install_receipt_sha256: String,
}

impl OciObservationRecord {
    fn has_valid_shape(&self) -> bool {
        self.schema == "buzz-ci-seccomp-oci-prestart-v1"
            && valid_git_oid_text(&self.candidate_oid)
            && is_digest(&self.broker_build_sha256)
            && is_digest(&self.host_profile_sha256)
            && is_digest(&self.suite_sha256)
            && is_digest(&self.signer_sha256)
            && is_digest(&self.request_sha256)
            && is_digest(&self.manifest_sha256)
            && is_digest(&self.isolation_sha256)
            && is_digest(&self.job_sha256)
            && self.lease_id.len() == 32
            && self.lease_id.bytes().all(is_lower_hex)
            && self.generation != 0
            && is_digest(&self.canonical_create_sha256)
            && is_digest(&self.effective_spec_sha256)
            && exact_security_options(&self.security_options)
            && self.observed_at_unix_ns != 0
            && self.prestart_at_unix_ns >= self.observed_at_unix_ns
            && is_digest(&self.install_receipt_sha256)
    }

    fn same_identity(&self, expected: &Self) -> bool {
        self.has_valid_shape()
            && self.schema == expected.schema
            && self.candidate_oid == expected.candidate_oid
            && self.broker_build_sha256 == expected.broker_build_sha256
            && self.host_profile_sha256 == expected.host_profile_sha256
            && self.suite_sha256 == expected.suite_sha256
            && self.signer_sha256 == expected.signer_sha256
            && self.request_sha256 == expected.request_sha256
            && self.manifest_sha256 == expected.manifest_sha256
            && self.isolation_sha256 == expected.isolation_sha256
            && self.job_sha256 == expected.job_sha256
            && self.lease_id == expected.lease_id
            && self.generation == expected.generation
            && self.canonical_create_sha256 == expected.canonical_create_sha256
            && self.effective_spec_sha256 == expected.effective_spec_sha256
            && self.security_options == expected.security_options
            && self.install_receipt_sha256 == expected.install_receipt_sha256
    }
}

fn unix_time_ns() -> Result<u64, SeccompExecError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SeccompExecError::Clock)?
        .as_nanos()
        .try_into()
        .map_err(|_| SeccompExecError::Clock)
}

fn persist_install_receipt(
    root: &OwnedFd,
    install: SeccompInstallReceipt,
    names: &mut impl TemporaryNames,
    installed_at_unix_ns: u64,
) -> Result<SeccompInstallReceipt, SeccompExecError> {
    if installed_at_unix_ns == 0 {
        return Err(SeccompExecError::Clock);
    }
    let receipts = open_receipt_directory(root, install_owner(install))?;
    let desired = InstallReceiptRecord::from_install(install, installed_at_unix_ns);
    let desired_bytes = canonical_json(&desired)?;
    let (bytes, digest) = persist_record(
        &receipts,
        INSTALL_RECEIPT_NAME,
        &desired_bytes,
        names,
        install_owner(install),
        |bytes| {
            let record: InstallReceiptRecord = parse_canonical_json(bytes)?;
            if record.matches_install(install) {
                Ok(())
            } else {
                Err(SeccompExecError::ReceiptDrift)
            }
        },
    )?;
    let stored: InstallReceiptRecord = parse_canonical_json(&bytes)?;
    Ok(SeccompInstallReceipt {
        install_receipt_digest: digest,
        installed_at_unix_ns: stored.installed_at_unix_ns,
        ..install
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_oci_observation_from_root(
    root: &OwnedFd,
    install: SeccompInstallReceipt,
    admission: &OrdinaryAdmission,
    lease: LeaseToken,
    create: &CanonicalCreate,
    verified_start: &VerifiedStart,
    effective: &EffectiveContainerSpec,
    names: &mut impl TemporaryNames,
    observed_at_unix_ns: u64,
    prestart_at_unix_ns: u64,
) -> Result<VerifiedOciPrestartLink, SeccompExecError> {
    if install.install_receipt_digest == [0; 32]
        || install.installed_at_unix_ns == 0
        || lease.lease_id() != admission.lease_id
        || lease.generation() == 0
        || admission.trust_class != crate::activation::AdmissionTrustClass::AcceptedReviewed
        || observed_at_unix_ns == 0
        || prestart_at_unix_ns < observed_at_unix_ns
        || observed_at_unix_ns / 1_000_000_000 >= admission.expires_at
        || !verified_start.matches_create(create)
    {
        return Err(SeccompExecError::OciCapabilityMismatch);
    }
    let body_options = create_security_options(&create.body)?;
    if body_options != effective.security_opt || !exact_security_options(&body_options) {
        return Err(SeccompExecError::OciPrestartDrift);
    }
    let receipts = open_receipt_directory(root, install_owner(install))?;
    verify_persisted_install_receipt(&receipts, install)?;
    let oci = ensure_receipt_directory(
        &receipts,
        OCI_RECEIPT_DIRECTORY,
        install_owner(install).0,
        install_owner(install).1,
    )?;
    let record = OciObservationRecord {
        schema: "buzz-ci-seccomp-oci-prestart-v1".into(),
        candidate_oid: git_oid_text(admission.host.integrated_candidate_sha),
        broker_build_sha256: hex::encode(admission.host.broker_build_identity),
        host_profile_sha256: hex::encode(admission.host.host_profile_digest),
        suite_sha256: hex::encode(admission.host.suite_identity),
        signer_sha256: hex::encode(admission.signer.0),
        request_sha256: hex::encode(admission.job.request_digest),
        manifest_sha256: hex::encode(admission.job.manifest_digest),
        isolation_sha256: hex::encode(admission.job.isolation_profile_digest),
        job_sha256: hex::encode(admission.job.job_identity),
        lease_id: hex::encode(lease.lease_id()),
        generation: lease.generation(),
        canonical_create_sha256: digest_bytes(&create.body),
        effective_spec_sha256: digest_bytes(
            &serde_json::to_vec(effective).map_err(|_| SeccompExecError::SerializeReceipt)?,
        ),
        security_options: body_options,
        observed_at_unix_ns,
        prestart_at_unix_ns,
        install_receipt_sha256: hex::encode(install.install_receipt_digest),
    };
    if !record.has_valid_shape() {
        return Err(SeccompExecError::OciPrestartDrift);
    }
    let bytes = canonical_json(&record)?;
    let filename = oci_receipt_filename(lease);
    let (_, observation_digest) = persist_record(
        &oci,
        &filename,
        &bytes,
        names,
        install_owner(install),
        |bytes| {
            let existing: OciObservationRecord = parse_canonical_json(bytes)?;
            if existing.same_identity(&record) {
                Ok(())
            } else {
                Err(SeccompExecError::ReceiptDrift)
            }
        },
    )?;
    Ok(VerifiedOciPrestartLink {
        install,
        observation_digest,
        lease_id: lease.lease_id(),
        generation: lease.generation(),
    })
}

pub(crate) fn oci_receipt_filename(lease: LeaseToken) -> String {
    format!(
        "{}-g{}.json",
        hex::encode(lease.lease_id()),
        lease.generation()
    )
}

fn install_owner(install: SeccompInstallReceipt) -> (u32, u32) {
    (install.owner_uid, install.owner_gid)
}

fn open_receipt_directory(root: &OwnedFd, owner: (u32, u32)) -> Result<OwnedFd, SeccompExecError> {
    let parent = open_existing_chain(root, &DESTINATION_PARENT_COMPONENTS, owner.0, owner.1)?;
    let mut current = reopen_exact_directory(
        &parent,
        RECEIPT_COMPONENTS[0],
        owner.0,
        owner.1,
        SECCOMP_DIRECTORY_MODE,
    )?;
    for component in &RECEIPT_COMPONENTS[1..] {
        current = ensure_receipt_directory(&current, component, owner.0, owner.1)?;
    }
    Ok(current)
}

fn ensure_receipt_directory(
    parent: &OwnedFd,
    name: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OwnedFd, SeccompExecError> {
    let created = match mkdirat(
        parent,
        name,
        Mode::from_bits_truncate(PRIVATE_RECEIPT_DIRECTORY_MODE),
    ) {
        Ok(()) => true,
        Err(Errno::EEXIST) => false,
        Err(_) => return Err(SeccompExecError::CreateReceiptDirectory),
    };
    let directory = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SeccompExecError::InvalidReceiptDirectory)?;
    if created {
        fchown(
            &directory,
            Some(Uid::from_raw(owner_uid)),
            Some(Gid::from_raw(owner_gid)),
        )
        .and_then(|()| {
            fchmod(
                &directory,
                Mode::from_bits_truncate(PRIVATE_RECEIPT_DIRECTORY_MODE),
            )
        })
        .and_then(|()| fsync(&directory))
        .and_then(|()| fsync(parent))
        .map_err(|_| SeccompExecError::SyncReceiptDirectory)?;
    }
    let stat = fstat(&directory).map_err(|_| SeccompExecError::InvalidReceiptDirectory)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_mode & 0o7777 != PRIVATE_RECEIPT_DIRECTORY_MODE
    {
        return Err(SeccompExecError::InvalidReceiptDirectory);
    }
    Ok(directory)
}

fn persist_record(
    directory: &OwnedFd,
    final_name: &str,
    desired: &[u8],
    names: &mut impl TemporaryNames,
    owner: (u32, u32),
    validate_existing: impl Fn(&[u8]) -> Result<(), SeccompExecError>,
) -> Result<(Vec<u8>, [u8; 32]), SeccompExecError> {
    match read_receipt(directory, final_name, owner) {
        Ok(bytes) => {
            validate_existing(&bytes)?;
            return Ok((bytes.clone(), Sha256::digest(bytes).into()));
        }
        Err(SeccompExecError::OpenReceipt) => {}
        Err(error) => return Err(error),
    }
    let (temp_name, mut temporary) = create_receipt_temporary(directory, names)?;
    let result = (|| {
        temporary
            .write_all(desired)
            .map_err(|_| SeccompExecError::WriteReceipt)?;
        fchown(
            temporary.as_fd(),
            Some(Uid::from_raw(owner.0)),
            Some(Gid::from_raw(owner.1)),
        )
        .and_then(|()| fchmod(temporary.as_fd(), Mode::from_bits_truncate(RECEIPT_MODE)))
        .map_err(|_| SeccompExecError::SealReceipt)?;
        validate_receipt_regular(temporary.as_fd(), owner)?;
        fsync(temporary.as_fd()).map_err(|_| SeccompExecError::SyncReceipt)?;
        let installed = match renameat2(
            directory,
            temp_name.as_str(),
            directory,
            final_name,
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => true,
            Err(Errno::EEXIST) => {
                unlinkat(directory, temp_name.as_str(), UnlinkatFlags::NoRemoveDir)
                    .map_err(|_| SeccompExecError::RenameReceipt)?;
                false
            }
            Err(_) => return Err(SeccompExecError::RenameReceipt),
        };
        fsync(directory).map_err(|_| SeccompExecError::SyncReceiptDirectory)?;
        let bytes = read_receipt(directory, final_name, owner)?;
        validate_existing(&bytes)?;
        if installed && bytes != desired {
            return Err(SeccompExecError::ReceiptDrift);
        }
        let digest = Sha256::digest(&bytes).into();
        Ok((bytes, digest))
    })();
    if result.is_err() {
        let _ = unlinkat(directory, temp_name.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

fn create_receipt_temporary(
    directory: &OwnedFd,
    names: &mut impl TemporaryNames,
) -> Result<(String, File), SeccompExecError> {
    for _ in 0..TEMP_ATTEMPTS {
        let name = names.next_name()?;
        if !valid_temp_name(&name) {
            return Err(SeccompExecError::RandomName);
        }
        match openat(
            directory,
            name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(RECEIPT_MODE),
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(Errno::EEXIST) => continue,
            Err(_) => return Err(SeccompExecError::CreateReceiptTemporary),
        }
    }
    Err(SeccompExecError::CreateReceiptTemporary)
}

fn read_receipt(
    directory: &OwnedFd,
    name: &str,
    owner: (u32, u32),
) -> Result<Vec<u8>, SeccompExecError> {
    let mut file = open_receipt_file(directory, name, owner)?;
    read_receipt_bytes(&mut file)
}

fn open_receipt_file(
    directory: &OwnedFd,
    name: &str,
    owner: (u32, u32),
) -> Result<File, SeccompExecError> {
    let file = open_regular_at(
        directory,
        name,
        OFlag::O_RDONLY,
        SeccompExecError::OpenReceipt,
    )?;
    validate_receipt_regular(file.as_fd(), owner)?;
    Ok(file)
}

fn read_receipt_bytes(file: &mut File) -> Result<Vec<u8>, SeccompExecError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| SeccompExecError::InvalidReceipt)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(SeccompExecError::InvalidReceipt);
    }
    Ok(bytes)
}

fn validate_receipt_regular(fd: impl AsFd, owner: (u32, u32)) -> Result<(), SeccompExecError> {
    let stat = fstat(fd).map_err(|_| SeccompExecError::InvalidReceipt)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != owner.0
        || stat.st_gid != owner.1
        || stat.st_mode & 0o7777 != RECEIPT_MODE
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_RECEIPT_BYTES
    {
        return Err(SeccompExecError::InvalidReceipt);
    }
    Ok(())
}

fn verify_persisted_install_receipt(
    receipts: &OwnedFd,
    install: SeccompInstallReceipt,
) -> Result<(), SeccompExecError> {
    let bytes = read_receipt(receipts, INSTALL_RECEIPT_NAME, install_owner(install))?;
    verify_install_receipt_bytes(&bytes, install)
}

fn verify_install_receipt_bytes(
    bytes: &[u8],
    install: SeccompInstallReceipt,
) -> Result<(), SeccompExecError> {
    let record: InstallReceiptRecord = parse_canonical_json(bytes)?;
    if record.matches_install(install)
        && record.installed_at_unix_ns == install.installed_at_unix_ns
        && Sha256::digest(bytes).as_slice() == install.install_receipt_digest
    {
        Ok(())
    } else {
        Err(SeccompExecError::ReceiptDrift)
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SeccompExecError> {
    serde_json::to_vec(value).map_err(|_| SeccompExecError::SerializeReceipt)
}

fn parse_canonical_json<T>(bytes: &[u8]) -> Result<T, SeccompExecError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice(bytes).map_err(|_| SeccompExecError::InvalidReceipt)?;
    if canonical_json(&value)? != bytes {
        return Err(SeccompExecError::ReceiptDrift);
    }
    Ok(value)
}

fn create_security_options(body: &[u8]) -> Result<Vec<String>, SeccompExecError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| SeccompExecError::OciPrestartDrift)?;
    let options = value
        .get("HostConfig")
        .and_then(|host| host.get("SecurityOpt"))
        .and_then(serde_json::Value::as_array)
        .ok_or(SeccompExecError::OciPrestartDrift)?;
    options
        .iter()
        .map(|option| {
            option
                .as_str()
                .map(str::to_owned)
                .ok_or(SeccompExecError::OciPrestartDrift)
        })
        .collect()
}

fn exact_security_options(options: &[String]) -> bool {
    options
        == [
            "no-new-privileges".to_owned(),
            "label=type:container_t".to_owned(),
            format!("seccomp={PHASE1_SECCOMP_PROFILE_PATH}"),
        ]
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn git_oid_text(oid: GitOid) -> String {
    match oid {
        GitOid::Sha1(bytes) => format!("sha1:{}", hex::encode(bytes)),
        GitOid::Sha256(bytes) => format!("sha256:{}", hex::encode(bytes)),
    }
}

fn valid_git_oid_text(value: &str) -> bool {
    value
        .strip_prefix("sha1:")
        .is_some_and(|digest| digest.len() == 40 && digest.bytes().all(is_lower_hex))
        || value
            .strip_prefix("sha256:")
            .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(is_lower_hex))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lower_hex)
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[derive(Clone, Debug)]
struct InstallContract {
    expected_digest: [u8; 32],
    final_name: String,
    owner_uid: u32,
    owner_gid: u32,
}

impl InstallContract {
    fn phase1() -> Self {
        let expected_digest = decode_digest(PHASE1_SECCOMP_PROFILE_DIGEST)
            .expect("reviewed seccomp digest is valid lowercase SHA-256");
        Self {
            expected_digest,
            final_name: format!("{PHASE1_SECCOMP_PROFILE_DIGEST}.json"),
            owner_uid: SECCOMP_OWNER_UID,
            owner_gid: SECCOMP_OWNER_GID,
        }
    }

    fn from_install(install: SeccompInstallReceipt) -> Self {
        Self {
            expected_digest: install.install_digest,
            final_name: format!("{}.json", hex::encode(install.install_digest)),
            owner_uid: install.owner_uid,
            owner_gid: install.owner_gid,
        }
    }
}

trait TemporaryNames {
    fn next_name(&mut self) -> Result<String, SeccompExecError>;
}

struct KernelTemporaryNames;

impl TemporaryNames for KernelTemporaryNames {
    fn next_name(&mut self) -> Result<String, SeccompExecError> {
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|_| SeccompExecError::RandomName)?;
        Ok(format!(".buzzci-seccomp-{}.tmp", hex::encode(random)))
    }
}

fn open_root(path: &Path) -> Result<OwnedFd, SeccompExecError> {
    open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SeccompExecError::OpenRoot)
}

fn install_from_root(
    root: &OwnedFd,
    contract: InstallContract,
    names: &mut impl TemporaryNames,
) -> Result<SeccompInstallReceipt, SeccompExecError> {
    validate_parent_directory(root, contract.owner_uid, contract.owner_gid)?;

    let source_parent = open_existing_chain(
        root,
        &SOURCE_COMPONENTS[..SOURCE_COMPONENTS.len() - 1],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let mut source = open_regular_at(
        &source_parent,
        SOURCE_COMPONENTS[SOURCE_COMPONENTS.len() - 1],
        OFlag::O_RDONLY,
        SeccompExecError::OpenSource,
    )?;
    validate_regular(
        source.as_fd(),
        contract.owner_uid,
        contract.owner_gid,
        FEDORA_SECCOMP_SOURCE_MODE,
        SeccompExecError::InvalidSource,
    )?;
    let source_digest = hash_file(&mut source).map_err(|_| SeccompExecError::SourceDigest)?;
    if source_digest != contract.expected_digest {
        return Err(SeccompExecError::SourceDigest);
    }

    let destination_parent = open_existing_chain(
        root,
        &DESTINATION_PARENT_COMPONENTS,
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let destination = open_or_create_destination_chain(
        &destination_parent,
        &DESTINATION_COMPONENTS,
        contract.owner_uid,
        contract.owner_gid,
    )?;

    match open_installed(&destination, &contract.final_name) {
        Ok(mut installed) => {
            let install_digest = verify_installed(&mut installed, &contract)?;
            return Ok(SeccompInstallReceipt {
                disposition: SeccompInstallDisposition::Existing,
                source_digest,
                build_digest: install_digest,
                install_digest,
                install_receipt_digest: [0; 32],
                installed_at_unix_ns: 0,
                owner_uid: contract.owner_uid,
                owner_gid: contract.owner_gid,
            });
        }
        Err(Errno::ENOENT) => {}
        Err(_) => return Err(SeccompExecError::OpenInstalled),
    }

    let (temp_name, mut temporary) = create_temporary(&destination, names)?;
    let result = install_temporary(
        &destination,
        &temp_name,
        &mut source,
        &mut temporary,
        &contract,
        source_digest,
    );
    if result.is_err() {
        let _ = unlinkat(&destination, temp_name.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

fn fresh_phase1_readback_from_root(
    root_path: &Path,
    install: SeccompInstallReceipt,
) -> Result<FreshSeccompReadback, SeccompExecError> {
    fresh_phase1_readback_from_root_with_installed_owner(root_path, install, install_owner(install))
}

fn fresh_phase1_readback_from_root_with_installed_owner(
    root_path: &Path,
    install: SeccompInstallReceipt,
    installed_owner: (u32, u32),
) -> Result<FreshSeccompReadback, SeccompExecError> {
    let root = open_root(root_path)?;
    verify_descriptor_path(&root, root_path, SeccompExecError::ReadbackPath)?;
    let contract = InstallContract::from_install(install);
    validate_parent_directory(&root, contract.owner_uid, contract.owner_gid)?;

    let source_parent = open_existing_chain(
        &root,
        &SOURCE_COMPONENTS[..SOURCE_COMPONENTS.len() - 1],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let mut source = open_regular_at(
        &source_parent,
        SOURCE_COMPONENTS[SOURCE_COMPONENTS.len() - 1],
        OFlag::O_RDONLY,
        SeccompExecError::OpenSource,
    )?;
    validate_regular(
        source.as_fd(),
        contract.owner_uid,
        contract.owner_gid,
        FEDORA_SECCOMP_SOURCE_MODE,
        SeccompExecError::InvalidSource,
    )?;
    verify_descriptor_path(
        &source,
        &rooted_path(root_path, crate::seccomp::FEDORA_SECCOMP_SOURCE_PATH),
        SeccompExecError::ReadbackPath,
    )?;
    let source_digest = hash_file(&mut source).map_err(|_| SeccompExecError::SourceDigest)?;
    if source_digest != contract.expected_digest {
        return Err(SeccompExecError::SourceDigest);
    }
    let source = file_readback(
        source.as_fd(),
        crate::seccomp::FEDORA_SECCOMP_SOURCE_PATH,
        source_digest,
        SeccompExecError::InvalidSource,
    )?;

    let destination_parent = open_existing_chain(
        &root,
        &DESTINATION_PARENT_COMPONENTS,
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let specs = SeccompHostPlan::phase1().directories();
    let buzzci = reopen_directory(
        &destination_parent,
        DESTINATION_COMPONENTS[0],
        root_path,
        specs[0],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let seccomp = reopen_directory(
        &buzzci.0,
        DESTINATION_COMPONENTS[1],
        root_path,
        specs[1],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let version = reopen_directory(
        &seccomp.0,
        DESTINATION_COMPONENTS[2],
        root_path,
        specs[2],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let destination = reopen_directory(
        &version.0,
        DESTINATION_COMPONENTS[3],
        root_path,
        specs[3],
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let mut installed = open_installed(&destination.0, &contract.final_name)
        .map_err(|_| SeccompExecError::OpenInstalled)?;
    let installed_contract = InstallContract {
        owner_uid: installed_owner.0,
        owner_gid: installed_owner.1,
        ..contract.clone()
    };
    let install_digest = verify_installed(&mut installed, &installed_contract)?;
    let installed_logical_path =
        format!("/var/lib/buzzci/seccomp/v1/sha256/{}", contract.final_name);
    verify_descriptor_path(
        &installed,
        &rooted_path(root_path, &installed_logical_path),
        SeccompExecError::ReadbackPath,
    )?;
    let installed = file_readback(
        installed.as_fd(),
        PHASE1_SECCOMP_PROFILE_PATH,
        install_digest,
        SeccompExecError::InvalidInstalled,
    )?;
    let directories = [buzzci.1, seccomp.1, version.1, destination.1];

    let receipt_parent = open_existing_chain(
        &root,
        &DESTINATION_PARENT_COMPONENTS,
        contract.owner_uid,
        contract.owner_gid,
    )?;
    let receipt_buzzci = reopen_exact_directory(
        &receipt_parent,
        RECEIPT_COMPONENTS[0],
        contract.owner_uid,
        contract.owner_gid,
        SECCOMP_DIRECTORY_MODE,
    )?;
    let activation = reopen_exact_directory(
        &receipt_buzzci,
        RECEIPT_COMPONENTS[1],
        contract.owner_uid,
        contract.owner_gid,
        PRIVATE_RECEIPT_DIRECTORY_MODE,
    )?;
    let receipts = reopen_exact_directory(
        &activation,
        RECEIPT_COMPONENTS[2],
        contract.owner_uid,
        contract.owner_gid,
        PRIVATE_RECEIPT_DIRECTORY_MODE,
    )?;
    verify_descriptor_path(
        &receipts,
        &rooted_path(root_path, "/var/lib/buzzci/activation/receipts"),
        SeccompExecError::ReadbackPath,
    )?;
    let mut receipt = open_receipt_file(&receipts, INSTALL_RECEIPT_NAME, install_owner(install))?;
    verify_descriptor_path(
        &receipt,
        &rooted_path(root_path, SECCOMP_INSTALL_RECEIPT_PATH),
        SeccompExecError::ReadbackPath,
    )?;
    let receipt_bytes = read_receipt_bytes(&mut receipt)?;
    verify_install_receipt_bytes(&receipt_bytes, install)?;

    Ok(FreshSeccompReadback {
        source,
        directories,
        installed,
    })
}

fn reopen_directory(
    parent: &OwnedFd,
    name: &str,
    root_path: &Path,
    spec: crate::seccomp_host::SeccompDirectorySpec,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OwnedFd, SeccompDirectoryReadback), SeccompExecError> {
    let directory = reopen_exact_directory(parent, name, owner_uid, owner_gid, spec.mode())?;
    verify_descriptor_path(
        &directory,
        &rooted_path(root_path, spec.path()),
        SeccompExecError::ReadbackPath,
    )?;
    let stat = fstat(&directory).map_err(|_| SeccompExecError::InvalidDestinationDirectory)?;
    Ok((
        directory,
        SeccompDirectoryReadback {
            path: spec.path().into(),
            canonical_path: spec.path().into(),
            file_type: SeccompHostFileType::Directory,
            owner_uid: stat.st_uid,
            owner_gid: stat.st_gid,
            mode: stat.st_mode & 0o7777,
            opened_no_follow: true,
        },
    ))
}

fn reopen_exact_directory(
    parent: &OwnedFd,
    name: &str,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
) -> Result<OwnedFd, SeccompExecError> {
    let directory = open_directory_at(parent, name)
        .map_err(|_| SeccompExecError::InvalidDestinationDirectory)?;
    validate_directory_exact(&directory, owner_uid, owner_gid, mode)?;
    Ok(directory)
}

fn file_readback(
    fd: impl AsFd,
    path: &str,
    digest: [u8; 32],
    error: SeccompExecError,
) -> Result<SeccompFileReadback, SeccompExecError> {
    let stat = fstat(fd).map_err(|_| error)?;
    Ok(SeccompFileReadback {
        path: path.into(),
        canonical_path: path.into(),
        file_type: SeccompFileType::Regular,
        link_count: stat.st_nlink,
        owner_uid: stat.st_uid,
        owner_gid: stat.st_gid,
        mode: stat.st_mode & 0o7777,
        digest: hex::encode(digest),
    })
}

fn verify_descriptor_path(
    fd: impl AsFd,
    expected: &Path,
    error: SeccompExecError,
) -> Result<(), SeccompExecError> {
    let descriptor = PathBuf::from(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()));
    let observed = std::fs::read_link(descriptor).map_err(|_| error)?;
    if observed != expected {
        return Err(error);
    }
    Ok(())
}

fn rooted_path(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn install_temporary(
    destination: &OwnedFd,
    temp_name: &str,
    source: &mut File,
    temporary: &mut File,
    contract: &InstallContract,
    source_digest: [u8; 32],
) -> Result<SeccompInstallReceipt, SeccompExecError> {
    let build_digest = copy_and_hash(source, temporary)?;
    if build_digest != contract.expected_digest {
        return Err(SeccompExecError::BuildDigest);
    }
    fchown(
        temporary.as_fd(),
        Some(Uid::from_raw(contract.owner_uid)),
        Some(Gid::from_raw(contract.owner_gid)),
    )
    .and_then(|()| {
        fchmod(
            temporary.as_fd(),
            Mode::from_bits_truncate(SECCOMP_PROFILE_MODE),
        )
    })
    .map_err(|_| SeccompExecError::SealTemporary)?;
    validate_regular(
        temporary.as_fd(),
        contract.owner_uid,
        contract.owner_gid,
        SECCOMP_PROFILE_MODE,
        SeccompExecError::SealTemporary,
    )?;
    fsync(temporary.as_fd()).map_err(|_| SeccompExecError::SyncTemporary)?;

    match renameat2(
        destination,
        temp_name,
        destination,
        contract.final_name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    ) {
        Ok(()) => {}
        Err(Errno::EEXIST) => {
            unlinkat(destination, temp_name, UnlinkatFlags::NoRemoveDir)
                .map_err(|_| SeccompExecError::Rename)?;
            let mut installed = open_installed(destination, &contract.final_name)
                .map_err(|_| SeccompExecError::OpenInstalled)?;
            let install_digest = verify_installed(&mut installed, contract)?;
            return Ok(SeccompInstallReceipt {
                disposition: SeccompInstallDisposition::Existing,
                source_digest,
                build_digest,
                install_digest,
                install_receipt_digest: [0; 32],
                installed_at_unix_ns: 0,
                owner_uid: contract.owner_uid,
                owner_gid: contract.owner_gid,
            });
        }
        Err(_) => return Err(SeccompExecError::Rename),
    }
    fsync(destination.as_fd()).map_err(|_| SeccompExecError::SyncDestinationDirectory)?;
    let mut installed = open_installed(destination, &contract.final_name)
        .map_err(|_| SeccompExecError::OpenInstalled)?;
    let install_digest = verify_installed(&mut installed, contract)?;
    Ok(SeccompInstallReceipt {
        disposition: SeccompInstallDisposition::Installed,
        source_digest,
        build_digest,
        install_digest,
        install_receipt_digest: [0; 32],
        installed_at_unix_ns: 0,
        owner_uid: contract.owner_uid,
        owner_gid: contract.owner_gid,
    })
}

fn open_existing_chain(
    root: &OwnedFd,
    components: &[&str],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OwnedFd, SeccompExecError> {
    let mut current = open_directory_at(root, components[0])?;
    validate_parent_directory(&current, owner_uid, owner_gid)?;
    for component in &components[1..] {
        current = open_directory_at(&current, component)?;
        validate_parent_directory(&current, owner_uid, owner_gid)?;
    }
    Ok(current)
}

fn open_or_create_destination_chain(
    parent: &OwnedFd,
    components: &[&str],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OwnedFd, SeccompExecError> {
    let mut current = ensure_destination_directory(parent, components[0], owner_uid, owner_gid)?;
    for component in &components[1..] {
        current = ensure_destination_directory(&current, component, owner_uid, owner_gid)?;
    }
    Ok(current)
}

fn ensure_destination_directory(
    parent: &OwnedFd,
    name: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OwnedFd, SeccompExecError> {
    let created = match mkdirat(
        parent,
        name,
        Mode::from_bits_truncate(SECCOMP_DIRECTORY_MODE),
    ) {
        Ok(()) => true,
        Err(Errno::EEXIST) => false,
        Err(_) => return Err(SeccompExecError::CreateDestinationDirectory),
    };
    let directory = open_directory_at(parent, name)
        .map_err(|_| SeccompExecError::InvalidDestinationDirectory)?;
    if created {
        fchown(
            &directory,
            Some(Uid::from_raw(owner_uid)),
            Some(Gid::from_raw(owner_gid)),
        )
        .and_then(|()| fchmod(&directory, Mode::from_bits_truncate(SECCOMP_DIRECTORY_MODE)))
        .and_then(|()| fsync(&directory))
        .and_then(|()| fsync(parent))
        .map_err(|_| SeccompExecError::CreateDestinationDirectory)?;
    }
    validate_directory_exact(&directory, owner_uid, owner_gid, SECCOMP_DIRECTORY_MODE)?;
    Ok(directory)
}

fn open_directory_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, SeccompExecError> {
    openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SeccompExecError::InvalidParentDirectory)
}

fn open_regular_at(
    parent: &OwnedFd,
    name: &str,
    access: OFlag,
    error: SeccompExecError,
) -> Result<File, SeccompExecError> {
    let fd = openat(
        parent,
        name,
        access | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| error)?;
    Ok(File::from(fd))
}

fn open_installed(parent: &OwnedFd, name: &str) -> Result<File, Errno> {
    openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn create_temporary(
    destination: &OwnedFd,
    names: &mut impl TemporaryNames,
) -> Result<(String, File), SeccompExecError> {
    for _ in 0..TEMP_ATTEMPTS {
        let name = names.next_name()?;
        if !valid_temp_name(&name) {
            return Err(SeccompExecError::RandomName);
        }
        match openat(
            destination,
            name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(Errno::EEXIST) => continue,
            Err(_) => return Err(SeccompExecError::CreateTemporary),
        }
    }
    Err(SeccompExecError::CreateTemporary)
}

fn validate_parent_directory(
    fd: &OwnedFd,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), SeccompExecError> {
    let stat = fstat(fd).map_err(|_| SeccompExecError::InvalidParentDirectory)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_mode & 0o022 != 0
    {
        return Err(SeccompExecError::InvalidParentDirectory);
    }
    Ok(())
}

fn validate_directory_exact(
    fd: &OwnedFd,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
) -> Result<(), SeccompExecError> {
    let stat = fstat(fd).map_err(|_| SeccompExecError::InvalidDestinationDirectory)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_mode & 0o7777 != mode
    {
        return Err(SeccompExecError::InvalidDestinationDirectory);
    }
    Ok(())
}

fn validate_regular(
    fd: impl AsFd,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    error: SeccompExecError,
) -> Result<(), SeccompExecError> {
    let stat = fstat(fd).map_err(|_| error)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_mode & 0o7777 != mode
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_PROFILE_BYTES
    {
        return Err(error);
    }
    Ok(())
}

fn hash_file(file: &mut File) -> std::io::Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(digest.finalize().into())
}

fn copy_and_hash(source: &mut File, destination: &mut File) -> Result<[u8; 32], SeccompExecError> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| SeccompExecError::CopyProfile)?;
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| SeccompExecError::CopyProfile)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(SeccompExecError::CopyProfile)?;
        if copied > MAX_PROFILE_BYTES {
            return Err(SeccompExecError::CopyProfile);
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|_| SeccompExecError::CopyProfile)?;
        digest.update(&buffer[..read]);
    }
    if copied == 0 {
        return Err(SeccompExecError::CopyProfile);
    }
    Ok(digest.finalize().into())
}

fn verify_installed(
    installed: &mut File,
    contract: &InstallContract,
) -> Result<[u8; 32], SeccompExecError> {
    validate_regular(
        installed.as_fd(),
        contract.owner_uid,
        contract.owner_gid,
        SECCOMP_PROFILE_MODE,
        SeccompExecError::InvalidInstalled,
    )?;
    let digest = hash_file(installed).map_err(|_| SeccompExecError::InstallDigest)?;
    if digest != contract.expected_digest {
        return Err(SeccompExecError::InstallDigest);
    }
    Ok(digest)
}

fn valid_temp_name(name: &str) -> bool {
    name.starts_with(".buzzci-seccomp-")
        && name.ends_with(".tmp")
        && name.len() == ".buzzci-seccomp-".len() + 32 + ".tmp".len()
        && name[".buzzci-seccomp-".len()..name.len() - ".tmp".len()]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use nix::unistd::{getegid, geteuid};
    use tempfile::TempDir;

    use super::*;
    use crate::seccomp::FEDORA_SECCOMP_SOURCE_PATH;

    const PROFILE: &[u8] = br#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}"#;

    struct FixedNames(u64);

    impl TemporaryNames for FixedNames {
        fn next_name(&mut self) -> Result<String, SeccompExecError> {
            self.0 += 1;
            Ok(format!(".buzzci-seccomp-{:032x}.tmp", self.0))
        }
    }

    struct RacingNames {
        final_path: std::path::PathBuf,
        winner_bytes: Vec<u8>,
        sequence: u64,
    }

    impl TemporaryNames for RacingNames {
        fn next_name(&mut self) -> Result<String, SeccompExecError> {
            fs::write(&self.final_path, &self.winner_bytes).unwrap();
            fs::set_permissions(&self.final_path, fs::Permissions::from_mode(RECEIPT_MODE))
                .unwrap();
            self.sequence += 1;
            Ok(format!(".buzzci-seccomp-{:032x}.tmp", self.sequence))
        }
    }

    fn fixture() -> (TempDir, InstallContract) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/share/containers")).unwrap();
        fs::create_dir_all(root.path().join("var/lib")).unwrap();
        fs::write(
            root.path().join("usr/share/containers/seccomp.json"),
            PROFILE,
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("usr/share/containers/seccomp.json"),
            fs::Permissions::from_mode(FEDORA_SECCOMP_SOURCE_MODE),
        )
        .unwrap();
        let digest: [u8; 32] = Sha256::digest(PROFILE).into();
        let contract = InstallContract {
            expected_digest: digest,
            final_name: format!("{}.json", hex::encode(digest)),
            owner_uid: geteuid().as_raw(),
            owner_gid: getegid().as_raw(),
        };
        (root, contract)
    }

    fn execute(
        root: &Path,
        contract: InstallContract,
    ) -> Result<SeccompInstallReceipt, SeccompExecError> {
        let root = open_root(root)?;
        install_from_root(&root, contract, &mut FixedNames(0))
    }

    fn execute_with_receipt(
        root: &Path,
        contract: InstallContract,
        timestamp: u64,
    ) -> Result<SeccompInstallReceipt, SeccompExecError> {
        let root_fd = open_root(root)?;
        let mut names = FixedNames(0);
        let install = install_from_root(&root_fd, contract, &mut names)?;
        persist_install_receipt(&root_fd, install, &mut names, timestamp)
    }

    fn installed_path(root: &Path, contract: &InstallContract) -> std::path::PathBuf {
        root.join("var/lib/buzzci/seccomp/v1/sha256")
            .join(&contract.final_name)
    }

    fn receipt_path(root: &Path) -> std::path::PathBuf {
        root.join(SECCOMP_INSTALL_RECEIPT_PATH.trim_start_matches('/'))
    }

    fn observation_record() -> OciObservationRecord {
        OciObservationRecord {
            schema: "buzz-ci-seccomp-oci-prestart-v1".into(),
            candidate_oid: format!("sha1:{}", "1".repeat(40)),
            broker_build_sha256: "2".repeat(64),
            host_profile_sha256: "3".repeat(64),
            suite_sha256: "4".repeat(64),
            signer_sha256: "5".repeat(64),
            request_sha256: "6".repeat(64),
            manifest_sha256: "7".repeat(64),
            isolation_sha256: "8".repeat(64),
            job_sha256: "9".repeat(64),
            lease_id: "a".repeat(32),
            generation: 3,
            canonical_create_sha256: "b".repeat(64),
            effective_spec_sha256: "c".repeat(64),
            security_options: vec![
                "no-new-privileges".into(),
                "label=type:container_t".into(),
                format!("seccomp={PHASE1_SECCOMP_PROFILE_PATH}"),
            ],
            observed_at_unix_ns: 10,
            prestart_at_unix_ns: 11,
            install_receipt_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn first_install_is_atomic_sealed_and_digest_bound() {
        let (root, contract) = fixture();
        assert_eq!(
            format!("/{}", SOURCE_COMPONENTS.join("/")),
            FEDORA_SECCOMP_SOURCE_PATH
        );
        assert_eq!(
            format!(
                "/{}/{}.json",
                DESTINATION_PARENT_COMPONENTS
                    .into_iter()
                    .chain(DESTINATION_COMPONENTS)
                    .collect::<Vec<_>>()
                    .join("/"),
                PHASE1_SECCOMP_PROFILE_DIGEST
            ),
            PHASE1_SECCOMP_PROFILE_PATH
        );
        let receipt = execute(root.path(), contract.clone()).unwrap();
        assert_eq!(receipt.disposition(), SeccompInstallDisposition::Installed);
        assert_eq!(
            receipt.source_digest(),
            hex::encode(contract.expected_digest)
        );
        assert_eq!(
            receipt.build_digest(),
            hex::encode(contract.expected_digest)
        );
        assert_eq!(
            receipt.install_digest(),
            hex::encode(contract.expected_digest)
        );

        let installed = installed_path(root.path(), &contract);
        let metadata = fs::metadata(&installed).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, SECCOMP_PROFILE_MODE);
        assert_eq!(metadata.uid(), contract.owner_uid);
        assert_eq!(metadata.gid(), contract.owner_gid);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(fs::read(installed).unwrap(), PROFILE);
        assert_eq!(
            fs::metadata(root.path().join("var/lib/buzzci"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            SECCOMP_DIRECTORY_MODE
        );
        assert!(
            fs::read_dir(root.path().join("var/lib/buzzci/seccomp/v1/sha256"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn exact_existing_artifact_is_idempotent_and_never_rewritten() {
        let (root, contract) = fixture();
        let first = execute(root.path(), contract.clone()).unwrap();
        assert_eq!(first.disposition(), SeccompInstallDisposition::Installed);
        let installed = installed_path(root.path(), &contract);
        let before = fs::metadata(&installed).unwrap();

        let second = execute(root.path(), contract.clone()).unwrap();
        assert_eq!(second.disposition(), SeccompInstallDisposition::Existing);
        let after = fs::metadata(installed).unwrap();
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    }

    #[test]
    fn existing_artifact_drift_fails_without_replacement() {
        let (root, contract) = fixture();
        execute(root.path(), contract.clone()).unwrap();
        let installed = installed_path(root.path(), &contract);
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&installed, b"drift").unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::InvalidInstalled)
        );
        assert_eq!(fs::read(installed).unwrap(), b"drift");
    }

    #[test]
    fn source_and_destination_symlinks_fail_closed() {
        let (root, contract) = fixture();
        let source = root.path().join("usr/share/containers/seccomp.json");
        fs::remove_file(&source).unwrap();
        symlink("/etc/passwd", &source).unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::OpenSource)
        );

        let (root, contract) = fixture();
        symlink("/tmp", root.path().join("var/lib/buzzci")).unwrap();
        assert!(matches!(
            execute(root.path(), contract),
            Err(SeccompExecError::InvalidDestinationDirectory)
                | Err(SeccompExecError::InvalidParentDirectory)
        ));

        let (root, contract) = fixture();
        let final_directory = root.path().join("var/lib/buzzci/seccomp/v1/sha256");
        fs::create_dir_all(&final_directory).unwrap();
        for path in [
            root.path().join("var/lib/buzzci"),
            root.path().join("var/lib/buzzci/seccomp"),
            root.path().join("var/lib/buzzci/seccomp/v1"),
            final_directory.clone(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(SECCOMP_DIRECTORY_MODE)).unwrap();
        }
        symlink("/etc/passwd", final_directory.join(&contract.final_name)).unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::OpenInstalled)
        );
    }

    #[test]
    fn source_owner_mode_digest_and_link_count_are_mandatory() {
        let (root, contract) = fixture();
        let source = root.path().join("usr/share/containers/seccomp.json");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::InvalidSource)
        );

        let (root, contract) = fixture();
        fs::write(
            root.path().join("usr/share/containers/seccomp.json"),
            b"wrong",
        )
        .unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::SourceDigest)
        );

        let (root, contract) = fixture();
        fs::hard_link(
            root.path().join("usr/share/containers/seccomp.json"),
            root.path().join("usr/share/containers/second-link.json"),
        )
        .unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::InvalidSource)
        );
    }

    #[test]
    fn immutable_profile_chain_requires_traverse_only_mode_0711() {
        let (root, contract) = fixture();
        let directory = root.path().join("var/lib/buzzci");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            execute(root.path(), contract),
            Err(SeccompExecError::InvalidDestinationDirectory)
        );
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn install_receipt_is_sealed_canonical_and_idempotent() {
        let (root, contract) = fixture();
        let first = execute_with_receipt(root.path(), contract.clone(), 100).unwrap();
        assert_eq!(first.installed_at_unix_ns(), 100);
        assert_ne!(first.install_receipt_digest, [0; 32]);
        let path = receipt_path(root.path());
        let bytes = fs::read(&path).unwrap();
        let parsed: InstallReceiptRecord = parse_canonical_json(&bytes).unwrap();
        assert!(parsed.matches_install(first));
        let before = fs::metadata(&path).unwrap();
        assert_eq!(before.permissions().mode() & 0o7777, RECEIPT_MODE);
        assert_eq!(before.nlink(), 1);
        assert_eq!(
            Sha256::digest(&bytes).as_slice(),
            first.install_receipt_digest
        );

        let second = execute_with_receipt(root.path(), contract, 200).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(second.installed_at_unix_ns(), 100);
        assert_eq!(second.install_receipt_digest, first.install_receipt_digest);
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        for directory in [
            root.path().join("var/lib/buzzci/activation"),
            root.path().join("var/lib/buzzci/activation/receipts"),
        ] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
                PRIVATE_RECEIPT_DIRECTORY_MODE
            );
        }
    }

    #[test]
    fn install_receipt_drift_and_symlink_fail_without_replacement() {
        let (root, contract) = fixture();
        execute_with_receipt(root.path(), contract.clone(), 100).unwrap();
        let path = receipt_path(root.path());
        let before = fs::metadata(&path).unwrap().ino();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            execute_with_receipt(root.path(), contract.clone(), 200),
            Err(SeccompExecError::InvalidReceipt)
        );
        assert_eq!(fs::metadata(&path).unwrap().ino(), before);

        fs::remove_file(&path).unwrap();
        symlink("/etc/passwd", &path).unwrap();
        assert!(execute_with_receipt(root.path(), contract, 300).is_err());
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn install_receipt_rename_race_accepts_exact_winner_and_rejects_drift() {
        let (root, contract) = fixture();
        let root_fd = open_root(root.path()).unwrap();
        let install = install_from_root(&root_fd, contract, &mut FixedNames(0)).unwrap();
        let receipts = open_receipt_directory(&root_fd, install_owner(install)).unwrap();
        drop(receipts);
        let final_path = receipt_path(root.path());
        let winner = InstallReceiptRecord::from_install(install, 50);
        let mut exact_race = RacingNames {
            final_path: final_path.clone(),
            winner_bytes: canonical_json(&winner).unwrap(),
            sequence: 100,
        };
        let persisted = persist_install_receipt(&root_fd, install, &mut exact_race, 100).unwrap();
        assert_eq!(persisted.installed_at_unix_ns(), 50);
        assert_eq!(
            fs::read(&final_path).unwrap(),
            canonical_json(&winner).unwrap()
        );

        fs::remove_file(&final_path).unwrap();
        let mut drift = winner;
        drift.final_sha256 = "f".repeat(64);
        let drift_bytes = canonical_json(&drift).unwrap();
        let mut hostile_race = RacingNames {
            final_path: final_path.clone(),
            winner_bytes: drift_bytes.clone(),
            sequence: 200,
        };
        assert_eq!(
            persist_install_receipt(&root_fd, install, &mut hostile_race, 200),
            Err(SeccompExecError::ReceiptDrift)
        );
        assert_eq!(fs::read(final_path).unwrap(), drift_bytes);
    }

    #[test]
    fn synthetic_oci_records_reject_missing_extra_unconfined_and_drift() {
        let expected = observation_record();
        assert!(expected.has_valid_shape());

        let mut missing = expected.clone();
        missing.security_options.pop();
        assert!(!missing.has_valid_shape());

        let mut extra = expected.clone();
        extra.security_options.push("apparmor=unconfined".into());
        assert!(!extra.has_valid_shape());

        let mut unconfined = expected.clone();
        unconfined.security_options[2] = "seccomp=unconfined".into();
        assert!(!unconfined.has_valid_shape());

        let mut forged_create = expected.clone();
        forged_create.canonical_create_sha256 = "e".repeat(64);
        assert!(!forged_create.same_identity(&expected));

        let mut forged_install = expected.clone();
        forged_install.install_receipt_sha256 = "f".repeat(64);
        assert!(!forged_install.same_identity(&expected));
    }

    #[test]
    fn oci_record_existing_is_idempotent_but_drift_and_symlink_fail_closed() {
        let (root, contract) = fixture();
        let install = execute_with_receipt(root.path(), contract, 100).unwrap();
        let root_fd = open_root(root.path()).unwrap();
        let receipts = open_receipt_directory(&root_fd, install_owner(install)).unwrap();
        let oci = ensure_receipt_directory(
            &receipts,
            OCI_RECEIPT_DIRECTORY,
            install.owner_uid,
            install.owner_gid,
        )
        .unwrap();
        let expected = observation_record();
        let filename = format!("{}-g{}.json", expected.lease_id, expected.generation);
        let bytes = canonical_json(&expected).unwrap();
        let validate = |candidate: &[u8]| {
            let record: OciObservationRecord = parse_canonical_json(candidate)?;
            if record.same_identity(&expected) {
                Ok(())
            } else {
                Err(SeccompExecError::ReceiptDrift)
            }
        };
        persist_record(
            &oci,
            &filename,
            &bytes,
            &mut FixedNames(10),
            install_owner(install),
            validate,
        )
        .unwrap();
        let path = root
            .path()
            .join("var/lib/buzzci/activation/receipts/oci")
            .join(&filename);
        let before = fs::metadata(&path).unwrap();
        let mut retried = expected.clone();
        retried.observed_at_unix_ns = 20;
        retried.prestart_at_unix_ns = 21;
        persist_record(
            &oci,
            &filename,
            &canonical_json(&retried).unwrap(),
            &mut FixedNames(20),
            install_owner(install),
            validate,
        )
        .unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());

        fs::remove_file(&path).unwrap();
        let mut drift = expected.clone();
        drift.effective_spec_sha256 = "e".repeat(64);
        fs::write(&path, canonical_json(&drift).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(RECEIPT_MODE)).unwrap();
        let drift_inode = fs::metadata(&path).unwrap().ino();
        assert_eq!(
            persist_record(
                &oci,
                &filename,
                &bytes,
                &mut FixedNames(30),
                install_owner(install),
                validate,
            ),
            Err(SeccompExecError::ReceiptDrift)
        );
        assert_eq!(fs::metadata(&path).unwrap().ino(), drift_inode);

        fs::remove_file(&path).unwrap();
        symlink("/etc/passwd", &path).unwrap();
        assert!(persist_record(
            &oci,
            &filename,
            &bytes,
            &mut FixedNames(40),
            install_owner(install),
            validate,
        )
        .is_err());
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
}
