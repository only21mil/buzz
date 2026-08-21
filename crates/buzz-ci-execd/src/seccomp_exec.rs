//! Concrete Linux filesystem executor for the fixed Phase-1 seccomp profile.
//!
//! Production entry points accept no paths or profile bytes. Every component is
//! opened relative to an already-open directory with no-follow semantics.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat2, OFlag, RenameFlags};
use nix::sys::stat::{fchmod, fstat, mkdirat, Mode, SFlag};
use nix::unistd::{fchown, fsync, unlinkat, Gid, Uid, UnlinkatFlags};
use sha2::{Digest, Sha256};

use crate::seccomp::{
    FEDORA_SECCOMP_SOURCE_MODE, SECCOMP_PROFILE_MODE,
};
use crate::seccomp_host::{
    SECCOMP_DIRECTORY_MODE, SECCOMP_OWNER_GID, SECCOMP_OWNER_UID,
};
use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};

const SOURCE_COMPONENTS: [&str; 4] = ["usr", "share", "containers", "seccomp.json"];
const DESTINATION_PARENT_COMPONENTS: [&str; 2] = ["var", "lib"];
const DESTINATION_COMPONENTS: [&str; 4] = ["buzzci", "seccomp", "v1", "sha256"];
const MAX_PROFILE_BYTES: u64 = 1_048_576;
const TEMP_ATTEMPTS: usize = 8;

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
    OciPrestartDrift,
}

/// Install or verify the sole reviewed profile under the real host root.
///
/// This function performs host mutation when called and therefore belongs only
/// in the root execd activation path.
pub fn install_phase1() -> Result<SeccompInstallReceipt, SeccompExecError> {
    let root = open_root(Path::new("/"))?;
    let mut names = KernelTemporaryNames;
    install_from_root(
        &root,
        InstallContract::phase1(),
        &mut names,
    )
}

/// OCI lifecycle position observed from the concrete create request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OciLifecyclePhase {
    /// Create request has been rebuilt but the container has not started.
    Prestart,
    /// Container start has already been requested.
    Started,
}

/// Concrete OCI create-spec facts linked to an install receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciPrestartSpec {
    pub phase: OciLifecyclePhase,
    pub seccomp_profile_path: String,
    pub seccomp_profile_digest: String,
    pub no_new_privileges: bool,
    pub security_options: Vec<String>,
}

/// Opaque proof that the exact installed artifact is linked before start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedOciPrestartLink {
    install: SeccompInstallReceipt,
}

impl VerifiedOciPrestartLink {
    /// Exact install receipt bound to this verified prestart spec.
    pub const fn install_receipt(self) -> SeccompInstallReceipt {
        self.install
    }
}

/// Verify exact OCI prestart linkage without accepting a synthetic linked flag.
pub fn verify_oci_prestart_link(
    install: SeccompInstallReceipt,
    spec: &OciPrestartSpec,
) -> Result<VerifiedOciPrestartLink, SeccompExecError> {
    let expected_option = format!("seccomp={PHASE1_SECCOMP_PROFILE_PATH}");
    let mut seccomp_options = spec
        .security_options
        .iter()
        .filter(|value| value.to_ascii_lowercase().starts_with("seccomp="));
    if spec.phase != OciLifecyclePhase::Prestart
        || spec.seccomp_profile_path != PHASE1_SECCOMP_PROFILE_PATH
        || spec.seccomp_profile_digest != install.install_digest()
        || !spec.no_new_privileges
        || seccomp_options.next() != Some(&expected_option)
        || seccomp_options.next().is_some()
    {
        return Err(SeccompExecError::OciPrestartDrift);
    }
    Ok(VerifiedOciPrestartLink { install })
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
    match mkdirat(
        parent,
        name,
        Mode::from_bits_truncate(SECCOMP_DIRECTORY_MODE),
    ) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(_) => return Err(SeccompExecError::CreateDestinationDirectory),
    }
    let directory = open_directory_at(parent, name)
        .map_err(|_| SeccompExecError::InvalidDestinationDirectory)?;
    validate_directory_exact(
        &directory,
        owner_uid,
        owner_gid,
        SECCOMP_DIRECTORY_MODE,
    )?;
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
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC,
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

    fn installed_path(root: &Path, contract: &InstallContract) -> std::path::PathBuf {
        root.join("var/lib/buzzci/seccomp/v1/sha256")
            .join(&contract.final_name)
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
        assert_eq!(receipt.source_digest(), hex::encode(contract.expected_digest));
        assert_eq!(receipt.build_digest(), hex::encode(contract.expected_digest));
        assert_eq!(receipt.install_digest(), hex::encode(contract.expected_digest));

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
        assert!(fs::read_dir(root.path().join("var/lib/buzzci/seccomp/v1/sha256"))
            .unwrap()
            .all(|entry| !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
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
        assert_eq!(execute(root.path(), contract), Err(SeccompExecError::OpenSource));

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
        assert_eq!(execute(root.path(), contract), Err(SeccompExecError::InvalidSource));

        let (root, contract) = fixture();
        fs::write(root.path().join("usr/share/containers/seccomp.json"), b"wrong").unwrap();
        assert_eq!(execute(root.path(), contract), Err(SeccompExecError::SourceDigest));

        let (root, contract) = fixture();
        fs::hard_link(
            root.path().join("usr/share/containers/seccomp.json"),
            root.path().join("usr/share/containers/second-link.json"),
        )
        .unwrap();
        assert_eq!(execute(root.path(), contract), Err(SeccompExecError::InvalidSource));
    }

    #[test]
    fn destination_chain_must_remain_root_private_mode_0700() {
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
    fn oci_link_requires_exact_prestart_profile_and_rejects_unconfined() {
        let (root, contract) = fixture();
        let receipt = execute(root.path(), contract).unwrap();
        let spec = OciPrestartSpec {
            phase: OciLifecyclePhase::Prestart,
            seccomp_profile_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
            seccomp_profile_digest: receipt.install_digest(),
            no_new_privileges: true,
            security_options: vec![
                format!("seccomp={PHASE1_SECCOMP_PROFILE_PATH}"),
                "label=type:buzzci_job_t".into(),
            ],
        };
        let linked = verify_oci_prestart_link(receipt, &spec).unwrap();
        assert_eq!(linked.install_receipt(), receipt);

        let mut started = spec.clone();
        started.phase = OciLifecyclePhase::Started;
        assert_eq!(
            verify_oci_prestart_link(receipt, &started),
            Err(SeccompExecError::OciPrestartDrift)
        );

        let mut unconfined = spec;
        unconfined.security_options = vec!["seccomp=unconfined".into()];
        assert_eq!(
            verify_oci_prestart_link(receipt, &unconfined),
            Err(SeccompExecError::OciPrestartDrift)
        );
    }
}
