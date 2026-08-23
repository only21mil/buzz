#![cfg(all(target_os = "linux", target_env = "gnu"))]

//! Descriptor-relative persistence for one policy-proxy journal per lease.
//!
//! The journal is replaced as one file under a per-lease `flock`.  The root
//! directory and every named object are opened through descriptors, and every
//! read is checked against a second name lookup before serde sees the bytes.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsFd, OwnedFd},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use nix::{
    errno::Errno,
    fcntl::{open as open_path, openat, renameat2, Flock, FlockArg, OFlag, RenameFlags},
    sys::stat::{fchmod, fstat, Mode, SFlag},
    unistd::{fchown, fsync, unlinkat, Gid, Uid, UnlinkatFlags},
};
use serde_json::from_slice;
use thiserror::Error;

use super::{
    safe_lease_id, CiEventBinding, Digest32, ProxyJournal, ProxyJournalError, ProxyJournalFact,
    ProxyJournalReplay,
};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

// The lifecycle ceiling leaves seven records for the complete reconciliation
// cleanup. The read path checks the descriptor's size before allocating and
// the encoded path checks the final byte count before creating a temporary
// replacement.
const MAX_JOURNAL_BYTES: usize = 2 * 1024 * 1024;
const TEMP_ATTEMPTS: usize = 128;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedOwner {
    uid: u32,
    gid: u32,
}

/// Root-directory handle for descriptor-relative proxy journal operations.
pub(crate) struct ProxyJournalStore {
    root: OwnedFd,
    owner: ExpectedOwner,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProxyJournalStoreError {
    #[error("proxy journal already exists")]
    AlreadyExists,
    #[error("proxy journal does not exist")]
    NotFound,
    #[error("proxy journal filesystem object is unsafe")]
    UnsafeFilesystem,
    #[error("proxy journal name or descriptor changed during the operation")]
    RaceDetected,
    #[error("proxy journal exceeds the encoded or read byte ceiling")]
    Oversized,
    #[error("proxy journal encoding failed")]
    Encoding,
    #[error("proxy journal I/O failed")]
    Io,
    #[error("proxy journal validation failed: {0}")]
    Journal(#[from] ProxyJournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: i64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

impl FileIdentity {
    fn same_inode(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

struct JournalSnapshot {
    journal: ProxyJournal,
    bytes: Vec<u8>,
    identity: FileIdentity,
}

pub(crate) struct ProxyJournalCreation {
    lease_id: String,
    event_binding: CiEventBinding,
    upstream_capability_sha256: Digest32,
    identity: FileIdentity,
}

struct PublishedJournal {
    replay: ProxyJournalReplay,
    identity: FileIdentity,
}

struct TemporaryFile {
    name: String,
    file: File,
    identity: FileIdentity,
    committed: bool,
}

struct LeaseLock {
    _guard: Flock<File>,
}

impl ProxyJournalStore {
    /// Open the already-existing production root. Production is root-owned.
    pub(crate) fn open<P: AsRef<Path>>(root: P) -> Result<Self, ProxyJournalStoreError> {
        Self::open_for_owner(root, ExpectedOwner { uid: 0, gid: 0 })
    }

    /// Open a test root owned by the test process instead of requiring uid/gid 0.
    #[cfg(test)]
    pub(crate) fn open_with_expected_owner<P: AsRef<Path>>(
        root: P,
        uid: u32,
        gid: u32,
    ) -> Result<Self, ProxyJournalStoreError> {
        Self::open_for_owner(root, ExpectedOwner { uid, gid })
    }

    fn open_for_owner<P: AsRef<Path>>(
        root: P,
        owner: ExpectedOwner,
    ) -> Result<Self, ProxyJournalStoreError> {
        let root = open_path(
            root.as_ref(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        validate_directory(&root, owner)?;
        Ok(Self { root, owner })
    }

    /// Create one initial journal. A pre-existing canonical name is rejected.
    #[cfg(test)]
    pub(crate) fn create(
        &self,
        journal: ProxyJournal,
    ) -> Result<ProxyJournalReplay, ProxyJournalStoreError> {
        Ok(self.create_with_identity(journal)?.replay)
    }

    fn create_with_identity(
        &self,
        journal: ProxyJournal,
    ) -> Result<PublishedJournal, ProxyJournalStoreError> {
        let lease_id = journal.lease_id.clone();
        let event_binding = journal.event_binding;
        let upstream_capability_sha256 = journal.upstream_capability_sha256;
        validate_lease_id(&lease_id)?;
        let replay = journal.replay_for(&lease_id, event_binding, upstream_capability_sha256)?;
        let bytes = encode_journal(&journal)?;
        let canonical_name = canonical_name(&lease_id)?;
        let lock_name = lock_name(&lease_id)?;
        let _lock = self.acquire_lock(&lock_name)?;
        ensure_canonical_absent(&self.root, &canonical_name)?;
        self.publish(
            &canonical_name,
            &lease_id,
            event_binding,
            upstream_capability_sha256,
            &bytes,
            None,
            true,
            replay,
        )
    }

    /// Construct and create an empty initial journal for one lease.
    pub(crate) fn create_initial(
        &self,
        lease_id: String,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
    ) -> Result<ProxyJournalCreation, ProxyJournalStoreError> {
        let published = self.create_with_identity(ProxyJournal::new(
            lease_id.clone(),
            event_binding,
            upstream_capability_sha256,
        )?)?;
        Ok(ProxyJournalCreation {
            lease_id,
            event_binding,
            upstream_capability_sha256,
            identity: published.identity,
        })
    }

    /// Load and replay the journal only when both lease and event binding match.
    pub(crate) fn load(
        &self,
        lease_id: &str,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
    ) -> Result<ProxyJournalReplay, ProxyJournalStoreError> {
        let canonical_name = canonical_name(lease_id)?;
        let lock_name = lock_name(lease_id)?;
        let _lock = self.acquire_lock(&lock_name)?;
        let snapshot = read_snapshot(&self.root, &canonical_name, self.owner)?;
        Ok(snapshot
            .journal
            .replay_for(lease_id, event_binding, upstream_capability_sha256)?)
    }

    /// Append one timestamped fact and durably replace the complete journal.
    pub(crate) fn append(
        &self,
        lease_id: &str,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
        timestamp_unix_ns: u64,
        fact: ProxyJournalFact,
    ) -> Result<ProxyJournalReplay, ProxyJournalStoreError> {
        let canonical_name = canonical_name(lease_id)?;
        let lock_name = lock_name(lease_id)?;
        let _lock = self.acquire_lock(&lock_name)?;
        let snapshot = read_snapshot(&self.root, &canonical_name, self.owner)?;
        let mut journal = snapshot.journal;
        journal.replay_for(lease_id, event_binding, upstream_capability_sha256)?;
        journal.append(timestamp_unix_ns, fact)?;
        let replay = journal.replay_for(lease_id, event_binding, upstream_capability_sha256)?;
        let bytes = encode_journal(&journal)?;
        self.publish(
            &canonical_name,
            lease_id,
            event_binding,
            upstream_capability_sha256,
            &bytes,
            Some(snapshot.identity),
            false,
            replay,
        )
        .map(|published| published.replay)
    }

    /// Remove only the exact journal inode created by this store invocation.
    pub(crate) fn remove_created(
        &self,
        creation: ProxyJournalCreation,
    ) -> Result<(), ProxyJournalStoreError> {
        let canonical_name = canonical_name(&creation.lease_id)?;
        let lock_name = lock_name(&creation.lease_id)?;
        let _lock = self.acquire_lock(&lock_name)?;
        let snapshot = read_snapshot(&self.root, &canonical_name, self.owner)?;
        snapshot.journal.replay_for(
            &creation.lease_id,
            creation.event_binding,
            creation.upstream_capability_sha256,
        )?;
        if snapshot.identity != creation.identity {
            return Err(ProxyJournalStoreError::RaceDetected);
        }
        verify_named_identity(&self.root, &canonical_name, self.owner, creation.identity)?;
        unlinkat(
            &self.root,
            canonical_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|error| match error {
            Errno::ENOENT => ProxyJournalStoreError::RaceDetected,
            _ => ProxyJournalStoreError::Io,
        })?;
        fsync(self.root.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
        ensure_canonical_absent(&self.root, &canonical_name)
    }

    fn acquire_lock(&self, name: &str) -> Result<LeaseLock, ProxyJournalStoreError> {
        let (file, created) = match openat(
            &self.root,
            name,
            OFlag::O_RDWR
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(FILE_MODE),
        ) {
            Ok(fd) => (File::from(fd), true),
            Err(Errno::EEXIST) => {
                let fd = openat(
                    &self.root,
                    name,
                    OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(map_open_error)?;
                (File::from(fd), false)
            }
            Err(error) => return Err(map_open_error(error)),
        };

        if created {
            let created_identity = file_identity(&file)?;
            let result = (|| {
                set_exact_file_metadata(&file, self.owner)?;
                validate_regular(&file, self.owner, None)?;
                file.sync_all().map_err(|_| ProxyJournalStoreError::Io)?;
                fsync(self.root.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
                Ok::<(), ProxyJournalStoreError>(())
            })();
            if result.is_err() {
                cleanup_exact_inode(&self.root, name, created_identity);
            }
            result?;
        } else {
            validate_regular(&file, self.owner, None)?;
        }

        let guard = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, _)| ProxyJournalStoreError::Io)?;
        let held_identity = file_identity(&*guard)?;
        verify_named_identity(&self.root, name, self.owner, held_identity)?;
        Ok(LeaseLock { _guard: guard })
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        canonical_name: &str,
        lease_id: &str,
        event_binding: CiEventBinding,
        upstream_capability_sha256: Digest32,
        bytes: &[u8],
        expected_existing: Option<FileIdentity>,
        create_only: bool,
        expected_replay: ProxyJournalReplay,
    ) -> Result<PublishedJournal, ProxyJournalStoreError> {
        cap_encoded_bytes(bytes)?;
        let mut temporary = self.create_temporary(canonical_name)?;
        let result = (|| {
            temporary
                .file
                .write_all(bytes)
                .map_err(|_| ProxyJournalStoreError::Io)?;
            temporary
                .file
                .sync_all()
                .map_err(|_| ProxyJournalStoreError::Io)?;
            set_exact_file_metadata(&temporary.file, self.owner)?;
            validate_regular(&temporary.file, self.owner, Some(bytes.len()))?;
            temporary
                .file
                .sync_all()
                .map_err(|_| ProxyJournalStoreError::Io)?;
            let written_identity = file_identity(&temporary.file)?;
            verify_named_identity(&self.root, &temporary.name, self.owner, written_identity)?;

            if let Some(expected) = expected_existing {
                verify_named_identity(&self.root, canonical_name, self.owner, expected)?;
            } else {
                ensure_canonical_absent(&self.root, canonical_name)?;
            }

            let flags = if create_only {
                RenameFlags::RENAME_NOREPLACE
            } else {
                RenameFlags::empty()
            };
            match renameat2(
                &self.root,
                temporary.name.as_str(),
                &self.root,
                canonical_name,
                flags,
            ) {
                Ok(()) => temporary.committed = true,
                Err(Errno::EEXIST) if create_only => {
                    return Err(ProxyJournalStoreError::AlreadyExists)
                }
                Err(Errno::ENOENT) => return Err(ProxyJournalStoreError::RaceDetected),
                Err(_) => return Err(ProxyJournalStoreError::Io),
            }
            fsync(self.root.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;

            let final_snapshot = read_snapshot(&self.root, canonical_name, self.owner)?;
            if final_snapshot.bytes != bytes
                || !final_snapshot.identity.same_inode(temporary.identity)
            {
                return Err(ProxyJournalStoreError::RaceDetected);
            }
            let replay = final_snapshot.journal.replay_for(
                lease_id,
                event_binding,
                upstream_capability_sha256,
            )?;
            if replay != expected_replay {
                return Err(ProxyJournalStoreError::RaceDetected);
            }
            Ok(PublishedJournal {
                replay,
                identity: final_snapshot.identity,
            })
        })();
        if result.is_err() && !temporary.committed {
            cleanup_exact_inode(&self.root, &temporary.name, temporary.identity);
        }
        result
    }

    fn create_temporary(
        &self,
        canonical_name: &str,
    ) -> Result<TemporaryFile, ProxyJournalStoreError> {
        let pid = std::process::id();
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".{canonical_name}.{pid}.{sequence}.tmp");
            match openat(
                &self.root,
                name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(FILE_MODE),
            ) {
                Ok(fd) => {
                    let file = File::from(fd);
                    let identity = file_identity(&file)?;
                    return Ok(TemporaryFile {
                        name,
                        file,
                        identity,
                        committed: false,
                    });
                }
                Err(Errno::EEXIST) => continue,
                Err(error) => return Err(map_open_error(error)),
            }
        }
        Err(ProxyJournalStoreError::RaceDetected)
    }
}

fn canonical_name(lease_id: &str) -> Result<String, ProxyJournalStoreError> {
    validate_lease_id(lease_id)?;
    Ok(format!("proxy-journal-{lease_id}.json"))
}

fn lock_name(lease_id: &str) -> Result<String, ProxyJournalStoreError> {
    validate_lease_id(lease_id)?;
    Ok(format!("proxy-journal-{lease_id}.lock"))
}

fn validate_lease_id(lease_id: &str) -> Result<(), ProxyJournalStoreError> {
    if safe_lease_id(lease_id) {
        Ok(())
    } else {
        Err(ProxyJournalStoreError::Journal(
            ProxyJournalError::InvalidLeaseId,
        ))
    }
}

fn validate_directory(
    directory: &OwnedFd,
    owner: ExpectedOwner,
) -> Result<(), ProxyJournalStoreError> {
    let stat = fstat(directory.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o7777 != DIRECTORY_MODE
    {
        return Err(ProxyJournalStoreError::UnsafeFilesystem);
    }
    Ok(())
}

fn validate_regular(
    file: impl AsFd,
    owner: ExpectedOwner,
    expected_size: Option<usize>,
) -> Result<(), ProxyJournalStoreError> {
    let stat = fstat(file.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != FILE_MODE
    {
        return Err(ProxyJournalStoreError::UnsafeFilesystem);
    }
    if let Some(expected_size) = expected_size {
        if stat.st_size != expected_size as i64 {
            return Err(ProxyJournalStoreError::RaceDetected);
        }
    }
    Ok(())
}

fn file_identity(file: impl AsFd) -> Result<FileIdentity, ProxyJournalStoreError> {
    let stat = fstat(file.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
    Ok(identity_from_stat(&stat))
}

fn identity_from_stat(stat: &nix::libc::stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: stat.st_size,
        mtime_seconds: stat.st_mtime,
        mtime_nanoseconds: stat.st_mtime_nsec,
        ctime_seconds: stat.st_ctime,
        ctime_nanoseconds: stat.st_ctime_nsec,
    }
}

fn set_exact_file_metadata(
    file: &File,
    owner: ExpectedOwner,
) -> Result<(), ProxyJournalStoreError> {
    fchown(
        file.as_fd(),
        Some(Uid::from_raw(owner.uid)),
        Some(Gid::from_raw(owner.gid)),
    )
    .map_err(|_| ProxyJournalStoreError::Io)?;
    fchmod(file.as_fd(), Mode::from_bits_truncate(FILE_MODE))
        .map_err(|_| ProxyJournalStoreError::Io)?;
    Ok(())
}

fn ensure_canonical_absent(root: &OwnedFd, name: &str) -> Result<(), ProxyJournalStoreError> {
    match openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let stat = fstat(fd.as_fd()).map_err(|_| ProxyJournalStoreError::Io)?;
            if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
                Err(ProxyJournalStoreError::UnsafeFilesystem)
            } else {
                Err(ProxyJournalStoreError::AlreadyExists)
            }
        }
        Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(map_open_error(error)),
    }
}

fn verify_named_identity(
    root: &OwnedFd,
    name: &str,
    owner: ExpectedOwner,
    expected: FileIdentity,
) -> Result<(), ProxyJournalStoreError> {
    let fd = openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| match error {
        Errno::ENOENT => ProxyJournalStoreError::RaceDetected,
        other => map_open_error(other),
    })?;
    validate_regular(&fd, owner, None)?;
    let current = file_identity(&fd)?;
    if current.same_inode(expected) && current == expected {
        Ok(())
    } else {
        Err(ProxyJournalStoreError::RaceDetected)
    }
}

fn read_snapshot(
    root: &OwnedFd,
    name: &str,
    owner: ExpectedOwner,
) -> Result<JournalSnapshot, ProxyJournalStoreError> {
    let fd = openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let mut file = File::from(fd);
    validate_regular(&file, owner, None)?;
    let identity = file_identity(&file)?;
    let size = usize::try_from(identity.size).map_err(|_| ProxyJournalStoreError::Oversized)?;
    cap_read_size(size)?;

    file.seek(SeekFrom::Start(0))
        .map_err(|_| ProxyJournalStoreError::Io)?;
    let mut bytes = Vec::with_capacity(size);
    (&mut file)
        .take((MAX_JOURNAL_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProxyJournalStoreError::Io)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ProxyJournalStoreError::Oversized);
    }
    if bytes.len() != size || file_identity(&file)? != identity {
        return Err(ProxyJournalStoreError::RaceDetected);
    }

    let reopened = openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| match error {
        Errno::ENOENT => ProxyJournalStoreError::RaceDetected,
        other => map_open_error(other),
    })?;
    validate_regular(&reopened, owner, Some(size))?;
    if file_identity(&reopened)? != identity {
        return Err(ProxyJournalStoreError::RaceDetected);
    }

    let journal =
        from_slice::<ProxyJournal>(&bytes).map_err(|_| ProxyJournalStoreError::Encoding)?;
    Ok(JournalSnapshot {
        journal,
        bytes,
        identity,
    })
}

fn encode_journal(journal: &ProxyJournal) -> Result<Vec<u8>, ProxyJournalStoreError> {
    journal.replay()?;
    let bytes = serde_json::to_vec(journal).map_err(|_| ProxyJournalStoreError::Encoding)?;
    cap_encoded_bytes(&bytes)?;
    Ok(bytes)
}

fn cap_read_size(size: usize) -> Result<(), ProxyJournalStoreError> {
    if size <= MAX_JOURNAL_BYTES {
        Ok(())
    } else {
        Err(ProxyJournalStoreError::Oversized)
    }
}

fn cap_encoded_bytes(bytes: &[u8]) -> Result<(), ProxyJournalStoreError> {
    if bytes.len() <= MAX_JOURNAL_BYTES {
        Ok(())
    } else {
        Err(ProxyJournalStoreError::Oversized)
    }
}

fn cleanup_exact_inode(root: &OwnedFd, name: &str, expected: FileIdentity) {
    let Ok(fd) = openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) else {
        return;
    };
    let Ok(stat) = nix::sys::stat::fstat(fd.as_fd()) else {
        return;
    };
    let current = identity_from_stat(&stat);
    if current.same_inode(expected) && stat.st_nlink == 1 {
        let _ = unlinkat(root, name, UnlinkatFlags::NoRemoveDir);
    }
}

fn map_open_error(error: Errno) -> ProxyJournalStoreError {
    match error {
        Errno::ENOENT => ProxyJournalStoreError::NotFound,
        Errno::ELOOP => ProxyJournalStoreError::UnsafeFilesystem,
        _ => ProxyJournalStoreError::Io,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::{Path, PathBuf},
    };

    use nix::unistd::{getgid, getuid, mkfifo};
    use tempfile::{tempdir, TempDir};

    use super::*;

    fn binding(seed: u8) -> CiEventBinding {
        CiEventBinding {
            request_event_id_46105: [seed; 32],
            teardown_event_id_46106: [seed.wrapping_add(1); 32],
        }
    }

    fn initial(lease_id: &str, event_binding: CiEventBinding) -> ProxyJournal {
        ProxyJournal::new(lease_id.to_owned(), event_binding, capability_digest())
            .expect("valid initial journal")
    }

    fn capability_digest() -> Digest32 {
        Digest32([9; 32])
    }

    fn root() -> (TempDir, ProxyJournalStore) {
        let directory = tempdir().expect("temp root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("root mode");
        let store = ProxyJournalStore::open_with_expected_owner(
            directory.path(),
            getuid().as_raw(),
            getgid().as_raw(),
        )
        .expect("open test root");
        (directory, store)
    }

    fn canonical_path(root: &Path, lease_id: &str) -> PathBuf {
        root.join(canonical_name(lease_id).expect("safe name"))
    }

    fn authority() -> super::super::CanonicalCreateAuthority {
        super::super::CanonicalCreateAuthority {
            fingerprint: format!("{:064x}", 1),
            target: "/containers/create?name=test".to_owned(),
            body_sha256: super::super::Digest32([1; 32]),
        }
    }

    #[test]
    fn create_load_append_roundtrip() {
        let (_directory, store) = root();
        let event_binding = binding(1);
        let lease_id = "lease-roundtrip";
        let replay = store
            .create(initial(lease_id, event_binding))
            .expect("create journal");
        assert_eq!(
            replay.phase,
            buzz_ci_policy_proxy::LifecyclePhase::AwaitCreate
        );

        let replay = store
            .append(
                lease_id,
                event_binding,
                capability_digest(),
                1,
                ProxyJournalFact::create_intent(authority()),
            )
            .expect("append fact");
        assert_eq!(
            replay.unresolved_intent,
            Some(super::super::ProxyMutationIntent::Create)
        );
        assert_eq!(
            store.load(lease_id, event_binding, capability_digest()),
            Ok(replay)
        );
    }

    #[test]
    fn fresh_store_reopen_replays_after_restart() {
        let (directory, store) = root();
        let event_binding = binding(3);
        let lease_id = "lease-restart";
        store
            .create(initial(lease_id, event_binding))
            .expect("create journal");
        store
            .append(
                lease_id,
                event_binding,
                capability_digest(),
                7,
                ProxyJournalFact::create_intent(authority()),
            )
            .expect("append fact");
        drop(store);
        let reopened = ProxyJournalStore::open_with_expected_owner(
            directory.path(),
            getuid().as_raw(),
            getgid().as_raw(),
        )
        .expect("reopen root");
        let replay = reopened
            .load(lease_id, event_binding, capability_digest())
            .expect("load after restart");
        assert_eq!(
            replay.unresolved_intent,
            Some(super::super::ProxyMutationIntent::Create)
        );
    }

    #[test]
    fn read_and_encoded_byte_ceilings_are_enforced() {
        assert!(cap_encoded_bytes(&vec![0; MAX_JOURNAL_BYTES]).is_ok());
        assert_eq!(
            cap_encoded_bytes(&vec![0; MAX_JOURNAL_BYTES + 1]),
            Err(ProxyJournalStoreError::Oversized)
        );

        let (directory, store) = root();
        let lease_id = "lease-oversized";
        let event_binding = binding(5);
        let path = canonical_path(directory.path(), lease_id);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("oversized file");
        file.write_all(&vec![0; MAX_JOURNAL_BYTES + 1])
            .expect("write oversized file");
        file.sync_all().expect("sync oversized file");
        drop(file);
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("file mode");
        assert_eq!(
            store.load(lease_id, event_binding, capability_digest()),
            Err(ProxyJournalStoreError::Oversized)
        );
    }

    #[test]
    fn oversized_publication_leaves_canonical_identity_and_bytes_unchanged() {
        let (directory, store) = root();
        let lease_id = "lease-atomic-oversized";
        let event_binding = binding(25);
        store
            .create(initial(lease_id, event_binding))
            .expect("create canonical");
        let canonical_name = canonical_name(lease_id).unwrap();
        let before = read_snapshot(&store.root, &canonical_name, store.owner).unwrap();
        let replay = before
            .journal
            .replay_for(lease_id, event_binding, capability_digest())
            .unwrap();

        assert!(matches!(
            store.publish(
                &canonical_name,
                lease_id,
                event_binding,
                capability_digest(),
                &vec![0; MAX_JOURNAL_BYTES + 1],
                Some(before.identity),
                false,
                replay,
            ),
            Err(ProxyJournalStoreError::Oversized)
        ));

        let after = read_snapshot(&store.root, &canonical_name, store.owner).unwrap();
        assert_eq!(after.identity, before.identity);
        assert_eq!(after.bytes, before.bytes);
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn largest_valid_target_and_lifecycle_fit_the_encoded_ceiling() {
        let event_binding = binding(21);
        let mut journal = initial("lease-largest", event_binding);
        let authority = super::super::CanonicalCreateAuthority::new(
            format!("{:064x}", 1),
            format!("/{}", "a".repeat(super::super::MAX_TARGET_BYTES - 1)),
            super::super::Digest32([1; 32]),
        )
        .expect("maximum target authority");

        for _ in 0..((super::super::MAX_LIFECYCLE_ENTRIES - 6) / 2) {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(
                    timestamp,
                    ProxyJournalFact::create_intent(authority.clone()),
                )
                .expect("create intent fits");
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(
                    timestamp,
                    ProxyJournalFact::create_rejected(authority.clone()),
                )
                .expect("create rejection fits");
        }
        for fact in [
            ProxyJournalFact::create_intent(authority.clone()),
            ProxyJournalFact::created(authority.clone(), "container-1".to_owned()),
            ProxyJournalFact::start_intent("container-1".to_owned()),
            ProxyJournalFact::started("container-1".to_owned()),
        ] {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(timestamp, fact)
                .expect("lifecycle fact fits");
        }
        let running_inventory =
            ProxyJournalFact::reconcile_inventory(vec![super::super::ReconcileObject {
                id: "container-1".to_owned(),
                running: true,
            }]);
        for fact in [
            running_inventory.clone(),
            ProxyJournalFact::stop_intent("container-1".to_owned()),
        ] {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(timestamp, fact)
                .expect("cleanup reserve fits");
        }
        let repeated_readbacks = super::super::MAX_ENTRIES - journal.entries.len() - 7;
        let before_repeated_readbacks = journal.entries.len();
        for _ in 0..repeated_readbacks {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(timestamp, running_inventory.clone())
                .expect("restart inventory fits");
        }
        assert_eq!(journal.entries.len(), before_repeated_readbacks + 1);
        for fact in [
            ProxyJournalFact::stopped("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(vec![super::super::ReconcileObject {
                id: "container-1".to_owned(),
                running: false,
            }]),
            ProxyJournalFact::delete_object_intent("container-1".to_owned()),
            ProxyJournalFact::reconcile_inventory(vec![super::super::ReconcileObject {
                id: "container-1".to_owned(),
                running: false,
            }]),
            ProxyJournalFact::deleted_object("container-1".to_owned()),
        ] {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(timestamp, fact)
                .expect("cleanup reserve fits");
        }
        assert!(journal.entries.len() <= super::super::MAX_ENTRIES - 2);
        for fact in [
            ProxyJournalFact::reconcile_inventory(Vec::new()),
            ProxyJournalFact::reconcile_verified_empty(),
        ] {
            let timestamp = journal.entries.len() as u64 + 1;
            journal
                .append(timestamp, fact)
                .expect("final empty proof fits at capacity");
        }

        let bytes = encode_journal(&journal).expect("maximum valid journal encodes");
        assert!(journal.replay().unwrap().is_clean_terminal());
        assert!(bytes.len() <= MAX_JOURNAL_BYTES);
    }

    #[test]
    fn symlink_and_hardlink_canonical_names_are_rejected() {
        let (directory, store) = root();
        let lease_id = "lease-links";
        let event_binding = binding(7);
        let path = canonical_path(directory.path(), lease_id);
        symlink("missing-target", &path).expect("canonical symlink");
        assert!(store.create(initial(lease_id, event_binding)).is_err());

        fs::remove_file(&path).expect("remove symlink");
        store
            .create(initial(lease_id, event_binding))
            .expect("create canonical");
        fs::hard_link(&path, directory.path().join("alias")).expect("hardlink canonical");
        assert!(store
            .load(lease_id, event_binding, capability_digest())
            .is_err());
    }

    #[test]
    fn canonical_fifo_is_rejected_without_blocking() {
        let (directory, store) = root();
        let lease_id = "lease-fifo";
        let event_binding = binding(23);
        let path = canonical_path(directory.path(), lease_id);
        mkfifo(&path, Mode::from_bits_truncate(FILE_MODE)).expect("canonical fifo");

        assert_eq!(
            store.create(initial(lease_id, event_binding)),
            Err(ProxyJournalStoreError::UnsafeFilesystem)
        );
        assert_eq!(
            store.load(lease_id, event_binding, capability_digest()),
            Err(ProxyJournalStoreError::UnsafeFilesystem)
        );
    }

    #[test]
    fn wrong_mode_and_binding_are_rejected() {
        let (directory, store) = root();
        let lease_id = "lease-validation";
        let event_binding = binding(9);
        let path = canonical_path(directory.path(), lease_id);
        store
            .create(initial(lease_id, event_binding))
            .expect("create canonical");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("wrong mode");
        assert!(store
            .load(lease_id, event_binding, capability_digest())
            .is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("restore mode");
        assert_eq!(
            store.load(lease_id, binding(11), capability_digest()),
            Err(ProxyJournalStoreError::Journal(
                ProxyJournalError::BindingMismatch
            ))
        );
    }

    #[test]
    fn canonical_inode_replacement_fails_identity_check() {
        let (directory, store) = root();
        let lease_id = "lease-inode";
        let event_binding = binding(13);
        let path = canonical_path(directory.path(), lease_id);
        store
            .create(initial(lease_id, event_binding))
            .expect("create canonical");
        let snapshot = read_snapshot(
            &store.root,
            &canonical_name(lease_id).expect("safe name"),
            store.owner,
        )
        .expect("read snapshot");
        let replacement = directory.path().join("replacement");
        fs::copy(&path, &replacement).expect("copy replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE))
            .expect("replacement mode");
        fs::rename(&replacement, &path).expect("replace canonical");
        assert_eq!(
            verify_named_identity(
                &store.root,
                &canonical_name(lease_id).expect("safe name"),
                store.owner,
                snapshot.identity,
            ),
            Err(ProxyJournalStoreError::RaceDetected)
        );
    }

    #[test]
    fn lock_inode_replacement_fails_identity_check() {
        let (directory, store) = root();
        let lease_id = "lease-lock-inode";
        let event_binding = binding(17);
        store
            .create(initial(lease_id, event_binding))
            .expect("create canonical and lock");
        let name = lock_name(lease_id).expect("safe name");
        let path = directory.path().join(&name);
        let fd = openat(
            &store.root,
            name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("open lock");
        let identity = file_identity(&fd).expect("lock identity");
        let replacement = directory.path().join("lock-replacement");
        let replacement_file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&replacement)
            .expect("replacement lock");
        replacement_file.sync_all().expect("sync replacement lock");
        drop(replacement_file);
        fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE))
            .expect("replacement lock mode");
        fs::rename(&replacement, &path).expect("replace lock");
        assert_eq!(
            verify_named_identity(&store.root, &name, store.owner, identity),
            Err(ProxyJournalStoreError::RaceDetected)
        );
    }

    #[test]
    fn create_rejects_existing_canonical_name() {
        let (_directory, store) = root();
        let lease_id = "lease-existing";
        let event_binding = binding(15);
        store
            .create(initial(lease_id, event_binding))
            .expect("first create");
        assert_eq!(
            store.create(initial(lease_id, event_binding)),
            Err(ProxyJournalStoreError::AlreadyExists)
        );
    }

    #[test]
    fn remove_created_refuses_replaced_canonical_inode() {
        let (directory, store) = root();
        let lease_id = "lease-remove-race";
        let event_binding = binding(25);
        let creation = store
            .create_initial(lease_id.to_owned(), event_binding, capability_digest())
            .expect("create journal");
        let path = canonical_path(directory.path(), lease_id);
        let replacement = directory.path().join("replacement-remove");
        fs::copy(&path, &replacement).expect("copy replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE))
            .expect("replacement mode");
        fs::rename(&replacement, &path).expect("replace canonical");

        assert_eq!(
            store.remove_created(creation),
            Err(ProxyJournalStoreError::RaceDetected)
        );
        assert!(path.exists());
    }
}
