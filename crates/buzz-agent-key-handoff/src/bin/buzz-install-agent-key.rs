#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use anyhow::{anyhow, bail, Context, Result};
use buzz_agent_key_handoff::{
    exact_secret_line, harden_process, parse_enrollment_map, require_anonymous_pipe,
    validate_secret_binding, Slug, MAX_ENROLLMENT_MAP_BYTES,
};
use rustix::fs::{
    fchmod, fchown, flock, fstat, fsync, linkat, open, openat, statat, unlinkat, AtFlags, FileType,
    FlockOperation, Mode, OFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::{geteuid, Gid, Uid};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use zeroize::Zeroizing;

const MAP_PATH: &str = "/etc/buzz-agents/enrollment-keys.json";
const CREDENTIAL_DIR: &str = "/etc/buzz-agents/credentials";

#[derive(Clone, Copy)]
struct PublishedInode {
    dev: u64,
    ino: u64,
}

fn parse_args() -> Result<Slug> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[0] != "install" || args[1] != "--slug" {
        bail!("usage: buzz-install-agent-key install --slug SLUG");
    }
    Slug::parse(&args[2])
}

fn require_secure_regular<Fd: AsFd>(fd: Fd, path: &Path, mode: u32) -> Result<Stat> {
    let stat = fstat(fd).with_context(|| format!("stat {}", path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || Mode::from_raw_mode(stat.st_mode).as_raw_mode() != mode
    {
        bail!("unsafe metadata: {}", path.display());
    }
    Ok(stat)
}

fn open_secure_regular(path: &Path, mode: u32) -> Result<File> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("open {}", path.display()))?;
    let file = File::from(fd);
    require_secure_regular(file.as_fd(), path, mode)?;
    Ok(file)
}

fn expected_pubkey(slug: Slug) -> Result<String> {
    let path = Path::new(MAP_PATH);
    let mut file = open_secure_regular(path, 0o600)?;
    let mut bytes = Vec::with_capacity(MAX_ENROLLMENT_MAP_BYTES + 1);
    std::io::Read::by_ref(&mut file)
        .take((MAX_ENROLLMENT_MAP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read enrollment map")?;
    if bytes.len() > MAX_ENROLLMENT_MAP_BYTES {
        bail!("enrollment map is too large");
    }
    let text = std::str::from_utf8(&bytes).context("enrollment map is not UTF-8")?;
    let keys = parse_enrollment_map(text)?;
    Ok(match slug {
        Slug::Mempool => keys.mempool,
        Slug::Genesis => keys.genesis,
    })
}

fn lock_slug(slug: Slug) -> Result<File> {
    let path = format!("/run/lock/buzz-agent-key-{}.lock", slug.as_str());
    let fd = open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("open enrollment lock")?;
    let file = File::from(fd);
    require_secure_regular(file.as_fd(), Path::new(&path), 0o600)?;
    flock(file.as_fd(), FlockOperation::LockExclusive).context("lock enrollment")?;
    Ok(file)
}

fn read_secret<R: Read>(input: &mut R) -> Result<Zeroizing<String>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(66));
    std::io::Read::by_ref(input)
        .take(66)
        .read_to_end(&mut bytes)
        .context("read secret")?;
    exact_secret_line(&bytes)
}

fn require_target_absent(dir: BorrowedFd<'_>, name: &OsStr, path: &Path) -> Result<()> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
        Ok(_) => bail!("credential target already exists: {}", path.display()),
    }
}

fn signal_ready<W: Write>(output: &mut W) -> Result<()> {
    output
        .write_all(b"R")
        .and_then(|_| output.flush())
        .context("signal receiver readiness")
}

fn prepare_absent_install<W: Write>(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    readiness: &mut W,
) -> Result<()> {
    require_target_absent(dir, name, path)?;
    signal_ready(readiness)
}

fn require_secure_credential_dir(path: &Path) -> Result<OwnedFd> {
    let dir = open(
        path,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .context("open credential directory")?;
    let stat = fstat(dir.as_fd()).context("stat credential directory")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || Mode::from_raw_mode(stat.st_mode).as_raw_mode() != 0o700
    {
        bail!("unsafe credential directory");
    }
    Ok(dir)
}

fn rollback_same_inode(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    published: PublishedInode,
) -> Result<()> {
    let fd = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("open {} for rollback", path.display()))
        }
    };
    let stat =
        fstat(fd.as_fd()).with_context(|| format!("stat {} for rollback", path.display()))?;
    if stat.st_dev as u64 != published.dev
        || stat.st_ino as u64 != published.ino
        || stat.st_nlink != 1
    {
        bail!("refusing to roll back a replaced credential");
    }
    unlinkat(dir, name, AtFlags::empty())
        .with_context(|| format!("unlink {} during rollback", path.display()))?;
    fsync(dir).context("sync credential directory after rollback")
}

fn install_absent(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    content: &[u8],
) -> Result<PublishedInode> {
    let fd = openat(
        dir,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .context("create anonymous credential")?;
    let mut temporary = File::from(fd);
    temporary.write_all(content).context("write credential")?;
    fchown(temporary.as_fd(), Some(Uid::ROOT), Some(Gid::ROOT)).context("own credential")?;
    fchmod(temporary.as_fd(), Mode::RUSR | Mode::WUSR).context("mode credential")?;
    fsync(temporary.as_fd()).context("sync credential")?;
    let stat = fstat(temporary.as_fd()).context("stat anonymous credential")?;
    let published = PublishedInode {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    };
    linkat(temporary.as_fd(), "", dir, name, AtFlags::EMPTY_PATH)
        .with_context(|| format!("publish {}", path.display()))?;
    if let Err(error) = fsync(dir) {
        if let Err(rollback_error) = rollback_same_inode(dir, name, path, published) {
            return Err(anyhow!(
                "sync credential directory failed: {error}; rollback failed: {rollback_error:#}"
            ));
        }
        return Err(error).context("sync credential directory");
    }
    Ok(published)
}

fn verify_installed(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    content: &[u8],
    published: PublishedInode,
) -> Result<()> {
    let fd = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => bail!("credential target is absent after install"),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut file = File::from(fd);
    let stat = require_secure_regular(file.as_fd(), path, 0o600)?;
    if stat.st_dev as u64 != published.dev || stat.st_ino as u64 != published.ino {
        bail!("credential target changed during verification");
    }
    let mut data = zeroize::Zeroizing::new(Vec::with_capacity(66));
    std::io::Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut data)
        .context("read installed credential")?;
    if data.as_slice() != content {
        bail!("credential exists with different content");
    }
    Ok(())
}

fn main() -> Result<()> {
    harden_process()?;
    if !geteuid().is_root() {
        bail!("receiver must run as root");
    }
    let slug = parse_args()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    require_anonymous_pipe(stdin.as_fd())?;
    require_anonymous_pipe(stdout.as_fd())?;
    let _lock = lock_slug(slug)?;
    let target = Path::new(CREDENTIAL_DIR).join(format!("{}.key", slug.as_str()));
    let name = target
        .file_name()
        .context("credential target has no name")?;
    let dir =
        require_secure_credential_dir(target.parent().context("credential target has no parent")?)?;
    require_target_absent(dir.as_fd(), name, &target)?;
    let expected = expected_pubkey(slug)?;
    let mut readiness = stdout.lock();
    prepare_absent_install(dir.as_fd(), name, &target, &mut readiness)?;
    let mut input = stdin.lock();
    let secret = read_secret(&mut input)?;
    let secret_hex = validate_secret_binding(&secret, &expected)?;
    let mut content = Zeroizing::new(secret_hex.as_bytes().to_vec());
    content.push(b'\n');
    let published = install_absent(dir.as_fd(), name, &target, &content)?;
    if let Err(error) = verify_installed(dir.as_fd(), name, &target, &content, published) {
        if let Err(rollback_error) = rollback_same_inode(dir.as_fd(), name, &target, published) {
            return Err(anyhow!(
                "credential verification failed: {error:#}; rollback failed: {rollback_error:#}"
            ));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::pipe::{pipe_with, PipeFlags};

    fn open_test_directory(path: &Path) -> OwnedFd {
        open(
            path,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn absent_only_gate_rejects_existing_target_before_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("mempool.key");
        std::fs::write(&target, b"already present\n").unwrap();
        let dir = open_test_directory(directory.path());
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        let mut readiness_output = File::from(write_end);
        assert!(prepare_absent_install(
            dir.as_fd(),
            OsStr::new("mempool.key"),
            &target,
            &mut readiness_output,
        )
        .is_err());
        drop(readiness_output);
        let mut readiness_input = File::from(read_end);
        let mut byte = [0_u8; 1];
        assert_eq!(readiness_input.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn absent_only_gate_signals_exact_readiness_byte() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("genesis.key");
        let dir = open_test_directory(directory.path());
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        let mut readiness_output = File::from(write_end);
        prepare_absent_install(
            dir.as_fd(),
            OsStr::new("genesis.key"),
            &target,
            &mut readiness_output,
        )
        .unwrap();
        drop(readiness_output);
        let mut readiness_input = File::from(read_end);
        let mut bytes = Vec::new();
        readiness_input.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"R");
    }
}
