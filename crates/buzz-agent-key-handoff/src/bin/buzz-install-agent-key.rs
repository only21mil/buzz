#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{
    exact_secret_line, harden_process, parse_enrollment_map, require_anonymous_pipe,
    validate_secret_binding, Slug, MAX_ENROLLMENT_MAP_BYTES,
};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const MAP_PATH: &str = "/etc/buzz-agents/enrollment-keys.json";
const CREDENTIAL_DIR: &str = "/etc/buzz-agents/credentials";

fn parse_args() -> Result<(Slug, RawFd)> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 || args[0] != "install" || args[1] != "--slug" || args[3] != "--secret-fd" {
        bail!("usage: buzz-install-agent-key install --slug SLUG --secret-fd 3");
    }
    let fd: RawFd = args[4].parse().context("invalid secret fd")?;
    if fd != 3 {
        bail!("secret fd must be 3");
    }
    Ok((Slug::parse(&args[2])?, fd))
}

fn require_secure_regular(file: &File, path: &Path, mode: u32) -> Result<fs::Metadata> {
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != mode
    {
        bail!("unsafe metadata: {}", path.display());
    }
    Ok(metadata)
}

fn open_secure_regular(path: &Path, mode: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    require_secure_regular(&file, path, mode)?;
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
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .context("open enrollment lock")?;
    require_secure_regular(&file, Path::new(&path), 0o600)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("lock enrollment");
    }
    Ok(file)
}

fn read_secret(fd: RawFd) -> Result<Zeroizing<String>> {
    require_anonymous_pipe(fd)?;
    let mut input = unsafe { File::from_raw_fd(fd) };
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(66));
    std::io::Read::by_ref(&mut input)
        .take(66)
        .read_to_end(&mut bytes)
        .context("read secret")?;
    exact_secret_line(&bytes)
}

fn verify_existing(path: &Path, content: &[u8]) -> Result<bool> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    require_secure_regular(&file, path, 0o600)?;
    let mut data = zeroize::Zeroizing::new(Vec::with_capacity(66));
    std::io::Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut data)
        .context("read existing credential")?;
    if data.as_slice() != content {
        bail!("credential exists with different content");
    }
    Ok(true)
}

fn require_secure_credential_dir(path: &Path) -> Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open credential directory");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().context("stat credential directory")?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("unsafe credential directory");
    }
    Ok(file)
}

fn rollback_same_inode(dir_fd: RawFd, name: &CString, dev: u64, ino: u64) {
    let fd = unsafe {
        libc::openat(
            dir_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return;
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if let Ok(metadata) = file.metadata() {
        if metadata.dev() == dev && metadata.ino() == ino && metadata.nlink() == 1 {
            unsafe {
                libc::unlinkat(dir_fd, name.as_ptr(), 0);
                libc::fsync(dir_fd);
            }
        }
    }
}

fn install_absent(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().context("credential target has no parent")?;
    let dir = require_secure_credential_dir(parent)?;
    let dot = CString::new(".")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create anonymous credential");
    }
    let mut temporary = unsafe { File::from_raw_fd(fd) };
    temporary.write_all(content).context("write credential")?;
    if unsafe { libc::fchown(temporary.as_raw_fd(), 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("own credential");
    }
    if unsafe { libc::fchmod(temporary.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error()).context("mode credential");
    }
    temporary.sync_all().context("sync credential")?;
    let temporary_metadata = temporary.metadata().context("stat anonymous credential")?;
    let empty = CString::new("")?;
    let name = CString::new(
        path.file_name()
            .context("credential target has no name")?
            .as_bytes(),
    )?;
    if unsafe {
        libc::linkat(
            temporary.as_raw_fd(),
            empty.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(error).context("publish credential");
    }
    if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
        let error = std::io::Error::last_os_error();
        rollback_same_inode(
            dir.as_raw_fd(),
            &name,
            temporary_metadata.dev(),
            temporary_metadata.ino(),
        );
        return Err(error).context("sync credential directory");
    }
    Ok(())
}

fn main() -> Result<()> {
    harden_process()?;
    if unsafe { libc::geteuid() } != 0 {
        bail!("receiver must run as root");
    }
    let (slug, fd) = parse_args()?;
    let _lock = lock_slug(slug)?;
    let expected = expected_pubkey(slug)?;
    let secret = read_secret(fd)?;
    let secret_hex = validate_secret_binding(&secret, &expected)?;
    let mut content = Zeroizing::new(secret_hex.as_bytes().to_vec());
    content.push(b'\n');
    let target = Path::new(CREDENTIAL_DIR).join(format!("{}.key", slug.as_str()));
    if verify_existing(&target, &content)? {
        println!("ALREADY_PRESENT {}", slug.as_str());
        return Ok(());
    }
    install_absent(&target, &content)?;
    if !verify_existing(&target, &content)? {
        bail!("credential readback failed");
    }
    println!("INSTALLED {}", slug.as_str());
    Ok(())
}
