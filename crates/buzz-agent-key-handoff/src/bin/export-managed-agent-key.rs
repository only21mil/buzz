#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{
    harden_process, parse_public_key_hex, parse_unique_string_map, require_anonymous_pipe,
    validate_secret_binding,
};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

fn parse_args() -> Result<(String, RawFd)> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--pubkey" || args[2] != "--output-fd" {
        bail!("usage: export-managed-agent-key --pubkey HEX --output-fd FD");
    }
    Ok((
        parse_public_key_hex(&args[1])?,
        args[3].parse().context("invalid output fd")?,
    ))
}

fn normalize_lock_mode(file: &File, uid: u32) -> Result<()> {
    let meta = file.metadata().context("stat Buzz keyring lock")?;
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.nlink() != 1
        || !matches!(meta.permissions().mode() & 0o777, 0o600 | 0o640 | 0o644)
    {
        bail!("unsafe Buzz keyring lock metadata");
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("restrict Buzz keyring lock mode")?;
    let restricted = file.metadata().context("re-stat Buzz keyring lock")?;
    if restricted.uid() != uid
        || restricted.nlink() != 1
        || restricted.permissions().mode() & 0o777 != 0o600
    {
        bail!("Buzz keyring lock mode did not normalize safely");
    }
    Ok(())
}

fn lock_keyring() -> Result<File> {
    let uid = unsafe { libc::getuid() };
    let path = format!("/tmp/buzz-keychain-{uid}-buzz-desktop.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("open Buzz keyring lock")?;
    normalize_lock_mode(&file, uid)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error()).context("lock Buzz keyring");
    }
    Ok(file)
}

fn main() -> Result<()> {
    harden_process()?;
    let (pubkey, output_fd) = parse_args()?;
    require_anonymous_pipe(output_fd)?;
    let _lock = lock_keyring()?;
    let entry = keyring::Entry::new("buzz-desktop", "secrets")
        .context("open Buzz Desktop keyring entry")?;
    let blob = zeroize::Zeroizing::new(
        entry
            .get_password()
            .context("read Buzz Desktop keyring entry")?,
    );
    let mut secrets = parse_unique_string_map(&blob)?;
    let nsec = secrets
        .0
        .remove(&format!("agent:{pubkey}"))
        .context("requested managed-agent key is absent")?;
    let secret_hex = validate_secret_binding(&nsec, &pubkey)?;
    let mut output = unsafe { File::from_raw_fd(output_fd) };
    output
        .write_all(secret_hex.as_bytes())
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .context("write managed-agent key to pipe")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_desktop_compatible_lock_modes() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let file = named.as_file();
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        normalize_lock_mode(file, unsafe { libc::getuid() }).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn rejects_writable_lock_modes() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let file = named.as_file();
        file.set_permissions(std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(normalize_lock_mode(file, unsafe { libc::getuid() }).is_err());
    }
}
