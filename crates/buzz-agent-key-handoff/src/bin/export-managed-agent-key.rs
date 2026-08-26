#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{
    harden_process, parse_public_key_hex, parse_unique_string_map, require_anonymous_pipe,
    validate_secret_binding,
};
use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
use rustix::process::getuid;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn parse_args() -> Result<String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--pubkey" {
        bail!("usage: export-managed-agent-key --pubkey HEX");
    }
    parse_public_key_hex(&args[1])
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
    let uid = getuid().as_raw();
    let path = format!("/tmp/buzz-keychain-{uid}-buzz-desktop.lock");
    let fd = open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("open Buzz keyring lock")?;
    let file = File::from(fd);
    normalize_lock_mode(&file, uid)?;
    flock(file.as_fd(), FlockOperation::LockShared).context("lock Buzz keyring")?;
    Ok(file)
}

fn main() -> Result<()> {
    harden_process()?;
    let pubkey = parse_args()?;
    let stdout = io::stdout();
    require_anonymous_pipe(stdout.as_fd())?;
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
    let mut output = stdout.lock();
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
        normalize_lock_mode(file, getuid().as_raw()).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn rejects_writable_lock_modes() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let file = named.as_file();
        file.set_permissions(std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(normalize_lock_mode(file, getuid().as_raw()).is_err());
    }
}
