#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{harden_process, parse_public_key_hex, Slug};
use std::io;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const EXPORTER: &str = "/usr/local/libexec/buzz/export-managed-agent-key";
const RECEIVER: &str = "/usr/local/sbin/buzz-install-agent-key";
const SECRET_FD: RawFd = 3;
const READY_FD: RawFd = 4;

fn set_keyring_environment(command: &mut Command) {
    let uid = unsafe { libc::getuid() };
    let runtime_dir = format!("/run/user/{uid}");
    command.env_clear();
    command
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_dir}/bus"),
        );
}

fn parse_args() -> Result<(Slug, String)> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--slug" || args[2] != "--pubkey" {
        bail!("usage: buzz-agent-key-handoff --slug SLUG --pubkey HEX");
    }
    Ok((Slug::parse(&args[1])?, parse_public_key_hex(&args[3])?))
}

unsafe fn install_child_fd(source_fd: RawFd, peer_fd: Option<RawFd>) -> io::Result<()> {
    if let Some(peer_fd) = peer_fd {
        if peer_fd != SECRET_FD && peer_fd != source_fd {
            libc::close(peer_fd);
        }
    }
    if source_fd != SECRET_FD {
        if libc::dup2(source_fd, SECRET_FD) < 0 {
            return Err(io::Error::last_os_error());
        }
        libc::close(source_fd);
    }
    if libc::fcntl(SECRET_FD, libc::F_SETFD, 0) < 0 {
        return Err(io::Error::last_os_error());
    }
    if libc::syscall(
        libc::SYS_close_range,
        4_u32,
        u32::MAX,
        libc::CLOSE_RANGE_CLOEXEC,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe fn install_receiver_fds(
    secret_fd: RawFd,
    ready_fd: RawFd,
    secret_peer_fd: RawFd,
    ready_peer_fd: RawFd,
) -> io::Result<()> {
    libc::close(secret_peer_fd);
    libc::close(ready_peer_fd);
    if secret_fd != SECRET_FD {
        if libc::dup2(secret_fd, SECRET_FD) < 0 {
            return Err(io::Error::last_os_error());
        }
        libc::close(secret_fd);
    }
    if ready_fd != READY_FD {
        if libc::dup2(ready_fd, READY_FD) < 0 {
            return Err(io::Error::last_os_error());
        }
        libc::close(ready_fd);
    }
    if libc::fcntl(SECRET_FD, libc::F_SETFD, 0) < 0
        || libc::fcntl(READY_FD, libc::F_SETFD, 0) < 0
    {
        return Err(io::Error::last_os_error());
    }
    if libc::syscall(
        libc::SYS_close_range,
        5_u32,
        u32::MAX,
        libc::CLOSE_RANGE_CLOEXEC,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn after_receiver_ready<R: Read, T>(
    readiness: &mut R,
    start_exporter: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mut ready = [0_u8; 1];
    readiness
        .read_exact(&mut ready)
        .context("wait for receiver readiness")?;
    if ready != *b"R" {
        bail!("invalid receiver readiness signal");
    }
    start_exporter()
}

fn main() -> Result<()> {
    harden_process()?;
    let (slug, pubkey) = parse_args()?;
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error()).context("create secret pipe");
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    let mut ready_fds = [0; 2];
    if unsafe { libc::pipe2(ready_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        close_fd(read_fd);
        close_fd(write_fd);
        return Err(io::Error::last_os_error()).context("create receiver readiness pipe");
    }
    let (ready_read_fd, ready_write_fd) = (ready_fds[0], ready_fds[1]);

    let mut receiver_command = Command::new("/usr/bin/sudo");
    receiver_command.env_clear().env("PATH", "/usr/bin:/bin");
    receiver_command
        .args([
            "-n",
            "-C",
            "5",
            RECEIVER,
            "install",
            "--slug",
            slug.as_str(),
            "--secret-fd",
            "3",
        ])
        .stdin(Stdio::null());
    unsafe {
        receiver_command.pre_exec(move || {
            install_receiver_fds(read_fd, ready_write_fd, write_fd, ready_read_fd)
        });
    }
    let mut receiver = match receiver_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            close_fd(read_fd);
            close_fd(write_fd);
            close_fd(ready_read_fd);
            close_fd(ready_write_fd);
            return Err(error).context("start receiver");
        }
    };
    close_fd(read_fd);
    close_fd(ready_write_fd);

    let mut readiness = unsafe { std::fs::File::from_raw_fd(ready_read_fd) };
    let mut exporter = match after_receiver_ready(&mut readiness, || {
        let mut exporter_command = Command::new(EXPORTER);
        set_keyring_environment(&mut exporter_command);
        exporter_command
            .args(["--pubkey", &pubkey, "--output-fd", "3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        unsafe {
            exporter_command.pre_exec(move || install_child_fd(write_fd, None));
        }
        exporter_command.spawn().context("start exporter")
    }) {
        Ok(child) => child,
        Err(error) => {
            close_fd(write_fd);
            let _ = receiver.wait();
            return Err(error);
        }
    };
    close_fd(write_fd);

    let exporter_status = exporter.wait().context("wait for exporter")?;
    let receiver_status = receiver.wait().context("wait for receiver")?;
    if !exporter_status.success() || !receiver_status.success() {
        bail!("managed-agent key handoff failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::io::Cursor;

    #[test]
    fn exporter_environment_excludes_caller_secrets() {
        let mut command = Command::new("/bin/true");
        command.env("BUZZ_PRIVATE_KEY", "sentinel");
        set_keyring_environment(&mut command);
        let environment: Vec<_> = command.get_envs().collect();
        assert!(environment
            .iter()
            .all(|(name, _)| *name != OsStr::new("BUZZ_PRIVATE_KEY")));
        assert!(environment
            .iter()
            .any(|(name, _)| *name == OsStr::new("DBUS_SESSION_BUS_ADDRESS")));
        assert!(environment
            .iter()
            .any(|(name, _)| *name == OsStr::new("XDG_RUNTIME_DIR")));
    }

    #[test]
    fn child_fd_install_handles_source_equal_to_three() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let saved = unsafe { libc::dup(SECRET_FD) };
        unsafe {
            libc::dup2(fds[0], SECRET_FD);
            assert!(install_child_fd(SECRET_FD, Some(fds[1])).is_ok());
            assert_eq!(libc::fcntl(SECRET_FD, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            libc::close(SECRET_FD);
            if saved >= 0 {
                libc::dup2(saved, SECRET_FD);
                libc::close(saved);
            }
        }
    }

    #[test]
    fn absent_only_ordering_does_not_start_exporter_without_readiness() {
        let started = Cell::new(false);
        let mut readiness = Cursor::new(Vec::<u8>::new());
        let result = after_receiver_ready(&mut readiness, || {
            started.set(true);
            Ok(())
        });
        assert!(result.is_err());
        assert!(!started.get());
    }
}
