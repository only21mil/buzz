#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{
    harden_process, parity_signature, parse_public_key_hex, require_anonymous_pipe, Slug,
};
use rustix::pipe::{pipe_with, PipeFlags};
use rustix::process::getuid;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};

const EXPORTER: &str = "/usr/local/libexec/buzz/export-managed-agent-key";
const RECEIVER: &str = "/usr/local/sbin/buzz-install-agent-key";

fn spawn_and_drop_command(mut command: Command) -> io::Result<Child> {
    command.spawn()
}

fn set_keyring_environment(command: &mut Command) {
    let runtime_dir = format!("/run/user/{}", getuid().as_raw());
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

fn verify_parity_envelope(args: &[String]) -> Result<()> {
    if args.len() != 2 || args[0] != "--owner-pubkey" {
        bail!("usage: buzz-agent-key-handoff verify-parity-envelope --owner-pubkey HEX");
    }
    let owner_pubkey = parse_public_key_hex(&args[1])?;
    require_anonymous_pipe(io::stdin().as_fd())?;
    let mut envelope = Vec::new();
    io::stdin()
        .take(512 * 1024 + 1)
        .read_to_end(&mut envelope)?;
    parity_signature::verify_envelope(&envelope, &owner_pubkey)
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
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("verify-parity-envelope") {
        return verify_parity_envelope(&arguments[1..]);
    }
    let (slug, pubkey) = parse_args()?;
    let (secret_read, secret_write) =
        pipe_with(PipeFlags::CLOEXEC).context("create secret pipe")?;

    let mut receiver = {
        let mut receiver_command = Command::new("/usr/bin/sudo");
        receiver_command.env_clear().env("PATH", "/usr/bin:/bin");
        receiver_command
            .args(["-n", RECEIVER, "install", "--slug", slug.as_str()])
            .stdin(Stdio::from(secret_read))
            .stdout(Stdio::piped());
        spawn_and_drop_command(receiver_command)
    }
    .context("start receiver")?;
    let mut readiness = match receiver.stdout.take() {
        Some(readiness) => readiness,
        None => {
            drop(secret_write);
            let _ = receiver.wait();
            bail!("capture receiver readiness");
        }
    };

    let mut exporter = match after_receiver_ready(&mut readiness, || {
        let mut exporter_command = Command::new(EXPORTER);
        set_keyring_environment(&mut exporter_command);
        exporter_command
            .args(["--pubkey", &pubkey])
            .stdin(Stdio::null())
            .stdout(Stdio::from(secret_write));
        exporter_command.spawn().context("start exporter")
    }) {
        Ok(child) => child,
        Err(error) => {
            let _ = receiver.wait();
            return Err(error);
        }
    };

    let exporter_status = exporter.wait().context("wait for exporter");
    let receiver_status = receiver.wait().context("wait for receiver");
    let exporter_status = exporter_status?;
    let receiver_status = receiver_status?;
    if !exporter_status.success() || !receiver_status.success() {
        bail!("managed-agent key handoff failed");
    }
    println!("INSTALLED {}", slug.as_str());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Cursor, Write};

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
    fn scoped_receiver_command_releases_parent_pipe_endpoint() {
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        let mut receiver_command = Command::new("/bin/true");
        receiver_command.stdin(Stdio::from(read_end));
        let mut receiver = spawn_and_drop_command(receiver_command).unwrap();
        assert!(receiver.wait().unwrap().success());

        let mut writer = File::from(write_end);
        let error = writer.write_all(b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn owned_fd_stdio_pipeline_transfers_bytes() {
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::from(read_end))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut writer = File::from(write_end);
        writer.write_all(b"pipe-owned\n").unwrap();
        drop(writer);
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(output, b"pipe-owned\n");
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

    #[test]
    fn invalid_readiness_does_not_start_exporter() {
        let started = Cell::new(false);
        let mut readiness = Cursor::new(b"X".to_vec());
        let result = after_receiver_ready(&mut readiness, || {
            started.set(true);
            Ok(())
        });
        assert!(result.is_err());
        assert!(!started.get());
    }
}
