#![deny(unsafe_code)]

mod config;
mod service;

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use thiserror::Error;

use buzz_ci_controld::acceptance_socket::{
    serve_connection, validate_systemd_environment, validate_systemd_listener, AcceptanceBinding,
    AcceptanceSocketError, SYSTEMD_LISTEN_FD,
};
use buzz_ci_controld::controller::CapacityOneStatus;

use crate::config::DaemonConfig;
use crate::service::{CapacityOneService, CapacityZeroService};

fn main() {
    if let Err(error) = run() {
        eprintln!("buzz-ci-controld: {error}");
        std::process::exit(1);
    };
}

fn run() -> Result<(), StartupError> {
    let config_path = parse_args(env::args_os())?;
    let owner_uid = effective_uid()?;
    let config = DaemonConfig::load(&config_path, owner_uid)?;
    let acceptance_binding = match config.acceptance_binding() {
        Some(path) => {
            Some(AcceptanceBinding::load(path).map_err(|_| AcceptanceSocketError::Binding)?)
        }
        None => None,
    };
    let listener = acceptance_listener(
        acceptance_binding
            .as_ref()
            .map(|binding| binding.acceptance_peer_gid),
    )?;
    if config.active().is_none() {
        let mut service = CapacityZeroService::start(&config, owner_uid, acceptance_binding)?;
        report_status(&service.status())?;
        return match listener {
            Some(listener) => run_capacity_zero(listener, &mut service),
            None => service.run(),
        };
    }
    let mut service = match CapacityOneService::start(&config, owner_uid, acceptance_binding) {
        Ok(service) => service,
        Err(error) => {
            report_status(&CapacityOneStatus::startup_failure(error.terminal_reason()))?;
            return Err(StartupError::Service(error));
        }
    };
    report_status(&service.status())?;
    let listener = listener.ok_or(StartupError::Acceptance(AcceptanceSocketError::Activation))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| StartupError::Acceptance(AcceptanceSocketError::Activation))?;
    let mut next_poll = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let (uid, gid, timeout) = service.acceptance_credentials();
                if let Err(error) = serve_connection(stream, uid, gid, timeout, &mut service) {
                    if error == AcceptanceSocketError::Operation {
                        report_status(&CapacityOneStatus::startup_failure(
                            buzz_ci_controld::controller::TerminalInfrastructureReason::State,
                        ))?;
                        return Err(StartupError::Acceptance(error));
                    }
                    eprintln!("buzz-ci-controld: acceptance request rejected: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {
                return Err(StartupError::Acceptance(AcceptanceSocketError::Transport));
            }
        }
        let now = Instant::now();
        if now >= next_poll {
            if let Err(error) = service.poll_once() {
                report_status(&service.status())?;
                return Err(StartupError::Controller(error));
            }
            report_status(&service.status())?;
            next_poll = now + service.poll_interval();
        }
        std::thread::sleep(
            next_poll
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(25)),
        );
    }
}

fn run_capacity_zero(
    listener: UnixListener,
    service: &mut CapacityZeroService,
) -> Result<(), StartupError> {
    let (uid, gid, timeout) = service
        .acceptance_credentials()
        .ok_or(StartupError::Acceptance(AcceptanceSocketError::Activation))?;
    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|_| StartupError::Acceptance(AcceptanceSocketError::Transport))?;
        if let Err(error) = serve_connection(stream, uid, gid, timeout, service) {
            eprintln!("buzz-ci-controld: acceptance request rejected: {error}");
        }
    }
}

#[cfg(target_os = "linux")]
fn acceptance_listener(
    expected_group_gid: Option<u32>,
) -> Result<Option<UnixListener>, StartupError> {
    let Some(expected_group_gid) = expected_group_gid else {
        if std::env::var_os("LISTEN_FDS").is_some()
            || std::env::var_os("LISTEN_FDNAMES").is_some()
            || std::env::var_os("LISTEN_PID").is_some()
        {
            return Err(StartupError::Acceptance(AcceptanceSocketError::Activation));
        }
        return Ok(None);
    };
    validate_systemd_environment()?;
    let listener = adopt_systemd_listener();
    Ok(Some(validate_systemd_listener(
        listener,
        expected_group_gid,
    )?))
}

/// systemd owns descriptor 3 until this process adopts it. Environment and
/// socket identity are validated immediately before and after this one transfer.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn adopt_systemd_listener() -> UnixListener {
    unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) }
}

#[cfg(not(target_os = "linux"))]
fn acceptance_listener(
    _expected_group_gid: Option<u32>,
) -> Result<Option<UnixListener>, StartupError> {
    Err(StartupError::UnsupportedPlatform)
}

fn report_status(status: &impl serde::Serialize) -> Result<(), StartupError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, status).map_err(|_| StartupError::Status)?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|_| StartupError::Status)?;
    Ok(())
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<PathBuf, StartupError> {
    let _program = args.next();
    let config_path = args.next().ok_or(StartupError::Usage)?;
    if args.next().is_some() {
        return Err(StartupError::Usage);
    }
    Ok(PathBuf::from(config_path))
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, StartupError> {
    Ok(nix::unistd::geteuid().as_raw())
}

#[cfg(not(target_os = "linux"))]
fn effective_uid() -> Result<u32, StartupError> {
    Err(StartupError::UnsupportedPlatform)
}

#[derive(Debug, Error)]
enum StartupError {
    #[error("usage: buzz-ci-controld /absolute/path/to/config.json")]
    Usage,
    #[cfg(not(target_os = "linux"))]
    #[error("controld is supported only on Linux")]
    UnsupportedPlatform,
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Service(#[from] service::ServiceError),
    #[error(transparent)]
    Controller(#[from] buzz_ci_controld::controller::ControllerError),
    #[error(transparent)]
    Acceptance(#[from] AcceptanceSocketError),
    #[error("failed to report service status")]
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_one_config_path() {
        let path = parse_args(
            ["buzz-ci-controld", "/etc/buzzci/controld.json"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("one argument");
        assert_eq!(path, PathBuf::from("/etc/buzzci/controld.json"));

        assert!(matches!(
            parse_args(["buzz-ci-controld"].into_iter().map(OsString::from)),
            Err(StartupError::Usage)
        ));
        assert!(matches!(
            parse_args(
                ["buzz-ci-controld", "one", "two"]
                    .into_iter()
                    .map(OsString::from)
            ),
            Err(StartupError::Usage)
        ));
    }
}
