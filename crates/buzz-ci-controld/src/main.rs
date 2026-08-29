#![forbid(unsafe_code)]

mod config;
mod service;

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use thiserror::Error;

use crate::config::DaemonConfig;
use crate::service::CapacityZeroService;

fn main() {
    if let Err(error) = run() {
        eprintln!("buzz-ci-controld: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), StartupError> {
    let config_path = parse_args(env::args_os())?;
    let owner_uid = effective_uid()?;
    let config = DaemonConfig::load(&config_path, owner_uid)?;
    let service = CapacityZeroService::start(&config, owner_uid)?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &service.status()).map_err(|_| StartupError::Status)?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|_| StartupError::Status)?;
    drop(stdout);
    service.run()
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
