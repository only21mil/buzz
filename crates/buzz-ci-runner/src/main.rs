#![deny(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::os::{fd::FromRawFd, unix::net::UnixListener};

use buzz_ci_runner::config::RunnerConfig;
#[cfg(target_os = "linux")]
use buzz_ci_runner::host::ConfiguredRunner;
#[cfg(target_os = "linux")]
use buzz_ci_runner::service::{
    serve_runner_connection, serve_runner_connection_with_handler, validate_systemd_environment,
    validate_systemd_listener,
};
#[cfg(target_os = "linux")]
use buzz_ci_runner::transport::SYSTEMD_LISTEN_FD;
use serde_json::json;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn adopt_systemd_listener() -> UnixListener {
    // SAFETY: the caller validates the current PID, sole descriptor count,
    // and exact descriptor name first. The systemd ABI assigns that listener
    // to fd 3, which this process adopts once.
    unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) }
}

fn main() -> ExitCode {
    match command(std::env::args_os()) {
        Ok(Command::Help) => {
            println!("usage: buzz-ci-runner --config <mode-0600-json-file>");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("buzz-ci-runner {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Command::Run { config_path }) => match RunnerConfig::load(&config_path) {
            Ok(config) => run(config),
            Err(error) => {
                log(json!({
                    "level": "error",
                    "error": "invalid_runner_config",
                    "message": error.to_string(),
                }));
                ExitCode::from(1)
            }
        },
        Err(_) => {
            log(json!({"level": "error", "error": "invalid_arguments"}));
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(config: RunnerConfig) -> ExitCode {
    if let Err(error) = validate_systemd_environment() {
        log(json!({
            "level": "error",
            "error": "socket_activation",
            "message": error.to_string(),
        }));
        return ExitCode::from(4);
    }
    let listener = match validate_systemd_listener(adopt_systemd_listener()) {
        Ok(listener) => listener,
        Err(error) => {
            log(json!({
                "level": "error",
                "error": "socket_activation",
                "message": error.to_string(),
            }));
            return ExitCode::from(4);
        }
    };
    let mut configured = match config.host.as_ref().map(ConfiguredRunner::new).transpose() {
        Ok(configured) => configured,
        Err(_) => {
            log(json!({"level": "error", "error": "invalid_runner_host"}));
            return ExitCode::from(1);
        }
    };
    log(json!({
        "level": "info",
        "event": "runner_ready",
        "schema_version": config.schema_version,
    }));
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                log(json!({
                    "level": "error",
                    "error": "runner_accept_failed",
                    "message": error.to_string(),
                }));
                return ExitCode::from(4);
            }
        };
        let result = match configured.as_mut() {
            Some(handler) => serve_runner_connection_with_handler(
                stream,
                config.controld_uid,
                &mut |request, writer| handler.handle(request, writer).map_err(|_| ()),
            ),
            None => serve_runner_connection(stream, config.controld_uid),
        };
        if let Err(error) = result {
            log(json!({
                "level": "warn",
                "event": "runner_connection_rejected",
                "message": error.to_string(),
            }));
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_config: RunnerConfig) -> ExitCode {
    log(json!({"level": "error", "error": "unsupported_platform"}));
    ExitCode::from(4)
}

enum Command {
    Help,
    Version,
    Run { config_path: PathBuf },
}

fn command(args: impl IntoIterator<Item = OsString>) -> Result<Command, ()> {
    let mut args = args.into_iter();
    let _program = args.next();
    match (args.next(), args.next(), args.next()) {
        (Some(arg), None, None) if arg == "--help" || arg == "-h" => Ok(Command::Help),
        (Some(arg), None, None) if arg == "--version" => Ok(Command::Version),
        (Some(flag), Some(path), None) if flag == "--config" && !path.is_empty() => {
            Ok(Command::Run {
                config_path: PathBuf::from(path),
            })
        }
        _ => Err(()),
    }
}

fn log(value: serde_json::Value) {
    eprintln!("{value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_help_version_or_config_path() {
        assert!(matches!(
            command(["runner", "--help"].map(OsString::from)),
            Ok(Command::Help)
        ));
        assert!(matches!(
            command(["runner", "--config", "/config"].map(OsString::from)),
            Ok(Command::Run { .. })
        ));
        assert!(command(["runner"].map(OsString::from)).is_err());
        assert!(command(["runner", "--config"].map(OsString::from)).is_err());
    }
}
