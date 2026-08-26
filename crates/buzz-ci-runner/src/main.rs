use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use buzz_ci_runner::config::RunnerConfig;
use serde_json::json;

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
            Ok(config) => {
                log(json!({
                    "level": "info",
                    "event": "runner_config_loaded",
                    "schema_version": config.schema_version,
                }));
                log(json!({
                    "level": "error",
                    "error": "controld_contract_unavailable",
                }));
                ExitCode::from(4)
            }
            Err(error) => {
                log(json!({
                    "level": "error",
                    "error": "invalid_runner_config",
                    "message": error.to_string(),
                }));
                ExitCode::from(1)
            }
        },
        Err(()) => {
            log(json!({"level": "error", "error": "invalid_arguments"}));
            ExitCode::from(1)
        }
    }
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
