#![deny(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::os::{fd::FromRawFd, unix::net::UnixListener};

#[cfg(target_os = "linux")]
use buzz_ci_keyholder::{
    acceptance_signing_policy, serve_connection, validate_systemd_environment,
    validate_systemd_listener, AcceptanceBindingReceipt, KeyholderConfig, ProductionKeyholder,
    Secp256k1Backend, SigningPolicy, SYSTEMD_LISTEN_FD,
};

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
            println!("usage: buzz-ci-keyholder --config <public-json-file>");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("buzz-ci-keyholder {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Command::Run { config_path }) => run(config_path),
        Err(()) => {
            eprintln!(r#"{{"error":"invalid_arguments"}}"#);
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(config_path: PathBuf) -> ExitCode {
    if harden_process().is_err() {
        eprintln!(r#"{{"error":"process_hardening"}}"#);
        return ExitCode::from(4);
    }
    if validate_systemd_environment().is_err() {
        eprintln!(r#"{{"error":"socket_activation"}}"#);
        return ExitCode::from(4);
    }
    let listener = match validate_systemd_listener(adopt_systemd_listener()) {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!(r#"{{"error":"socket_activation"}}"#);
            return ExitCode::from(4);
        }
    };
    let config = match KeyholderConfig::load(&config_path) {
        Ok(config) => config,
        Err(_) => {
            eprintln!(r#"{{"error":"invalid_config"}}"#);
            return ExitCode::from(1);
        }
    };
    let credentials_directory = match std::env::var_os("CREDENTIALS_DIRECTORY") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            eprintln!(r#"{{"error":"credentials_unavailable"}}"#);
            return ExitCode::from(4);
        }
    };
    let acceptance_policy = match config.acceptance.as_ref() {
        Some(acceptance) => {
            let receipt = match AcceptanceBindingReceipt::load(&acceptance.binding_receipt_path) {
                Ok(receipt) => receipt,
                Err(_) => {
                    eprintln!(r#"{{"error":"invalid_acceptance_binding"}}"#);
                    return ExitCode::from(4);
                }
            };
            if (receipt.peer_uid, receipt.peer_gid)
                != (config.peer_policy.uid, config.peer_policy.gid)
            {
                eprintln!(r#"{{"error":"invalid_acceptance_binding"}}"#);
                return ExitCode::from(4);
            }
            match acceptance_signing_policy(&receipt) {
                Ok(policy) => Some(policy),
                Err(_) => {
                    eprintln!(r#"{{"error":"invalid_acceptance_binding"}}"#);
                    return ExitCode::from(4);
                }
            }
        }
        None => None,
    };
    let backend_result = if acceptance_policy.is_some() {
        Secp256k1Backend::from_systemd_credentials_with_acceptance(&credentials_directory)
    } else {
        Secp256k1Backend::from_systemd_credentials(&credentials_directory)
    };
    let backend = match backend_result {
        Ok(backend) => backend,
        Err(_) => {
            eprintln!(r#"{{"error":"credentials_unavailable"}}"#);
            return ExitCode::from(4);
        }
    };
    let policy_result = match acceptance_policy {
        Some(acceptance) => SigningPolicy::new_with_acceptance(
            config.peer_policy,
            config.selectors,
            config.nip98_origin,
            acceptance,
        ),
        None => SigningPolicy::new(config.peer_policy, config.selectors, config.nip98_origin),
    };
    let policy = match policy_result {
        Ok(policy) => policy,
        Err(_) => {
            eprintln!(r#"{{"error":"invalid_config"}}"#);
            return ExitCode::from(1);
        }
    };
    let service = match ProductionKeyholder::new(policy, backend) {
        Ok(service) => service,
        Err(_) => {
            eprintln!(r#"{{"error":"credentials_unavailable"}}"#);
            return ExitCode::from(4);
        }
    };
    eprintln!(r#"{{"event":"keyholder_ready","schema_version":1}}"#);
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(_) => {
                eprintln!(r#"{{"error":"accept_failed"}}"#);
                return ExitCode::from(4);
            }
        };
        if serve_connection(stream, &service).is_err() {
            eprintln!(r#"{{"event":"connection_rejected"}}"#);
        }
    }
}

#[cfg(target_os = "linux")]
fn harden_process() -> Result<(), rustix::io::Errno> {
    use rustix::mm::{mlockall, MlockAllFlags};
    use rustix::process::{set_dumpable_behavior, setrlimit, DumpableBehavior, Resource, Rlimit};

    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)
}

#[cfg(not(target_os = "linux"))]
fn run(_config_path: PathBuf) -> ExitCode {
    eprintln!(r#"{{"error":"unsupported_platform"}}"#);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_help_version_or_one_config_path() {
        assert!(matches!(
            command(["keyholder", "--help"].map(OsString::from)),
            Ok(Command::Help)
        ));
        assert!(matches!(
            command(["keyholder", "--config", "/config"].map(OsString::from)),
            Ok(Command::Run { .. })
        ));
        assert!(command(["keyholder"].map(OsString::from)).is_err());
        assert!(command(["keyholder", "--config"].map(OsString::from)).is_err());
    }
}
