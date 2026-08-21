#![deny(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::os::{fd::FromRawFd, unix::net::UnixListener};

#[cfg(target_os = "linux")]
use buzz_ci_execd::control::{
    control_account_uid, validate_systemd_environment, validate_systemd_listener, ControlError,
    ControlServer,
};
#[cfg(target_os = "linux")]
use buzz_ci_execd::durable_dispatch::{
    load_dispatch, UnavailableExecution, UnavailableReadyValidation,
};

#[cfg(target_os = "linux")]
const SYSTEMD_LISTEN_FD: i32 = 3;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn adopt_systemd_listener() -> UnixListener {
    // SAFETY: the caller first validates the exact PID, count, and descriptor
    // name. systemd's ABI assigns the sole inherited listener to fd 3, which
    // this process then owns exactly once.
    unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!("buzz-ci-execd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        (Some(arg), None) if arg == "--self-check" => match buzz_ci_execd::self_check() {
            Ok(()) => {
                println!(r#"{{"status":"not_provisioned","capacity":0}}"#);
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!(r#"{{"error":"self_check_failed","reason":"{reason}"}}"#);
                ExitCode::from(4)
            }
        },
        (Some(arg), None) if arg == "--socket-activation" => {
            let forbidden = buzz_ci_execd::FORBIDDEN_ENVIRONMENT_KEYS
                .iter()
                .copied()
                .find(|key| std::env::var_os(key).is_some());
            if let Some(key) = forbidden {
                eprintln!(r#"{{"error":"forbidden_environment","key":"{key}"}}"#);
                return ExitCode::from(4);
            }
            #[cfg(target_os = "linux")]
            {
                if let Err(error) = validate_systemd_environment() {
                    eprintln!(r#"{{"error":"socket_activation","reason":"{error}"}}"#);
                    return ExitCode::from(4);
                }
                let inherited = adopt_systemd_listener();
                let listener = match validate_systemd_listener(inherited) {
                    Ok(listener) => listener,
                    Err(error) => {
                        eprintln!(r#"{{"error":"socket_activation","reason":"{error}"}}"#);
                        return ExitCode::from(4);
                    }
                };
                let control_uid = match control_account_uid() {
                    Ok(uid) => uid,
                    Err(error) => {
                        eprintln!(r#"{{"error":"control_account","reason":"{error}"}}"#);
                        return ExitCode::from(4);
                    }
                };
                let startup_now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs(),
                    Err(_) => {
                        eprintln!(r#"{{"error":"system_clock"}}"#);
                        return ExitCode::from(4);
                    }
                };
                let mut validation = UnavailableReadyValidation;
                let dispatch = load_dispatch(
                    startup_now,
                    &mut validation,
                    UnavailableExecution,
                    UnavailableExecution,
                );
                let mut server = ControlServer::new(listener, control_uid, dispatch);
                loop {
                    match server.serve_once() {
                        Ok(()) => {}
                        Err(error @ ControlError::Accept(_)) => {
                            eprintln!(r#"{{"error":"control_listener","reason":"{error}"}}"#);
                            return ExitCode::from(4);
                        }
                        Err(error) => {
                            eprintln!(r#"{{"error":"control_connection","reason":"{error}"}}"#);
                        }
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!(r#"{{"error":"unsupported_platform"}}"#);
                ExitCode::from(4)
            }
        }
        _ => {
            eprintln!(
                r#"{{"error":"usage","expected":"--version|--self-check|--socket-activation"}}"#
            );
            ExitCode::from(1)
        }
    }
}
