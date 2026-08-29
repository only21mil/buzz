#![deny(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use std::os::{fd::FromRawFd, unix::net::UnixListener};

#[cfg(target_os = "linux")]
use buzz_ci_execd::control::{
    validate_systemd_environment, validate_systemd_listener, ControlError, ControlServer,
};
#[cfg(target_os = "linux")]
use buzz_ci_execd::materializer_handoff::run_materializer_handoff_service;
#[cfg(target_os = "linux")]
use buzz_ci_execd::production_composition::load_production_dispatch;

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
    let args = args.collect::<Vec<_>>();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            println!("buzz-ci-execd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [arg] if arg == "--self-check" => match buzz_ci_execd::self_check() {
            Ok(()) => {
                println!(r#"{{"status":"not_provisioned","capacity":0}}"#);
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!(r#"{{"error":"self_check_failed","reason":"{reason}"}}"#);
                ExitCode::from(4)
            }
        },
        [arg] if arg == "--socket-activation" => {
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
                let startup_now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs(),
                    Err(_) => {
                        eprintln!(r#"{{"error":"system_clock"}}"#);
                        return ExitCode::from(4);
                    }
                };
                let runtime = match load_production_dispatch(startup_now) {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!(r#"{{"error":"production_v2","reason":"{error:?}"}}"#);
                        return ExitCode::from(4);
                    }
                };
                let mut server = match ControlServer::new_polling(
                    listener,
                    runtime.peer_policy,
                    runtime.dispatch,
                ) {
                    Ok(server) => server,
                    Err(error) => {
                        eprintln!(r#"{{"error":"control_listener","reason":"{error}"}}"#);
                        return ExitCode::from(4);
                    }
                };
                loop {
                    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            eprintln!(r#"{{"error":"system_clock"}}"#);
                            return ExitCode::from(4);
                        }
                    };
                    match server.serve_tick(now) {
                        Ok(()) => thread::sleep(Duration::from_millis(100)),
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
        #[cfg(target_os = "linux")]
        [mode, socket] if mode == "--materializer-handoff" => {
            let Some(socket) = socket
                .to_str()
                .and_then(|value| value.strip_prefix("--socket="))
            else {
                eprintln!(
                    r#"{{"error":"usage","expected":"--materializer-handoff --socket=/run/<unit>/materializer.sock"}}"#
                );
                return ExitCode::from(1);
            };
            match run_materializer_handoff_service(std::path::Path::new(socket)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!(r#"{{"error":"materializer_handoff","reason":"{error}"}}"#);
                    ExitCode::from(4)
                }
            }
        }
        _ => {
            eprintln!(
                r#"{{"error":"usage","expected":"--version|--self-check|--socket-activation|--materializer-handoff --socket=/run/<unit>/materializer.sock"}}"#
            );
            ExitCode::from(1)
        }
    }
}
