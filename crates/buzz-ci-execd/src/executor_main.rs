#![deny(unsafe_code)]

use std::{os::fd::FromRawFd, os::unix::net::UnixListener, process::ExitCode};

const SYSTEMD_LISTEN_FD: i32 = 3;

#[allow(unsafe_code)]
fn adopt_listener() -> UnixListener {
    // SAFETY: startup validates the exact systemd descriptor contract before
    // adopting the sole listener at fd 3 exactly once.
    unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) }
}

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            println!("buzz-ci-executor {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [arg] if arg == "--socket-activation" => {
            if std::env::var("LISTEN_PID")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                != Some(std::process::id())
                || std::env::var("LISTEN_FDS").as_deref() != Ok("1")
                || std::env::var("LISTEN_FDNAMES").as_deref() != Ok("buzz-ci-executor")
            {
                eprintln!(r#"{{"error":"socket_activation"}}"#);
                return ExitCode::from(4);
            }
            match buzz_ci_execd::production_v2::run_executor_service(adopt_listener()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!(r#"{{"error":"executor","reason":"{error}"}}"#);
                    ExitCode::from(4)
                }
            }
        }
        _ => {
            eprintln!(r#"{{"error":"usage","expected":"--version|--socket-activation"}}"#);
            ExitCode::from(1)
        }
    }
}
