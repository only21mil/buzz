#![deny(unsafe_code)]

use std::{os::fd::FromRawFd, os::unix::net::UnixListener, process::ExitCode};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};

const SYSTEMD_LISTEN_FD: i32 = 3;

#[allow(unsafe_code)]
fn adopt_listener() -> UnixListener {
    // SAFETY: startup validates the exact systemd descriptor contract before
    // adopting the sole listener at fd 3 exactly once.
    unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) }
}

fn seal_listener(listener: UnixListener) -> Result<UnixListener, ()> {
    let flags = fcntl(&listener, FcntlArg::F_GETFD).map_err(|_| ())?;
    let flags = FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC;
    fcntl(&listener, FcntlArg::F_SETFD(flags)).map_err(|_| ())?;
    Ok(listener)
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
            let listener = match seal_listener(adopt_listener()) {
                Ok(listener) => listener,
                Err(()) => {
                    eprintln!(r#"{{"error":"socket_activation"}}"#);
                    return ExitCode::from(4);
                }
            };
            match buzz_ci_execd::production_v2::run_executor_service(listener) {
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

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::process::Command;

    use super::*;

    #[test]
    fn executor_listener_is_closed_across_fixture_exec() {
        let root = tempfile::tempdir().expect("socket root");
        let listener = UnixListener::bind(root.path().join("executor.sock")).expect("listener");
        fcntl(&listener, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear close-on-exec");
        let listener = seal_listener(listener).expect("seal listener");
        let flags = fcntl(&listener, FcntlArg::F_GETFD).expect("listener flags");
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
        let fd = listener.as_raw_fd().to_string();
        let status = Command::new("/bin/sh")
            .args(["-c", "test ! -e /proc/self/fd/$1", "fixture", &fd])
            .status()
            .expect("fixture probe");
        assert!(status.success());
    }
}
