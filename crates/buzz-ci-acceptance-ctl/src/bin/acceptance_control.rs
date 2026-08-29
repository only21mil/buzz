#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
};

#[cfg(target_os = "linux")]
use buzz_ci_acceptance_ctl::production::{
    handle_control_durable, AcceptanceControlConfig, ControlError, HostControl, SystemdHostControl,
    CONTROL_CONFIG_PATH, MAX_ADAPTER_FRAME_BYTES,
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorLine {
    schema_version: &'static str,
    code: &'static str,
    message: &'static str,
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = run() {
        emit_error(error);
        std::process::exit(4);
    }
    #[cfg(not(target_os = "linux"))]
    {
        emit_error(ControlError::InvalidConfig);
        std::process::exit(4);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), ControlError> {
    if std::env::args_os().len() != 1 {
        return Err(ControlError::InvalidConfig);
    }
    validate_systemd_environment()?;
    let config = AcceptanceControlConfig::load(Path::new(CONTROL_CONFIG_PATH))?;
    let mut host = SystemdHostControl::open(config.clone())?;
    let listener = adopt_listener();
    validate_listener(&listener)?;
    loop {
        let (stream, _) = listener.accept().map_err(|_| ControlError::HostAction)?;
        if serve_connection(stream, &config, &mut host).is_err() {
            let _ = host.emergency_capacity_zero();
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_systemd_environment() -> Result<(), ControlError> {
    let pid = std::process::id().to_string();
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(pid.as_str())
        || std::env::var("LISTEN_FDS").ok().as_deref() != Some("1")
        || std::env::var("LISTEN_FDNAMES").ok().as_deref() != Some("buzz-ci-acceptance-control")
    {
        return Err(ControlError::InvalidConfig);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn adopt_listener() -> UnixListener {
    // SAFETY: validate_systemd_environment proves systemd assigned the sole
    // named listener to descriptor 3. This function adopts it exactly once.
    unsafe { UnixListener::from_raw_fd(3) }
}

#[cfg(target_os = "linux")]
fn validate_listener(listener: &UnixListener) -> Result<(), ControlError> {
    let address = listener
        .local_addr()
        .map_err(|_| ControlError::InvalidConfig)?;
    if address.as_pathname() != Some(Path::new("/run/buzzci/acceptance-control.sock")) {
        return Err(ControlError::InvalidConfig);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_connection(
    mut stream: UnixStream,
    config: &AcceptanceControlConfig,
    host: &mut SystemdHostControl,
) -> Result<(), ControlError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let peer = getsockopt(&stream, PeerCredentials).map_err(|_| ControlError::BindingMismatch)?;
    if peer.uid() != config.qualification_uid || peer.gid() != config.qualification_gid {
        return Err(ControlError::BindingMismatch);
    }
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(300)))
        .and_then(|()| stream.set_write_timeout(Some(std::time::Duration::from_secs(300))))
        .map_err(|_| ControlError::HostAction)?;
    let mut request = Vec::new();
    std::io::Read::by_ref(&mut stream)
        .take(MAX_ADAPTER_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut request)
        .map_err(|_| ControlError::HostAction)?;
    if request.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(ControlError::BindingMismatch);
    }
    let response = handle_control_durable(config, &request, host)?;
    let bytes = serde_json::to_vec(&response).map_err(|_| ControlError::HostAction)?;
    if bytes.len() > MAX_ADAPTER_FRAME_BYTES {
        return Err(ControlError::HostAction);
    }
    stream
        .write_all(&bytes)
        .and_then(|()| stream.flush())
        .map_err(|_| ControlError::HostAction)
}

fn emit_error(error: ControlError) {
    let line = ErrorLine {
        schema_version: "buzz-ci-acceptance-control-error/v1",
        code: error.code(),
        message: match error {
            ControlError::InvalidConfig => "control configuration rejected",
            ControlError::BindingMismatch => "control binding rejected",
            ControlError::HostAction => "host action failed",
            ControlError::ReadbackMismatch => "host readback rejected",
            ControlError::StaleGeneration => "host generation rejected",
            ControlError::ReplayMismatch => "operation replay rejected",
            ControlError::Ledger => "operation ledger unavailable",
        },
    };
    if serde_json::to_writer(std::io::stderr().lock(), &line).is_ok() {
        eprintln!();
    }
}
