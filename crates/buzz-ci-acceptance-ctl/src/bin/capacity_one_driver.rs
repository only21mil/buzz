#![deny(unsafe_code)]

use std::{
    io::{self, Read},
    path::Path,
};

use buzz_ci_acceptance_ctl::{
    acceptance::{AcceptanceDriver, ZeroRequest, ZERO_REQUEST_VERSION},
    production::{
        DriverError, OwnedDriverRequest, ProductionDriver, ProductionDriverConfig,
        UnixAdapterTransport, DRIVER_CONFIG_PATH, MAX_ADAPTER_FRAME_BYTES,
    },
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorLine {
    schema_version: &'static str,
    code: &'static str,
    message: &'static str,
}

fn main() {
    if std::env::args_os().len() != 1 {
        fail(DriverError::BindingMismatch, 2);
    }
    let mut input = Vec::new();
    if io::stdin()
        .take(MAX_ADAPTER_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > MAX_ADAPTER_FRAME_BYTES
    {
        fail(DriverError::FrameTooLarge, 2);
    }
    let schema_version = serde_json::from_slice::<serde_json::Value>(&input)
        .ok()
        .and_then(|value| value.get("schema_version")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| fail(DriverError::Protocol, 2));
    let (uid, gid) = effective_ids();
    let config = match ProductionDriverConfig::load(Path::new(DRIVER_CONFIG_PATH), gid) {
        Ok(value) if value.qualification_uid == uid && value.qualification_gid == gid => value,
        Ok(_) => fail(DriverError::InvalidConfig, 3),
        Err(error) => fail(error, 3),
    };
    let transport = UnixAdapterTransport::new(config.clone());
    let mut driver = match ProductionDriver::new(config, transport) {
        Ok(value) => value,
        Err(error) => fail(error, 3),
    };
    let response = if schema_version == ZERO_REQUEST_VERSION {
        let request: ZeroRequest =
            serde_json::from_slice(&input).unwrap_or_else(|_| fail(DriverError::Protocol, 2));
        serde_json::to_value(
            driver
                .return_to_zero(&request)
                .unwrap_or_else(|error| fail(error, 4)),
        )
        .unwrap_or_else(|_| fail(DriverError::Protocol, 4))
    } else {
        let owned: OwnedDriverRequest =
            serde_json::from_slice(&input).unwrap_or_else(|_| fail(DriverError::Protocol, 2));
        if let Err(error) = owned.validate_version() {
            fail(error, 2);
        }
        serde_json::to_value(
            driver
                .execute(&owned.borrowed())
                .unwrap_or_else(|error| fail(error, 4)),
        )
        .unwrap_or_else(|_| fail(DriverError::Protocol, 4))
    };
    if serde_json::to_writer(io::stdout().lock(), &response).is_err() {
        fail(DriverError::Protocol, 4);
    }
    println!();
}

#[cfg(target_os = "linux")]
fn effective_ids() -> (u32, u32) {
    (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

#[cfg(not(target_os = "linux"))]
fn effective_ids() -> (u32, u32) {
    (0, 0)
}

fn fail(error: DriverError, status: i32) -> ! {
    let line = ErrorLine {
        schema_version: "buzz-ci-capacity-one-driver-error/v1",
        code: error.code(),
        message: match error {
            DriverError::InvalidConfig => "driver configuration rejected",
            DriverError::BindingMismatch => "driver binding rejected",
            DriverError::Transport => "adapter unavailable",
            DriverError::WrongPeer => "adapter peer rejected",
            DriverError::FrameTooLarge => "adapter frame rejected",
            DriverError::Protocol => "adapter response rejected",
            DriverError::StaleGeneration => "adapter generation rejected",
            DriverError::UnsupportedPlatform => "platform rejected",
        },
    };
    if serde_json::to_writer(io::stderr().lock(), &line).is_ok() {
        eprintln!();
    }
    std::process::exit(status);
}
