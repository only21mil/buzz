use std::{
    io::{self, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use buzz_ci_acceptance_ctl::production_qualification::{
    dispatch, DispatchError, UnixProductionQualificationTransport, MAX_INPUT_BYTES,
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorLine<'a> {
    schema_version: &'static str,
    status: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    message: &'a str,
}

fn main() {
    if std::env::args_os().len() != 1 {
        emit_error(
            "invalid_cli",
            None,
            "this command accepts only JSON on stdin",
        );
        std::process::exit(2);
    }
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        emit_error(
            "input_read_error",
            None,
            "could not read qualification request",
        );
        std::process::exit(2);
    }
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs(),
        Err(_) => {
            emit_error("clock_error", None, "system clock is before the Unix epoch");
            std::process::exit(3);
        }
    };
    let mut transport = UnixProductionQualificationTransport::new();
    match dispatch(&input, now, &mut transport) {
        Ok(receipt) => {
            if serde_json::to_writer(io::stdout().lock(), &receipt).is_err() {
                emit_error(
                    "output_write_error",
                    None,
                    "could not write qualification receipt",
                );
                std::process::exit(3);
            }
            println!();
        }
        Err(DispatchError::Input(error)) => {
            emit_error(error.code(), error.field(), &error.to_string());
            std::process::exit(2);
        }
        Err(DispatchError::Exchange(error)) => {
            emit_error(error.code(), None, &error.to_string());
            std::process::exit(3);
        }
    }
}

fn emit_error(code: &'static str, field: Option<&'static str>, message: &str) {
    let line = ErrorLine {
        schema_version: "buzz-ci-production-qualification-error/v2",
        status: "qualification_failed_closed",
        code,
        field,
        message,
    };
    if serde_json::to_writer(io::stderr().lock(), &line).is_ok() {
        eprintln!();
    }
}
