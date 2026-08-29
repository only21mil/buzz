use std::io::{self, Read};

use buzz_ci_acceptance_ctl::acceptance::{
    parse_scenario, run_acceptance, CommandAcceptanceDriver, Outcome, MAX_SCENARIO_BYTES,
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorLine<'a> {
    schema_version: &'static str,
    code: &'static str,
    message: &'a str,
}

fn main() {
    if std::env::args_os().len() != 1 {
        emit_error(
            "invalid_cli",
            "this command accepts only scenario JSON on stdin",
        );
        std::process::exit(2);
    }

    let mut input = Vec::new();
    if let Err(error) = io::stdin()
        .take((MAX_SCENARIO_BYTES + 1) as u64)
        .read_to_end(&mut input)
    {
        emit_error("input_read_error", &error.to_string());
        std::process::exit(2);
    }

    let scenario = match parse_scenario(&input) {
        Ok(scenario) => scenario,
        Err(error) => {
            emit_error(error.code(), &error.to_string());
            std::process::exit(2);
        }
    };
    let mut driver = CommandAcceptanceDriver::new(scenario.driver.clone());
    let receipt = run_acceptance(&scenario, &mut driver);
    let outcome = receipt.outcome;
    if serde_json::to_writer_pretty(io::stdout().lock(), &receipt).is_err() {
        emit_error("output_write_error", "could not write acceptance receipt");
        std::process::exit(3);
    }
    println!();
    if outcome != Outcome::Pass {
        std::process::exit(1);
    }
}

fn emit_error(code: &'static str, message: &str) {
    let line = ErrorLine {
        schema_version: "buzz-ci-capacity-one-acceptance-error/v1",
        code,
        message,
    };
    if serde_json::to_writer(io::stderr().lock(), &line).is_ok() {
        eprintln!();
    }
}
