use std::io::{self, Read};

use buzz_ci_acceptance_ctl::{
    dispatch, response_code_name, DispatchError, UnixQualificationTransport, MAX_INPUT_BYTES,
};
use buzz_ci_broker_protocol::{BrokerResponse, BrokerState, Conclusion};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorLine<'a> {
    r#type: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    message: &'a str,
}

#[derive(Serialize)]
struct ResultLine {
    r#type: &'static str,
    code: &'static str,
    attempt_id: String,
    broker_state: &'static str,
    conclusion: &'static str,
    generation: u64,
    lease_generation: u64,
    updated_at: u64,
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
    if let Err(error) = io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
    {
        emit_error("input_read_error", None, &error.to_string());
        std::process::exit(2);
    }

    let mut transport = UnixQualificationTransport::new();
    match dispatch(&input, &mut transport) {
        Ok(()) => match transport.response() {
            Some(response) => emit_result(response),
            None => {
                emit_error(
                    "invalid_broker_response",
                    None,
                    "broker returned no response",
                );
                std::process::exit(3);
            }
        },
        Err(DispatchError::Input(error)) => {
            emit_error(error.code(), error.field(), &error.to_string());
            std::process::exit(2);
        }
        Err(DispatchError::Transport(error)) => {
            emit_error(error.code(), None, &error.to_string());
            std::process::exit(3);
        }
    }
}

fn emit_result(response: BrokerResponse) {
    let line = ResultLine {
        r#type: "qualification_result",
        code: response_code_name(response.code),
        attempt_id: encode_hex(&response.attempt_id),
        broker_state: broker_state_name(response.broker_state),
        conclusion: conclusion_name(response.conclusion),
        generation: response.generation,
        lease_generation: response.lease_generation,
        updated_at: response.updated_at,
    };
    if serde_json::to_writer(io::stdout().lock(), &line).is_err() {
        emit_error("output_write_error", None, "could not write result");
        std::process::exit(3);
    }
    println!();
}

const fn broker_state_name(state: BrokerState) -> &'static str {
    match state {
        BrokerState::Booting => "booting",
        BrokerState::Reconciling => "reconciling",
        BrokerState::Ready => "ready",
        BrokerState::Draining => "draining",
        BrokerState::Quarantined => "quarantined",
        BrokerState::Terminal => "terminal",
    }
}

const fn conclusion_name(conclusion: Conclusion) -> &'static str {
    match conclusion {
        Conclusion::None => "none",
        Conclusion::Success => "success",
        Conclusion::Failure => "failure",
        Conclusion::Cancelled => "cancelled",
        Conclusion::TimedOut => "timed_out",
        Conclusion::InfrastructureFailure => "infrastructure_failure",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn emit_error(code: &'static str, field: Option<&'static str>, message: &str) {
    let line = ErrorLine {
        r#type: "qualification_error",
        code,
        field,
        message,
    };
    if serde_json::to_writer(io::stderr().lock(), &line).is_ok() {
        eprintln!();
    }
}
