//! Read a signed CI fixture from stdin and print the relay-selected job-attempt graph.

use std::{io, process::ExitCode};

use buzz_relay::ci::{reduce_signed_ci_graph, SignedCiGraphInput};
use serde_json::json;

fn main() -> ExitCode {
    let input = match serde_json::from_reader::<_, SignedCiGraphInput>(io::stdin().lock()) {
        Ok(input) => input,
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error": "invalid_input", "reason": error.to_string()})
            );
            return ExitCode::from(1);
        }
    };

    match reduce_signed_ci_graph(&input) {
        Ok(graph) => match serde_json::to_writer(io::stdout().lock(), &graph) {
            Ok(()) => {
                println!();
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({"error": "output_failure", "reason": error.to_string()})
                );
                ExitCode::from(4)
            }
        },
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error": error.code(), "reason": error.to_string()})
            );
            ExitCode::from(1)
        }
    }
}
