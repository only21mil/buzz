//! Standalone test adapter for the existing cron dependency, not a scheduler.
//! Compile with rustc --edition=2021 --extern cron=<cached rlib> -L dependency=<deps>.
use cron::{Schedule, TimeUnitSpec};

fn main() {
    for expression in std::env::args().skip(1) {
        // Match the relay's five-field normalization without changing runtime code.
        let normalized = format!("0 {expression} *");
        let schedule: Schedule = normalized.parse().expect("valid emitted cron");
        println!(
            "{}",
            schedule
                .days_of_week()
                .iter()
                .map(|day| day.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}
