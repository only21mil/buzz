use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!("buzz-ci-runner {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        (None, None) => {
            eprintln!(r#"{{"error":"not_provisioned","capacity":0}}"#);
            ExitCode::from(4)
        }
        _ => {
            eprintln!(r#"{{"error":"usage","expected":"--version"}}"#);
            ExitCode::from(1)
        }
    }
}
