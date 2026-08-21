use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!("buzz-ci-runner {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        (Some(arg), None) if arg == "--help" || arg == "-h" => {
            println!("usage: buzz-ci-runner [--help|--version]");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(r#"{{"error":"execution_backend_unavailable"}}"#);
            ExitCode::from(4)
        }
    }
}
